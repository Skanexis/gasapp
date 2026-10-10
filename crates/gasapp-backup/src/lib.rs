// SPDX-License-Identifier: Apache-2.0

//! Zero-knowledge backup и recovery key.
//!
//! # Обещание
//!
//! Сервер, облако и всякий, кому попал файл копии, видят шум.
//! Расшифровать копию можно только recovery key, который существует
//! ровно в одном месте — там, куда его записал пользователь.
//! Сброса по почте или SMS нет и не будет (обещание №4 раздела 2):
//! механизм сброса означал бы, что кто-то кроме пользователя может
//! получить доступ к копии, — а значит, и что его можно принудить.
//!
//! # Слои
//!
//! | Модуль | Отвечает за |
//! |---|---|
//! | [`recovery_key`] | 256 бит в Crockford Base32, контрольная сумма |
//! | [`kdf`] | Argon2id → BRK, HKDF → три рабочих ключа |
//! | [`bundle`] | что попадает в копию, а что — никогда |
//! | [`archive`] | файл копии: заголовок, XChaCha20-Poly1305, целостность |
//!
//! # Как это выглядит целиком
//!
//! ```text
//!   recovery key ──Argon2id(соль из заголовка)──▶ BRK
//!                                                  │ HKDF
//!                           ┌──────────────────────┼──────────────┐
//!                           ▼                      ▼              ▼
//!                     K_backup_data            K_meta       K_backup_att
//!                       (тело)              (метаданные)   (файлы vault)
//! ```
//!
//! # Инкрементальность
//!
//! Полный снимок делается один раз, дальше идут инкременты — только
//! то, что изменилось. Цепочка скрепляется SHA-256: каждый инкремент
//! помнит хеш предыдущего файла, и этот хеш аутентифицирован тегом
//! AEAD. Восстановление проверяет цепочку звено за звеном и
//! отказывается работать с разорванной — молча восстановить «сколько
//! получилось» значило бы отчитаться об успехе, потеряв часть
//! переписки.
//!
//! # Пример
//!
//! ```
//! use gasapp_backup::{BackupChain, RecoveryKey};
//! use gasapp_backup::bundle::BackupBundle;
//! use gasapp_backup::kdf::KdfParams;
//! use rand_core::OsRng;
//!
//! # fn main() -> Result<(), gasapp_types::GasAppError> {
//! // Параметры взяты облегчёнными, чтобы пример считался быстро;
//! // в приложении используется `KdfParams::default()`.
//! let params = KdfParams { memory_kib: 32 * 1024, iterations: 2, parallelism: 1 };
//!
//! let key = RecoveryKey::generate(&mut OsRng);
//! let mut chain = BackupChain::start(&key, params, &mut OsRng)?;
//!
//! let snapshot = chain.seal_full(&BackupBundle::default(), None, &mut OsRng)?;
//!
//! let restored = BackupChain::restore(&key, &[snapshot])?;
//! assert!(restored.bundle.is_empty());
//! # Ok(())
//! # }
//! ```

pub mod archive;
pub mod bundle;
pub mod kdf;
pub mod recovery_key;

pub use archive::{ArchiveHeader, ArchiveKind, ArchiveMeta};
pub use bundle::BackupBundle;
pub use kdf::{BackupRootKey, KdfParams};
pub use recovery_key::RecoveryKey;

use gasapp_types::{GasAppError, Result};

/// Версия крейта, доступная во время выполнения.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Предел длины цепочки инкрементов.
///
/// 🔐 Восстановление разбирает звенья по очереди, и каждое стоит
/// одного Argon2id... нет — BRK выводится один раз на всю цепочку.
/// Предел здесь про другое: цепочка из миллиона звеньев означает
/// миллион файлов в облаке и минуты на слияние. После сотни
/// инкрементов приложение делает новый полный снимок.
pub const MAX_CHAIN_LEN: usize = 128;

/// Итог восстановления.
#[derive(Debug, Clone)]
pub struct RestoredBackup {
    /// Собранное состояние после применения всей цепочки.
    pub bundle: BackupBundle,
    /// Метаданные последнего звена.
    pub meta: ArchiveMeta,
    /// Сколько звеньев применено.
    pub applied: usize,
}

/// Цепочка резервных копий одного recovery key.
///
/// # Зачем состояние
///
/// Соль и параметры растягивания одни на всю цепочку: иначе каждое
/// звено требовало бы отдельного Argon2id, и восстановление ста
/// инкрементов заняло бы минуты вместо секунд. Цепочка хранит
/// выведенный BRK и хеш последнего файла — то, что нужно, чтобы
/// дописать следующий инкремент.
pub struct BackupChain {
    root: BackupRootKey,
    salt: [u8; kdf::SALT_LEN],
    params: KdfParams,
    generation: u32,
    last_digest: [u8; archive::DIGEST_LEN],
}

impl core::fmt::Debug for BackupChain {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BackupChain")
            .field("generation", &self.generation)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl BackupChain {
    /// Начинает новую цепочку: новая соль, новый BRK.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — параметры вне границ;
    /// [`GasAppError::Crypto`] — сбой Argon2id.
    pub fn start<R: rand_core::RngCore + rand_core::CryptoRng>(
        recovery_key: &RecoveryKey,
        params: KdfParams,
        rng: &mut R,
    ) -> Result<Self> {
        let salt = kdf::generate_salt(rng);

        Self::resume(recovery_key, salt, params, 0, [0u8; archive::DIGEST_LEN])
    }

    /// Продолжает существующую цепочку.
    ///
    /// Соль, параметры, номер поколения и хеш последнего файла
    /// приложение хранит рядом с базой — этого достаточно, чтобы
    /// дописать инкремент, не читая прежние файлы из облака.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — параметры вне границ;
    /// [`GasAppError::Crypto`] — сбой Argon2id.
    pub fn resume(
        recovery_key: &RecoveryKey,
        salt: [u8; kdf::SALT_LEN],
        params: KdfParams,
        generation: u32,
        last_digest: [u8; archive::DIGEST_LEN],
    ) -> Result<Self> {
        let root = BackupRootKey::derive(recovery_key, &salt, params)?;

        Ok(Self {
            root,
            salt,
            params,
            generation,
            last_digest,
        })
    }

    /// Соль цепочки — её нужно сохранить рядом с базой.
    #[must_use]
    pub const fn salt(&self) -> &[u8; kdf::SALT_LEN] {
        &self.salt
    }

    /// Параметры растягивания цепочки.
    #[must_use]
    pub const fn params(&self) -> KdfParams {
        self.params
    }

    /// Номер последнего записанного поколения.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Хеш последнего записанного файла.
    #[must_use]
    pub const fn last_digest(&self) -> &[u8; archive::DIGEST_LEN] {
        &self.last_digest
    }

    /// Проверочное значение ключа цепочки — см. [`kdf::BackupRootKey::key_check`].
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой HKDF.
    pub fn key_check(&self) -> Result<[u8; kdf::KEY_LEN]> {
        self.root.key_check()
    }

    /// Собирает полный снимок — начало цепочки.
    ///
    /// Сбрасывает номер поколения в ноль: полный снимок делает
    /// прежние звенья ненужными.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — бандл вне пределов;
    /// [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_full<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        bundle: &BackupBundle,
        device_label: Option<&str>,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let header = ArchiveHeader {
            kind: ArchiveKind::Full,
            generation: 0,
            params: self.params,
            salt: self.salt,
            parent_digest: [0u8; archive::DIGEST_LEN],
        };

        let sealed = archive::seal(
            &self.root,
            &header,
            &meta_for(bundle, device_label)?,
            bundle,
            rng,
        )?;

        self.generation = 0;
        self.last_digest = archive::digest(&sealed);

        Ok(sealed)
    }

    /// Собирает инкремент поверх последнего звена.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Uninitialized`] — цепочка ещё не начата полным
    /// снимком: инкременту не на что ссылаться;
    /// [`GasAppError::Malformed`] — цепочка достигла [`MAX_CHAIN_LEN`]
    /// либо бандл вне пределов;
    /// [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_increment<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        bundle: &BackupBundle,
        device_label: Option<&str>,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if self.last_digest == [0u8; archive::DIGEST_LEN] {
            return Err(GasAppError::Uninitialized);
        }

        let generation = self
            .generation
            .checked_add(1)
            .ok_or(GasAppError::Malformed)?;

        if usize::try_from(generation).unwrap_or(usize::MAX) >= MAX_CHAIN_LEN {
            return Err(GasAppError::Malformed);
        }

        let header = ArchiveHeader {
            kind: ArchiveKind::Increment,
            generation,
            params: self.params,
            salt: self.salt,
            parent_digest: self.last_digest,
        };

        let sealed = archive::seal(
            &self.root,
            &header,
            &meta_for(bundle, device_label)?,
            bundle,
            rng,
        )?;

        self.generation = generation;
        self.last_digest = archive::digest(&sealed);

        Ok(sealed)
    }

    /// Восстанавливает состояние из цепочки файлов.
    ///
    /// Звенья передаются в порядке создания: сначала полный снимок,
    /// затем инкременты.
    ///
    /// # Что проверяется
    ///
    /// 1. Цепочка не пуста и не длиннее [`MAX_CHAIN_LEN`].
    /// 2. Первое звено — полный снимок, остальные — инкременты.
    /// 3. Номера поколений идут подряд без пропусков.
    /// 4. 🔐 SHA-256 каждого файла совпадает со ссылкой в следующем.
    /// 5. 🔐 Соль и параметры одни на всю цепочку.
    ///
    /// Любое расхождение — отказ целиком. Восстановить «сколько
    /// получилось» здесь нельзя: пользователь решит, что копия
    /// цела, и сотрёт остальное.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — цепочка пуста, слишком длинна,
    /// собрана не в том порядке либо разорвана;
    /// [`GasAppError::Crypto`] — не тот recovery key либо файл изменён.
    pub fn restore(recovery_key: &RecoveryKey, links: &[Vec<u8>]) -> Result<RestoredBackup> {
        let first = links.first().ok_or(GasAppError::Malformed)?;

        if links.len() > MAX_CHAIN_LEN {
            return Err(GasAppError::Malformed);
        }

        // Соль и параметры читаются из первого звена: только оно
        // задаёт их для всей цепочки.
        let head = ArchiveHeader::from_bytes(first)?;

        if head.kind != ArchiveKind::Full {
            return Err(GasAppError::Malformed);
        }

        // 🔐 Единственный Argon2id на всё восстановление. Он стоит
        // здесь, а не в цикле, именно поэтому: цепочка из сотни
        // звеньев не должна стоить сотни растягиваний.
        let root = BackupRootKey::derive(recovery_key, &head.salt, head.params)?;

        let mut state = BackupBundle::default();
        let mut last_meta = ArchiveMeta::default();
        let mut expected_parent = [0u8; archive::DIGEST_LEN];

        for (index, raw) in links.iter().enumerate() {
            let header = ArchiveHeader::from_bytes(raw)?;

            // 🔐 Соль и параметры обязаны совпадать: звено с другой
            // солью выведено другим BRK, то есть принадлежит другой
            // цепочке и попало сюда либо по ошибке, либо подложено.
            if header.salt != head.salt || header.params != head.params {
                return Err(GasAppError::Malformed);
            }

            let expected_generation = u32::try_from(index).map_err(|_| GasAppError::Malformed)?;
            if header.generation != expected_generation {
                return Err(GasAppError::Malformed);
            }

            let expected_kind = if index == 0 {
                ArchiveKind::Full
            } else {
                ArchiveKind::Increment
            };
            if header.kind != expected_kind {
                return Err(GasAppError::Malformed);
            }

            // 🔐 Собственно проверка целостности цепочки: хеш
            // предыдущего файла обязан совпасть со ссылкой в этом.
            if header.parent_digest != expected_parent {
                return Err(GasAppError::Malformed);
            }

            let (_, meta, increment) = archive::open(&root, raw)?;

            state.merge(increment);
            last_meta = meta;
            expected_parent = archive::digest(raw);
        }

        Ok(RestoredBackup {
            bundle: state,
            meta: last_meta,
            applied: links.len(),
        })
    }

    /// Читает метаданные звена, не расшифровывая тело.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — файл не разбирается;
    /// [`GasAppError::Crypto`] — не тот ключ.
    pub fn peek(&self, raw: &[u8]) -> Result<ArchiveMeta> {
        archive::open_meta(&self.root, raw)
    }

    /// Шифрует локальный файл ключом вложений цепочки.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_file<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        archive::seal_file(&self.root, plaintext, rng)
    }

    /// Расшифровывает файл, зашифрованный [`BackupChain::seal_file`].
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — файл короче nonce;
    /// [`GasAppError::Crypto`] — тег не сходится.
    pub fn open_file(&self, raw: &[u8]) -> Result<Vec<u8>> {
        archive::open_file(&self.root, raw)
    }
}

/// Собирает метаданные звена по его содержимому.
fn meta_for(bundle: &BackupBundle, device_label: Option<&str>) -> Result<ArchiveMeta> {
    Ok(ArchiveMeta {
        created_at_millis: bundle.created_at_millis,
        record_count: u32::try_from(bundle.record_count()).map_err(|_| GasAppError::Malformed)?,
        message_count: u32::try_from(bundle.messages.len()).map_err(|_| GasAppError::Malformed)?,
        device_label: device_label.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{ContactRecord, MessageRecord, ID_LEN};
    use rand_core::OsRng;

    /// Дешёвые параметры: схема та же, стоимость меньше.
    fn cheap() -> KdfParams {
        KdfParams {
            memory_kib: kdf::MIN_MEMORY_KIB,
            iterations: kdf::MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    fn message(id: u8) -> MessageRecord {
        MessageRecord {
            id: [id; ID_LEN],
            chat_id: [0x11; ID_LEN],
            sender_id: [0x22; ID_LEN],
            timestamp_millis: 1_760_000_000_000,
            content: vec![id; 48],
            status: 1,
            message_type: 0,
            expires_at_millis: None,
        }
    }

    /// Версия крейта должна следовать формату MAJOR.MINOR.PATCH.
    #[test]
    fn crate_version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();

        assert_eq!(parts.len(), 3, "ожидался формат MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "компонент версии не является числом: {part}"
            );
        }
    }

    /// Полный снимок восстанавливается один в один.
    #[test]
    fn full_snapshot_round_trips() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let bundle = BackupBundle {
            created_at_millis: 1_760_000_000_000,
            messages: vec![message(1), message(2)],
            ..BackupBundle::default()
        };

        let sealed = chain
            .seal_full(&bundle, Some("Pixel 6a"), &mut OsRng)
            .expect("снимок");

        let restored = BackupChain::restore(&key, &[sealed]).expect("восстановление");

        assert_eq!(restored.bundle, bundle);
        assert_eq!(restored.applied, 1);
        assert_eq!(restored.meta.message_count, 2);
        assert_eq!(restored.meta.device_label.as_deref(), Some("Pixel 6a"));
    }

    /// Цепочка снимок → инкремент → инкремент собирается верно.
    #[test]
    fn increments_apply_in_order() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("снимок");

        let first = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(2)],
                    contacts: vec![ContactRecord {
                        account_id: [7; ID_LEN],
                        identity_key: vec![8; 32],
                        username: Some("bob".to_owned()),
                        chat_id: None,
                        verified: true,
                        confirmed_by_link: false,
                        added_at_millis: None,
                    }],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        let second = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(3)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        let restored =
            BackupChain::restore(&key, &[snapshot, first, second]).expect("восстановление");

        assert_eq!(restored.applied, 3);
        assert_eq!(restored.bundle.messages.len(), 3);
        assert_eq!(restored.bundle.contacts.len(), 1);
    }

    /// 🔐 Удаление, приехавшее инкрементом, переживает восстановление.
    ///
    /// Без этого исчезающие сообщения возвращались бы из копии —
    /// то есть функция «сообщение исчезает» переставала бы работать.
    #[test]
    fn tombstone_survives_restore() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(
                &BackupBundle {
                    messages: vec![message(1), message(2)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("снимок");

        let increment = chain
            .seal_increment(
                &BackupBundle {
                    tombstones: vec![[1; ID_LEN]],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        let restored = BackupChain::restore(&key, &[snapshot, increment]).expect("восстановление");

        assert_eq!(restored.bundle.messages.len(), 1);
        assert_eq!(
            restored.bundle.messages.first().map(|record| record.id),
            Some([2; ID_LEN])
        );
    }

    /// 🧪 Задача M6: без recovery key копия не расшифровывается.
    #[test]
    fn chain_does_not_open_without_the_recovery_key() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("снимок");

        let wrong = RecoveryKey::generate(&mut OsRng);

        assert!(matches!(
            BackupChain::restore(&wrong, &[snapshot]),
            Err(GasAppError::Crypto)
        ));
    }

    /// 🔐 Пропущенное звено ломает восстановление.
    #[test]
    fn missing_link_breaks_the_chain() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");
        let _skipped = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");
        let third = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(2)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        // Второе звено потеряно: цепочка обязана распасться,
        // а не восстановиться наполовину.
        assert!(matches!(
            BackupChain::restore(&key, &[snapshot, third]),
            Err(GasAppError::Malformed)
        ));
    }

    /// 🔐 Перестановка звеньев ломает восстановление.
    #[test]
    fn reordered_links_break_the_chain() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");
        let first = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");
        let second = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(2)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        assert!(BackupChain::restore(&key, &[snapshot, second, first]).is_err());
    }

    /// 🔐 Звено из чужой цепочки не подставляется.
    #[test]
    fn link_from_another_chain_is_rejected() {
        let key = RecoveryKey::generate(&mut OsRng);

        let mut first_chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");
        let snapshot = first_chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");

        // Вторая цепочка тем же ключом, но с другой солью.
        let mut second_chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");
        let _ = second_chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");
        let foreign = second_chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        assert!(matches!(
            BackupChain::restore(&key, &[snapshot, foreign]),
            Err(GasAppError::Malformed)
        ));
    }

    /// Цепочка, начатая с инкремента, отвергается.
    #[test]
    fn chain_must_start_with_a_full_snapshot() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");
        let increment = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        drop(snapshot);

        assert!(matches!(
            BackupChain::restore(&key, &[increment]),
            Err(GasAppError::Malformed)
        ));
    }

    /// Пустая цепочка отвергается.
    #[test]
    fn empty_chain_is_rejected() {
        let key = RecoveryKey::generate(&mut OsRng);

        assert!(matches!(
            BackupChain::restore(&key, &[]),
            Err(GasAppError::Malformed)
        ));
    }

    /// Инкремент без снимка невозможен.
    #[test]
    fn increment_requires_a_snapshot_first() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        assert!(matches!(
            chain.seal_increment(&BackupBundle::default(), None, &mut OsRng),
            Err(GasAppError::Uninitialized)
        ));
    }

    /// Цепочку можно продолжить после перезапуска приложения.
    ///
    /// Именно ради этого соль, поколение и хеш последнего файла
    /// отдаются наружу: приложение хранит их рядом с базой.
    #[test]
    fn chain_resumes_from_stored_state() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");

        let salt = *chain.salt();
        let generation = chain.generation();
        let digest = *chain.last_digest();
        drop(chain);

        let mut resumed =
            BackupChain::resume(&key, salt, cheap(), generation, digest).expect("цепочка");
        let increment = resumed
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        let restored = BackupChain::restore(&key, &[snapshot, increment]).expect("восстановление");

        assert_eq!(restored.bundle.messages.len(), 1);
    }

    /// Новый полный снимок начинает нумерацию заново.
    #[test]
    fn full_snapshot_resets_generation() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let _ = chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");
        let _ = chain
            .seal_increment(
                &BackupBundle {
                    messages: vec![message(1)],
                    ..BackupBundle::default()
                },
                None,
                &mut OsRng,
            )
            .expect("инкремент");

        assert_eq!(chain.generation(), 1);

        let fresh = chain
            .seal_full(&BackupBundle::default(), None, &mut OsRng)
            .expect("снимок");

        assert_eq!(chain.generation(), 0);
        assert_eq!(
            BackupChain::restore(&key, &[fresh])
                .expect("восстановление")
                .applied,
            1
        );
    }

    /// Метаданные читаются без расшифровки тела.
    #[test]
    fn peek_reads_meta_only() {
        let key = RecoveryKey::generate(&mut OsRng);
        let mut chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let snapshot = chain
            .seal_full(
                &BackupBundle {
                    created_at_millis: 1_760_000_000_000,
                    messages: vec![message(1), message(2), message(3)],
                    ..BackupBundle::default()
                },
                Some("Pixel 6a"),
                &mut OsRng,
            )
            .expect("снимок");

        let meta = chain.peek(&snapshot).expect("метаданные");

        assert_eq!(meta.message_count, 3);
        assert_eq!(meta.created_at_millis, 1_760_000_000_000);
    }

    /// Debug цепочки не раскрывает ключевой материал.
    #[test]
    fn debug_does_not_leak_key_material() {
        let key = RecoveryKey::generate(&mut OsRng);
        let chain = BackupChain::start(&key, cheap(), &mut OsRng).expect("цепочка");

        let text = format!("{chain:?}");

        assert!(
            !text.contains("root"),
            "в Debug попал корневой ключ: {text}"
        );
        assert!(!text.contains("salt"), "в Debug попала соль: {text}");
    }
}
