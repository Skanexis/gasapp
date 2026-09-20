// SPDX-License-Identifier: Apache-2.0

//! Файл резервной копии: заголовок, шифрование, цепочка целостности.
//!
//! # Что видит тот, у кого файл, но нет recovery key
//!
//! Заголовок и шум. Заголовок обязан быть открытым: в нём соль
//! и параметры Argon2id, без которых ключ не вывести, — то есть
//! прочитать их нужно **до** того, как появится чем расшифровать.
//! Всё остальное — тело копии и её метаданные — шифротекст.
//!
//! Из заголовка наблюдатель узнаёт: перед ним копия AEGIS, её номер
//! в цепочке, параметры растягивания и приблизительный объём.
//! Ни имени пользователя, ни числа собеседников, ни времени
//! последнего сообщения он не узнаёт: всё это лежит в блоке
//! метаданных под отдельным ключом.
//!
//! # Почему XChaCha20-Poly1305, а не AES-GCM
//!
//! У XChaCha nonce длиной 192 бита, и его можно брать случайным
//! без риска совпадения: вероятность коллизии остаётся ничтожной
//! после любого разумного числа копий. У AES-GCM nonce 96 бит,
//! и случайный выбор там уже требует считать, сколько раз ключ
//! использован. Резервные копии делаются в фоне много раз подряд
//! одним и тем же BRK — это ровно тот случай, ради которого
//! существует расширенный nonce.
//!
//! # Цепочка
//!
//! ```text
//!   поколение 0 (полный снимок)
//!        │  digest = SHA-256(весь файл)
//!        ▼
//!   поколение 1 (инкремент, помнит digest родителя)
//!        │
//!        ▼
//!   поколение 2 (инкремент, помнит digest поколения 1)
//! ```
//!
//! 🔐 Каждый инкремент несёт SHA-256 предыдущего файла, и этот
//! digest входит в AAD — то есть подписан тегом AEAD. Подменить
//! или переставить звено, не зная recovery key, нельзя: тег
//! перестанет сходиться. Правило раздела 12.3 «каждый инкремент
//! проверяется по SHA-256» реализовано именно так.

use aegis_types::{AegisError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};

use crate::bundle::BackupBundle;
use crate::kdf::{BackupRootKey, KdfParams, SALT_LEN};

/// Опознавательная последовательность в начале файла.
///
/// Нужна, чтобы «это не копия AEGIS» отличалось от «это копия,
/// но ключ не тот»: первое сообщение пользователю полезно,
/// второе — тревожно.
pub const MAGIC: &[u8; 8] = b"AEGISBK1";

/// Версия формата файла.
const ARCHIVE_VERSION: u8 = 1;

/// Длина nonce XChaCha20: 192 бита.
pub const NONCE_LEN: usize = 24;

/// Длина SHA-256.
pub const DIGEST_LEN: usize = 32;

/// Предел размера блока метаданных.
const MAX_META_LEN: usize = 64 * 1024;

/// Предел размера всего файла копии.
///
/// 🔐 Разбор начинается с чтения файла в память. Гигабайтный предел
/// не даёт подложенному файлу исчерпать её раньше, чем дело дойдёт
/// до проверки тега.
pub const MAX_ARCHIVE_LEN: usize = 1024 * 1024 * 1024;

/// Вид копии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// Полный снимок — начало цепочки.
    Full,
    /// Инкремент — только изменения с прошлого раза.
    Increment,
}

impl ArchiveKind {
    /// Числовое представление для заголовка.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Increment => 1,
        }
    }

    /// Разбирает вид из заголовка.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — неизвестное значение.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::Increment),
            _ => Err(AegisError::Malformed),
        }
    }
}

/// Открытая часть файла копии.
///
/// 🔐 Всё, что здесь лежит, читается без ключа. Поэтому здесь нет
/// ничего про содержимое переписки — только то, без чего копию
/// физически нельзя открыть.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveHeader {
    /// Вид копии.
    pub kind: ArchiveKind,
    /// Номер в цепочке: 0 у полного снимка.
    pub generation: u32,
    /// Параметры растягивания, которыми выведен BRK.
    pub params: KdfParams,
    /// Соль растягивания.
    pub salt: [u8; SALT_LEN],
    /// SHA-256 предыдущего файла цепочки.
    ///
    /// У полного снимка — нули: родителя нет.
    pub parent_digest: [u8; DIGEST_LEN],
}

impl ArchiveHeader {
    /// Длина заголовка в байтах.
    ///
    /// Считается из состава, а не пишется числом: при добавлении
    /// поля забыть поправить константу невозможно.
    const LEN: usize = MAGIC.len()
        + 1 // версия
        + 1 // вид
        + 4 // поколение
        + 4 // память
        + 4 // проходы
        + 4 // параллелизм
        + SALT_LEN
        + DIGEST_LEN;

    /// Сериализует заголовок.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);

        out.extend_from_slice(MAGIC);
        out.push(ARCHIVE_VERSION);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.params.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.params.iterations.to_be_bytes());
        out.extend_from_slice(&self.params.parallelism.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.parent_digest);

        out
    }

    /// Разбирает заголовок из начала файла.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — не та сигнатура, не та версия,
    /// короткий буфер либо параметры Argon2id вне допустимых границ.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let head = raw.get(..Self::LEN).ok_or(AegisError::Malformed)?;
        let mut offset = 0usize;

        let magic = take(head, &mut offset, MAGIC.len())?;
        if magic != MAGIC {
            return Err(AegisError::Malformed);
        }

        let version = *take(head, &mut offset, 1)?
            .first()
            .ok_or(AegisError::Malformed)?;
        if version != ARCHIVE_VERSION {
            return Err(AegisError::Malformed);
        }

        let kind = ArchiveKind::from_u8(
            *take(head, &mut offset, 1)?
                .first()
                .ok_or(AegisError::Malformed)?,
        )?;

        let generation = take_u32(head, &mut offset)?;
        let params = KdfParams {
            memory_kib: take_u32(head, &mut offset)?,
            iterations: take_u32(head, &mut offset)?,
            parallelism: take_u32(head, &mut offset)?,
        };

        // 🔐 Границы проверяются до того, как параметры попадут
        // в Argon2id: заголовок ещё не аутентифицирован — тег
        // проверяется ключом, которого без этих параметров нет, —
        // поэтому число в нём пишет кто угодно, кто держит файл.
        params.validate()?;

        let salt: [u8; SALT_LEN] = take(head, &mut offset, SALT_LEN)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?;
        let parent_digest: [u8; DIGEST_LEN] = take(head, &mut offset, DIGEST_LEN)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?;

        // У полного снимка родителя нет, и ссылка на него обязана
        // быть пустой: непустая означала бы, что звено вырвано
        // из цепочки и выдано за её начало.
        if kind == ArchiveKind::Full && parent_digest != [0u8; DIGEST_LEN] {
            return Err(AegisError::Malformed);
        }

        if kind == ArchiveKind::Increment && generation == 0 {
            return Err(AegisError::Malformed);
        }

        Ok(Self {
            kind,
            generation,
            params,
            salt,
            parent_digest,
        })
    }
}

/// Метаданные копии — то, что показывает Recovery Center.
///
/// 🔐 Шифруются отдельным ключом (`K_meta`) и отдельным nonce.
/// Смысл разделения практический: чтобы показать «последняя копия
/// два часа назад, 1247 сообщений», приложению не нужно тянуть
/// и расшифровывать всё тело. Ключ тела при этом не используется
/// вовсе — то есть список копий строится, не касаясь переписки.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveMeta {
    /// Когда собрана копия, в миллисекундах.
    pub created_at_millis: i64,
    /// Сколько записей внутри.
    pub record_count: u32,
    /// Сколько из них сообщений.
    pub message_count: u32,
    /// Метка устройства, собравшего копию.
    pub device_label: Option<String>,
}

impl ArchiveMeta {
    /// Сериализует метаданные.
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        out.extend_from_slice(&self.created_at_millis.to_be_bytes());
        out.extend_from_slice(&self.record_count.to_be_bytes());
        out.extend_from_slice(&self.message_count.to_be_bytes());

        match &self.device_label {
            None => out.push(0),
            Some(label) => {
                out.push(1);
                let bytes = label.as_bytes();
                let length = u32::try_from(bytes.len()).map_err(|_| AegisError::Malformed)?;
                out.extend_from_slice(&length.to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }

        Ok(out)
    }

    /// Разбирает метаданные.
    fn from_bytes(raw: &[u8]) -> Result<Self> {
        let mut offset = 0usize;

        let created_at_millis = i64::from_be_bytes(
            take(raw, &mut offset, 8)?
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
        );
        let record_count = take_u32(raw, &mut offset)?;
        let message_count = take_u32(raw, &mut offset)?;

        let present = *take(raw, &mut offset, 1)?
            .first()
            .ok_or(AegisError::Malformed)?;
        let device_label = match present {
            0 => None,
            1 => {
                let length = usize::try_from(take_u32(raw, &mut offset)?)
                    .map_err(|_| AegisError::Malformed)?;
                let bytes = take(raw, &mut offset, length)?;

                Some(String::from_utf8(bytes.to_vec()).map_err(|_| AegisError::Malformed)?)
            }
            _ => return Err(AegisError::Malformed),
        };

        if offset != raw.len() {
            return Err(AegisError::Malformed);
        }

        Ok(Self {
            created_at_millis,
            record_count,
            message_count,
            device_label,
        })
    }
}

/// Собирает зашифрованный файл копии.
///
/// # Что чем шифруется
///
/// * блок метаданных — ключом `K_meta`, AAD = заголовок;
/// * тело копии — ключом `K_backup_data`, AAD = заголовок вместе
///   с шифротекстом метаданных.
///
/// 🔐 Второй AAD не избыточен: без него шифротекст метаданных
/// одной копии переставлялся бы в другую, и Recovery Center показал
/// бы «свежая копия» поверх старого тела.
///
/// # Errors
///
/// [`AegisError::Malformed`] — бандл не проходит проверку пределов;
/// [`AegisError::Crypto`] — сбой вывода ключей или шифрования.
pub fn seal<R: rand_core::RngCore + rand_core::CryptoRng>(
    root: &BackupRootKey,
    header: &ArchiveHeader,
    meta: &ArchiveMeta,
    bundle: &BackupBundle,
    rng: &mut R,
) -> Result<Vec<u8>> {
    header.params.validate()?;

    let header_bytes = header.to_bytes();
    let meta_bytes = meta.to_bytes()?;
    let body_bytes = bundle.to_bytes()?;

    let meta_nonce = random_nonce(rng);
    let meta_cipher = cipher(root.meta_key()?.as_slice())?;
    let meta_ciphertext = meta_cipher
        .encrypt(
            XNonce::from_slice(&meta_nonce),
            Payload {
                msg: &meta_bytes,
                aad: &header_bytes,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    if meta_ciphertext.len() > MAX_META_LEN {
        return Err(AegisError::Malformed);
    }

    // AAD тела: заголовок, nonce метаданных и их шифротекст целиком.
    let mut body_aad = header_bytes.clone();
    body_aad.extend_from_slice(&meta_nonce);
    body_aad.extend_from_slice(&meta_ciphertext);

    let body_nonce = random_nonce(rng);
    let body_cipher = cipher(root.data_key()?.as_slice())?;
    let body_ciphertext = body_cipher
        .encrypt(
            XNonce::from_slice(&body_nonce),
            Payload {
                msg: &body_bytes,
                aad: &body_aad,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    let meta_len = u32::try_from(meta_ciphertext.len()).map_err(|_| AegisError::Malformed)?;

    let mut out = header_bytes;
    out.extend_from_slice(&meta_nonce);
    out.extend_from_slice(&meta_len.to_be_bytes());
    out.extend_from_slice(&meta_ciphertext);
    out.extend_from_slice(&body_nonce);
    out.extend_from_slice(&body_ciphertext);

    if out.len() > MAX_ARCHIVE_LEN {
        return Err(AegisError::Malformed);
    }

    Ok(out)
}

/// Читает метаданные копии, не расшифровывая тело.
///
/// # Errors
///
/// [`AegisError::Malformed`] — файл не разбирается;
/// [`AegisError::Crypto`] — тег не сходится: не тот recovery key
/// либо файл изменён.
pub fn open_meta(root: &BackupRootKey, raw: &[u8]) -> Result<ArchiveMeta> {
    let (_, meta, _) = split_and_open(root, raw, false)?;

    meta.ok_or(AegisError::Crypto)
}

/// Расшифровывает файл копии целиком.
///
/// # Errors
///
/// [`AegisError::Malformed`] — файл не разбирается;
/// [`AegisError::Crypto`] — тег не сходится.
pub fn open(
    root: &BackupRootKey,
    raw: &[u8],
) -> Result<(ArchiveHeader, ArchiveMeta, BackupBundle)> {
    let (header, meta, bundle) = split_and_open(root, raw, true)?;

    Ok((
        header,
        meta.ok_or(AegisError::Crypto)?,
        bundle.ok_or(AegisError::Crypto)?,
    ))
}

/// Общий разбор: заголовок, метаданные и — по требованию — тело.
fn split_and_open(
    root: &BackupRootKey,
    raw: &[u8],
    with_body: bool,
) -> Result<(ArchiveHeader, Option<ArchiveMeta>, Option<BackupBundle>)> {
    if raw.len() > MAX_ARCHIVE_LEN {
        return Err(AegisError::Malformed);
    }

    let header = ArchiveHeader::from_bytes(raw)?;
    let header_bytes = raw
        .get(..ArchiveHeader::LEN)
        .ok_or(AegisError::Malformed)?
        .to_vec();

    let mut offset = ArchiveHeader::LEN;

    let meta_nonce = take(raw, &mut offset, NONCE_LEN)?.to_vec();
    let meta_len =
        usize::try_from(take_u32(raw, &mut offset)?).map_err(|_| AegisError::Malformed)?;

    if meta_len > MAX_META_LEN {
        return Err(AegisError::Malformed);
    }

    let meta_ciphertext = take(raw, &mut offset, meta_len)?.to_vec();

    let meta_cipher = cipher(root.meta_key()?.as_slice())?;
    let meta_plain = meta_cipher
        .decrypt(
            XNonce::from_slice(&meta_nonce),
            Payload {
                msg: &meta_ciphertext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    let meta = ArchiveMeta::from_bytes(&meta_plain)?;

    if !with_body {
        return Ok((header, Some(meta), None));
    }

    let body_nonce = take(raw, &mut offset, NONCE_LEN)?.to_vec();
    let body_ciphertext = raw.get(offset..).ok_or(AegisError::Malformed)?;

    let mut body_aad = header_bytes;
    body_aad.extend_from_slice(&meta_nonce);
    body_aad.extend_from_slice(&meta_ciphertext);

    let body_cipher = cipher(root.data_key()?.as_slice())?;
    let body_plain = body_cipher
        .decrypt(
            XNonce::from_slice(&body_nonce),
            Payload {
                msg: body_ciphertext,
                aad: &body_aad,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    let bundle = BackupBundle::from_bytes(&body_plain)?;

    Ok((header, Some(meta), Some(bundle)))
}

/// Считает SHA-256 файла копии — то, что запомнит следующий инкремент.
#[must_use]
pub fn digest(raw: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(raw);

    let out = hasher.finalize();
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&out);

    digest
}

/// Шифрует локальный файл ключом вложений копии.
///
/// # Где это применяется
///
/// Блобы вложений переписки в копию не попадают: их адрес и ключ
/// лежат в описании внутри бандла, а сам блоб остаётся на сервере,
/// и восстановленное устройство скачивает его заново. Отдельный
/// ключ нужен для файлов, которых на сервере нет, — содержимого
/// File Vault, добавленного с устройства.
///
/// # Errors
///
/// [`AegisError::Crypto`] — сбой вывода ключа или шифрования.
pub fn seal_file<R: rand_core::RngCore + rand_core::CryptoRng>(
    root: &BackupRootKey,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let nonce = random_nonce(rng);
    let file_cipher = cipher(root.attachment_key()?.as_slice())?;

    let ciphertext = file_cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    let mut out = Vec::with_capacity(NONCE_LEN.saturating_add(ciphertext.len()));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Расшифровывает файл, зашифрованный [`seal_file`].
///
/// # Errors
///
/// [`AegisError::Malformed`] — файл короче nonce;
/// [`AegisError::Crypto`] — тег не сходится.
pub fn open_file(root: &BackupRootKey, raw: &[u8]) -> Result<Vec<u8>> {
    let nonce = raw.get(..NONCE_LEN).ok_or(AegisError::Malformed)?;
    let ciphertext = raw.get(NONCE_LEN..).ok_or(AegisError::Malformed)?;

    let file_cipher = cipher(root.attachment_key()?.as_slice())?;

    file_cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .map_err(|_| AegisError::Crypto)
}

/// Собирает шифр из ключа.
fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| AegisError::Crypto)
}

/// Случайный nonce XChaCha20.
///
/// 🔐 Именно случайный, а не счётчик. 192 бита достаточно, чтобы
/// коллизия оставалась невероятной и без учёта числа копий, —
/// а счётчик пришлось бы где-то хранить и синхронизировать между
/// устройствами, каждое из которых делает копии само.
fn random_nonce<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    nonce
}

/// Читает `count` байт, двигая смещение.
fn take<'a>(raw: &'a [u8], offset: &mut usize, count: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(count).ok_or(AegisError::Malformed)?;
    let slice = raw.get(*offset..end).ok_or(AegisError::Malformed)?;
    *offset = end;

    Ok(slice)
}

/// Читает `u32` в сетевом порядке.
fn take_u32(raw: &[u8], offset: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        take(raw, offset, 4)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{MessageRecord, ID_LEN};
    use crate::kdf::{MIN_ITERATIONS, MIN_MEMORY_KIB};
    use crate::recovery_key::RecoveryKey;
    use rand_core::OsRng;

    /// Дешёвые параметры для тестов: схема та же, стоимость меньше.
    fn cheap() -> KdfParams {
        KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    fn root_for(key: &RecoveryKey, salt: &[u8; SALT_LEN]) -> BackupRootKey {
        BackupRootKey::derive(key, salt, cheap()).expect("BRK")
    }

    fn header(salt: [u8; SALT_LEN]) -> ArchiveHeader {
        ArchiveHeader {
            kind: ArchiveKind::Full,
            generation: 0,
            params: cheap(),
            salt,
            parent_digest: [0u8; DIGEST_LEN],
        }
    }

    fn bundle() -> BackupBundle {
        BackupBundle {
            created_at_millis: 1_760_000_000_000,
            messages: vec![MessageRecord {
                id: [1; ID_LEN],
                chat_id: [2; ID_LEN],
                sender_id: [3; ID_LEN],
                timestamp_millis: 1_760_000_000_000,
                content: b"CANARY-CIPHERTEXT".to_vec(),
                status: 1,
                message_type: 0,
                expires_at_millis: None,
            }],
            ..BackupBundle::default()
        }
    }

    fn meta() -> ArchiveMeta {
        ArchiveMeta {
            created_at_millis: 1_760_000_000_000,
            record_count: 1,
            message_count: 1,
            device_label: Some("Pixel 6a".to_owned()),
        }
    }

    /// Копия открывается тем же ключом и отдаёт то же содержимое.
    #[test]
    fn archive_round_trips() {
        let key = RecoveryKey::generate(&mut OsRng);
        let salt = [0x42u8; SALT_LEN];
        let root = root_for(&key, &salt);

        let sealed = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");
        let (parsed_header, parsed_meta, parsed_bundle) = open(&root, &sealed).expect("открытие");

        assert_eq!(parsed_header, header(salt));
        assert_eq!(parsed_meta, meta());
        assert_eq!(parsed_bundle, bundle());
    }

    /// 🧪 Задача M6: без recovery key копия не расшифровывается.
    #[test]
    fn archive_does_not_open_without_the_recovery_key() {
        let salt = [0x42u8; SALT_LEN];
        let right = RecoveryKey::from_bytes([1u8; 32]);
        let wrong = RecoveryKey::from_bytes([2u8; 32]);

        let sealed = seal(
            &root_for(&right, &salt),
            &header(salt),
            &meta(),
            &bundle(),
            &mut OsRng,
        )
        .expect("копия");

        assert!(matches!(
            open(&root_for(&wrong, &salt), &sealed),
            Err(AegisError::Crypto)
        ));
        // Даже метаданные не читаются: чужой ключ не даёт узнать
        // ни числа сообщений, ни времени копии.
        assert!(matches!(
            open_meta(&root_for(&wrong, &salt), &sealed),
            Err(AegisError::Crypto)
        ));
    }

    /// 🔐 В файле копии нет открытого текста из бандла.
    #[test]
    fn archive_contains_no_plaintext_from_the_bundle() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);

        let sealed = seal(
            &root_for(&key, &salt),
            &header(salt),
            &meta(),
            &bundle(),
            &mut OsRng,
        )
        .expect("копия");

        for canary in [b"CANARY-CIPHERTEXT".as_slice(), b"Pixel 6a".as_slice()] {
            assert!(
                !sealed.windows(canary.len()).any(|window| window == canary),
                "содержимое видно в файле копии"
            );
        }
    }

    /// Метаданные читаются отдельно от тела.
    #[test]
    fn meta_opens_without_touching_the_body() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &salt);

        let sealed = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");

        assert_eq!(open_meta(&root, &sealed).expect("метаданные"), meta());
    }

    /// 🔐 Изменение одного байта ломает проверку тега.
    #[test]
    fn any_flipped_byte_is_detected() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &salt);

        let sealed = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");

        // Проверяются все байты после сигнатуры: сигнатура даёт
        // отдельную, более понятную ошибку.
        for position in MAGIC.len()..sealed.len() {
            let mut damaged = sealed.clone();
            if let Some(byte) = damaged.get_mut(position) {
                *byte ^= 0xFF;
            }

            assert!(
                open(&root, &damaged).is_err(),
                "порча байта {position} осталась незамеченной"
            );
        }
    }

    /// 🔐 Подмена ссылки на родителя ломает тег.
    ///
    /// Именно это делает цепочку инкрементов неразрывной: переставить
    /// звено, не зная recovery key, нельзя.
    #[test]
    fn parent_digest_is_authenticated() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &salt);

        let increment = ArchiveHeader {
            kind: ArchiveKind::Increment,
            generation: 1,
            parent_digest: [0xAAu8; DIGEST_LEN],
            ..header(salt)
        };

        let sealed = seal(&root, &increment, &meta(), &bundle(), &mut OsRng).expect("копия");

        // Ссылка на родителя лежит в конце заголовка.
        let start = ArchiveHeader::LEN.saturating_sub(DIGEST_LEN);
        let mut damaged = sealed;
        if let Some(slot) = damaged.get_mut(start..ArchiveHeader::LEN) {
            slot.copy_from_slice(&[0xBBu8; DIGEST_LEN]);
        }

        // Заголовок разбирается — он открытый, — но тег не сходится.
        assert_eq!(
            ArchiveHeader::from_bytes(&damaged)
                .expect("заголовок открытый")
                .parent_digest,
            [0xBBu8; DIGEST_LEN]
        );
        assert!(matches!(open(&root, &damaged), Err(AegisError::Crypto)));
    }

    /// Чужой файл отличается от испорченной копии.
    #[test]
    fn foreign_file_is_rejected_by_magic() {
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &[0u8; SALT_LEN]);

        assert!(matches!(
            open(&root, b"not an aegis backup at all"),
            Err(AegisError::Malformed)
        ));
    }

    /// 🔐 Заголовок с непомерными параметрами отвергается до Argon2id.
    #[test]
    fn absurd_kdf_params_in_header_are_rejected() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &salt);

        let sealed = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");

        // Поле памяти идёт после сигнатуры, версии, вида и поколения.
        let offset = MAGIC.len() + 1 + 1 + 4;
        let mut damaged = sealed;
        if let Some(slot) = damaged.get_mut(offset..offset + 4) {
            slot.copy_from_slice(&(8u32 * 1024 * 1024).to_be_bytes());
        }

        assert!(matches!(
            ArchiveHeader::from_bytes(&damaged),
            Err(AegisError::Malformed)
        ));
    }

    /// Полный снимок не может ссылаться на родителя.
    #[test]
    fn full_snapshot_with_parent_is_rejected() {
        let mut raw = ArchiveHeader {
            parent_digest: [1u8; DIGEST_LEN],
            ..header([0u8; SALT_LEN])
        }
        .to_bytes();
        raw.extend_from_slice(&[0u8; 64]);

        assert!(matches!(
            ArchiveHeader::from_bytes(&raw),
            Err(AegisError::Malformed)
        ));
    }

    /// Инкремент не может быть нулевым поколением.
    #[test]
    fn increment_at_generation_zero_is_rejected() {
        let mut raw = ArchiveHeader {
            kind: ArchiveKind::Increment,
            generation: 0,
            ..header([0u8; SALT_LEN])
        }
        .to_bytes();
        raw.extend_from_slice(&[0u8; 64]);

        assert!(matches!(
            ArchiveHeader::from_bytes(&raw),
            Err(AegisError::Malformed)
        ));
    }

    /// Обрубок файла не приводит к панике.
    #[test]
    fn truncated_archive_never_panics() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &salt);

        let sealed = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");

        for length in 0..sealed.len() {
            let slice = sealed.get(..length).expect("срез");

            assert!(open(&root, slice).is_err(), "обрубок {length} разобрался");
        }
    }

    /// Два вызова с одним содержимым дают разные файлы.
    ///
    /// 🔐 Nonce случаен: одинаковые файлы означали бы повтор пары
    /// «ключ, nonce» при каждой ежедневной копии.
    #[test]
    fn nonces_differ_between_runs() {
        let salt = [0x42u8; SALT_LEN];
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &salt);

        let first = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");
        let second = seal(&root, &header(salt), &meta(), &bundle(), &mut OsRng).expect("копия");

        assert_ne!(first, second, "две копии совпали — nonce не случаен");
    }

    /// Файл vault шифруется и расшифровывается ключом вложений.
    #[test]
    fn file_round_trips() {
        let key = RecoveryKey::generate(&mut OsRng);
        let root = root_for(&key, &[0x42u8; SALT_LEN]);

        let sealed = seal_file(&root, b"vault file contents", &mut OsRng).expect("шифрование");

        assert_eq!(
            open_file(&root, &sealed).expect("расшифровка"),
            b"vault file contents"
        );
        assert!(!sealed.windows(5).any(|window| window == b"vault"));
    }

    /// Чужой ключ файл vault не открывает.
    #[test]
    fn file_does_not_open_with_a_foreign_key() {
        let salt = [0x42u8; SALT_LEN];
        let sealed = seal_file(
            &root_for(&RecoveryKey::from_bytes([1u8; 32]), &salt),
            b"secret",
            &mut OsRng,
        )
        .expect("шифрование");

        assert!(matches!(
            open_file(
                &root_for(&RecoveryKey::from_bytes([2u8; 32]), &salt),
                &sealed
            ),
            Err(AegisError::Crypto)
        ));
    }

    /// SHA-256 файла зависит от его содержимого.
    #[test]
    fn digest_changes_with_content() {
        assert_ne!(digest(b"a"), digest(b"b"));
        assert_eq!(digest(b"a"), digest(b"a"));
    }
}
