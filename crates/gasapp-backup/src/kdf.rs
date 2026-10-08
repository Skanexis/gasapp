// SPDX-License-Identifier: Apache-2.0

//! Вывод ключей резервной копии: recovery key → BRK → рабочие ключи.
//!
//! # Зачем здесь Argon2id
//!
//! Recovery key — это 256 случайных бит, и перебирать их бессмысленно
//! при любой стоимости хеша. Растягивание здесь не про перебор ключа,
//! а про то, что пользователь может записать его не полностью, свести
//! к парольной фразе или сохранить в менеджере паролей рядом с копией.
//! Argon2id делает цену такой ошибки терпимой: даже урезанный ввод
//! обходится атакующему в память и время (ADR-018).
//!
//! # Параметры
//!
//! План (раздел 10, ADR-018) задаёт m = 256 МиБ, t = 4, p = 4 —
//! вчетверо тяжелее, чем растягивание PIN, потому что вывод BRK
//! случается раз в сутки в фоне, а не при каждой разблокировке.
//!
//! ⚠️ План отдельно отмечает риск OOM на бюджетных устройствах.
//! Поэтому параметры не зашиты в код, а **записываются в заголовок
//! копии**: устройство, которому 256 МиБ не по силам, сохраняет то,
//! что смогло, и восстановление на другом устройстве повторяет
//! именно его выбор. Без записи параметров копия, созданная
//! с пониженной памятью, не открылась бы нигде.
//!
//! # 🔐 Почему параметры из файла ограничены сверху и снизу
//!
//! Заголовок копии не аутентифицирован — он читается **до** того, как
//! появится ключ, которым можно проверить тег. Значит, число в нём
//! пишет кто угодно, кто держит файл в руках. Без верхней границы
//! подложенный заголовок с m = 8 ГиБ уронил бы телефон при попытке
//! восстановления; без нижней — тихо ослабил бы растягивание до
//! бессмысленного. Обе границы проверяются при разборе.

use argon2::{Algorithm, Argon2, Params, Version};
use gasapp_types::{GasAppError, Result, Secret};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Длина выводимых ключей в байтах.
pub const KEY_LEN: usize = 32;

/// Длина соли: 128 бит (раздел 7.2 плана).
pub const SALT_LEN: usize = 16;

/// Память Argon2id по умолчанию в килобайтах: 256 МиБ.
pub const DEFAULT_MEMORY_KIB: u32 = 256 * 1024;

/// Число проходов по умолчанию.
pub const DEFAULT_ITERATIONS: u32 = 4;

/// Степень параллелизма по умолчанию.
pub const DEFAULT_PARALLELISM: u32 = 4;

/// Нижняя граница памяти: 32 МиБ.
///
/// Ниже растягивание перестаёт мешать перебору на видеокарте,
/// а значит перестаёт делать то, ради чего оно есть.
pub const MIN_MEMORY_KIB: u32 = 32 * 1024;

/// Верхняя граница памяти: 1 ГиБ.
///
/// 🔐 Защита от заголовка, подложенного посторонним: без неё
/// восстановление можно было бы превратить в отказ устройства,
/// просто вписав в файл большое число.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// Нижняя граница числа проходов.
pub const MIN_ITERATIONS: u32 = 2;

/// Верхняя граница числа проходов.
pub const MAX_ITERATIONS: u32 = 16;

/// Верхняя граница параллелизма.
pub const MAX_PARALLELISM: u32 = 16;

/// Метка вывода ключа данных.
const INFO_DATA: &[u8] = b"GASAPP_BACKUP_v1_DATA";

/// Метка вывода ключа метаданных.
const INFO_META: &[u8] = b"GASAPP_BACKUP_v1_META";

/// Метка вывода ключа вложений.
const INFO_ATTACHMENTS: &[u8] = b"GASAPP_BACKUP_v1_ATTACHMENT";

/// Метка проверочного значения ключа (см. [`BackupRootKey::key_check`]).
const INFO_KEY_CHECK: &[u8] = b"GASAPP_BACKUP_v1_KEY_CHECK";

/// Параметры растягивания, записанные в заголовок копии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Память в килобайтах.
    pub memory_kib: u32,
    /// Число проходов.
    pub iterations: u32,
    /// Степень параллелизма.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl KdfParams {
    /// Проверяет, что параметры лежат в допустимых границах.
    ///
    /// Вызывается и при создании копии, и при её разборе: в первом
    /// случае ловит ошибку в своём коде, во втором — подложенный
    /// заголовок.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — какой-либо параметр вне границ.
    pub const fn validate(&self) -> Result<()> {
        if self.memory_kib < MIN_MEMORY_KIB || self.memory_kib > MAX_MEMORY_KIB {
            return Err(GasAppError::Malformed);
        }

        if self.iterations < MIN_ITERATIONS || self.iterations > MAX_ITERATIONS {
            return Err(GasAppError::Malformed);
        }

        if self.parallelism == 0 || self.parallelism > MAX_PARALLELISM {
            return Err(GasAppError::Malformed);
        }

        Ok(())
    }
}

/// Backup Root Key — корень ветки ключей резервной копии.
///
/// # Что это за уровень иерархии
///
/// BRK намеренно **не связан** с LSMK и остальной иерархией устройства
/// (раздел 7.2 плана): ветка резервной копии независима, чтобы копия
/// открывалась на устройстве, которого ещё не существовало в момент
/// её создания. Из BRK выводятся три рабочих ключа — данных,
/// метаданных и вложений.
///
/// 🔐 Живёт только в оперативной памяти на время операции и
/// обнуляется при уничтожении.
pub struct BackupRootKey(Secret<[u8; KEY_LEN]>);

impl core::fmt::Debug for BackupRootKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BackupRootKey<redacted>")
    }
}

impl BackupRootKey {
    /// Выводит BRK из recovery key.
    ///
    /// Принимает [`RecoveryKey`](crate::recovery_key::RecoveryKey),
    /// а не строку: к этому моменту контрольная сумма уже сверена,
    /// то есть дорогое растягивание не запускается на вводе
    /// с опечаткой.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — соль не той длины либо параметры
    /// вне границ;
    /// [`GasAppError::Crypto`] — сбой Argon2id.
    pub fn derive(
        recovery_key: &crate::recovery_key::RecoveryKey,
        salt: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
        if salt.len() != SALT_LEN {
            return Err(GasAppError::Malformed);
        }

        params.validate()?;

        let argon_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| GasAppError::Crypto)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

        let mut key = [0u8; KEY_LEN];
        let outcome = argon.hash_password_into(recovery_key.expose_bytes(), salt, &mut key);

        if outcome.is_err() {
            key.zeroize();

            return Err(GasAppError::Crypto);
        }

        Ok(Self(Secret::new(key)))
    }

    /// Ключ шифрования тела копии.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой HKDF.
    pub fn data_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        self.expand(INFO_DATA)
    }

    /// Ключ шифрования метаданных копии.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой HKDF.
    pub fn meta_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        self.expand(INFO_META)
    }

    /// Ключ шифрования вложений копии.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой HKDF.
    pub fn attachment_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        self.expand(INFO_ATTACHMENTS)
    }

    /// Проверочное значение ключа: тот ли recovery key продолжает цепочку.
    ///
    /// 🔐 Не секрет и не ключ: отдельная метка HKDF, по значению нельзя
    /// вывести ни один из ключей копии. Хранится рядом с состоянием
    /// цепочки и сверяется перед дописыванием инкремента — иначе любой
    /// годный по контрольной сумме ключ (старый с бумажки или чужой)
    /// дописывал бы звено, которое настоящим ключом не открывается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой HKDF.
    pub fn key_check(&self) -> Result<[u8; KEY_LEN]> {
        Ok(*self.expand(INFO_KEY_CHECK)?)
    }

    /// Общий шаг HKDF-Expand с меткой назначения.
    ///
    /// 🔐 Разные метки дают несвязанные ключи: раскрытие ключа
    /// вложений не даёт ничего для тела копии.
    fn expand(&self, info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let hkdf = Hkdf::<Sha256>::from_prk(self.0.expose_secret().as_slice())
            .map_err(|_| GasAppError::Crypto)?;

        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(info, out.as_mut_slice())
            .map_err(|_| GasAppError::Crypto)?;

        Ok(out)
    }
}

/// Генерирует случайную соль для растягивания.
pub fn generate_salt<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_key::RecoveryKey;
    use rand_core::OsRng;

    /// Параметры для тестов: те же по форме, но дешёвые по памяти.
    ///
    /// 256 МиБ × 4 прохода на каждый из десятка тестов превратили бы
    /// прогон в минуты. Границы при этом соблюдены: тест проверяет
    /// схему вывода, а не стоимость — за стоимость отвечает
    /// `default_params_are_the_planned_ones`.
    fn cheap() -> KdfParams {
        KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    /// Значения по умолчанию — ровно те, что записаны в ADR-018.
    ///
    /// Тест существует, чтобы понижение параметров «ради скорости»
    /// не прошло молча: оно ровно настолько же удешевляет перебор.
    #[test]
    fn default_params_are_the_planned_ones() {
        let params = KdfParams::default();

        assert_eq!(params.memory_kib, 256 * 1024, "план требует m = 256 МиБ");
        assert_eq!(params.iterations, 4, "план требует t = 4");
        assert_eq!(params.parallelism, 4, "план требует p = 4");
        assert!(params.validate().is_ok());
    }

    /// Один ключ и одна соль дают один BRK.
    #[test]
    fn derivation_is_deterministic() {
        let key = RecoveryKey::from_bytes([7u8; 32]);
        let salt = [3u8; SALT_LEN];

        let first = BackupRootKey::derive(&key, &salt, cheap()).expect("BRK");
        let second = BackupRootKey::derive(&key, &salt, cheap()).expect("BRK");

        assert_eq!(
            first.data_key().expect("ключ").as_slice(),
            second.data_key().expect("ключ").as_slice()
        );
    }

    /// 🔐 Разные recovery key дают разные BRK.
    #[test]
    fn different_recovery_keys_give_different_roots() {
        let salt = [3u8; SALT_LEN];

        let first = BackupRootKey::derive(&RecoveryKey::from_bytes([1u8; 32]), &salt, cheap())
            .expect("BRK");
        let second = BackupRootKey::derive(&RecoveryKey::from_bytes([2u8; 32]), &salt, cheap())
            .expect("BRK");

        assert_ne!(
            first.data_key().expect("ключ").as_slice(),
            second.data_key().expect("ключ").as_slice()
        );
    }

    /// 🔐 Разная соль даёт разные BRK при том же ключе.
    #[test]
    fn different_salts_give_different_roots() {
        let key = RecoveryKey::from_bytes([9u8; 32]);

        let first = BackupRootKey::derive(&key, &[1u8; SALT_LEN], cheap()).expect("BRK");
        let second = BackupRootKey::derive(&key, &[2u8; SALT_LEN], cheap()).expect("BRK");

        assert_ne!(
            first.data_key().expect("ключ").as_slice(),
            second.data_key().expect("ключ").as_slice()
        );
    }

    /// 🔐 Три рабочих ключа не совпадают между собой.
    ///
    /// Совпадение означало бы, что раскрытие ключа вложений
    /// раскрывает и тело копии.
    #[test]
    fn working_keys_are_independent() {
        let root = BackupRootKey::derive(
            &RecoveryKey::from_bytes([4u8; 32]),
            &[5u8; SALT_LEN],
            cheap(),
        )
        .expect("BRK");

        let data = root.data_key().expect("ключ");
        let meta = root.meta_key().expect("ключ");
        let attachments = root.attachment_key().expect("ключ");

        assert_ne!(data.as_slice(), meta.as_slice());
        assert_ne!(data.as_slice(), attachments.as_slice());
        assert_ne!(meta.as_slice(), attachments.as_slice());
    }

    /// Соль неверной длины отвергается, а не дополняется.
    #[test]
    fn wrong_salt_length_is_rejected() {
        assert!(matches!(
            BackupRootKey::derive(&RecoveryKey::from_bytes([0u8; 32]), &[0u8; 8], cheap()),
            Err(GasAppError::Malformed)
        ));
    }

    /// 🔐 Параметры вне границ отвергаются.
    ///
    /// Проверяются обе стороны: слишком слабые ослабляют защиту
    /// молча, слишком тяжёлые дают отказ устройства при
    /// восстановлении подложенной копии.
    #[test]
    fn params_outside_bounds_are_rejected() {
        let too_weak = KdfParams {
            memory_kib: 1024,
            ..KdfParams::default()
        };
        let too_heavy = KdfParams {
            memory_kib: 8 * 1024 * 1024,
            ..KdfParams::default()
        };
        let too_few_passes = KdfParams {
            iterations: 1,
            ..KdfParams::default()
        };
        let no_parallelism = KdfParams {
            parallelism: 0,
            ..KdfParams::default()
        };

        for params in [too_weak, too_heavy, too_few_passes, no_parallelism] {
            assert!(
                matches!(params.validate(), Err(GasAppError::Malformed)),
                "приняты недопустимые параметры: {params:?}"
            );
            assert!(BackupRootKey::derive(
                &RecoveryKey::from_bytes([0u8; 32]),
                &[0u8; SALT_LEN],
                params
            )
            .is_err());
        }
    }

    /// Debug не раскрывает содержимое BRK.
    #[test]
    fn debug_does_not_leak_root_key() {
        let root = BackupRootKey::derive(
            &RecoveryKey::from_bytes([0xABu8; 32]),
            &[0xCDu8; SALT_LEN],
            cheap(),
        )
        .expect("BRK");

        assert_eq!(format!("{root:?}"), "BackupRootKey<redacted>");
    }

    #[test]
    fn generated_salts_differ() {
        assert_ne!(generate_salt(&mut OsRng), generate_salt(&mut OsRng));
    }
}
