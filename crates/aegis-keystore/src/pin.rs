// SPDX-License-Identifier: Apache-2.0

//! Растягивание PIN в ключ хранилища.
//!
//! # Зачем растягивание
//!
//! Шестизначный PIN — это миллион вариантов. Хеш вроде SHA-256
//! перебирает их за секунды на обычной видеокарте, поэтому ключ базы
//! нельзя выводить из PIN напрямую: изъятое устройство открывалось бы
//! почти мгновенно.
//!
//! `Argon2id` с параметрами из плана (m = 64 мегабайта, t = 3, p = 4)
//! делает один вычислительный шаг дорогим по памяти, а не только
//! по арифметике — именно это лишает специализированное железо
//! преимущества. Миллион вариантов при такой стоимости превращается
//! в годы работы.
//!
//! # Почему параметры именно такие
//!
//! 64 мегабайта — компромисс: достаточно, чтобы GPU потерял преимущество,
//! и не настолько много, чтобы бюджетный телефон ушёл в своп. Понизить
//! их «ради скорости разблокировки» значит ровно на столько же
//! ускорить перебор тому, кто изъял устройство.
//!
//! # Про соль
//!
//! Соль случайна и хранится **рядом** с базой в открытом виде. Это
//! не ослабление: соль защищает не от того, кто получил устройство,
//! а от заранее посчитанных таблиц — с ней атакующий обязан считать
//! перебор заново для каждого устройства.
//!
//! # Чего здесь нет
//!
//! Проверки правильности PIN. Её не существует как отдельного шага:
//! неверный PIN даёт неверный ключ, и SQLCipher просто не откроет
//! базу. Отдельная проверка означала бы хранить где-то признак
//! правильного PIN — то есть подсказку для перебора.

use aegis_types::{AegisError, Result, Secret};
use argon2::{Algorithm, Argon2, Params, Version};

/// Длина ключа хранилища.
pub const KEY_LEN: usize = 32;

/// Длина соли.
///
/// 16 байт — 128 бит: столько же, сколько рекомендует RFC 9106.
/// Меньше означало бы риск совпадения солей между устройствами,
/// а совпадение возвращает смысл заранее посчитанным таблицам.
pub const SALT_LEN: usize = 16;

/// Память `Argon2id` в килобайтах: 64 мегабайта (раздел 10 плана).
const MEMORY_KIB: u32 = 64 * 1024;

/// Число проходов.
const ITERATIONS: u32 = 3;

/// Степень параллелизма.
const PARALLELISM: u32 = 4;

/// Минимальная длина PIN.
///
/// Шесть цифр — миллион вариантов; вместе с растягиванием этого
/// достаточно, чтобы перебор занимал годы. Четыре цифры (10 000
/// вариантов) перебираются за часы даже при дорогом хеше.
pub const MIN_PIN_LEN: usize = 6;

/// Выводит ключ хранилища из PIN.
///
/// # Errors
///
/// [`AegisError::Malformed`] — PIN короче [`MIN_PIN_LEN`] либо соль
/// не той длины;
/// [`AegisError::Crypto`] — сбой `Argon2id`.
///
/// # Про время выполнения
///
/// Одна секунда на телефоне — это норма, а не проблема
/// производительности. Попытка «оптимизировать» её понижением
/// параметров прямо пропорционально ускоряет перебор.
pub fn derive_key(pin: &str, salt: &[u8]) -> Result<Secret<[u8; KEY_LEN]>> {
    if pin.chars().count() < MIN_PIN_LEN {
        return Err(AegisError::Malformed);
    }

    if salt.len() != SALT_LEN {
        return Err(AegisError::Malformed);
    }

    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(KEY_LEN))
        .map_err(|_| AegisError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(pin.as_bytes(), salt, &mut key)
        .map_err(|_| AegisError::Crypto)?;

    Ok(Secret::new(key))
}

/// Генерирует случайную соль.
pub fn generate_salt<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Один PIN и одна соль дают один ключ.
    ///
    /// Иначе база, зашифрованная при создании PIN, не открылась бы
    /// при следующем запуске.
    #[test]
    fn derivation_is_deterministic() {
        let salt = [0x42u8; SALT_LEN];

        let first = derive_key("123456", &salt).expect("ключ");
        let second = derive_key("123456", &salt).expect("ключ");

        assert_eq!(first.expose_secret(), second.expose_secret());
    }

    /// 🔐 Разные PIN дают разные ключи.
    #[test]
    fn different_pins_give_different_keys() {
        let salt = [0x42u8; SALT_LEN];

        let first = derive_key("123456", &salt).expect("ключ");
        let second = derive_key("123457", &salt).expect("ключ");

        assert_ne!(first.expose_secret(), second.expose_secret());
    }

    /// 🔐 Одинаковый PIN на разных устройствах даёт разные ключи.
    ///
    /// Это и есть работа соли: без неё атакующий посчитал бы таблицу
    /// для распространённых PIN один раз и применял её ко всем
    /// изъятым устройствам.
    #[test]
    fn different_salts_give_different_keys() {
        let first = derive_key("123456", &[0x01u8; SALT_LEN]).expect("ключ");
        let second = derive_key("123456", &[0x02u8; SALT_LEN]).expect("ключ");

        assert_ne!(first.expose_secret(), second.expose_secret());
    }

    /// Короткий PIN отвергается.
    #[test]
    fn short_pin_is_rejected() {
        assert!(matches!(
            derive_key("12345", &[0u8; SALT_LEN]),
            Err(AegisError::Malformed)
        ));
    }

    /// Соль неверной длины отвергается.
    ///
    /// Короткая соль ослабляет защиту молча, поэтому проверяется
    /// явно, а не дополняется до нужной длины.
    #[test]
    fn wrong_salt_length_is_rejected() {
        assert!(matches!(
            derive_key("123456", &[0u8; 8]),
            Err(AegisError::Malformed)
        ));
    }

    #[test]
    fn generated_salts_differ() {
        let first = generate_salt(&mut OsRng);
        let second = generate_salt(&mut OsRng);

        assert_ne!(first, second, "соли совпали — генератор сломан");
    }

    /// PIN из букв и символов тоже принимается.
    ///
    /// Ограничение только на длину: пользователь, выбравший парольную
    /// фразу вместо цифр, получает больше энтропии, и запрещать это
    /// незачем.
    #[test]
    fn passphrase_is_accepted() {
        let salt = [0x11u8; SALT_LEN];

        assert!(derive_key("correct horse battery", &salt).is_ok());
    }

    /// 🔐 Растягивание действительно дорогое.
    ///
    /// Тест существует, чтобы понижение параметров «ради скорости»
    /// не прошло незамеченным: оно прямо пропорционально ускоряет
    /// перебор на изъятом устройстве.
    #[test]
    fn derivation_is_deliberately_slow() {
        let salt = [0x33u8; SALT_LEN];
        let start = std::time::Instant::now();

        let _ = derive_key("123456", &salt).expect("ключ");

        let elapsed = start.elapsed();

        assert!(
            elapsed > std::time::Duration::from_millis(20),
            "растягивание заняло {elapsed:?}: параметры Argon2id занижены, \
             перебор PIN стал дешевле"
        );
    }
}
