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
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

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

/// Длина аппаратного секрета.
///
/// 32 байта: столько же, сколько у ключа хранилища. Меньше не имеет
/// смысла — секрет и так не перебирается, а больше ничего не добавляет.
pub const HARDWARE_SECRET_LEN: usize = 32;

/// Метка HKDF для ключа хранилища, связанного с устройством.
///
/// Версия в метке обязательна: ключ, выведенный старой схемой,
/// не должен совпасть с ключом новой ни при каких входах.
const BOUND_KEY_INFO: &[u8] = b"AEGIS storage key v2 (hardware-bound)";

/// Выводит ключ хранилища из PIN **и** секрета, не покидающего
/// устройство.
///
/// # Зачем это поверх [`derive_key`]
///
/// [`derive_key`] выводит ключ из одного PIN. PIN шестизначный —
/// миллион вариантов, — и `Argon2id` растягивает перебор, но не
/// делает его невозможным: он ограничен памятью, и машина с 64 ядрами
/// и 4 ГиБ свободной памяти проходит весь миллион за пару часов.
/// То есть снятый с телефона файл базы вместе с солью раскрывается
/// за аренду в несколько долларов.
///
/// 🔐 `hardware` — секрет, который хранится **зашифрованным ключом
/// аппаратного хранилища** (Android Keystore, по возможности
/// StrongBox). Сам ключ из хранилища не извлекается: его нельзя
/// скопировать вместе с файлами, и без самого устройства расшифровать
/// секрет нечем. Перебирать становится нечего — у атакующего нет
/// половины входа.
///
/// Это и есть схема раздела 7.3 и ADR-017; до внутреннего пентеста
/// (P-5, раздел 23.6) её не существовало, хотя план описывал её как
/// действующую.
///
/// # Почему PIN всё равно нужен
///
/// Аппаратный секрет защищает от **снятого файла**, а не от снятого
/// телефона: на самом устройстве его отдаст хранилище. PIN защищает
/// от того, кто держит разблокированный телефон в руках. Одно без
/// другого неполно, поэтому ключ выводится из обоих.
///
/// # Порядок склейки
///
/// `HKDF-Extract(salt, argon2_out ‖ hardware)`, затем `Expand` с меткой
/// версии. Не XOR и не конкатенация напрямую в ключ: HKDF даёт
/// равномерный результат, даже если аппаратное хранилище отдало
/// секрет с неидеальным распределением.
///
/// # Errors
///
/// [`AegisError::Malformed`] — PIN короче [`MIN_PIN_LEN`], соль не той
/// длины либо `hardware` не [`HARDWARE_SECRET_LEN`] байт;
/// [`AegisError::Crypto`] — сбой `Argon2id` или HKDF.
pub fn derive_key_bound(pin: &str, salt: &[u8], hardware: &[u8]) -> Result<Secret<[u8; KEY_LEN]>> {
    if hardware.len() != HARDWARE_SECRET_LEN {
        return Err(AegisError::Malformed);
    }

    // Проверки PIN и соли делает `derive_key`; дублировать их здесь
    // значило бы завести второе место, где эти правила могут разойтись.
    let stretched = derive_key(pin, salt)?;

    let mut ikm = [0u8; KEY_LEN + HARDWARE_SECRET_LEN];

    // Обе половины пишутся по фиксированным смещениям: срез по
    // вычисленной длине здесь запрещён правилами линтинга, а ошибка
    // в нём дала бы молча другой ключ.
    let (left, right) = ikm.split_at_mut(KEY_LEN);
    left.copy_from_slice(stretched.expose_secret());
    right.copy_from_slice(hardware);

    let hkdf = Hkdf::<Sha256>::new(Some(salt), &ikm);

    let mut key = [0u8; KEY_LEN];
    hkdf.expand(BOUND_KEY_INFO, &mut key)
        .map_err(|_| AegisError::Crypto)?;

    // Промежуточный материал затирается сразу: он равносилен ключу.
    ikm.zeroize();

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

    // --- Ключ, связанный с устройством (P-5, раздел 23.6) ---

    fn hardware() -> [u8; HARDWARE_SECRET_LEN] {
        [0x5Au8; HARDWARE_SECRET_LEN]
    }

    /// Тот же PIN, соль и аппаратный секрет дают тот же ключ.
    ///
    /// Иначе база не открылась бы при следующем запуске.
    #[test]
    fn bound_derivation_is_deterministic() {
        let salt = [0x42u8; SALT_LEN];

        let first = derive_key_bound("123456", &salt, &hardware()).expect("ключ");
        let second = derive_key_bound("123456", &salt, &hardware()).expect("ключ");

        assert_eq!(first.expose_secret(), second.expose_secret());
    }

    /// 🔐 Главное свойство: без аппаратного секрета ключ не тот.
    ///
    /// Это и есть защита от снятого файла базы. Атакующий, скопировавший
    /// `aegis.db` и `aegis.salt`, перебирает миллион PIN и **ни на одном**
    /// не получает рабочий ключ, потому что второй половины входа у него
    /// нет и взять её неоткуда: она лежит зашифрованной ключом, который
    /// не покидает аппаратное хранилище.
    #[test]
    fn different_hardware_secret_gives_a_different_key() {
        let salt = [0x42u8; SALT_LEN];

        let mine = derive_key_bound("123456", &salt, &hardware()).expect("ключ");

        let mut other = hardware();
        other[0] ^= 0xFF;

        let theirs = derive_key_bound("123456", &salt, &other).expect("ключ");

        assert_ne!(
            mine.expose_secret(),
            theirs.expose_secret(),
            "ключ не зависит от аппаратного секрета: защита от снятого файла отсутствует"
        );
    }

    /// Связанный ключ не совпадает с несвязанным при тех же PIN и соли.
    ///
    /// 🔐 Совпадение означало бы, что аппаратный секрет в вывод не
    /// попадает вовсе. Метка версии в HKDF существует ровно для того,
    /// чтобы две схемы нельзя было спутать.
    #[test]
    fn bound_key_differs_from_pin_only_key() {
        let salt = [0x42u8; SALT_LEN];

        let bound = derive_key_bound("123456", &salt, &hardware()).expect("ключ");
        let plain = derive_key("123456", &salt).expect("ключ");

        assert_ne!(bound.expose_secret(), plain.expose_secret());
    }

    /// PIN по-прежнему влияет на результат.
    ///
    /// Парный к предыдущим: схема, в которой ключ определяется одним
    /// аппаратным секретом, открывала бы базу на любом PIN — то есть
    /// у того, кто держит разблокированный телефон.
    #[test]
    fn bound_key_still_depends_on_the_pin() {
        let salt = [0x42u8; SALT_LEN];

        let right = derive_key_bound("123456", &salt, &hardware()).expect("ключ");
        let wrong = derive_key_bound("123457", &salt, &hardware()).expect("ключ");

        assert_ne!(right.expose_secret(), wrong.expose_secret());
    }

    /// Соль влияет на результат.
    #[test]
    fn bound_key_depends_on_the_salt() {
        let mine = derive_key_bound("123456", &[0x01u8; SALT_LEN], &hardware()).expect("ключ");
        let other = derive_key_bound("123456", &[0x02u8; SALT_LEN], &hardware()).expect("ключ");

        assert_ne!(mine.expose_secret(), other.expose_secret());
    }

    /// Аппаратный секрет неверной длины отвергается.
    ///
    /// Молчаливое дополнение нулями до 32 байт дало бы рабочий ключ
    /// при пустом секрете — то есть тихий откат к защите одним PIN.
    #[test]
    fn hardware_secret_of_wrong_length_is_rejected() {
        let salt = [0x42u8; SALT_LEN];

        for length in [0usize, 1, 16, 31, 33, 64] {
            let secret = vec![0u8; length];

            assert!(
                derive_key_bound("123456", &salt, &secret).is_err(),
                "секрет длиной {length} принят"
            );
        }
    }

    /// Правила PIN и соли остаются теми же.
    #[test]
    fn bound_derivation_keeps_pin_and_salt_rules() {
        assert!(derive_key_bound("12345", &[0u8; SALT_LEN], &hardware()).is_err());
        assert!(derive_key_bound("123456", &[0u8; SALT_LEN - 1], &hardware()).is_err());
    }
}
