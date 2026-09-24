// SPDX-License-Identifier: AGPL-3.0-only

//! Proof-of-work при регистрации.
//!
//! # Зачем он нужен
//!
//! AEGIS не спрашивает номер телефона (ADR-007), а значит лишается
//! барьера, который в других мессенджерах ограничивает массовую
//! регистрацию: SIM-карта стоит денег. Нужен другой барьер, не требующий
//! ни личных данных, ни хранения социального графа — инвайты отвергнуты
//! именно потому, что заставили бы сервер помнить, кто кого пригласил
//! (раздел 14.5 плана).
//!
//! Proof-of-work подходит: он дорог для того, кто регистрирует миллион
//! аккаунтов, и почти незаметен для того, кто регистрирует один.
//!
//! # Почему SHA-256, а не `Argon2id`
//!
//! Memory-hard функция здесь выглядит привлекательно — она сокращает
//! преимущество GPU и ASIC. Но у proof-of-work на стороне сервера есть
//! ограничение, которого нет у растягивания пароля: сервер проверяет
//! решение **на каждый запрос**, включая мусорные. Хеш ценой 64 мегабайт
//! памяти превращает саму проверку в вектор DoS.
//!
//! Решающим стал замер: `Argon2id` с 64 мегабайтами давал 51 мс на хеш, то
//! есть около двух часов перебора при сложности 18 бит. Регистрация
//! просто не работала бы. Асимметрия «дорого подобрать, дёшево
//! проверить» важнее устойчивости к специализированному железу:
//! ферма на ASIC всё равно упрётся в лимиты по частоте регистраций,
//! а неработающая регистрация вредит только честным пользователям.
//!
//! # Что именно проверяется
//!
//! Клиент подбирает `nonce` такой, что `SHA-256(домен ‖ challenge ‖ nonce)`
//! начинается с заданного числа нулевых битов. Сервер выполняет **одно**
//! вычисление, чтобы это подтвердить — асимметрия работы и есть смысл
//! схемы.
//!
//! # Откуда берётся челлендж
//!
//! Из самой регистрации: [`registration_challenge`] — хеш имени
//! и обоих ключей. Сервер вычисляет его сам и отвергает любой другой.
//! Так одно решение годится ровно для одного аккаунта: новому имени
//! нужен новый челлендж, а значит, и новая работа.
//!
//! ⚠️ Прежде здесь было написано, что челлендж «подписывается сервером
//! и содержит время выпуска». Ни того, ни другого не было: челлендж
//! выбирал клиент, сервер проверял только работу над ним, и одно
//! решение регистрировало сколько угодно аккаунтов — аудитор завёл
//! пять из пяти.
//!
//! # Чего здесь нет
//!
//! Хранения выданных челленджей и времени в нём. Состояние на каждого
//! гостя сделало бы регистрацию мишенью для DoS, а время отказывало бы
//! людям с неверными часами на телефоне. Заранее посчитанные решения
//! не дешевле: работа на аккаунт та же, она лишь сдвинута во времени.

use sha2::{Digest, Sha256};

/// Длина челленджа в байтах.
pub const CHALLENGE_LEN: usize = 32;

/// Домен-разделитель челленджа регистрации.
const REGISTRATION_DOMAIN: &[u8] = b"AEGIS_POW_REG_v1";

/// Челлендж регистрации: хеш имени и обоих ключей.
///
/// Каждое поле идёт с длиной впереди, иначе имя `ab` с ключом `c…`
/// и имя `a` с ключом `bc…` дали бы один челлендж.
///
/// ⚠️ Продублирован в `aegis-net::pow` (разные лицензии, общий крейт
/// невозможен); совпадение проверяет `client_contract`.
#[must_use]
pub fn registration_challenge(
    username: &str,
    identity_key: &[u8],
    device_identity_key: &[u8],
) -> [u8; CHALLENGE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(REGISTRATION_DOMAIN);

    for field in [username.as_bytes(), identity_key, device_identity_key] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }

    hasher.finalize().into()
}

/// Длина выхода хеша, по которому считаются нули.
const OUTPUT_LEN: usize = 32;

/// Сложность по умолчанию: сколько старших нулевых битов требуется.
///
/// Каждый бит удваивает ожидаемое число попыток. 20 бит — около
/// миллиона хешей SHA-256, то есть порядка секунды на телефоне
/// и заметная стоимость при массовой регистрации.
///
/// # Почему не `Argon2id`
///
/// Первая редакция считала `PoW` через `Argon2id` с 64 мегабайтами памяти.
/// Замер показал 51 мс на один хеш, то есть **около двух часов**
/// перебора на десктопе при сложности 18 — регистрация не работала
/// бы вовсе. Ошибка была в подмене задачи: `Argon2id` растягивает
/// пароль, где дорогим должен быть **один** вызов, а proof-of-work
/// требует обратного — дешёвого хеша и большого числа попыток.
/// Память здесь не нужна ещё и потому, что проверять решение серверу
/// приходится на каждый запрос, включая мусорные.
pub const DEFAULT_DIFFICULTY: u32 = 20;

/// Домен-разделитель челленджа первого контакта.
const FIRST_CONTACT_DOMAIN: &[u8] = b"AEGIS_POW_FIRST_v1";

/// Сложность proof-of-work первого контакта, в битах.
///
/// 🔐 Первое сообщение новому собеседнику приходит запечатанным без
/// ключа доступа получателя: право на анонимную отправку доказывается
/// работой. Прежде такое сообщение шло за подписью отправителя,
/// и сервер видел, кто начал переписку с кем.
///
/// ⚠️ Совпадает с `aegis-net::pow::FIRST_CONTACT_DIFFICULTY`.
pub const FIRST_CONTACT_DIFFICULTY: u32 = 18;

/// Челлендж первого контакта: устройство получателя и хеш конверта.
///
/// Сервер вычисляет его сам из запроса — подставить другой нечем,
/// и одно решение годится ровно для одного конверта одному
/// получателю.
///
/// ⚠️ Продублирован в `aegis-net::pow` (разные лицензии); эталон —
/// тест ниже и тот же вектор у клиента.
#[must_use]
pub fn first_contact_challenge(destination_device_id: &str, sealed: &[u8]) -> [u8; CHALLENGE_LEN] {
    let destination = destination_device_id.to_ascii_lowercase();
    let sealed_hash = Sha256::digest(sealed);

    let mut hasher = Sha256::new();
    hasher.update(FIRST_CONTACT_DOMAIN);
    for field in [destination.as_bytes(), sealed_hash.as_slice()] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Домен-разделитель челленджа анонимной загрузки вложения.
const UPLOAD_DOMAIN: &[u8] = b"AEGIS_POW_UPLOAD_v1";

/// Базовая сложность загрузки вложения, в битах.
const UPLOAD_BASE_DIFFICULTY: u32 = 16;

/// Челлендж загрузки: хеш самого блоба.
///
/// 🔐 Загрузка анонимна — подпись устройства связала бы файл с тем,
/// кто его прислал. Право на место на диске доказывается работой над
/// **этим** блобом: решение не переносится на другой.
///
/// ⚠️ Продублирован на другой стороне (разные лицензии); эталон — тест.
#[must_use]
pub fn upload_challenge(payload: &[u8]) -> [u8; CHALLENGE_LEN] {
    let payload_hash = Sha256::digest(payload);

    let mut hasher = Sha256::new();
    hasher.update(UPLOAD_DOMAIN);
    hasher.update(
        u64::try_from(payload_hash.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(payload_hash);
    hasher.finalize().into()
}

/// Сложность загрузки: 16 бит плюс бит на каждое удвоение мегабайт.
///
/// Место на диске — то, что анонимная загрузка позволяет тратить,
/// поэтому цена растёт с размером: маленький файл — мгновенно,
/// стомегабайтный — 23 бита, секунды на телефоне при минутах
/// самой передачи.
#[must_use]
pub fn upload_difficulty(len: usize) -> u32 {
    const MIB: usize = 1 << 20;

    let megabytes = len.div_ceil(MIB).max(1);
    // ⌈log2 n⌉: число бит, нужных для n − 1.
    let doublings = usize::BITS.saturating_sub(megabytes.saturating_sub(1).leading_zeros());

    UPLOAD_BASE_DIFFICULTY.saturating_add(doublings)
}

/// Потолок сложности.
///
/// Существует, чтобы ошибка в конфигурации не превратила регистрацию
/// в бесконечное ожидание: каждый бит сверху удваивает время.
pub const MAX_DIFFICULTY: u32 = 32;

/// Ошибка проверки proof-of-work.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PowError {
    /// Решение не даёт требуемого числа нулевых битов.
    #[error("proof of work is insufficient")]
    Insufficient,
    /// Сложность вне допустимого диапазона.
    #[error("difficulty out of range")]
    BadDifficulty,
    /// Сбой вычисления хеша.
    #[error("hash computation failed")]
    HashFailed,
}

/// Вычисляет хеш решения.
///
/// # Errors
///
/// [`PowError::HashFailed`] — не возникает для SHA-256, но остаётся
/// в сигнатуре: смена хеша не должна ломать вызывающий код.
/// Недостижимо при константах выше, но ошибка возвращается, а не
/// подавляется: паника на сервере — это отказ в обслуживании.
pub fn hash(challenge: &[u8], nonce: u64) -> Result<[u8; OUTPUT_LEN], PowError> {
    // Домен-разделитель: без него тот же хеш мог бы засчитаться
    // как решение в другом протоколе, использующем SHA-256 над
    // похожими данными.
    let mut hasher = Sha256::new();
    hasher.update(b"AEGIS_POW_v1");
    hasher.update(challenge);
    hasher.update(nonce.to_be_bytes());

    Ok(hasher.finalize().into())
}

/// Проверяет решение proof-of-work.
///
/// # Errors
///
/// * [`PowError::BadDifficulty`] — сложность вне диапазона.
/// * [`PowError::Insufficient`] — нулевых битов меньше требуемого.
/// * [`PowError::HashFailed`] — сбой вычисления хеша.
pub fn verify(challenge: &[u8], nonce: u64, difficulty: u32) -> Result<(), PowError> {
    if difficulty == 0 || difficulty > MAX_DIFFICULTY {
        return Err(PowError::BadDifficulty);
    }

    let output = hash(challenge, nonce)?;

    if leading_zero_bits(&output) >= difficulty {
        Ok(())
    } else {
        Err(PowError::Insufficient)
    }
}

/// Считает старшие нулевые биты.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count: u32 = 0;

    for byte in bytes {
        let zeros = byte.leading_zeros();
        count = count.saturating_add(zeros);

        // Встретился ненулевой байт — дальше считать нечего.
        if *byte != 0 {
            break;
        }
    }

    count
}

#[cfg(test)]
mod tests {

    /// Эталон посчитан независимой реализацией (Python); тот же у клиента.
    #[test]
    fn upload_challenge_matches_the_reference() {
        assert_eq!(
            upload_challenge(&[1, 2, 3]).get(..8),
            Some(&[0xa7, 0x49, 0x03, 0x93, 0x15, 0x5f, 0xe3, 0x98][..])
        );
        assert_eq!(upload_difficulty(100 << 20), 23);
    }

    /// Эталон посчитан независимой реализацией (Python, hashlib);
    /// тот же вектор у клиента в `aegis-net::pow`.
    #[test]
    fn first_contact_challenge_matches_the_reference() {
        let challenge = first_contact_challenge("00000000-0000-0000-0000-000000000001", &[1, 2, 3]);

        assert_eq!(
            challenge.get(..8),
            Some(&[0x14, 0x11, 0x06, 0xfa, 0x70, 0xb8, 0xb0, 0x95][..])
        );
    }
    use super::*;

    /// Малая сложность для тестов: полноценный `PoW` считался бы секундами.
    const EASY: u32 = 4;

    fn challenge() -> [u8; CHALLENGE_LEN] {
        [0x42u8; CHALLENGE_LEN]
    }

    /// Сколько попыток перебора допускается в тестах.
    ///
    /// Верхняя граница нужна, чтобы неудачный подбор завершался ошибкой
    /// теста, а не висел бесконечно. При сложности `EASY` решение
    /// находится за десятки попыток, так что запас огромен.
    const SOLVE_ATTEMPTS: u64 = 100_000;

    /// Подбирает решение перебором — то, чем занят клиент.
    fn solve(challenge: &[u8], difficulty: u32) -> u64 {
        (0u64..SOLVE_ATTEMPTS)
            .find(|nonce| verify(challenge, *nonce, difficulty).is_ok())
            .unwrap_or_else(|| panic!("решение не найдено за {SOLVE_ATTEMPTS} попыток"))
    }

    /// 🔐 Корректное решение принимается.
    #[test]
    fn valid_solution_is_accepted() {
        let nonce = solve(&challenge(), EASY);

        assert!(verify(&challenge(), nonce, EASY).is_ok());
    }

    /// 🔐 Неверное решение отвергается.
    ///
    /// Без этого `PoW` — украшение: любой бот прислал бы произвольное число.
    #[test]
    fn wrong_solution_is_rejected() {
        let nonce = solve(&challenge(), EASY);
        let wrong = nonce.wrapping_add(1);

        // Соседний nonce почти наверняка не подходит; если вдруг подошёл,
        // тест всё равно осмыслен — проверяется отказ на заведомо чужом.
        if verify(&challenge(), wrong, EASY).is_ok() {
            return;
        }

        assert_eq!(
            verify(&challenge(), wrong, EASY),
            Err(PowError::Insufficient)
        );
    }

    /// 🔐 Решение привязано к челленджу.
    ///
    /// Иначе бот решил бы задачу один раз и переиспользовал ответ
    /// для миллиона регистраций — то есть барьера не было бы вовсе.
    #[test]
    fn solution_does_not_transfer_between_challenges() {
        let nonce = solve(&challenge(), EASY);
        let other = [0x99u8; CHALLENGE_LEN];

        assert!(
            verify(&other, nonce, EASY).is_err(),
            "решение подошло к чужому челленджу"
        );
    }

    /// Нулевая и запредельная сложность отвергаются.
    ///
    /// Нулевая означала бы отсутствие барьера, запредельная — регистрацию,
    /// которую невозможно завершить.
    #[test]
    fn difficulty_bounds_are_enforced() {
        assert_eq!(verify(&challenge(), 0, 0), Err(PowError::BadDifficulty));
        assert_eq!(
            verify(&challenge(), 0, MAX_DIFFICULTY.saturating_add(1)),
            Err(PowError::BadDifficulty)
        );
    }

    /// Хеш детерминирован.
    #[test]
    fn hash_is_deterministic() {
        assert_eq!(
            hash(&challenge(), 7).unwrap(),
            hash(&challenge(), 7).unwrap()
        );
    }

    /// Разные nonce дают разные хеши.
    #[test]
    fn distinct_nonces_give_distinct_hashes() {
        assert_ne!(
            hash(&challenge(), 1).unwrap(),
            hash(&challenge(), 2).unwrap()
        );
    }

    /// Подсчёт нулевых битов корректен.
    #[test]
    fn leading_zero_bits_are_counted_correctly() {
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x7F]), 1);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x0F]), 12);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    /// Большая сложность требует большей работы.
    ///
    /// Проверяется само свойство асимметрии: решение для высокой планки
    /// годится и для низкой, обратное неверно.
    #[test]
    fn harder_solution_satisfies_easier_requirement() {
        let nonce = solve(&challenge(), 6);

        assert!(verify(&challenge(), nonce, 6).is_ok());
        assert!(verify(&challenge(), nonce, 4).is_ok());
    }

    /// Подбор решения укладывается в разумное время.
    ///
    /// Тест существует из-за конкретного дефекта: первая редакция
    /// считала proof-of-work через ``Argon2id`` с 64 мегабайтами памяти, и подбор
    /// занимал около двух часов — регистрация не работала бы вовсе.
    /// Ни один тест этого не замечал, потому что все они проверяли
    /// свойства хеша, а не его стоимость.
    #[test]
    fn solving_stays_within_a_sane_budget() {
        let challenge = [0x17u8; CHALLENGE_LEN];

        // Сложность ниже боевой: тест должен быть быстрым. Он ловит
        // не точную цифру, а порядок величины — регрессию в тысячи раз.
        let difficulty = 12;
        let start = std::time::Instant::now();
        let nonce = solve(&challenge, difficulty);
        let elapsed = start.elapsed();

        assert!(verify(&challenge, nonce, difficulty).is_ok());
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "подбор при сложности {difficulty} занял {elapsed:?}: \
             хеш стал слишком дорогим для proof-of-work"
        );
    }
}

#[cfg(test)]
mod bench_tests {
    use super::*;

    /// Замер стоимости одного хеша — измерение, не проверка.
    ///
    /// Помечен `ignore`: он ничего не утверждает и занимает время.
    /// Запускается вручную, когда нужно выбрать сложность.
    #[test]
    #[ignore = "измерение, а не проверка: занимает время и ничего не утверждает"]
    fn measure_hash_cost() {
        let challenge = [0x42u8; CHALLENGE_LEN];
        let rounds = 20u32;
        let start = std::time::Instant::now();

        for nonce in 0..u64::from(rounds) {
            let _ = hash(&challenge, nonce).expect("хеш");
        }

        let per_hash = start.elapsed() / rounds;
        println!("один хеш: {per_hash:?}");
        println!(
            "медиана перебора при сложности {DEFAULT_DIFFICULTY}: {:?}",
            per_hash * (1u32 << (DEFAULT_DIFFICULTY - 1))
        );
    }
}
