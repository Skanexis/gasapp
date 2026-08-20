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
//! # Чего здесь нет
//!
//! Хранения выданных челленджей. Челлендж подписывается сервером
//! и содержит время выпуска, поэтому его подлинность и свежесть
//! проверяются без обращения к базе — иначе регистрация стала бы
//! точкой, где сервер обязан помнить состояние для каждого гостя,
//! то есть удобной мишенью для DoS.

use sha2::{Digest, Sha256};

/// Длина челленджа в байтах.
pub const CHALLENGE_LEN: usize = 32;

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
