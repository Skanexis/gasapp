// SPDX-License-Identifier: Apache-2.0

//! Решение proof-of-work для регистрации.
//!
//! # Зачем это на клиенте
//!
//! Сервер требует доказательство работы при регистрации: оно почти
//! незаметно тому, кто заводит один аккаунт, и дорого тому, кто заводит
//! миллион. Подбор ведёт клиент, проверку — сервер, и асимметрия между
//! ними и есть смысл схемы.
//!
//! # Почему код продублирован с сервером
//!
//! Клиент под Apache-2.0, сервер под AGPL-3.0: связать их одним крейтом
//! нельзя, иначе лицензия сервера распространилась бы на клиентские
//! приложения. Двадцать строк хеша дублируются намеренно, а расхождение
//! ловит тест на совместимость в `wire_contract`.

use sha2::{Digest, Sha256};

/// Длина челленджа в байтах.
pub const CHALLENGE_LEN: usize = 32;

/// Верхняя граница числа попыток.
///
/// Подбор при штатной сложности укладывается в миллионы попыток.
/// Граница нужна, чтобы завышенная сложность от подменённого сервера
/// не превращала регистрацию в бесконечный цикл, который выглядит
/// как зависшее приложение и разряжает батарею.
const MAX_ATTEMPTS: u64 = 1 << 28;

/// Вычисляет хеш решения.
///
/// Домен-разделитель обязан совпадать с серверным: без этого ни одно
/// решение не будет принято.
#[must_use]
pub fn hash(challenge: &[u8], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"AEGIS_POW_v1");
    hasher.update(challenge);
    hasher.update(nonce.to_be_bytes());

    hasher.finalize().into()
}

/// Подбирает `nonce`, дающий нужное число старших нулевых битов.
///
/// Возвращает `None`, если решение не найдено за [`MAX_ATTEMPTS`]
/// попыток: это признак завышенной сложности, а не невезения.
#[must_use]
pub fn solve(challenge: &[u8], difficulty: u32) -> Option<u64> {
    (0..MAX_ATTEMPTS).find(|&nonce| leading_zero_bits(&hash(challenge, nonce)) >= difficulty)
}

/// Считает старшие нулевые биты.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total: u32 = 0;

    for byte in bytes {
        let zeros = byte.leading_zeros();
        total = total.saturating_add(zeros);

        // Ненулевой байт обрывает цепочку: биты после первой единицы
        // уже не считаются.
        if *byte != 0 {
            break;
        }
    }

    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solution_satisfies_requested_difficulty() {
        let challenge = [0x42u8; CHALLENGE_LEN];
        let difficulty = 12;

        let nonce = solve(&challenge, difficulty).expect("решение найдено");

        assert!(leading_zero_bits(&hash(&challenge, nonce)) >= difficulty);
    }

    #[test]
    fn hash_is_deterministic() {
        let challenge = [0x07u8; CHALLENGE_LEN];

        assert_eq!(hash(&challenge, 99), hash(&challenge, 99));
    }

    /// Решение не переносится на другой челлендж.
    ///
    /// Иначе одну подобранную пару можно было бы предъявлять при каждой
    /// регистрации, и proof-of-work перестал бы что-либо стоить.
    #[test]
    fn solution_does_not_transfer_between_challenges() {
        let first = [0x01u8; CHALLENGE_LEN];
        let second = [0x02u8; CHALLENGE_LEN];
        let difficulty = 12;

        let nonce = solve(&first, difficulty).expect("решение найдено");

        assert!(leading_zero_bits(&hash(&second, nonce)) < difficulty);
    }

    #[test]
    fn leading_zero_bits_are_counted_correctly() {
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
    }

    /// Подбор укладывается в разумное время.
    ///
    /// Клиентский аналог серверного теста: он ловит регрессию, при
    /// которой хеш становится слишком дорогим и регистрация зависает
    /// на телефоне.
    #[test]
    fn solving_stays_within_a_sane_budget() {
        let challenge = [0x17u8; CHALLENGE_LEN];
        let start = std::time::Instant::now();

        let nonce = solve(&challenge, 12).expect("решение найдено");
        let elapsed = start.elapsed();

        assert!(leading_zero_bits(&hash(&challenge, nonce)) >= 12);
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "подбор занял {elapsed:?}: хеш стал слишком дорогим"
        );
    }
}
