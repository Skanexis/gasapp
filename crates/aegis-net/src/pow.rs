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

/// Домен-разделитель челленджа регистрации.
const REGISTRATION_DOMAIN: &[u8] = b"AEGIS_POW_REG_v1";

/// Челлендж регистрации: хеш имени и обоих ключей.
///
/// 🔐 Сервер вычисляет его сам и отвергает любой другой, так что одно
/// решение годится ровно для одного аккаунта. Прежде челлендж был
/// случайным, выбирал его клиент, и одно решение регистрировало сколько
/// угодно аккаунтов.
///
/// Каждое поле идёт с длиной впереди, иначе имя `ab` с ключом `c…`
/// и имя `a` с ключом `bc…` дали бы один челлендж.
///
/// ⚠️ Продублирован на сервере (разные лицензии); совпадение проверяет
/// `client_contract` сервера и тест ниже — оба по одному эталону.
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

/// Домен-разделитель челленджа первого контакта.
const FIRST_CONTACT_DOMAIN: &[u8] = b"AEGIS_POW_FIRST_v1";

/// Сложность proof-of-work первого контакта, в битах.
///
/// 🔐 Первое сообщение новому собеседнику уходит запечатанным, хотя
/// ключа доступа получателя у отправителя ещё нет: право на анонимную
/// отправку доказывается работой, а не личностью. Без этого первое
/// сообщение шло за подписью отправителя, и сервер видел, кто начал
/// переписку с кем.
///
/// 18 бит — около четверти миллиона хешей: доли секунды на телефоне
/// и заметная цена для того, кто рассылает спам тысячам адресатов.
/// Работа нужна только до первого ответа — он приносит ключ доступа.
pub const FIRST_CONTACT_DIFFICULTY: u32 = 18;

/// Челлендж первого контакта: устройство получателя и хеш конверта.
///
/// 🔐 Привязка к конверту делает решение одноразовым: для другого
/// сообщения или другого получателя нужна новая работа. Сервер
/// вычисляет челлендж сам из того, что пришло, — подставить чужой
/// нечем.
///
/// Устройство — в каноническом виде сервера: UUID строчными буквами.
///
/// ⚠️ Продублирован на сервере (разные лицензии); совпадение проверяет
/// эталон ниже и тот же эталон на сервере.
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
/// Возвращает `None`, если решение не найдено за `MAX_ATTEMPTS`
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

    /// 🔐 Челлендж регистрации совпадает с эталоном.
    ///
    /// Эталон посчитан третьей, независимой реализацией (Python,
    /// hashlib); тот же вектор проверяет сервер в `client_contract`.
    /// Расхождение означало бы отказ всех регистраций.
    #[test]
    fn registration_challenge_matches_the_reference() {
        let challenge = registration_challenge("alice", &[1u8; 32], &[2u8; 32]);

        assert_eq!(
            challenge.get(..8).expect("восемь байт"),
            [0x09, 0x8d, 0x43, 0xfe, 0x4b, 0x0f, 0xa3, 0xea]
        );
    }

    /// Эталон посчитан независимой реализацией (Python, hashlib);
    /// тот же вектор проверяет сервер. Расхождение означало бы отказ
    /// каждого первого сообщения.
    #[test]
    fn first_contact_challenge_matches_the_reference() {
        let challenge = first_contact_challenge("00000000-0000-0000-0000-000000000001", &[1, 2, 3]);

        assert_eq!(
            challenge.get(..8).expect("восемь байт"),
            [0x14, 0x11, 0x06, 0xfa, 0x70, 0xb8, 0xb0, 0x95]
        );
    }

    /// 🔐 Решение не переносится на другой конверт или другого получателя.
    #[test]
    fn first_contact_challenge_binds_envelope_and_recipient() {
        let base = first_contact_challenge("00000000-0000-0000-0000-000000000001", &[1, 2, 3]);

        assert_ne!(
            base,
            first_contact_challenge("00000000-0000-0000-0000-000000000002", &[1, 2, 3])
        );
        assert_ne!(
            base,
            first_contact_challenge("00000000-0000-0000-0000-000000000001", &[1, 2, 4])
        );
        // Регистр UUID не меняет челлендж: сервер пишет строчными.
        assert_eq!(
            base,
            first_contact_challenge(
                "00000000-0000-0000-0000-000000000001"
                    .to_uppercase()
                    .as_str(),
                &[1, 2, 3]
            )
        );
    }

    /// Разные имена — разные челленджи: одно решение на один аккаунт.
    #[test]
    fn different_usernames_give_different_challenges() {
        assert_ne!(
            registration_challenge("alice", &[1u8; 32], &[2u8; 32]),
            registration_challenge("alicf", &[1u8; 32], &[2u8; 32])
        );
    }
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
