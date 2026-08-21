// SPDX-License-Identifier: Apache-2.0

//! Векторы протокола: фиксация собственной реализации как эталона.
//!
//! # Почему здесь нет официальных векторов
//!
//! Их не существует. Signal публикует спецификации PQXDH и Double
//! Ratchet, но не тестовые векторы к ним, а дифференциальное
//! тестирование против libsignal оказалось невозможным: у нас другие
//! KDF-метки (`AEGIS_PQXDH_v1_*` против `WhisperText_*`), другой AEAD
//! (AES-GCM против AES-CBC+HMAC) и другой набор параметров KEM
//! (ML-KEM-1024 против Kyber-1024). Разные алгоритмы не обязаны
//! совпадать в выходных байтах — сравнивать нечего.
//!
//! # Что тогда проверяется
//!
//! **Неизменность**, а не соответствие спецификации. Это разные
//! свойства, и путать их нельзя: зафиксированные здесь байты получены
//! этой же реализацией и потому не доказывают её правильность.
//!
//! Они доказывают другое — что реализация не поменялась молча. Смена
//! KDF-метки, порядка входов в вывод ключа, формата заголовка или
//! версии зависимости изменит эти байты. Без такой фиксации подобное
//! расхождение проявилось бы только в бою: устройства на соседних
//! версиях приложения не смогли бы прочитать сообщения друг друга,
//! и причину пришлось бы искать в проде.
//!
//! # Что остаётся непроверенным
//!
//! Соответствие спецификации. Поймать расхождение с ней сегодня
//! нечем — этот долг зафиксирован в плане и закрывается только
//! внешним аудитом.

use aegis_protocol::double_ratchet::RatchetState;
use aegis_protocol::pqxdh;
use aegis_protocol::prekeys;
use aegis_protocol::x25519::X25519PublicKey;
use aegis_types::{DeviceId, Plaintext, Timestamp};
use rand_core::{CryptoRng, RngCore};

/// Детерминированный генератор для воспроизводимых векторов.
///
/// # Почему не настоящий ГПСЧ
///
/// Вектор обязан воспроизводиться при каждом запуске, иначе он ничего
/// не фиксирует. Криптостойкость здесь не нужна и была бы вредна:
/// от генератора требуется ровно противоположное — предсказуемость.
///
/// Реализован как счётчик, пропущенный через SHA-256: этого достаточно
/// для равномерности байтов, а сам алгоритм умещается в десяток строк
/// и не тянет зависимость.
///
/// `CryptoRng` реализован потому, что этого требуют сигнатуры
/// протокола. Это ложь по существу, и она допустима **только** здесь:
/// файл собирается лишь под `cfg(test)` и в приложение не попадает.
struct DeterministicRng {
    counter: u64,
    buffer: Vec<u8>,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self {
            counter: seed,
            buffer: Vec::new(),
        }
    }

    fn refill(&mut self) {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"AEGIS_TEST_VECTOR_RNG");
        hasher.update(self.counter.to_be_bytes());

        self.counter = self.counter.wrapping_add(1);
        self.buffer.extend_from_slice(&hasher.finalize());
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);

        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);

        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for slot in dest.iter_mut() {
            if self.buffer.is_empty() {
                self.refill();
            }

            *slot = self.buffer.remove(0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

fn now() -> Timestamp {
    Timestamp::from_millis(1_700_000_000_000)
}

/// Первые восемь байт в виде массива — для читаемых сообщений об ошибке.
fn head(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes.get(..8).unwrap_or(&[0u8; 8]));

    out
}

/// 🔐 Identity-ключ от фиксированного seed не меняется.
///
/// Ловит смену алгоритма вывода ключа X25519 или порядка байтов.
#[test]
fn identity_key_from_seed_is_stable() {
    let mut rng = DeterministicRng::new(1);
    let identity = prekeys::generate_identity(&mut rng).expect("identity");

    assert_eq!(
        head(identity.public().public().as_bytes()),
        [0xc5, 0x8a, 0x54, 0x0c, 0xa3, 0x79, 0x1a, 0x8e],
        "identity-ключ изменился: сессии между версиями не установятся"
    );
}

/// 🔐 Общий секрет PQXDH не меняется.
///
/// Самый важный вектор здесь: секрет — вход для всей последующей
/// цепочки ключей. Его изменение означает, что ни одно сообщение
/// между версиями не расшифруется.
#[test]
fn pqxdh_shared_secret_is_stable() {
    let mut rng = DeterministicRng::new(2);

    let alice = prekeys::generate_identity(&mut rng).expect("identity");
    let bob = prekeys::generate_identity(&mut rng).expect("identity");
    let (bundle, _) =
        prekeys::generate(&bob, DeviceId::generate(), now(), &mut rng).expect("предключи");

    let output = pqxdh::initiate(&alice, &bundle, &mut rng).expect("инициация");

    assert_eq!(
        head(output.shared_secret.expose_secret()),
        [0x3c, 0x07, 0x5d, 0x5b, 0xac, 0x79, 0x1a, 0x74],
        "общий секрет PQXDH изменился: сообщения между версиями \
         не расшифруются"
    );
}

/// 🔐 Шифротекст Double Ratchet не меняется.
///
/// Ловит смену формата заголовка, порядка полей или параметров AEAD.
#[test]
fn ratchet_ciphertext_is_stable() {
    let mut rng = DeterministicRng::new(3);

    let their_ratchet = X25519PublicKey::from_bytes(aegis_types::PublicKeyBytes::new([0x42; 32]))
        .expect("публичный ключ");

    let mut ratchet =
        RatchetState::initiate(&[0x11; 32], &their_ratchet, &mut rng).expect("храповик");

    let ciphertext = ratchet
        .encrypt(&Plaintext::new(b"vector".to_vec()))
        .expect("шифрование");

    assert_eq!(
        head(ciphertext.as_bytes()),
        [0xdd, 0x56, 0x90, 0xd2, 0x5f, 0xd1, 0x06, 0xb9],
        "шифротекст храповика изменился: формат сообщения разошёлся \
         между версиями"
    );
}

/// 🔐 Метки KDF участвуют в выводе ключей.
///
/// Проверяется косвенно: два храповика с одинаковым секретом, но
/// разными публичными ключами обязаны дать разные шифротексты. Если
/// бы метка или ключ не входили в вывод, шифротексты совпали бы —
/// и один и тот же ключ шифровал бы разные сессии.
#[test]
fn different_ratchet_keys_give_different_ciphertexts() {
    let make = |key: u8| {
        let mut rng = DeterministicRng::new(4);
        let public = X25519PublicKey::from_bytes(aegis_types::PublicKeyBytes::new([key; 32]))
            .expect("публичный ключ");

        let mut ratchet =
            RatchetState::initiate(&[0x11; 32], &public, &mut rng).expect("храповик");

        ratchet
            .encrypt(&Plaintext::new(b"vector".to_vec()))
            .expect("шифрование")
            .into_bytes()
    };

    assert_ne!(make(0x42), make(0x43));
}

/// Генератор векторов сам детерминирован.
///
/// Без этого все векторы выше проверяли бы случайность, а не
/// реализацию.
#[test]
fn vector_rng_is_reproducible() {
    let mut first = DeterministicRng::new(9);
    let mut second = DeterministicRng::new(9);

    let mut a = [0u8; 64];
    let mut b = [0u8; 64];

    first.fill_bytes(&mut a);
    second.fill_bytes(&mut b);

    assert_eq!(a, b, "генератор векторов недетерминирован");
}
