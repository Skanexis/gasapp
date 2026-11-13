// SPDX-License-Identifier: Apache-2.0

//! Улики к жалобе — запечатанные ключом оператора.
//!
//! Жалобщик сам решает показать оператору то, что ему прислали:
//! последние сообщения обидчика и скриншоты. 🔐 Они шифруются **на
//! телефоне** открытым ключом админ-центра; узлы сервера, через которые
//! жалоба проходит, и база, где она лежит, видят только шифр. Открыть
//! его может лишь админ-центр, у которого закрытый ключ
//! (`server/gasapp-server-admin`, `evidence`).
//!
//! # Формат
//!
//! Запечатанное: `GRE1 ‖ эфемерный X25519 (32) ‖ nonce (12) ‖ AES-256-GCM`.
//! Ключ — HKDF-SHA-256(соль = эфемерный ‖ ключ оператора, вход = общий
//! секрет X25519, info = `GasApp report evidence v1`). Заголовок `GRE1`
//! — дополнительные данные AEAD.
//!
//! Открытое (`encode`): `1 ‖ n ‖ n × (время i64 BE ‖ длина u32 BE ‖ UTF-8)
//! ‖ m ‖ m × (длина u32 BE ‖ JPEG)`.
//!
//! Ни подделки, ни проверки подлинности тут нет и быть не может:
//! сервер переписку не видел. Подлинно лишь то, что доказывает сам
//! сертификат жалобы, — что этот аккаунт жалобщику писал. Улики —
//! слова жалобщика, и админ-центр так их и показывает.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use gasapp_types::{GasAppError, Result};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Заголовок запечатанных улик.
pub const MAGIC: &[u8; 4] = b"GRE1";

/// Сколько сообщений обидчика можно приложить.
pub const MAX_QUOTES: usize = 10;

/// Предел длины одного сообщения, байт UTF-8.
pub const MAX_QUOTE_BYTES: usize = 4096;

/// Сколько скриншотов можно приложить.
pub const MAX_IMAGES: usize = 5;

/// Предел одного скриншота, байт.
pub const MAX_IMAGE_BYTES: usize = 400 * 1024;

/// Предел запечатанных улик целиком (столько же проверяет сервер).
pub const MAX_SEALED_BYTES: usize = 1_900 * 1024;

const INFO: &[u8] = b"GasApp report evidence v1";
/// Заголовок, эфемерный ключ, nonce.
const HEADER: usize = 48;

/// Сообщение обидчика: время отправки (мс) и текст.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    /// Время сообщения, миллисекунды Unix.
    pub sent_at_millis: i64,
    /// Текст сообщения.
    pub text: String,
}

/// Открытые улики.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// Сообщения обидчика.
    pub quotes: Vec<Quote>,
    /// Скриншоты, JPEG.
    pub images: Vec<Vec<u8>>,
}

impl Evidence {
    /// Нечего прикладывать.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.quotes.is_empty() && self.images.is_empty()
    }
}

/// Складывает улики в байты.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — сообщений или скриншотов больше
/// предела, либо один из них длиннее своего предела.
pub fn encode(evidence: &Evidence) -> Result<Vec<u8>> {
    if evidence.quotes.len() > MAX_QUOTES || evidence.images.len() > MAX_IMAGES {
        return Err(GasAppError::Malformed);
    }
    let mut out = vec![1u8];
    #[allow(clippy::cast_possible_truncation)] // проверено выше: ≤ 10
    out.push(evidence.quotes.len() as u8);
    for quote in &evidence.quotes {
        let text = quote.text.as_bytes();
        if text.len() > MAX_QUOTE_BYTES {
            return Err(GasAppError::Malformed);
        }
        out.extend_from_slice(&quote.sent_at_millis.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(text.len())
                .map_err(|_| GasAppError::Malformed)?
                .to_be_bytes(),
        );
        out.extend_from_slice(text);
    }
    #[allow(clippy::cast_possible_truncation)] // проверено выше: ≤ 5
    out.push(evidence.images.len() as u8);
    for image in &evidence.images {
        // Только JPEG: админ-центр показывает их как image/jpeg.
        if image.len() > MAX_IMAGE_BYTES || !image.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Err(GasAppError::Malformed);
        }
        out.extend_from_slice(
            &u32::try_from(image.len())
                .map_err(|_| GasAppError::Malformed)?
                .to_be_bytes(),
        );
        out.extend_from_slice(image);
    }
    Ok(out)
}

/// Разбирает байты улик обратно.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — формат нарушен.
pub fn decode(raw: &[u8]) -> Result<Evidence> {
    let mut reader = Reader(raw);
    if reader.array::<1>()? != [1] {
        return Err(GasAppError::Malformed);
    }
    let mut evidence = Evidence::default();
    let [quotes] = reader.array::<1>()?;
    let quotes = usize::from(quotes);
    if quotes > MAX_QUOTES {
        return Err(GasAppError::Malformed);
    }
    for _ in 0..quotes {
        let sent_at_millis = i64::from_be_bytes(reader.array()?);
        let length = reader.length(MAX_QUOTE_BYTES)?;
        let text =
            String::from_utf8(reader.take(length)?.to_vec()).map_err(|_| GasAppError::Malformed)?;
        evidence.quotes.push(Quote {
            sent_at_millis,
            text,
        });
    }
    let [images] = reader.array::<1>()?;
    let images = usize::from(images);
    if images > MAX_IMAGES {
        return Err(GasAppError::Malformed);
    }
    for _ in 0..images {
        let length = reader.length(MAX_IMAGE_BYTES)?;
        evidence.images.push(reader.take(length)?.to_vec());
    }
    if !reader.0.is_empty() {
        return Err(GasAppError::Malformed);
    }
    Ok(evidence)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.0.len() < count {
            return Err(GasAppError::Malformed);
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| GasAppError::Malformed)
    }

    fn length(&mut self, limit: usize) -> Result<usize> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| GasAppError::Malformed)?;
        if length > limit {
            return Err(GasAppError::Malformed);
        }
        Ok(length)
    }
}

fn derive_key(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    operator: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(operator);
    let mut key = Zeroizing::new([0u8; 32]);
    crate::aead::hkdf_sha256(Some(&salt), shared, INFO, key.as_mut())?;
    Ok(key)
}

/// Запечатывает улики ключом оператора.
///
/// # Errors
///
/// * [`GasAppError::Malformed`] — улики не проходят пределы или
///   запечатанное выходит больше [`MAX_SEALED_BYTES`];
/// * [`GasAppError::Crypto`] — ключ оператора слабый (общий секрет
///   нулевой) или сбой шифра.
pub fn seal<R: RngCore + CryptoRng>(
    operator_key: &[u8; 32],
    evidence: &Evidence,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(encode(evidence)?);

    let ephemeral = StaticSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*operator_key));
    // 🔐 Ключ малого порядка дал бы всем известный секрет.
    if !shared.was_contributory() {
        return Err(GasAppError::Crypto);
    }
    let key = derive_key(shared.as_bytes(), ephemeral_public.as_bytes(), operator_key)?;

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| GasAppError::Crypto)?;
    let body = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: MAGIC,
            },
        )
        .map_err(|_| GasAppError::Crypto)?;

    let mut out = Vec::with_capacity(body.len().saturating_add(HEADER));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    if out.len() > MAX_SEALED_BYTES {
        return Err(GasAppError::Malformed);
    }
    Ok(out)
}

/// Вскрывает улики закрытым ключом оператора (зеркало админ-центра;
/// здесь — для проверки формата тестами).
///
/// # Errors
///
/// [`GasAppError::Crypto`] — не тот ключ или шифр повреждён;
/// [`GasAppError::Malformed`] — формат нарушен.
pub fn open(operator_secret: &[u8; 32], sealed: &[u8]) -> Result<Evidence> {
    let mut reader = Reader(sealed);
    if reader.array::<4>()? != *MAGIC {
        return Err(GasAppError::Malformed);
    }
    let ephemeral: [u8; 32] = reader.array()?;
    let nonce: [u8; 12] = reader.array()?;
    let body = reader.0;
    let secret = StaticSecret::from(*operator_secret);
    let operator = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err(GasAppError::Crypto);
    }
    let key = derive_key(shared.as_bytes(), &ephemeral, operator.as_bytes())?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| GasAppError::Crypto)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: MAGIC,
                },
            )
            .map_err(|_| GasAppError::Crypto)?,
    );
    decode(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn sample() -> Evidence {
        Evidence {
            quotes: vec![
                Quote {
                    sent_at_millis: 1_700_000_000_000,
                    text: "Win a prize — click here".to_owned(),
                },
                Quote {
                    sent_at_millis: 1_700_000_060_000,
                    text: "Привет 👋".to_owned(),
                },
            ],
            images: vec![vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3]],
        }
    }

    #[test]
    fn seal_and_open_round_trip() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sealed = seal(public.as_bytes(), &sample(), &mut OsRng).unwrap();
        assert_eq!(&sealed[..4], MAGIC);
        assert_eq!(open(&secret.to_bytes(), &sealed).unwrap(), sample());
    }

    #[test]
    fn wrong_key_and_tampering_fail() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut sealed = seal(public.as_bytes(), &sample(), &mut OsRng).unwrap();
        let other = StaticSecret::random_from_rng(OsRng);
        assert!(open(&other.to_bytes(), &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&secret.to_bytes(), &sealed).is_err());
    }

    #[test]
    fn low_order_operator_key_is_refused() {
        assert!(matches!(
            seal(&[0u8; 32], &sample(), &mut OsRng),
            Err(GasAppError::Crypto)
        ));
    }

    #[test]
    fn limits_are_enforced() {
        let mut evidence = sample();
        evidence.images = vec![b"not a jpeg".to_vec()];
        assert!(matches!(encode(&evidence), Err(GasAppError::Malformed)));
        evidence.images.clear();
        evidence.quotes = vec![Quote {
            sent_at_millis: 0,
            text: "x".repeat(MAX_QUOTE_BYTES + 1),
        }];
        assert!(matches!(encode(&evidence), Err(GasAppError::Malformed)));
        assert!(decode(&[1, 0, 0, 9]).is_err());
        assert!(decode(&[2, 0, 0]).is_err());
    }
}
