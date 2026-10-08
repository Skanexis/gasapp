// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM с защитой от повторного использования nonce.
//!
//! # Чем опасен повтор nonce
//!
//! GCM — потоковый режим: шифротекст получается как XOR открытого текста
//! с гаммой, зависящей от пары «ключ, nonce». Если эта пара повторится,
//! XOR двух шифротекстов даёт XOR двух **открытых** текстов, и оба
//! восстанавливаются без знания ключа. Хуже: повтор позволяет восстановить
//! подключ аутентификации `H`, после чего подделываются теги — то есть
//! теряется не только конфиденциальность, но и целостность.
//!
//! Это не теоретический риск. В первой редакции `double_ratchet.rs` nonce
//! выводился из счётчика сообщений, а счётчик обнуляется на каждом шаге
//! DH-храповика — пара «ключ, nonce» повторялась бы на первом сообщении
//! каждой новой цепочки (дефект #7 раздела 23.0.1).
//!
//! # Как повтор исключается здесь
//!
//! Ключ шифрования оборачивается в [`MessageKey`], который:
//!
//! * **не реализует `Clone`** — второй экземпляр того же ключа нельзя
//!   получить, не выписав его байты явно;
//! * **потребляется** методом [`MessageKey::seal`] — после шифрования
//!   значение перемещено и повторно вызвать шифрование им нельзя.
//!   Попытка не компилируется, а не проваливается во время выполнения;
//! * **выводит nonce из самого ключа** — а не из счётчика. Message key
//!   в ratchet уникален по построению, значит уникален и nonce.
//!
//! Расшифровка ([`MessageKey::open`]) ключ тоже потребляет, но это уже
//! не про nonce: она просто отражает, что message key одноразовый.
//!
//! # Почему AES-GCM, а не ChaCha20-Poly1305
//!
//! На целевых платформах (`ARMv8` и современные x86) AES аппаратно ускорен,
//! и его реализация в железе устойчива к тайминг-атакам. Программная
//! реализация AES на таблицах уязвима к атакам по кэшу — поэтому крейт
//! `aes-gcm` собирается с аппаратным бэкендом `aes`, что даёт
//! постоянное время работы на всех целевых устройствах.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use gasapp_types::{GasAppError, Result, Secret};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Длина ключа AES-256 в байтах.
pub const KEY_LEN: usize = 32;

/// Длина nonce AES-GCM в байтах.
///
/// 96 бит — рекомендация NIST SP 800-38D: при такой длине nonce
/// подставляется в счётчик напрямую, без дополнительного хеширования,
/// которое иначе размывало бы гарантии уникальности.
pub const NONCE_LEN: usize = 12;

/// Длина тега аутентификации в байтах.
pub const TAG_LEN: usize = 16;

/// Метка HKDF для вывода nonce из ключа сообщения.
const NONCE_INFO: &[u8] = b"GASAPP_AEAD_v1_NONCE";

/// Одноразовый ключ шифрования сообщения.
///
/// # Одноразовость на уровне типа
///
/// Тип намеренно не реализует `Clone` и `Copy`, а [`MessageKey::seal`]
/// принимает `self` по значению. Поэтому «зашифровать двумя разными
/// сообщениями один ключ» — это не ошибка времени выполнения, которую
/// нужно ловить проверкой, а код, который **не компилируется**.
pub struct MessageKey(Secret<[u8; KEY_LEN]>);

impl core::fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MessageKey<redacted>")
    }
}

impl MessageKey {
    /// Оборачивает байты как одноразовый ключ сообщения.
    #[must_use]
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        Self(Secret::new(key))
    }

    /// Шифрует открытый текст, аутентифицируя `aad`.
    ///
    /// Ключ потребляется: повторно зашифровать им нельзя.
    ///
    /// # Про `aad`
    ///
    /// Дополнительные аутентифицируемые данные не шифруются, но входят
    /// в тег. Сюда передаётся заголовок сообщения — он управляет выбором
    /// ключа у получателя и потому обязан быть защищён от подмены.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой AEAD или вывода nonce.
    pub fn seal(self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self.0.expose_secret();
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| GasAppError::Crypto)?;
        let nonce = derive_nonce(key)?;

        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| GasAppError::Crypto)
    }

    /// Расшифровывает и проверяет тег вместе с `aad`.
    ///
    /// Ключ потребляется: message key одноразовый и после использования
    /// уничтожается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — тег не сошёлся, шифротекст повреждён либо
    /// `aad` не совпадает с тем, что был при шифровании.
    pub fn open(self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self.0.expose_secret();
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| GasAppError::Crypto)?;
        let nonce = derive_nonce(key)?;

        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| GasAppError::Crypto)
    }
}

/// Выводит nonce детерминированно из ключа сообщения.
///
/// # Почему из ключа, а не из счётчика
///
/// Уникальность пары «ключ, nonce» обеспечивается уникальностью ключа.
/// Счётчик для этого не годится: он обнуляется на каждом шаге
/// DH-храповика, и первое сообщение каждой цепочки получало бы один и тот
/// же nonce при разных ключах — что само по себе безопасно, но перестаёт
/// быть безопасным, стоит ключу повториться по любой другой причине.
/// Вывод из ключа делает совпадение nonce ровно настолько же
/// маловероятным, насколько маловероятно совпадение ключей.
fn derive_nonce(key: &[u8; KEY_LEN]) -> Result<[u8; NONCE_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(None, key);
    let mut nonce = [0u8; NONCE_LEN];

    hkdf.expand(NONCE_INFO, &mut nonce)
        .map_err(|_| GasAppError::Crypto)?;

    Ok(nonce)
}

/// Шифрует ключом и **явно заданным** nonce.
///
/// # Когда это нужно, а когда нет
///
/// [`MessageKey`] выводит nonce из самого ключа и потребляет себя,
/// потому что message key в храповике одноразовый по построению.
/// Есть места, где это не так: внешний слой sealed sender шифрует
/// ключом, выведенным из эфемерной пары, и уникальность там даёт
/// не одноразовость ключа, а сама эфемерность.
///
/// ⚠️ Вызывающий отвечает за то, что пара «ключ, nonce» не
/// повторится. Повтор в GCM раскрывает и оба открытых текста,
/// и подключ аутентификации — то есть ломает и конфиденциальность,
/// и целостность. Если уникальность не очевидна из устройства
/// вызывающего кода, брать нужно [`MessageKey`], а не эту функцию.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой AEAD.
pub fn seal_with_key(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| GasAppError::Crypto)?;

    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| GasAppError::Crypto)
}

/// Расшифровывает то, что зашифровано [`seal_with_key`].
///
/// # Errors
///
/// [`GasAppError::Crypto`] — тег не сходится: не тот ключ, не тот
/// nonce, не те `aad` либо данные изменены.
pub fn open_with_key(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| GasAppError::Crypto)?;

    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| GasAppError::Crypto)
}

/// HKDF-SHA-256: извлечение и расширение за один шаг.
///
/// Обёртка над `hkdf` с фиксированным `Sha256`, чтобы вызывающий код
/// не подключал крейт напрямую и не мог случайно взять другую хеш-функцию.
/// Проверена векторами RFC 5869 (`tests/rfc_vectors.rs`).
///
/// # Errors
///
/// [`GasAppError::Crypto`] — запрошено больше 255 × 32 = 8160 байт выхода.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| GasAppError::Crypto)
}

/// HMAC-SHA-256.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой инициализации (недостижим при корректной
/// длине ключа, но ошибка возвращается, а не подавляется).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| GasAppError::Crypto)?;
    mac.update(message);

    mac.finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| GasAppError::Crypto)
}

/// SHA-512.
///
/// Используется в вычислении отпечатка (раздел 6.6) и в XEdDSA.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut out = [0u8; 64];
    let digest = Sha512::digest(data);
    out.copy_from_slice(&digest);

    out
}

/// Вспомогательное: выводит ключ сообщения из входного материала.
///
/// Возвращает [`Zeroizing`], чтобы промежуточное значение обнулялось,
/// если вызывающий код не превратил его сразу в [`MessageKey`].
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой HKDF.
pub fn derive_message_key(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf_sha256(None, ikm, info, key.as_mut_slice())?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_round_trip() {
        let key = [0x42u8; KEY_LEN];

        let sealed = MessageKey::new(key)
            .seal(b"secret message", b"header")
            .unwrap();
        let opened = MessageKey::new(key).open(&sealed, b"header").unwrap();

        assert_eq!(opened, b"secret message");
    }

    /// 🔐 Подмена `aad` обнаруживается.
    ///
    /// Заголовок сообщения передаётся как `aad`: без этой проверки
    /// посредник менял бы номер сообщения незаметно.
    #[test]
    fn tampered_aad_is_rejected() {
        let key = [0x42u8; KEY_LEN];
        let sealed = MessageKey::new(key).seal(b"payload", b"header").unwrap();

        assert!(MessageKey::new(key).open(&sealed, b"other!").is_err());
    }

    /// 🔐 Подмена шифротекста обнаруживается.
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = [0x42u8; KEY_LEN];
        let mut sealed = MessageKey::new(key).seal(b"payload", b"header").unwrap();

        let last = sealed.len().saturating_sub(1);
        if let Some(byte) = sealed.get_mut(last) {
            *byte ^= 0x01;
        }

        assert!(MessageKey::new(key).open(&sealed, b"header").is_err());
    }

    /// 🔐 Разные ключи дают разные nonce.
    ///
    /// Это и есть защита от повтора nonce: пока ключи различаются,
    /// различаются и nonce, поэтому пара «ключ, nonce» не повторяется.
    #[test]
    fn distinct_keys_yield_distinct_nonces() {
        let first = derive_nonce(&[1u8; KEY_LEN]).unwrap();
        let second = derive_nonce(&[2u8; KEY_LEN]).unwrap();

        assert_ne!(first, second);
    }

    /// Один ключ всегда даёт один и тот же nonce.
    ///
    /// Детерминизм обязателен: получатель выводит nonce независимо
    /// и обязан получить тот же.
    #[test]
    fn nonce_is_deterministic() {
        let key = [0x7Fu8; KEY_LEN];

        assert_eq!(derive_nonce(&key).unwrap(), derive_nonce(&key).unwrap());
    }

    /// 🔐 Шифротекст длиннее открытого текста ровно на тег.
    ///
    /// Проверка того, что тег действительно добавляется: его отсутствие
    /// означало бы шифрование без аутентификации.
    #[test]
    fn ciphertext_carries_authentication_tag() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"exactly sixteen!";

        let sealed = MessageKey::new(key).seal(plaintext, b"").unwrap();

        assert_eq!(sealed.len(), plaintext.len().saturating_add(TAG_LEN));
    }

    /// Пустое сообщение шифруется и расшифровывается.
    #[test]
    fn empty_plaintext_round_trips() {
        let key = [0x42u8; KEY_LEN];

        let sealed = MessageKey::new(key).seal(b"", b"aad").unwrap();
        let opened = MessageKey::new(key).open(&sealed, b"aad").unwrap();

        assert!(opened.is_empty());
        assert_eq!(sealed.len(), TAG_LEN);
    }

    /// Ключ не печатается в отладочном выводе.
    #[test]
    fn message_key_debug_is_redacted() {
        let key = MessageKey::new([0xCD; KEY_LEN]);

        assert_eq!(format!("{key:?}"), "MessageKey<redacted>");
    }

    /// HMAC-SHA-256 детерминирован и зависит от сообщения.
    #[test]
    fn hmac_depends_on_message() {
        let key = [0x0Bu8; 32];

        assert_eq!(
            hmac_sha256(&key, b"same").unwrap(),
            hmac_sha256(&key, b"same").unwrap()
        );
        assert_ne!(
            hmac_sha256(&key, b"one").unwrap(),
            hmac_sha256(&key, b"two").unwrap()
        );
    }

    /// SHA-512 совпадает с известным вектором для пустого входа.
    ///
    /// Значение опубликовано в FIPS 180-4 и воспроизводится любой
    /// корректной реализацией.
    #[test]
    fn sha512_matches_known_vector() {
        let expected = concat!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );

        let digest = sha512(b"");
        let rendered = digest.iter().fold(String::new(), |mut acc, byte| {
            use core::fmt::Write as _;

            let _ = write!(acc, "{byte:02x}");
            acc
        });

        assert_eq!(rendered, expected);
    }

    /// Вывод ключа сообщения зависит от метки.
    #[test]
    fn message_key_derivation_separates_domains() {
        let ikm = [0x11u8; 32];

        let first = derive_message_key(&ikm, b"GASAPP_A").unwrap();
        let second = derive_message_key(&ikm, b"GASAPP_B").unwrap();

        assert_ne!(*first, *second);
    }
}
