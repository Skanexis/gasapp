// SPDX-License-Identifier: Apache-2.0

//! XEdDSA (Edwards-curve Digital Signature Algorithm) over Curve25519.
//!
//! Implementation using the ed25519-dalek crate.
//! XEdDSA allows using the same key pair for both X25519 Diffie-Hellman
//! and Ed25519 signatures.

use aegis_types::{AegisError, PrivateKeyBytes, PublicKeyBytes, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Длина подписи Ed25519 в байтах: R (32) ‖ S (32).
pub const SIGNATURE_LEN: usize = 64;

/// XEdDSA public key (Ed25519 verifying key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct XEdDSAPublicKey(pub VerifyingKey);

/// XEdDSA private key (Ed25519 signing key).
pub struct XEdDSAPrivateKey {
    /// The signing key.
    pub(crate) signing_key: SigningKey,
}

impl XEdDSAPublicKey {
    /// Creates a new XEdDSA public key from bytes.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — байты не являются корректной точкой Ed25519.
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        // For Ed25519, any 32-byte string is a valid public key
        let verifying_key =
            VerifyingKey::from_bytes(bytes.as_bytes()).map_err(|_| AegisError::Crypto)?;
        Ok(XEdDSAPublicKey(verifying_key))
    }

    /// Returns the raw bytes of the public key.
    #[must_use]
    pub fn as_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes::new(self.0.to_bytes())
    }

    /// Проверяет подпись сообщения.
    ///
    /// Используется именно `verify_strict`, а не `verify`: строгий вариант
    /// отвергает ключи и точки R малого порядка. Без этого одна и та же
    /// подпись может проходить проверку под несколькими ключами
    /// (malleability), а на этом свойстве строятся атаки подмены отправителя.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — подпись неверной длины либо не сходится
    /// с ключом.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig_array =
            <[u8; SIGNATURE_LEN]>::try_from(signature).map_err(|_| AegisError::Crypto)?;

        self.0
            .verify_strict(message, &Signature::from_bytes(&sig_array))
            .map_err(|_| AegisError::Crypto)
    }
}

impl XEdDSAPrivateKey {
    /// Generates a new random XEdDSA private key.
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        csprng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();

        Self { signing_key }
    }

    /// Creates a new XEdDSA private key from bytes.
    ///
    /// Любые 32 байта — корректный seed Ed25519: приватный скаляр получается
    /// из них хешированием, поэтому отказать здесь не в чем. `Result`
    /// сохранён ради единообразия с [`X25519PrivateKey::from_bytes`]
    /// и стабильности сигнатуры.
    ///
    /// [`X25519PrivateKey::from_bytes`]: crate::x25519::X25519PrivateKey::from_bytes
    ///
    /// # Errors
    ///
    /// Не возвращается никогда — см. описание выше.
    #[allow(clippy::result_unit_err, clippy::needless_pass_by_value)]
    pub fn from_bytes(bytes: PrivateKeyBytes) -> Result<Self> {
        Ok(Self {
            signing_key: SigningKey::from_bytes(bytes.expose_secret()),
        })
    }

    /// Returns the raw bytes of the private key.
    ///
    /// # Safety
    ///
    /// This function exposes secret key material. The caller must ensure
    /// that this material is properly protected and zeroized after use.
    #[must_use]
    pub fn expose_secret(&self) -> PrivateKeyBytes {
        PrivateKeyBytes::new(self.signing_key.to_bytes())
    }

    /// Returns the public key corresponding to this private key.
    #[must_use]
    pub fn public_key(&self) -> XEdDSAPublicKey {
        XEdDSAPublicKey(VerifyingKey::from(&self.signing_key))
    }

    /// Подписывает сообщение.
    ///
    /// Возвращает полную подпись R ‖ S (64 байта). Ранее здесь копировалась
    /// только половина S через `s_bytes()`, а старший полубуфер оставался
    /// нулевым — такая «подпись» не проходит проверку никогда, и подпись
    /// предключей в PQXDH была бы неработоспособна.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing_key.sign(message).to_bytes()
    }
}

// Ручной `impl Zeroize` здесь не нужен и был бы вреден.
//
// `ed25519_dalek::SigningKey`, собранный с фичей `zeroize`, реализует
// `ZeroizeOnDrop` и затирает себя сам. Прежняя реализация в этом файле
// копировала ключ во временный буфер и обнуляла *копию*, оставляя оригинал
// в памяти нетронутым — то есть давала ровно ту гарантию, которой не давала.
//
// Тест `private_key_is_zeroize_on_drop` ниже фиксирует свойство на уровне
// системы типов, чтобы смена версии зависимости не отменила его молча.

impl From<XEdDSAPublicKey> for PublicKeyBytes {
    fn from(key: XEdDSAPublicKey) -> Self {
        key.as_bytes()
    }
}

impl TryFrom<PublicKeyBytes> for XEdDSAPublicKey {
    type Error = AegisError;

    fn try_from(bytes: PublicKeyBytes) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl From<XEdDSAPrivateKey> for PrivateKeyBytes {
    fn from(key: XEdDSAPrivateKey) -> Self {
        key.expose_secret()
    }
}

impl TryFrom<PrivateKeyBytes> for XEdDSAPrivateKey {
    type Error = AegisError;

    fn try_from(bytes: PrivateKeyBytes) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

/// Подпись ключом X25519 — собственно XEdDSA.
///
/// # Зачем это нужно отдельно от Ed25519 выше
///
/// Типы [`XEdDSAPublicKey`] и [`XEdDSAPrivateKey`] работают с Ed25519:
/// публичный ключ там — точка Эдвардса, и проверить ею подпись под
/// X25519-ключом нельзя. Между тем протокол требует ровно этого:
/// `IK` — ключ X25519 (им выполняется DH), и он же проверяет подписи
/// предключей (раздел 6.2 плана, строка «Позволяет одной паре ключей
/// и DH, и подпись»).
///
/// Схема XEdDSA решает это переносом ключа между двумя представлениями
/// одной кривой Curve25519: подпись создаётся и проверяется в форме
/// Эдвардса, а хранится и используется для DH — в форме Монтгомери.
///
/// # Знак точки
///
/// Координата Монтгомери `u` не определяет знак соответствующей точки
/// Эдвардса: одному X25519-ключу отвечают две точки, различающиеся знаком.
/// Подписывающая сторона приводит ключ к форме с нулевым знаком, а
/// проверяющая восстанавливает точку с тем же соглашением — поэтому обе
/// стороны получают одну и ту же точку. Это стандартное соглашение XEdDSA.
pub mod montgomery {
    // Арифметика здесь — групповая, на скалярах и точках Curve25519, а не на
    // машинных целых: `+` и `*` реализуют операции конечного поля и
    // переполниться не могут. Лимит `arithmetic_side_effects` рассчитан на
    // целочисленное переполнение и к этим типам неприменим, поэтому снят
    // точечно — на одном модуле, а не на крейте.
    #![allow(clippy::arithmetic_side_effects)]

    use super::{AegisError, PrivateKeyBytes, PublicKeyBytes, Result, SIGNATURE_LEN};
    use curve25519_dalek::{montgomery::MontgomeryPoint, scalar::Scalar};
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha512};
    use zeroize::{Zeroize, Zeroizing};

    /// Приводит байты приватного ключа к скаляру X25519.
    ///
    /// # Про клампинг
    ///
    /// X25519 применяет клампинг (`decode_scalar`, RFC 7748 §5) внутри самой
    /// операции DH, а не при хранении ключа. Значит, DH фактически выполняется
    /// на *подчищенном* скаляре, и подпись обязана использовать ровно его же —
    /// иначе публичный ключ, выведенный здесь, не совпадёт с тем, который
    /// участвует в DH, и стороны не сойдутся в общем секрете.
    fn clamp(private: &PrivateKeyBytes) -> Scalar {
        let mut bytes = *private.expose_secret();

        // Обнуляем три младших бита, старший бит и выставляем предстарший —
        // ровно то, что делает decode_scalar в RFC 7748.
        if let Some(first) = bytes.first_mut() {
            *first &= 0xF8;
        }
        if let Some(last) = bytes.last_mut() {
            *last &= 0x7F;
            *last |= 0x40;
        }

        let scalar = Scalar::from_bytes_mod_order(bytes);
        bytes.zeroize();

        scalar
    }

    /// Восстанавливает точку Эдвардса из публичного ключа X25519.
    ///
    /// Знак фиксируется нулём — тем же соглашением, что и при подписи.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — байты не являются корректной точкой кривой.
    fn to_edwards(public: &PublicKeyBytes) -> Result<VerifyingKey> {
        let point = MontgomeryPoint(*public.as_bytes())
            .to_edwards(0)
            .ok_or(AegisError::Crypto)?;

        VerifyingKey::from_bytes(&point.compress().to_bytes()).map_err(|_| AegisError::Crypto)
    }

    /// Подписывает сообщение приватным ключом X25519.
    ///
    /// # Про источник случайности
    ///
    /// Подпись детерминированная: nonce выводится из приватного ключа и
    /// сообщения, как в Ed25519 (RFC 8032). Отдельный CSPRNG не нужен, а
    /// его отсутствие исключает целый класс отказов — повтор nonce при
    /// плохой энтропии раскрывает приватный ключ.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — приватный ключ не даёт корректной точки.
    pub fn sign(private: &PrivateKeyBytes, message: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
        // Тот же скаляр, что участвует в DH, — см. `clamp`.
        let scalar = clamp(private);

        // Точка Эдвардса, отвечающая этому скаляру, и её каноническая
        // (с нулевым знаком) кодировка — та же, что восстановит проверяющий.
        let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;
        let compressed = point.compress();
        let sign_bit = compressed.to_bytes().get(31).copied().unwrap_or(0) & 0x80;

        // Приводим к соглашению «знак = 0»: если точка имеет установленный
        // старший бит, берём противоположный скаляр.
        let (scalar, point) = if sign_bit == 0 {
            (scalar, point)
        } else {
            let negated = -scalar;
            let negated_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &negated;
            (negated, negated_point)
        };
        let public_bytes = point.compress().to_bytes();

        // Детерминированный nonce: SHA-512(префикс ‖ скаляр ‖ сообщение).
        // Префикс отделяет его от хеша самой подписи ниже.
        let mut nonce_hash = Sha512::new();
        nonce_hash.update([0xFEu8; 32]);
        nonce_hash.update(scalar.to_bytes());
        nonce_hash.update(message);
        let nonce = Zeroizing::new(Scalar::from_hash(nonce_hash));

        let r_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &*nonce;
        let r_bytes = r_point.compress().to_bytes();

        // Вызов (challenge) по правилам Ed25519: SHA-512(R ‖ A ‖ M).
        let mut challenge_hash = Sha512::new();
        challenge_hash.update(r_bytes);
        challenge_hash.update(public_bytes);
        challenge_hash.update(message);
        let challenge = Scalar::from_hash(challenge_hash);

        let s = *nonce + challenge * scalar;

        let mut signature = [0u8; SIGNATURE_LEN];
        let (r_half, s_half) = signature.split_at_mut(32);
        r_half.copy_from_slice(&r_bytes);
        s_half.copy_from_slice(&s.to_bytes());

        Ok(signature)
    }

    /// Проверяет подпись публичным ключом X25519.
    ///
    /// Используется `verify_strict`: он отвергает ключи и точки `R` малого
    /// порядка, на которых строятся атаки подмены отправителя.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — ключ не является точкой кривой либо подпись
    /// имеет неверную длину.
    ///
    /// [`AegisError::InvalidSignature`] — подпись не сходится с ключом.
    pub fn verify(public: &PublicKeyBytes, message: &[u8], signature: &[u8]) -> Result<()> {
        let verifying_key = to_edwards(public)?;
        let bytes = <[u8; SIGNATURE_LEN]>::try_from(signature).map_err(|_| AegisError::Crypto)?;

        verifying_key
            .verify_strict(message, &Signature::from_bytes(&bytes))
            .map_err(|_| AegisError::InvalidSignature)
    }

    /// Публичный ключ X25519, соответствующий приватному.
    ///
    /// Вынесено сюда, чтобы тесты и вызывающий код не зависели от того,
    /// каким именно способом выводится точка.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — приватный ключ некорректен.
    pub fn public_key(private: &PrivateKeyBytes) -> Result<PublicKeyBytes> {
        let scalar = clamp(private);
        let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;

        Ok(PublicKeyBytes::new(point.to_montgomery().to_bytes()))
    }
}

#[cfg(test)]
// Разбор hex-векторов RFC 8032 идёт по индексам — см. пояснение
// в тестовом модуле `crate::x25519`.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Официальный вектор RFC 8032, раздел 7.1, TEST 1 (пустое сообщение).
    ///
    /// Как и в [`crate::x25519`], значения заданы hex-строками для посимвольной
    /// сверки с текстом RFC. Прежние массивы `0x..` в этом файле не совпадали
    /// с RFC ни в приватном ключе, ни в публичном, а «ожидаемая подпись» была
    /// дописана до 64 байт значениями `0xff` — то есть тест был подогнан под
    /// сломанную реализацию `sign`, вместо того чтобы её поймать.
    const RFC8032_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        assert_eq!(s.len(), 64, "ожидалось 64 hex-символа");
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = s.get(i * 2..i * 2 + 2).expect("длина проверена выше");
            *byte = u8::from_str_radix(pair, 16).expect("не hex");
        }
        out
    }

    fn hex64(s: &str) -> [u8; SIGNATURE_LEN] {
        let mut out = [0u8; SIGNATURE_LEN];
        assert_eq!(s.len(), 128, "ожидалось 128 hex-символов");
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = s.get(i * 2..i * 2 + 2).expect("длина проверена выше");
            *byte = u8::from_str_radix(pair, 16).expect("не hex");
        }
        out
    }

    #[test]
    fn test_xeddsa_keypair_generation() {
        let mut csprng = OsRng;
        let alice = XEdDSAPrivateKey::generate(&mut csprng);
        let bob = XEdDSAPrivateKey::generate(&mut csprng);

        let message = b"test message";
        let signature = alice.sign(message);

        assert!(alice
            .public_key()
            .verify_strict(message, &signature)
            .is_ok());
        // Чужим ключом подпись проверяться не должна.
        assert!(bob.public_key().verify_strict(message, &signature).is_err());
    }

    /// Seed из RFC даёт ровно тот публичный ключ, что напечатан в RFC.
    #[test]
    fn rfc8032_public_key_matches() {
        let key =
            XEdDSAPrivateKey::from_bytes(PrivateKeyBytes::new(hex32(RFC8032_SECRET))).unwrap();

        assert_eq!(
            key.public_key().as_bytes(),
            PublicKeyBytes::new(hex32(RFC8032_PUBLIC))
        );
    }

    /// Подпись побайтово совпадает с RFC 8032 и проходит проверку.
    ///
    /// Тест поймал бы прежнюю реализацию `sign`, которая возвращала только
    /// половину S и нули вместо R.
    #[test]
    fn rfc8032_signature_matches_and_verifies() {
        let key =
            XEdDSAPrivateKey::from_bytes(PrivateKeyBytes::new(hex32(RFC8032_SECRET))).unwrap();
        let expected = hex64(RFC8032_SIGNATURE);

        let signature = key.sign(b"");

        assert_eq!(signature, expected, "подпись разошлась с RFC 8032 7.1");
        assert!(key.public_key().verify_strict(b"", &signature).is_ok());
    }

    /// Подпись не должна проверяться для другого сообщения.
    #[test]
    fn signature_does_not_verify_for_different_message() {
        let mut csprng = OsRng;
        let key = XEdDSAPrivateKey::generate(&mut csprng);
        let signature = key.sign(b"original");

        assert!(key
            .public_key()
            .verify_strict(b"tampered", &signature)
            .is_err());
    }

    /// 🔐 XEdDSA: подпись ключом X25519 проверяется тем же ключом.
    ///
    /// Основное свойство схемы. Без него подписи предключей в PQXDH
    /// проверять нечем: `IK` — ключ X25519, а не Ed25519.
    #[test]
    fn xeddsa_signature_verifies_with_x25519_key() {
        let private = PrivateKeyBytes::new(hex32(RFC8032_SECRET));
        let public = montgomery::public_key(&private).unwrap();

        let signature = montgomery::sign(&private, b"prekey material").unwrap();

        assert!(montgomery::verify(&public, b"prekey material", &signature).is_ok());
    }

    /// 🔐 XEdDSA и X25519 согласованы в публичном ключе.
    ///
    /// Ключевой инвариант всей схемы: `IK` один, а ролей у него две — DH
    /// и подпись. Если публичный ключ, выведенный для подписи, разойдётся
    /// с тем, который использует X25519, стороны PQXDH не сойдутся в общем
    /// секрете. Расхождение возникает при разном клампинге скаляра
    /// (RFC 7748 §5), поэтому свойство закреплено тестом.
    #[test]
    fn xeddsa_public_key_matches_x25519() {
        use crate::x25519::X25519PrivateKey;
        use rand_core::OsRng;

        for _ in 0..16 {
            let private = X25519PrivateKey::generate(&mut OsRng);
            let bytes = private.expose_secret();

            assert_eq!(
                montgomery::public_key(&bytes).unwrap(),
                private.public_key().as_bytes(),
                "публичный ключ XEdDSA разошёлся с X25519"
            );
        }
    }

    /// 🔐 XEdDSA: подпись не проходит для другого сообщения.
    #[test]
    fn xeddsa_signature_rejects_other_message() {
        let private = PrivateKeyBytes::new(hex32(RFC8032_SECRET));
        let public = montgomery::public_key(&private).unwrap();

        let signature = montgomery::sign(&private, b"original").unwrap();

        assert!(matches!(
            montgomery::verify(&public, b"tampered", &signature),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 XEdDSA: подпись не проходит под чужим ключом.
    #[test]
    fn xeddsa_signature_rejects_other_key() {
        let private = PrivateKeyBytes::new(hex32(RFC8032_SECRET));
        let mut other_bytes = hex32(RFC8032_SECRET);
        other_bytes[0] ^= 0xFF;
        let other = PrivateKeyBytes::new(other_bytes);

        let signature = montgomery::sign(&private, b"message").unwrap();
        let other_public = montgomery::public_key(&other).unwrap();

        assert!(matches!(
            montgomery::verify(&other_public, b"message", &signature),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// 🔐 XEdDSA: подпись детерминирована.
    ///
    /// Nonce выводится из ключа и сообщения, а не из CSPRNG: повтор nonce
    /// при плохой энтропии раскрыл бы приватный ключ.
    #[test]
    fn xeddsa_signature_is_deterministic() {
        let private = PrivateKeyBytes::new(hex32(RFC8032_SECRET));

        let first = montgomery::sign(&private, b"message").unwrap();
        let second = montgomery::sign(&private, b"message").unwrap();

        assert_eq!(first, second);
    }

    /// 🔐 XEdDSA: подпись неверной длины отвергается, а не паникует.
    #[test]
    fn xeddsa_malformed_signature_is_rejected() {
        let private = PrivateKeyBytes::new(hex32(RFC8032_SECRET));
        let public = montgomery::public_key(&private).unwrap();

        assert!(matches!(
            montgomery::verify(&public, b"message", b"short"),
            Err(AegisError::Crypto)
        ));
    }

    /// Приватный ключ затирается при уничтожении.
    ///
    /// Проверка на уровне системы типов: если обновление `ed25519-dalek`
    /// потеряет `ZeroizeOnDrop`, крейт перестанет компилироваться, а не
    /// продолжит тихо оставлять ключи в памяти.
    #[test]
    fn private_key_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    }

    /// Подпись неверной длины отвергается, а не паникует.
    ///
    /// Вход приходит из сети (подписи предключей в bundle), поэтому длина —
    /// не инвариант, а недоверенные данные.
    #[test]
    fn malformed_signature_length_is_rejected() {
        let mut csprng = OsRng;
        let key = XEdDSAPrivateKey::generate(&mut csprng);
        let public = key.public_key();

        for bad in [vec![0u8; 0], vec![0u8; 63], vec![0u8; 65], vec![0u8; 128]] {
            assert!(public.verify_strict(b"msg", &bad).is_err());
        }
    }
}
