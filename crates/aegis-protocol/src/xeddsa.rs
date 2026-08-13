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
    /// Returns `Err(AegisError::Crypto)` if the bytes do not represent a valid Ed25519 public key.
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        // For Ed25519, any 32-byte string is a valid public key
        let verifying_key =
            VerifyingKey::from_bytes(bytes.as_bytes()).map_err(|_| AegisError::Crypto)?;
        Ok(XEdDSAPublicKey(verifying_key))
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes::new(self.0.to_bytes())
    }

    /// Проверяет подпись сообщения.
    ///
    /// Используется именно `verify_strict`, а не `verify`: строгий вариант
    /// отвергает ключи и точки R малого порядка. Без этого одна и та же
    /// подпись может проходить проверку под несколькими ключами
    /// (malleability), а на этом свойстве строятся атаки подмены отправителя.
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
    #[allow(clippy::result_unit_err)]
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
    pub fn expose_secret(&self) -> PrivateKeyBytes {
        PrivateKeyBytes::new(self.signing_key.to_bytes())
    }

    /// Returns the public key corresponding to this private key.
    pub fn public_key(&self) -> XEdDSAPublicKey {
        XEdDSAPublicKey(VerifyingKey::from(&self.signing_key))
    }

    /// Подписывает сообщение.
    ///
    /// Возвращает полную подпись R ‖ S (64 байта). Ранее здесь копировалась
    /// только половина S через `s_bytes()`, а старший полубуфер оставался
    /// нулевым — такая «подпись» не проходит проверку никогда, и подпись
    /// предключей в PQXDH была бы неработоспособна.
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

#[cfg(test)]
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
