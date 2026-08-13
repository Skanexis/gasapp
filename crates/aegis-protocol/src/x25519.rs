// SPDX-License-Identifier: Apache-2.0

//! X25519 elliptic curve Diffie-Hellman operations.

use aegis_types::{AegisError, PrivateKeyBytes, PublicKeyBytes, Result};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub struct X25519PublicKey(pub PublicKey);

/// X25519 private key.
#[derive(Zeroize)]
pub struct X25519PrivateKey {
    /// The static secret.
    pub(crate) static_secret: StaticSecret,
}

impl X25519PublicKey {
    /// Creates a new X25519 public key from bytes.
    ///
    /// Returns `Err(AegisError::Crypto)` if the bytes do not represent a valid point on the curve.
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        // For X25519, any 32-byte string is a valid public key (after clamping)
        // Validation of whether the point is on the correct subgroup is left to
        // the cryptographic operations (which will produce invalid shared secrets
        // for invalid points, which won't match in authenticating parties)
        let public_key = PublicKey::from(*bytes.as_bytes());
        Ok(X25519PublicKey(public_key))
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes::new(self.0.to_bytes())
    }
}

impl X25519PrivateKey {
    /// Generates a new random X25519 private key.
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let static_secret = StaticSecret::random_from_rng(csprng);
        Self { static_secret }
    }

    /// Creates a new X25519 private key from bytes.
    ///
    /// Returns `Err(AegisError::Crypto)` if the bytes do not represent a valid private key.
    ///
    /// # О клампинге
    ///
    /// Байты передаются в `StaticSecret::from` как есть, без предварительного
    /// клампинга, и это правильно: `x25519-dalek` применяет клампинг внутри
    /// самой операции DH (`decode_scalar` в RFC 7748), а не при хранении.
    /// Клампить здесь дополнительно не нужно — и вредно, потому что тогда
    /// `expose_secret` вернул бы не тот скаляр, который был записан.
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: PrivateKeyBytes) -> Result<Self> {
        let static_secret = StaticSecret::from(*bytes.expose_secret());
        Ok(Self { static_secret })
    }

    /// Returns the raw bytes of the private key.
    ///
    /// # Safety
    ///
    /// This function exposes secret key material. The caller must ensure
    /// that this material is properly protected and zeroized after use.
    pub fn expose_secret(&self) -> PrivateKeyBytes {
        PrivateKeyBytes::new(*self.static_secret.as_bytes())
    }

    /// Returns the public key corresponding to this private key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(PublicKey::from(&self.static_secret))
    }

    /// Computes the Diffie-Hellman shared secret between this private key
    /// and the given public key.
    ///
    /// Returns the shared secret as 32 bytes.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        let shared_secret = self.static_secret.diffie_hellman(&peer_public.0);
        *shared_secret.as_bytes()
    }
}

impl From<X25519PublicKey> for PublicKeyBytes {
    fn from(key: X25519PublicKey) -> Self {
        key.as_bytes()
    }
}

impl TryFrom<PublicKeyBytes> for X25519PublicKey {
    type Error = AegisError;

    fn try_from(bytes: PublicKeyBytes) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl From<X25519PrivateKey> for PrivateKeyBytes {
    fn from(key: X25519PrivateKey) -> Self {
        key.expose_secret()
    }
}

impl TryFrom<PrivateKeyBytes> for X25519PrivateKey {
    type Error = AegisError;

    fn try_from(bytes: PrivateKeyBytes) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Официальные векторы RFC 7748, раздел 6.1.
    ///
    /// # Почему они заданы hex-строками, а не массивами байт
    ///
    /// Изначально эти векторы были набраны в код вручную массивами `0x..`,
    /// и в приватном ключе Алисы оказались переставлены два байта:
    /// `…b177fb5a1db92c2a` вместо `…b177fba51db92c2a`. Из-за одной перестановки
    /// не сходились ни публичный ключ, ни общий секрет, и отладка ушла в поиск
    /// несуществующей ошибки клампинга. Hex-строку можно посимвольно сверить
    /// с текстом RFC, а колонки из 8 байт на строку — практически нет.
    const RFC7748_ALICE_PRIVATE: &str =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const RFC7748_ALICE_PUBLIC: &str =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const RFC7748_BOB_PRIVATE: &str =
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const RFC7748_BOB_PUBLIC: &str =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const RFC7748_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    /// Разбирает 64-символьную hex-строку в 32 байта.
    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        assert_eq!(s.len(), 64, "ожидалось 64 hex-символа");
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = s.get(i * 2..i * 2 + 2).expect("длина проверена выше");
            *byte = u8::from_str_radix(pair, 16).expect("не hex");
        }
        out
    }

    #[test]
    fn test_x25519_keypair_generation() {
        let mut csprng = OsRng;
        let alice = X25519PrivateKey::generate(&mut csprng);
        let bob = X25519PrivateKey::generate(&mut csprng);

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_shared = alice.diffie_hellman(&bob_public);
        let bob_shared = bob.diffie_hellman(&alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    /// Скаляр из RFC даёт ровно тот публичный ключ, что напечатан в RFC.
    #[test]
    fn rfc7748_public_keys_match() {
        for (private, expected_public) in [
            (RFC7748_ALICE_PRIVATE, RFC7748_ALICE_PUBLIC),
            (RFC7748_BOB_PRIVATE, RFC7748_BOB_PUBLIC),
        ] {
            let key = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(hex32(private))).unwrap();

            assert_eq!(
                key.public_key().as_bytes(),
                PublicKeyBytes::new(hex32(expected_public)),
                "публичный ключ разошёлся с RFC 7748 6.1"
            );
        }
    }

    /// Публичный ключ переживает разбор из байт без изменений.
    #[test]
    fn public_key_roundtrips_through_bytes() {
        let bytes = PublicKeyBytes::new(hex32(RFC7748_ALICE_PUBLIC));

        assert_eq!(
            X25519PublicKey::from_bytes(bytes).unwrap().as_bytes(),
            bytes
        );
    }

    /// Общий секрет совпадает с RFC и вычисляется одинаково с обеих сторон.
    ///
    /// Симметрия проверяется отдельно: односторонняя проверка пропустила бы
    /// ошибку, при которой обе стороны считают по-разному, но одна случайно
    /// совпала с вектором.
    #[test]
    fn rfc7748_shared_secret_matches_and_is_symmetric() {
        let alice =
            X25519PrivateKey::from_bytes(PrivateKeyBytes::new(hex32(RFC7748_ALICE_PRIVATE)))
                .unwrap();
        let bob =
            X25519PrivateKey::from_bytes(PrivateKeyBytes::new(hex32(RFC7748_BOB_PRIVATE))).unwrap();
        let expected = hex32(RFC7748_SHARED);

        let a_to_b = alice.diffie_hellman(&bob.public_key());
        let b_to_a = bob.diffie_hellman(&alice.public_key());

        assert_eq!(a_to_b, expected, "K(a,B) разошёлся с RFC 7748 6.1");
        assert_eq!(b_to_a, expected, "K(b,A) разошёлся с RFC 7748 6.1");
    }

    /// Клампинг выполняет сама библиотека, внутри операции DH.
    ///
    /// Тест фиксирует именно это свойство, потому что на нём уже один раз
    /// построили неверный вывод: `StaticSecret::from` хранит байты как есть,
    /// поэтому `expose_secret` возвращает исходный, неклампленный скаляр —
    /// но результат DH при этом соответствует RFC.
    #[test]
    fn library_clamps_inside_dh_not_on_storage() {
        let raw = [0xFFu8; 32];
        let key = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(raw)).unwrap();

        assert_eq!(
            key.expose_secret().expose_secret(),
            &raw,
            "хранение не должно менять скаляр"
        );

        // Клампленный вручную скаляр даёт тот же публичный ключ — доказательство,
        // что клампинг всё-таки применяется, просто не на этапе хранения.
        let mut clamped = raw;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let clamped_key = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(clamped)).unwrap();

        assert_eq!(
            key.public_key().as_bytes(),
            clamped_key.public_key().as_bytes()
        );
    }
}
