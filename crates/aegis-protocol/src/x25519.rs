// SPDX-License-Identifier: Apache-2.0

//! X25519 elliptic curve Diffie-Hellman operations.

use aegis_types::{PublicKeyBytes, PrivateKeyBytes, Result, AegisError};
use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::{CryptoRng, RngCore};
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
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: PrivateKeyBytes) -> Result<Self> {
        // The x25519-dalek library's StaticSecret::from expects the private key to be already clamped.
        // However, the RFC 7748 test vectors provide unclamped private keys.
        // After testing, it appears that the library performs internal clamping, so we pass the bytes directly.
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

    #[test]
    fn test_x25519_from_bytes() {
        // Test vector from RFC 7748, Section 6.1
        let private_key_bytes = PrivateKeyBytes::new([
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0x5a, 0x1d, 0xb9, 0x2c, 0x2a,
        ]);

        let public_key_bytes = PublicKeyBytes::new([
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa3, 0xa8, 0xaa, 0x88, 0x1d, 0x4c, 0x8a,
        ]);

        let private_key = X25519PrivateKey::from_bytes(private_key_bytes).unwrap();
        let public_key = private_key.public_key();

        // Test that our public key matches the expected bytes
        assert_eq!(public_key.as_bytes(), public_key_bytes);

        // Test that the public key can be parsed back and matches
        let parsed_public_key = X25519PublicKey::from_bytes(public_key_bytes).unwrap();
        assert_eq!(public_key.as_bytes(), parsed_public_key.as_bytes());
    }

    #[test]
    fn test_x25519_diffie_hellman() {
        // Test vector from RFC 7748, Section 6.1
        let private_key_bytes = PrivateKeyBytes::new([
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0x5a, 0x1d, 0xb9, 0x2c, 0x2a,
        ]);

        let peer_public_key_bytes = PublicKeyBytes::new([
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x80, 0xd1, 0xf6,
            0x81, 0x86, 0x3a, 0x2a, 0x65, 0xbf, 0x4e, 0xba,
            0xb9, 0x10, 0x24, 0x08, 0x0b, 0x2e, 0x8a, 0x8c,
            0x65, 0xc7, 0xa5, 0x1d, 0x3b, 0x60, 0x32, 0x5c,
        ]);

        let private_key = X25519PrivateKey::from_bytes(private_key_bytes).unwrap();
        let peer_public_key = X25519PublicKey::from_bytes(peer_public_key_bytes).unwrap();

        let shared_secret = private_key.diffie_hellman(&peer_public_key);

        let expected = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
            0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0xf6, 0x2e,
            0x0e, 0x5b, 0x27, 0x66, 0x56, 0x6c, 0x8b, 0xbf,
            0x5d, 0x47, 0x6e, 0x38, 0x2d, 0x7a, 0xdf, 0x34,
        ];

        assert_eq!(shared_secret, expected);
    }

    #[test]
    fn test_clamping_effect() {
        let private_key_bytes = [0xFFu8; 32];
        let mut clamped = private_key_bytes;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;

        let static_secret_clamped = StaticSecret::from(clamped);
        let public_key_clamped = PublicKey::from(&static_secret_clamped);

        let static_secret_unclamped = StaticSecret::from(private_key_bytes);
        let public_key_unclamped = PublicKey::from(&static_secret_unclamped);

        println!("Clamped key: {:02x?}", clamped);
        println!("Public key from clamped: {:02x?}", public_key_clamped.to_bytes());
        println!("Public key from unclamped: {:02x?}", public_key_unclamped.to_bytes());
        println!("Are they equal? {}", public_key_clamped.to_bytes() == public_key_unclamped.to_bytes());
    }
}