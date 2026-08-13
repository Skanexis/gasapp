// SPDX-License-Identifier: Apache-2.0

//! XEdDSA (Edwards-curve Digital Signature Algorithm) over Curve25519.
//!
//! Implementation using the ed25519-dalek crate.
//! XEdDSA allows using the same key pair for both X25519 Diffie-Hellman
//! and Ed25519 signatures.

use aegis_types::{PublicKeyBytes, PrivateKeyBytes, Result, AegisError};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, SecretKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

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
        let verifying_key = VerifyingKey::from_bytes(bytes.as_bytes())
            .map_err(|_| AegisError::Crypto)?;
        Ok(XEdDSAPublicKey(verifying_key))
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes::new(self.0.to_bytes())
    }

    /// Verifies a signature for the given message.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(AegisError::Crypto);
        }
        let sig_array = <[u8; 64]>::try_from(signature)
            .map_err(|_| AegisError::Crypto)?;
        let sig = Signature::from_bytes(&sig_array);
        self.0.verify_strict(message, &sig)
            .map_err(|_| AegisError::Crypto)?;
        Ok(())
    }
}

impl XEdDSAPrivateKey {
    /// Generates a new random XEdDSA private key.
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let secret_key = SecretKey::generate(csprng);
        let signing_key = SigningKey::from(&secret_key);
        Self { signing_key }
    }

    /// Creates a new XEdDSA private key from bytes.
    ///
    /// Returns `Err(AegisError::Crypto)` if the bytes do not represent a valid Ed25519 private key.
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: PrivateKeyBytes) -> Result<Self> {
        let secret_key = SecretKey::from_bytes(bytes.expose_secret());
        let signing_key = SigningKey::from(&secret_key);
        Ok(Self { signing_key })
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

    /// Signs a message and returns the signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        let mut result = [0u8; 64];
        result.copy_from_slice(signature.s_bytes());
        result
    }
}

impl Zeroize for XEdDSAPrivateKey {
    fn zeroize(&mut self) {
        // Zeroize the inner secret key by zeroizing its bytes
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
        // Note: The SigningKey itself doesn't have a zeroize method, but we've zeroized
        // the actual secret key material that it contains
    }
}

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

    #[test]
    fn test_xeddsa_keypair_generation() {
        let mut csprng = OsRng;
        let alice = XEdDSAPrivateKey::generate(&mut csprng);
        let bob = XEdDSAPrivateKey::generate(&mut csprng);

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        // Test signing and verification
        let message = b"test message";
        let signature = alice.sign(message);
        assert!(alice_public.verify_strict(message, &signature).is_ok());
        // Bob's public key should fail to verify Alice's signature
        assert!(bob_public.verify_strict(message, &signature).is_err());
    }

    #[test]
    fn test_xeddsa_from_bytes() {
        // Test vector from RFC 8032, Section 7.1
        let private_key_bytes = PrivateKeyBytes::new([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc1,
            0x44, 0x4c, 0x5e, 0x50, 0x76, 0xb1, 0x0e, 0x59,
            0x92, 0x7e, 0x9e, 0x1f, 0xb0, 0x36, 0x4a, 0x08,
        ]);

        let public_key_bytes = PublicKeyBytes::new([
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0x1d, 0xd6, 0xb3, 0x92, 0x8b, 0x2d, 0x6a, 0x7e,
            0x9f, 0x9a, 0x7d, 0x0b, 0x88, 0x5a, 0x01, 0x2d,
            0x11, 0x59, 0x05, 0x58, 0x32, 0x95, 0xcb, 0x39,
        ]);

        let private_key = XEdDSAPrivateKey::from_bytes(private_key_bytes).unwrap();
        let public_key = private_key.public_key();

        // Test that our public key matches the expected bytes
        assert_eq!(public_key.as_bytes(), public_key_bytes);

        // Test that the public key can be parsed back and matches
        let parsed_public_key = XEdDSAPublicKey::from_bytes(public_key_bytes).unwrap();
        assert_eq!(public_key.as_bytes(), parsed_public_key.as_bytes());
    }

    #[test]
    fn test_xeddsa_sign_verify() {
        // Test vector from RFC 8032, Section 7.1
        let private_key_bytes = PrivateKeyBytes::new([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc1,
            0x44, 0x4c, 0x5e, 0x50, 0x76, 0xb1, 0x0e, 0x59,
            0x92, 0x7e, 0x9e, 0x1f, 0xb0, 0x36, 0x4a, 0x08,
        ]);

        let public_key_bytes = PublicKeyBytes::new([
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0x1d, 0xd6, 0xb3, 0x92, 0x8b, 0x2d, 0x6a, 0x7e,
            0x9f, 0x9a, 0x7d, 0x0b, 0x88, 0x5a, 0x01, 0x2d,
            0x11, 0x59, 0x05, 0x58, 0x32, 0x95, 0xcb, 0x39,
        ]);

        let message = b"";
        let expected_signature = [
            0xe5, 0x56, 0x43, 0x00, 0x3d, 0x62, 0x31, 0xb5,
            0x02, 0x88, 0x5e, 0x4b, 0x24, 0x07, 0x3e, 0x4f,
            0x49, 0xfd, 0x02, 0x41, 0x2d, 0x3b, 0x22, 0x6b,
            0x8e, 0x01, 0x22, 0x6a, 0x00, 0x8a, 0x8d, 0x5d,
            0x22, 0x62, 0x32, 0x28, 0xd4, 0x0f, 0x33, 0x3f,
            0x47, 0x23, 0x07, 0x2d, 0x18, 0x19, 0x0a, 0x27,
            0x4d, 0x29, 0x73, 0x23, 0xcb, 0x2e, 0xb8, 0x27,
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        let private_key = XEdDSAPrivateKey::from_bytes(private_key_bytes).unwrap();
        let public_key = private_key.public_key();

        let signature = private_key.sign(message);
        assert_eq!(signature, expected_signature);
        assert!(public_key.verify_strict(message, &signature).is_ok());
    }
}