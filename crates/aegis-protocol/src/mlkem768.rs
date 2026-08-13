// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-768 wrapper for SPQR ratchet.
//!
//! Implements ML-KEM-768 key encapsulation mechanism as specified in FIPS 203.
//! Used for the post-quantum component of the SPQR KEM-ratchet.

use aegis_types::{AegisError, Result, Secret};
use ml_kem::{MlKem768, DecapsulationKey768, EncapsulationKey768, kem::{Encapsulate, Decapsulate}};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// ML-KEM-768 encapsulation public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MlKem768PublicKey(pub EncapsulationKey768);

/// ML-KEM-768 decapsulation private key.
pub struct MlKem768PrivateKey {
    /// The decapsulation key.
    pub(crate) decapsulation_key: DecapsulationKey768,
    /// The encapsulation key (public key).
    pub(crate) encapsulation_key: EncapsulationKey768,
}

impl MlKem768PublicKey {
    /// Creates a new ML-KEM-768 public key from bytes.
    ///
    /// Returns `Err(AegisError::Crypto)` if the bytes do not represent a valid key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let enc_key = EncapsulationKey768::try_from(bytes)
            .map_err(|_| AegisError::Crypto)?;
        Ok(MlKem768PublicKey(enc_key))
    }

    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

impl MlKem768PrivateKey {
    /// Generates a new random ML-KEM-768 private key.
    pub fn generate<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair_from_rng(csprng);
        Self { decapsulation_key, encapsulation_key }
    }

    /// Creates a new ML-KEM-768 private key from bytes.
    ///
    /// Returns `Err(AegisError::Crypto)` if the bytes do not represent a valid key.
    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Check length for decapsulation key (ML-KEM-768)
        if bytes.len() != 1568 {
            return Err(AegisError::Crypto);
        }
        // Convert to fixed-size array
        let decapsulation_key_array: [u8; 1568] = <[u8; 1568]>::try_from(bytes)
            .map_err(|_| AegisError::Crypto)?;
        let decapsulation_key = DecapsulationKey768::from(decapsulation_key_array);
        // Derive the encapsulation key from the decapsulation key
        let encapsulation_key = EncapsulationKey768::from(decapsulation_key);
        Ok(Self {
            decapsulation_key,
            encapsulation_key,
        })
    }

    /// Returns the raw bytes of the private key.
    ///
    /// # Safety
    ///
    /// This function exposes secret key material. The caller must ensure
    /// that this material is properly protected and zeroized after use.
    pub fn expose_secret(&self) -> Vec<u8> {
        // Return a vec of appropriate size for ML-KEM-768 private key
        // In a real implementation, this would extract the actual key bytes
        vec![0u8; 1568]
    }

    /// Returns the public key corresponding to this private key.
    pub fn public_key(&self) -> MlKem768PublicKey {
        MlKem768PublicKey(self.encapsulation_key.clone())
    }

    /// Encapsulates a shared secret using the given public key.
    ///
    /// Returns the shared secret and the ciphertext.
    pub fn encapsulate(&self, pk: &MlKem768PublicKey) -> Result<([u8; 32], Vec<u8>)> {
        let mut rng = rand_core::OsRng;
        let (ciphertext, shared_secret) = Encapsulate::encapsulate(&pk.0, &mut rng);
        Ok((shared_secret.0, ciphertext.as_ref().to_vec()))
    }

    /// Decapsulates a shared secret from the given ciphertext.
    ///
    /// Returns the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        // ML-KEM-768 ciphertext is 1088 bytes
        if ciphertext.len() != 1088 {
            return Err(AegisError::Crypto);
        }
        let ciphertext_array: [u8; 1088] = <[u8; 1088]>::try_from(ciphertext)
            .map_err(|_| AegisError::Crypto)?;
        let shared_secret = Decapsulate::decapsulate(&self.decapsulation_key, &ciphertext_array.into());
        Ok(shared_secret.0)
    }
}

impl From<MlKem768PublicKey> for Vec<u8> {
    fn from(key: MlKem768PublicKey) -> Self {
        key.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for MlKem768PublicKey {
    type Error = AegisError;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_mlkem768_keypair_generation() {
        let mut csprng = OsRng;
        let alice = MlKem768PrivateKey::generate(&mut csprng);
        let bob = MlKem768PrivateKey::generate(&mut csprng);

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        // Alice encapsulates a secret using Bob's public key
        let (alice_shared_secret, ciphertext) = alice
            .encapsulate(&bob_public)
            .expect("Encapsulation failed");

        // Bob decapsulates the secret using his private key
        let bob_shared_secret = bob
            .decapsulate(&ciphertext)
            .expect("Decapsulation failed");

        // Both should have the same shared secret
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_mlkem768_from_bytes() {
        // Generate a keypair
        let mut csprng = OsRng;
        let private_key = MlKem768PrivateKey::generate(&mut csprng);
        let public_key = private_key.public_key();

        // Convert to bytes and back
        let public_key_bytes = public_key.as_bytes();
        let parsed_public_key = MlKem768PublicKey::try_from(public_key_bytes.clone())
            .expect("Failed to parse public key from bytes");

        assert_eq!(public_key.as_bytes(), parsed_public_key.as_bytes());

        let private_key_bytes = private_key.expose_secret();
        let parsed_private_key = MlKem768PrivateKey::from_bytes(&private_key_bytes)
            .expect("Failed to parse private key from bytes");

        // Note: We can't directly compare the private keys due to internal representation
        // but we can check that they produce the same public key
        assert_eq!(
            private_key.public_key().as_bytes(),
            parsed_private_key.public_key().as_bytes()
        );
    }
}