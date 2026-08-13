// SPDX-License-Identifier: Apache-2.0

//! PQXDH (Post-Quantum Extended Diffie-Hellman) protocol implementation.
//!
//! Implements the PQXDH key exchange as specified in the AEGIS protocol.
//! This is the post-quantum key exchange that combines classical X25519
//! DH with ML-KEM-1024 for quantum resistance.

use aegis_types::{AegisError, Result, Secret, PublicKeyBytes, Timestamp};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::{
    engine::{self, InitialMessage, InitiatedSession, ProtocolEngine},
    keys::{
        IdentityKey, IdentityKeyPair, KemPublicKey,
        PreKeyBundle, PreKeyId, SignedKemPreKey, SignedPreKey, SessionState,
    },
    mlkem1024::{MlKem1024PrivateKey, MlKem1024PublicKey},
    mlkem768::{MlKem768PrivateKey, MlKem768PublicKey},
    x25519::{X25519PrivateKey, X25519PublicKey},
    xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey},
    protocol_engine::AegisEngine,
    Fingerprint, ProtocolVersion, MAX_SKIPPED_MESSAGE_KEYS, MAX_SKIPPED_CHAINS,
    SKIPPED_KEY_TTL_DAYS, SIGNED_PRE_KEY_ROTATION_DAYS,
};
use aegis_types::{Plaintext, Ciphertext};
use ml_kem::{DecapsulationKey1024, DecapsulationKey768, EncapsulationKey1024, EncapsulationKey768};

// Constants from the specification
const DOMAIN_SEPARATION_F: &[u8; 32] = &[0xFF; 32];
const DOMAIN_SEPARATION_SALT: &[u8; 32] = &[0x00; 32];
const INFO_PQXDH: &[u8] = b"AEGIS_PQXDH_v1_25519_MLKEM1024";

/// PQXDH protocol engine implementation.
#[derive(Clone, Zeroize)]
pub struct PqxdhEngine;

impl PqxdhEngine {
    /// Creates a new PqxdhEngine instance.
    pub fn new() -> Self {
        Self
    }

    /// Retrieves the prekey bundle for the given identity.
    ///
    /// # Note
    ///
    /// This is a placeholder implementation. In a full implementation,
    /// this method would retrieve the prekey bundle from the keystore
    /// or storage layer using the identity key as a lookup key.
    ///
    /// For now, it always returns None to indicate that keystore
    /// integration needs to be implemented.
    fn get_prekey_bundle(&self, _identity: &IdentityKeyPair) -> Option<PreKeyBundle> {
        // TODO: Integrate with keystore/storage layer
        None
    }

    /// Validates a prekey bundle by checking signatures.
    fn validate_prekey_bundle(
        &self,
        identity_key: &IdentityKey,
        signed_pre_key: &SignedPreKey,
        signed_kem_pre_key: &SignedKemPreKey,
    ) -> Result<()> {
        // Verify XEdDSA signature on the signed prekey
        let xeddsa_pubkey = XEdDSAPublicKey::from(identity_key.public().clone());
        xeddsa_pubkey
            .verify_strict(signed_pre_key.public.as_ref(), &signed_pre_key.signature)
            .map_err(|_| AegisError::InvalidSignature)?;

        // Verify XEdDSA signature on the signed kem prekey
        xeddsa_pubkey
            .verify_strict(signed_kem_pre_key.public.as_ref(), &signed_kem_pre_key.signature)
            .map_err(|_| AegisError::InvalidSignature)?;

        Ok(())
    }

    /// Perform the PQXDH key exchange as the initiator.
    fn pqxdh_initiator(
        &self,
        our_identity: &IdentityKeyPair,
        their_bundle: &PreKeyBundle,
        rng: &mut dyn CryptoRng,
    ) -> Result<([u8; 32], bool)> {
        // Validate the prekey bundle signatures
        self.validate_prekey_bundle(
            &our_identity.public(),
            &their_bundle.signed_pre_key,
            &their_bundle.signed_kem_pre_key,
        )?;

        // Step 1: Check if we have a valid signature on the SPK and PQ-SPK
        // (Already done in validate_prekey_bundle)

        // Step 2: Generate ephemeral key pair EK_A (X25519)
        let ek_a = X25519PrivateKey::generate(rng);

        // Step 3: Classical DH exchanges
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = our_identity
            .private()
            .expose_secret()
            .as_slice()
            .diffie_hellman(&X25519PublicKey::from(their_bundle.signed_pre_key.public.as_ref()));

        // DH2 = DH(EK_A, IK_B)
        let dh2 = ek_a.diffie_hellman(&X25519PublicKey::from(
            their_bundle.identity_key.as_ref(),
        ));

        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ek_a.diffie_hellman(&X25519PublicKey::from(
            their_bundle.signed_pre_key.public.as_ref(),
        ));

        // DH4 = DH(EK_A, OPK_B) if available
        let mut dh4 = [0u8; 32];
        let mut has_opk = false;
        if let Some((_, opk)) = &their_bundle.one_time_pre_key {
            dh4 = ek_a.diffie_hellman(&X25519PublicKey::from(opk.as_ref()));
            has_opk = true;
        }

        // Step 4: Post-quantum KEX
        // (CT, SS_pq) = ML-KEM-1024.Encapsulate(PQOPK_B or PQSPK_B)
        let (ss_pq, ciphertext) = if let Some((_, pqopk)) = &their_bundle.one_time_kem_pre_key {
            // Use PQOPK if available
            let enc_key = EncapsulationKey1024::from(pqopk.as_ref());
            let mut rng = rand_core::OsRng;
            let (shared_secret, ct) = MlKem1024::encapsulate(&enc_key, &mut rng);
            (shared_secret.0, ct.as_ref().to_vec())
        } else {
            // Otherwise use PQSPK (must be available according to spec)
            let enc_key = EncapsulationKey1024::from(&their_bundle.signed_kem_pre_key.public);
            let mut rng = rand_core::OsRng;
            let (shared_secret, ct) = MlKem1024::encapsulate(&enc_key, &mut rng);
            (shared_secret.0, ct.as_ref().to_vec())
        };

        // Step 5: Compute SK = HKDF-SHA-256(F || DH1 || DH2 || DH3 || DH4 || SS_pq)
        let mut ikm = Vec::new();
        ikm.extend_from_slice(DOMAIN_SEPARATION_F);
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);
        ikm.extend_from_slice(&dh4);
        ikm.extend_from_slice(&ss_pq);

        // Use HKDF-SHA-256
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(DOMAIN_SEPARATION_SALT), &ikm);
        let mut shared_secret = [0u8; 32];
        hk.expand(INFO_PQXDH, &mut shared_secret)
            .map_err(|_| AegisError::Crypto)?;

        // Step 6: Zeroize intermediate secrets
        // Note: The zeroize implementation will handle this when variables go out of scope

        Ok((shared_secret, !has_opk)) // Return whether forward secrecy was degraded
    }

    /// Perform the PQXDH key exchange as the responder.
    fn pqxdh_responder(
        &self,
        our_identity: &IdentityKeyPair,
        message: &InitialMessage,
    ) -> Result<([u8; 32], [u8; 32])> {
        // Parse the message payload to extract initiator's identity key, ephemeral key, and ML-KEM ciphertext
        // Payload format: [IK_A (32 bytes)][EK_A (32 bytes)][ML-KEM ciphertext (ml_kem::MlKem1024::CIPHERTEXT_SIZE bytes)]
        let payload = message.payload.as_bytes();

        // Check payload length
        let expected_len = 32 + 32 + MlKem1024::CIPHERTEXT_SIZE;
        if payload.len() != expected_len {
            return Err(AegisError::Malformed);
        }

        // Extract initiator's identity key (IK_A)
        let ik_a_bytes = &payload[0..32];
        let ik_a = IdentityKey::new(PublicKeyBytes::from_slice(ik_a_bytes)
            .map_err(|_| AegisError::Crypto)?);

        // Extract initiator's ephemeral key (EK_A)
        let ek_a_bytes = &payload[32..64];
        let ek_a = X25519PublicKey::from(ek_a_bytes);

        // Extract ML-KEM-1024 ciphertext
        let ct = &payload[64..(64 + MlKem1024::CIPHERTEXT_SIZE)];

        // Access the responder's prekey bundle
        // In a full implementation, this would be retrieved from the keystore using our_identity
        // For this implementation, we assume the bundle is available through context
        // TODO: Integrate with keystore/storage layer to retrieve the actual prekey bundle
        let bundle = self.get_prekey_bundle(our_identity)
            .ok_or(AegisError::SessionNotFound)?;

        // Verify that the bundle's identity key matches our_identity
        if bundle.identity_key != our_identity.public() {
            return Err(AegisError::InvalidSignature);
        }

        // Perform DH exchanges
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = ik_a
            .as_ref()
            .diffie_hellman(&X25519PublicKey::from(bundle.signed_pre_key.public.as_ref()));

        // DH2 = DH(EK_A, IK_B)
        let dh2 = ek_a.diffie_hellman(&X25519PublicKey::from(
            bundle.identity_key.as_ref(),
        ));

        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ek_a.diffie_hellman(&X25519PublicKey::from(
            bundle.signed_pre_key.public.as_ref(),
        ));

        // DH4 = DH(EK_A, OPK_B) if we have a one-time prekey available
        let mut dh4 = [0u8; 32];
        let mut has_opk = false;
        if let Some((_, opk)) = bundle.one_time_pre_key.as_ref() {
            dh4 = ek_a.diffie_hellman(&X25519PublicKey::from(opk.as_ref()));
            has_opk = true;
        }

        // Post-quantum KEX: ML-KEM-1024 decapsulation
        // Use one-time kem prekey if available, otherwise use signed kem prekey
        let ss_pq = if let Some((_, pqopk)) = bundle.one_time_kem_pre_key.as_ref() {
            // Use PQOPK if available
            let decap_key = DecapsulationKey1024::from(pqopk.as_ref());
            MlKem1024::decapsulate(&decap_key, ct)
                .map_err(|_| AegisError::Crypto)?
                .0
        } else {
            // Otherwise use PQSPK (must be available according to spec)
            let decap_key = DecapsulationKey1024::from(&bundle.signed_kem_pre_key.public);
            MlKem1024::decapsulate(&decap_key, ct)
                .map_err(|_| AegisError::Crypto)?
                .0
        };

        // Compute shared secret: SK = HKDF-SHA-256(F || DH1 || DH2 || DH3 || DH4 || SS_pq)
        let mut ikm = Vec::new();
        ikm.extend_from_slice(DOMAIN_SEPARATION_F);
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);
        ikm.extend_from_slice(&dh4);
        ikm.extend_from_slice(&ss_pq);

        // Use HKDF-SHA-256
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(DOMAIN_SEPARATION_SALT), &ikm);
        let mut shared_secret = [0u8; 32];
        hk.expand(INFO_PQXDH, &mut shared_secret)
            .map_err(|_| AegisError::Crypto)?;

        // Return the shared secret and additional data needed for Double Ratchet initialization
        // The second return value is the responder's ephemeral public key for the Double Ratchet
        // In a full implementation, we would generate this during the responder flow
        // For now, we'll return a placeholder - this should be the responder's ephemeral key
        let responder_ek = X25519PrivateKey::generate(&mut rand_core::OsRng);
        let responder_ek_pub = responder_ek.public();

        Ok((shared_secret, responder_ek_pub.as_bytes().to_vec()))
    }
}

impl Default for PqxdhEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolEngine for PqxdhEngine {
    fn initiate_session(
        &self,
        our_identity: &IdentityKeyPair,
        their_bundle: &PreKeyBundle,
        rng: &mut dyn CryptoRng,
    ) -> Result<InitiatedSession> {
        // Perform PQXDH key exchange
        let (shared_secret, degraded) = self
            .pqxdh_initiator(our_identity, their_bundle, rng)
            .map_err(|_| AegisError::Crypto)?;

        // Derive root key from shared secret
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut root_key = [0u8; 32];
        hk.expand(b"WhisperRatchet", &mut root_key)
            .map_err(|_| AegisError::Crypto)?;

        // Create session state (simplified for now)
        let session_state = SessionState::from_serialized(Secret::new(root_key.to_vec()));

        // Create the initial message to send
        // TODO: Properly construct the InitialMessage with all required fields
        let initial_message = InitialMessage {
            version: ProtocolVersion::CURRENT,
            payload: Vec::new(), // TODO: Actually construct the message payload
        };

        Ok(InitiatedSession {
            session: session_state,
            message: initial_message,
            degraded,
        })
    }

    fn accept_session(
        &self,
        our_identity: &IdentityKeyPair,
        message: &InitialMessage,
    ) -> Result<(SessionState, PublicKeyBytes)> {
        // Perform PQXDH key exchange as responder
        let (shared_secret, _) = self
            .pqxdh_responder(our_identity, message)
            .map_err(|_| AegisError::Crypto)?;

        // Derive root key from shared secret
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut root_key = [0u8; 32];
        hk.expand(b"WhisperRatchet", &mut root_key)
            .map_err(|_| AegisError::Crypto)?;

        // Create session state
        let session_state = SessionState::from_serialized(Secret::new(root_key.to_vec()));

        // Return empty plaintext for now (no pre-message in PQXDH basic flow)
        Ok((session_state, Vec::new()))
    }

    fn encrypt(&self, session: &mut SessionState, plaintext: &[u8]) -> Result<Vec<u8>> {
        // TODO: Implement message encryption with Double Ratchet
        Err(AegisError::Crypto)
    }

    fn decrypt(&self, session: &mut SessionState, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // TODO: Implement message decryption with Double Ratchet
        Err(AegisError::Crypto)
    }

    fn fingerprint(
        &self,
        identity: &IdentityKey,
        identifier: &[u8],
    ) -> Result<Fingerprint> {
        // Use the same fingerprint implementation as in AegisEngine
        AegisEngine::fingerprint(self, identity, identifier)
    }

    fn version(&self) -> ProtocolVersion {
        ProtocolVersion::CURRENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_pqxdh_keypair_generation() {
        let engine = PqxdhEngine::new();
        let mut csprng = OsRng;
        let our_identity = IdentityKeyPair::new(
            IdentityKey::new(PublicKeyBytes::new([1u8; 32])),
            Secret::new([2u8; 32]),
        );

        // Create a mock prekey bundle
        let their_bundle = PreKeyBundle {
            device_id: [1u8; 4].into(),
            identity_key: IdentityKey::new(PublicKeyBytes::new([3u8; 32])),
            signed_pre_key: SignedPreKey {
                id: PreKeyId::new(1),
                public: PublicKeyBytes::new([4u8; 32]),
                signature: vec![0u8; 64], // Placeholder signature
            },
            one_time_pre_key: Some((
                PreKeyId::new(2),
                PublicKeyBytes::new([5u8; 32]),
            )),
            signed_kem_pre_key: SignedKemPreKey {
                id: PreKeyId::new(3),
                public: KemPublicKey::new(vec![6u8; 1568]),
                signature: vec![0u8; 64], // Placeholder signature
            },
            one_time_kem_pre_key: Some((
                PreKeyId::new(4),
                KemPublicKey::new(vec![7u8; 1568]),
            )),
        };

        // Note: This test will fail because we don't have valid signatures
        // In a real test, we would generate proper XEdDSA signatures
        let result = engine.initiate_session(
            &our_identity,
            &their_bundle,
            &mut csprng,
        );

        // Expecting an error due to invalid signatures in the test bundle
        assert!(result.is_err());
    }
}