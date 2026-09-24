// SPDX-License-Identifier: Apache-2.0

//! Пост-квантовая половина identity: ML-DSA-65 (FIPS 204) и гибридные
//! подписи.
//!
//! # Зачем
//!
//! Шифрование переписки уже гибридное (PQXDH + SPQR), но подлинность
//! ключей держалась на одной кривой: identity-ключ подписывал предключи
//! и ключ sealed sender подписью XEdDSA. Противник с квантовым
//! компьютером **в момент атаки** подделал бы такую подпись, подставил
//! свои предключи — и прочёл бы переписку, начатую после этого.
//! Прочесть записанную раньше подделка подписи не помогает: её
//! защищает гибридное шифрование.
//!
//! Теперь у аккаунта две половины identity:
//!
//! * классическая — X25519/XEdDSA, как прежде;
//! * пост-квантовая — ML-DSA-65, с **независимым** seed.
//!
//! ⚠️ Seed независим намеренно. Вывести его из классического секрета
//! было бы удобно (не нужно хранить), но квантовый противник восстановит
//! классический секрет по открытому ключу — а вслед за ним и seed.
//!
//! # Гибридная подпись
//!
//! `XEdDSA (64 байта) ‖ ML-DSA-65 (3309 байт)`. Проверка требует
//! **обе**: подделать одну недостаточно. ML-DSA подписывает с контекстом
//! домена (FIPS 204, `ctx`), поэтому подпись предключа не годится
//! за подпись ключа sealed sender и наоборот.
//!
//! # Привязка половин
//!
//! Гибридная подпись классической и пост-квантовой половиной над обоими
//! открытыми ключами ([`bind`]). Без неё сервер мог бы выдать чужой
//! ML-DSA-ключ рядом с настоящим классическим. Хеш пост-квантовой
//! половины ([`pq_identity_hash`]) входит в safety number и в ссылку
//! собеседника: сверка покрывает обе.

use aegis_types::{AegisError, PrivateKeyBytes, PublicKeyBytes, Result};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::IdentityKeyPair;
use crate::xeddsa;

/// Длина открытого ключа ML-DSA-65.
pub const PQ_PUBLIC_LEN: usize = 1952;

/// Длина подписи ML-DSA-65.
pub const PQ_SIGNATURE_LEN: usize = 3309;

/// Длина гибридной подписи: XEdDSA ‖ ML-DSA-65.
pub const HYBRID_SIGNATURE_LEN: usize = xeddsa::SIGNATURE_LEN + PQ_SIGNATURE_LEN;

/// Длина seed пост-квантовой половины.
pub const PQ_SEED_LEN: usize = 32;

/// Домен привязки половин identity.
pub const BIND_DOMAIN: &[u8] = b"AEGIS_PQID_BIND_v1";

/// Домен подписанного предключа X25519.
pub const SIGNED_PRE_KEY_DOMAIN: &[u8] = b"AEGIS_PQSIG_SPK_v1";

/// Домен подписанного предключа ML-KEM.
pub const KEM_PRE_KEY_DOMAIN: &[u8] = b"AEGIS_PQSIG_KEM_v1";

/// Домен одноразового предключа ML-KEM.
pub const ONE_TIME_KEM_DOMAIN: &[u8] = b"AEGIS_PQSIG_OTKEM_v1";

/// Домен ключа ML-KEM sealed sender.
pub const SEALED_KEM_DOMAIN: &[u8] = b"AEGIS_PQSIG_SEALED_KEM_v1";

/// Домен хеша пост-квантовой половины.
const HASH_DOMAIN: &[u8] = b"AEGIS_PQID_HASH_v1";

/// Пост-квантовая половина identity.
pub struct PqIdentityKeyPair {
    seed: Zeroizing<[u8; PQ_SEED_LEN]>,
    signing: SigningKey<MlDsa65>,
}

impl PqIdentityKeyPair {
    /// Новая пара из системного генератора.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; PQ_SEED_LEN]);
        rng.fill_bytes(seed.as_mut());

        Self::from_seed(&seed)
    }

    /// Пара из сохранённого seed (FIPS 204, `ML-DSA.KeyGen_internal`).
    #[must_use]
    pub fn from_seed(seed: &[u8; PQ_SEED_LEN]) -> Self {
        let signing = SigningKey::<MlDsa65>::from_seed(&(*seed).into());

        Self {
            seed: Zeroizing::new(*seed),
            signing,
        }
    }

    /// Seed — для хранилища и резервной копии.
    #[must_use]
    pub fn seed(&self) -> &[u8; PQ_SEED_LEN] {
        &self.seed
    }

    /// Открытый ключ ML-DSA-65.
    #[must_use]
    pub fn public(&self) -> Vec<u8> {
        self.signing
            .expanded_key()
            .verifying_key()
            .encode()
            .to_vec()
    }

    /// Подпись ML-DSA-65 с контекстом домена.
    ///
    /// Детерминированная: подписи не нужна случайность, и сбой
    /// генератора не превращается в утечку ключа.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — домен длиннее 255 байт.
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let signature = self
            .signing
            .expanded_key()
            .sign_deterministic(message, domain)
            .map_err(|_| AegisError::Crypto)?;

        Ok(signature.encode().to_vec())
    }
}

impl core::fmt::Debug for PqIdentityKeyPair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PqIdentityKeyPair")
            .finish_non_exhaustive()
    }
}

/// Проверяет подпись ML-DSA-65.
///
/// # Errors
///
/// [`AegisError::InvalidSignature`] — ключ или подпись не той длины
/// либо подпись не сходится.
pub fn verify(public: &[u8], domain: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let public = EncodedVerifyingKey::<MlDsa65>::try_from(public)
        .map_err(|_| AegisError::InvalidSignature)?;
    let signature = EncodedSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| AegisError::InvalidSignature)?;
    let signature = Signature::<MlDsa65>::decode(&signature).ok_or(AegisError::InvalidSignature)?;

    if VerifyingKey::<MlDsa65>::decode(&public).verify_with_context(message, domain, &signature) {
        Ok(())
    } else {
        Err(AegisError::InvalidSignature)
    }
}

/// Хеш пост-квантовой половины — для safety number и ссылки.
#[must_use]
pub fn pq_identity_hash(public: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(HASH_DOMAIN)
        .chain_update(public)
        .finalize()
        .into()
}

/// Гибридная подпись: XEdDSA над сообщением ‖ ML-DSA-65 над ним же
/// с контекстом домена.
///
/// XEdDSA подписывает сообщение как прежде — без домена, — чтобы
/// классическая половина оставалась той же подписью, что проверяли
/// и раньше.
///
/// # Errors
///
/// [`AegisError::Crypto`] — сбой одной из подписей.
pub fn hybrid_sign(
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    domain: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let classical = xeddsa::montgomery::sign(
        &PrivateKeyBytes::new(*identity.private().expose_secret()),
        message,
    )?;

    let mut out = Vec::with_capacity(HYBRID_SIGNATURE_LEN);
    out.extend_from_slice(&classical);
    out.extend_from_slice(&pq.sign(domain, message)?);

    Ok(out)
}

/// Проверяет гибридную подпись: обе половины обязаны сойтись.
///
/// # Errors
///
/// [`AegisError::InvalidSignature`] — длина не та либо не сошлась
/// хотя бы одна половина.
pub fn hybrid_verify(
    identity: &PublicKeyBytes,
    pq_public: &[u8],
    domain: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != HYBRID_SIGNATURE_LEN {
        return Err(AegisError::InvalidSignature);
    }

    let (classical, post_quantum) = signature.split_at(xeddsa::SIGNATURE_LEN);

    xeddsa::montgomery::verify(identity, message, classical)?;
    verify(pq_public, domain, message, post_quantum)
}

/// Сообщение привязки: домен ‖ классический ключ ‖ пост-квантовый.
fn binding_message(identity: &PublicKeyBytes, pq_public: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        BIND_DOMAIN
            .len()
            .saturating_add(32)
            .saturating_add(pq_public.len()),
    );
    message.extend_from_slice(BIND_DOMAIN);
    message.extend_from_slice(identity.as_bytes());
    message.extend_from_slice(pq_public);
    message
}

/// Привязывает половины identity друг к другу.
///
/// # Errors
///
/// [`AegisError::Crypto`] — сбой подписи.
pub fn bind(identity: &IdentityKeyPair, pq: &PqIdentityKeyPair) -> Result<Vec<u8>> {
    let message = binding_message(identity.public().public(), &pq.public());

    hybrid_sign(identity, pq, BIND_DOMAIN, &message)
}

/// Проверяет привязку половин identity.
///
/// # Errors
///
/// [`AegisError::InvalidSignature`] — привязка не сходится.
pub fn verify_binding(identity: &PublicKeyBytes, pq_public: &[u8], binding: &[u8]) -> Result<()> {
    if pq_public.len() != PQ_PUBLIC_LEN {
        return Err(AegisError::InvalidSignature);
    }

    hybrid_verify(
        identity,
        pq_public,
        BIND_DOMAIN,
        &binding_message(identity, pq_public),
        binding,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekeys::generate_identity;
    use rand_core::OsRng;

    #[test]
    fn sizes_match_fips_204() {
        let pq = PqIdentityKeyPair::generate(&mut OsRng);
        assert_eq!(pq.public().len(), PQ_PUBLIC_LEN);
        assert_eq!(pq.sign(b"d", b"m").unwrap().len(), PQ_SIGNATURE_LEN);
    }

    /// Seed воспроизводит ту же пару: хранилище держит только его.
    #[test]
    fn seed_reproduces_the_pair() {
        let pq = PqIdentityKeyPair::generate(&mut OsRng);
        let again = PqIdentityKeyPair::from_seed(pq.seed());
        assert_eq!(pq.public(), again.public());
    }

    #[test]
    fn hybrid_signature_round_trips() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let pq = PqIdentityKeyPair::generate(&mut OsRng);
        let signature = hybrid_sign(&identity, &pq, KEM_PRE_KEY_DOMAIN, b"key").unwrap();

        assert_eq!(signature.len(), HYBRID_SIGNATURE_LEN);
        hybrid_verify(
            identity.public().public(),
            &pq.public(),
            KEM_PRE_KEY_DOMAIN,
            b"key",
            &signature,
        )
        .expect("подпись сходится");
    }

    /// 🔐 Подделка одной половины не проходит — ни той, ни другой.
    #[test]
    fn either_half_breaking_rejects_the_signature() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let pq = PqIdentityKeyPair::generate(&mut OsRng);
        let good = hybrid_sign(&identity, &pq, KEM_PRE_KEY_DOMAIN, b"key").unwrap();

        for position in [0, xeddsa::SIGNATURE_LEN + 10] {
            let mut broken = good.clone();
            broken[position] ^= 1;
            assert!(hybrid_verify(
                identity.public().public(),
                &pq.public(),
                KEM_PRE_KEY_DOMAIN,
                b"key",
                &broken
            )
            .is_err());
        }

        // Чужая пост-квантовая половина при верной классической.
        let stranger = PqIdentityKeyPair::generate(&mut OsRng);
        let mut mixed = good[..xeddsa::SIGNATURE_LEN].to_vec();
        mixed.extend_from_slice(&stranger.sign(KEM_PRE_KEY_DOMAIN, b"key").unwrap());
        assert!(hybrid_verify(
            identity.public().public(),
            &pq.public(),
            KEM_PRE_KEY_DOMAIN,
            b"key",
            &mixed
        )
        .is_err());
    }

    /// 🔐 Домен разделяет подписи: подпись предключа не годится
    /// за подпись ключа sealed sender.
    #[test]
    fn domains_do_not_mix() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let pq = PqIdentityKeyPair::generate(&mut OsRng);
        let signature = hybrid_sign(&identity, &pq, KEM_PRE_KEY_DOMAIN, b"key").unwrap();

        assert!(hybrid_verify(
            identity.public().public(),
            &pq.public(),
            SEALED_KEM_DOMAIN,
            b"key",
            &signature
        )
        .is_err());
    }

    /// 🔐 Привязка: чужой ML-DSA-ключ рядом с настоящим классическим
    /// не проходит.
    #[test]
    fn binding_rejects_a_foreign_pq_key() {
        let identity = generate_identity(&mut OsRng).unwrap();
        let pq = PqIdentityKeyPair::generate(&mut OsRng);
        let binding = bind(&identity, &pq).unwrap();

        verify_binding(identity.public().public(), &pq.public(), &binding).expect("привязка");

        let stranger = PqIdentityKeyPair::generate(&mut OsRng);
        assert!(verify_binding(identity.public().public(), &stranger.public(), &binding).is_err());

        let other = generate_identity(&mut OsRng).unwrap();
        assert!(verify_binding(other.public().public(), &pq.public(), &binding).is_err());
    }

    #[test]
    fn hash_depends_on_the_key() {
        let a = PqIdentityKeyPair::generate(&mut OsRng).public();
        let b = PqIdentityKeyPair::generate(&mut OsRng).public();
        assert_ne!(pq_identity_hash(&a), pq_identity_hash(&b));
    }
}
