// SPDX-License-Identifier: Apache-2.0

//! Ключ восстановления аккаунта: имя остаётся за человеком после
//! переустановки.
//!
//! # Зачем
//!
//! Имя принадлежит аккаунту, а приватный identity-ключ между
//! устройствами не копируется (раздел 13.1 плана): после переустановки
//! устройство получает **новую** identity. Без отдельного ключа
//! аккаунт с прежним именем стал бы недоступен — имя висело бы
//! за брошенным аккаунтом до годового срока.
//!
//! Ключ восстановления — отдельная пара, не identity:
//!
//! * при регистрации его открытые половины уходят на сервер;
//! * секрет лежит в зашифрованной базе и в резервной копии (под
//!   recovery key копии);
//! * новая установка, восстановив копию, подписывает им запрос
//!   «перепривяжи аккаунт с этим именем к новой identity», и сервер,
//!   проверив подпись, переносит аккаунт. Собеседники видят смену
//!   ключа — так и задумано (раздел 12.5): устройство действительно
//!   новое, и сверять его надо заново.
//!
//! Подпись гибридная (XEdDSA ‖ ML-DSA-65): квантовый противник,
//! подделав одну классическую, увёл бы чужое имя.

use aegis_types::{AegisError, PrivateKeyBytes, PublicKeyBytes, Result, Secret};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::keys::{IdentityKey, IdentityKeyPair};
use crate::pq_identity::{self, PqIdentityKeyPair, PQ_SEED_LEN};
use crate::x25519::X25519PrivateKey;
use crate::xeddsa;

/// Длина секрета ключа восстановления: классическая половина ‖ seed ML-DSA.
pub const RECOVERY_SECRET_LEN: usize = 32 + PQ_SEED_LEN;

/// Домен подписи запроса перепривязки.
pub const RECOVER_DOMAIN: &[u8] = b"AEGIS_ACCOUNT_RECOVER_v1";

/// Ключ восстановления аккаунта.
pub struct AccountRecoveryKey {
    classical: IdentityKeyPair,
    pq: PqIdentityKeyPair,
}

impl AccountRecoveryKey {
    /// Новый ключ из системного генератора.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — ключ не разворачивается.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; RECOVERY_SECRET_LEN]);
        let private = X25519PrivateKey::generate(rng);
        let (classical, pq_seed) = secret.split_at_mut(32);
        classical.copy_from_slice(private.expose_secret().expose_secret());
        rng.fill_bytes(pq_seed);

        Self::from_secret(&secret)
    }

    /// Ключ из сохранённого секрета.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — классическая половина не разворачивается.
    pub fn from_secret(secret: &[u8; RECOVERY_SECRET_LEN]) -> Result<Self> {
        let (classical_part, pq_part) = secret.split_at(32);
        let mut classical = [0u8; 32];
        classical.copy_from_slice(classical_part);
        let mut pq_seed = Zeroizing::new([0u8; PQ_SEED_LEN]);
        pq_seed.copy_from_slice(pq_part);

        let public = xeddsa::montgomery::public_key(&PrivateKeyBytes::new(classical))?;

        Ok(Self {
            classical: IdentityKeyPair::new(IdentityKey::new(public), Secret::new(classical)),
            pq: PqIdentityKeyPair::from_seed(&pq_seed),
        })
    }

    /// Секрет — для хранилища и резервной копии.
    #[must_use]
    pub fn secret(&self) -> Zeroizing<[u8; RECOVERY_SECRET_LEN]> {
        let mut out = Zeroizing::new([0u8; RECOVERY_SECRET_LEN]);
        let (classical, pq_seed) = out.split_at_mut(32);
        classical.copy_from_slice(self.classical.private().expose_secret());
        pq_seed.copy_from_slice(self.pq.seed());
        out
    }

    /// Классическая открытая половина.
    #[must_use]
    pub fn public(&self) -> PublicKeyBytes {
        *self.classical.public().public()
    }

    /// Пост-квантовая открытая половина.
    #[must_use]
    pub fn pq_public(&self) -> Vec<u8> {
        self.pq.public()
    }

    /// Подписывает запрос перепривязки гибридно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой подписи.
    pub fn sign(&self, request: &RecoverRequest<'_>) -> Result<Vec<u8>> {
        pq_identity::hybrid_sign(
            &self.classical,
            &self.pq,
            RECOVER_DOMAIN,
            &request.message(),
        )
    }
}

impl core::fmt::Debug for AccountRecoveryKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AccountRecoveryKey")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

/// Содержимое запроса перепривязки — то, что подписывается.
#[derive(Debug, Clone, Copy)]
pub struct RecoverRequest<'a> {
    /// Имя аккаунта.
    pub username: &'a str,
    /// Новый identity-ключ.
    pub identity_key: &'a [u8],
    /// Identity-ключ нового устройства.
    pub device_identity_key: &'a [u8],
    /// Новая пост-квантовая половина identity.
    pub pq_identity_key: &'a [u8],
    /// Её привязка к новому identity-ключу.
    pub identity_binding: &'a [u8],
    /// Момент подписи, мс: сервер отвергает старые запросы.
    pub issued_at_millis: i64,
}

impl RecoverRequest<'_> {
    /// Каноническое сообщение: домен и поля с длинами (u32, big-endian).
    ///
    /// ⚠️ Совпадает с `aegis-server-api::recovery`: сервер строит то же
    /// сообщение сам. Тест `client_contract` сверяет обе стороны.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut out = RECOVER_DOMAIN.to_vec();

        for field in [
            self.username.as_bytes(),
            self.identity_key,
            self.device_identity_key,
            self.pq_identity_key,
            self.identity_binding,
        ] {
            out.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(field);
        }

        out.extend_from_slice(&self.issued_at_millis.to_be_bytes());
        out
    }
}

/// Проверяет подпись запроса перепривязки — для тестов и эталона
/// серверной проверки.
///
/// # Errors
///
/// [`AegisError::InvalidSignature`] — подпись не сходится.
pub fn verify(
    recovery_public: &PublicKeyBytes,
    recovery_pq_public: &[u8],
    request: &RecoverRequest<'_>,
    signature: &[u8],
) -> Result<()> {
    if recovery_pq_public.len() != pq_identity::PQ_PUBLIC_LEN {
        return Err(AegisError::InvalidSignature);
    }

    pq_identity::hybrid_verify(
        recovery_public,
        recovery_pq_public,
        RECOVER_DOMAIN,
        &request.message(),
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn request(username: &str) -> RecoverRequest<'_> {
        RecoverRequest {
            username,
            identity_key: &[1; 32],
            device_identity_key: &[1; 32],
            pq_identity_key: &[2; 16],
            identity_binding: &[3; 16],
            issued_at_millis: 1_700_000_000_000,
        }
    }

    /// ⚠️ Эталон совпадает с `aegis-server-api::recovery`
    /// (`message_matches_the_client_reference`).
    #[test]
    fn message_matches_the_server_reference() {
        let request = RecoverRequest {
            username: "alice",
            identity_key: &[1; 2],
            device_identity_key: &[2; 2],
            pq_identity_key: &[3; 1],
            identity_binding: &[4; 1],
            issued_at_millis: 7,
        };

        let mut expected = b"AEGIS_ACCOUNT_RECOVER_v1".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"alice");
        expected.extend_from_slice(&[0, 0, 0, 2, 1, 1]);
        expected.extend_from_slice(&[0, 0, 0, 2, 2, 2]);
        expected.extend_from_slice(&[0, 0, 0, 1, 3]);
        expected.extend_from_slice(&[0, 0, 0, 1, 4]);
        expected.extend_from_slice(&7i64.to_be_bytes());

        assert_eq!(request.message(), expected);
    }

    #[test]
    fn secret_reproduces_the_key() {
        let key = AccountRecoveryKey::generate(&mut OsRng).unwrap();
        let again = AccountRecoveryKey::from_secret(&key.secret()).unwrap();

        assert_eq!(key.public(), again.public());
        assert_eq!(key.pq_public(), again.pq_public());
    }

    #[test]
    fn signature_verifies_and_binds_every_field() {
        let key = AccountRecoveryKey::generate(&mut OsRng).unwrap();
        let signature = key.sign(&request("alice")).unwrap();

        verify(
            &key.public(),
            &key.pq_public(),
            &request("alice"),
            &signature,
        )
        .expect("подпись");

        // 🔐 Подпись не переносится на другое имя.
        assert!(verify(&key.public(), &key.pq_public(), &request("bob"), &signature).is_err());

        // И на другой момент.
        let mut later = request("alice");
        later.issued_at_millis += 1;
        assert!(verify(&key.public(), &key.pq_public(), &later, &signature).is_err());
    }

    #[test]
    fn a_foreign_key_does_not_verify() {
        let key = AccountRecoveryKey::generate(&mut OsRng).unwrap();
        let other = AccountRecoveryKey::generate(&mut OsRng).unwrap();
        let signature = key.sign(&request("alice")).unwrap();

        assert!(verify(
            &other.public(),
            &other.pq_public(),
            &request("alice"),
            &signature
        )
        .is_err());
    }
}
