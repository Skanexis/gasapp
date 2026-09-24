// SPDX-License-Identifier: Apache-2.0

//! Пост-квантовая половина identity в клиенте.
//!
//! * своя: seed ML-DSA-65 в зашифрованной базе, публикация на сервере
//!   (при регистрации, у прежних аккаунтов — обслуживанием ключей);
//! * чужая: приходит от сервера вместе с классическим ключом.
//!   Принимается, только если
//!   1. привязана к классическому ключу собеседника гибридной подписью
//!      (`pq_identity::verify_binding`) — иначе сервер выдал бы свой
//!      ML-DSA-ключ рядом с настоящим классическим;
//!   2. её хеш совпадает с запомненным при первой встрече или со ссылки
//!      собеседника — иначе это подмена, `IdentityChanged`.
//!
//! Хеш пост-квантовой половины входит в safety number: сверка вживую
//! покрывает обе половины.

use aegis_net::api::DiscoveryResponse;
use aegis_net::client::Transport;
use aegis_protocol::keys::IdentityKeyPair;
use aegis_protocol::pq_identity::{self, PqIdentityKeyPair, PQ_SEED_LEN};
use aegis_protocol::{Fingerprint, SafetyNumber};
use aegis_types::{AccountId, AegisError, PublicKeyBytes, Result, Timestamp};
use rand_core::RngCore;

use super::{hex, peer_account, unhex, Client};

impl<T: Transport> Client<T> {
    /// Своя пост-квантовая половина; заводится при первом обращении.
    pub(super) fn own_pq_identity(&self) -> Result<PqIdentityKeyPair> {
        if let Some((seed, _)) = self.storage.own_pq_identity()? {
            return Ok(PqIdentityKeyPair::from_seed(&seed));
        }

        let mut seed = zeroize::Zeroizing::new([0u8; PQ_SEED_LEN]);
        rand_core::OsRng.fill_bytes(seed.as_mut());
        self.storage.init_own_pq_identity(&seed)?;

        // Перечитывается: при гонке двух потоков в базе останется первый.
        let (stored, _) = self.storage.own_pq_identity()?.ok_or(AegisError::Storage)?;

        Ok(PqIdentityKeyPair::from_seed(&stored))
    }

    /// Открытая часть и привязка — если своя половина ещё не опубликована.
    pub(super) fn pending_pq_publication(
        &self,
        identity: &IdentityKeyPair,
    ) -> Result<Option<(String, String)>> {
        let published = self
            .storage
            .own_pq_identity()?
            .is_some_and(|(_, published)| published.is_some());

        if published {
            return Ok(None);
        }

        let pq = self.own_pq_identity()?;

        Ok(Some((
            hex(&pq.public()),
            hex(&pq_identity::bind(identity, &pq)?),
        )))
    }

    /// Хеш своей пост-квантовой половины.
    pub(super) fn own_pq_hash(&self) -> Result<[u8; 32]> {
        Ok(pq_identity::pq_identity_hash(
            &self.own_pq_identity()?.public(),
        ))
    }

    /// 🔐 Пост-квантовая половина собеседника из ответа discovery —
    /// проверенная привязкой и сверенная с запомненной.
    ///
    /// Первая встреча запоминает хеш (доверие при первом использовании —
    /// как у классического ключа; писать всё равно можно только после
    /// сверки или по ссылке). Несовпадение — подмена: `IdentityChanged`
    /// и запись в журнал безопасности.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Uninitialized`] — у собеседника нет
    ///   пост-квантовой половины: без неё гибридные подписи не проверить;
    /// * [`AegisError::InvalidSignature`] — привязка не сходится;
    /// * [`AegisError::IdentityChanged`] — половина не та, что запомнена.
    pub(super) fn verified_peer_pq(
        &self,
        peer: &DiscoveryResponse,
        peer_identity: &PublicKeyBytes,
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        let (Some(public), Some(binding)) = (&peer.pq_identity_key, &peer.identity_binding) else {
            return Err(AegisError::Uninitialized);
        };

        let public = unhex(public)?;
        pq_identity::verify_binding(peer_identity, &public, &unhex(binding)?)?;

        self.remember_peer_pq(&peer_account(peer_identity), &public, now)?;

        Ok(public)
    }

    /// Сверяет хеш пост-квантовой половины с запомненным; запоминает,
    /// если его ещё нет.
    pub(super) fn remember_peer_pq(
        &self,
        account: &AccountId,
        pq_public: &[u8],
        now: Timestamp,
    ) -> Result<()> {
        let hash = pq_identity::pq_identity_hash(pq_public);

        match self.storage.contact_pq_hash(account)? {
            Some(known) if known == hash => Ok(()),
            Some(_) => {
                self.storage
                    .log_security_event("pq_identity_changed", None, now)?;

                Err(AegisError::IdentityChanged)
            }
            None => self.storage.set_contact_pq_hash(account, &hash),
        }
    }

    /// Safety number по гибридным отпечаткам: классический ключ ‖ хеш
    /// пост-квантовой половины с каждой стороны.
    ///
    /// # Errors
    ///
    /// [`AegisError::Uninitialized`] — пост-квантовая половина
    /// собеседника ещё не известна.
    pub(super) fn hybrid_safety_number(
        &self,
        own: &PublicKeyBytes,
        peer: &PublicKeyBytes,
    ) -> Result<SafetyNumber> {
        let peer_hash = self
            .storage
            .contact_pq_hash(&peer_account(peer))?
            .ok_or(AegisError::Uninitialized)?;

        let own_print =
            Fingerprint::compute_hybrid(own, &self.own_pq_hash()?, peer_account(own).as_bytes());
        let peer_print =
            Fingerprint::compute_hybrid(peer, &peer_hash, peer_account(peer).as_bytes());

        Ok(SafetyNumber::new(&own_print, &peer_print))
    }
}
