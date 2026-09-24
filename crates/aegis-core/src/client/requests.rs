// SPDX-License-Identifier: Apache-2.0

//! Запросы на переписку: принять, отклонить, и что до этого нельзя.
//!
//! Состояние живёт в хранилище (`aegis_storage::requests`). Здесь —
//! правила:
//!
//! * новый чат, начатый собеседником, — запрос
//!   ([`ChatRequest::Incoming`]); пока он не принят, квитанции
//!   и «печатает…» ему не уходят;
//! * собственное сообщение в запрос — это согласие: писать в ответ
//!   и при этом «не принимать» не бывает;
//! * [`Client::accept_chat`] — согласие без сообщения: собеседнику
//!   уходит ключ доступа, и у него запрос перестаёт висеть;
//! * [`Client::decline_chat`] — отказ: переписка удаляется, в ответ
//!   не уходит ничего — незнакомец не узнаёт даже того, что его
//!   сообщение прочли.
//!
//! ⚠️ Принятие не подтверждает ключ. Писать по-прежнему можно только
//! после сверки safety number или по ссылке/QR собеседника
//! (`PeerUnconfirmed`).

use aegis_net::client::Transport;
use aegis_types::{canonical_username, ChatId, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{
    derive_chat_id, parse_public_key, peer_account, verified_sealed_kem, ChatRequest, Client,
};

impl<T: Transport> Client<T> {
    /// Состояние запроса на переписку; `None` — чата ещё нет.
    ///
    /// # Errors
    ///
    /// [`aegis_types::AegisError::Storage`] — чтение не удалось.
    pub fn chat_request(&self, chat_id: &ChatId) -> Result<Option<ChatRequest>> {
        self.storage.chat_request_state(chat_id)
    }

    /// Принимает запрос на переписку.
    ///
    /// Локально — сразу. Собеседнику уходит ключ доступа sealed sender:
    /// у него переписка перестаёт ждать ответа, а его следующие
    /// сообщения идут без proof-of-work. Сбой сети принятия не отменяет:
    /// ключ уйдёт с первым собственным сообщением.
    ///
    /// # Errors
    ///
    /// [`aegis_types::AegisError::Storage`] — запись не удалась.
    pub fn accept_chat<R: RngCore + CryptoRng>(
        &self,
        chat_id: &ChatId,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        self.storage
            .set_chat_request_state(chat_id, ChatRequest::Settled)?;

        // Ключ доступа — только собеседнику этого чата и только если
        // сервер называет для его имени тот же ключ, что у сессии.
        // Иначе согласие ушло бы тому, кого назвал сервер.
        let _ = self.share_access_key_in(chat_id, now, rng);

        Ok(())
    }

    /// Отклоняет запрос: переписка удаляется, в ответ не уходит ничего.
    ///
    /// # Errors
    ///
    /// [`aegis_types::AegisError::Storage`] — удаление не удалось.
    pub fn decline_chat(&self, chat_id: &ChatId, now: Timestamp) -> Result<()> {
        self.storage.delete_chat(chat_id, now)
    }

    /// Висит ли с этим собеседником непринятый входящий запрос.
    ///
    /// Без сети: чат выводится из ключа, уже известного для имени.
    /// Запрос в discovery выдал бы серверу, с кем человек переписывается.
    pub(super) fn request_pending_with(&self, peer_username: &str) -> Result<bool> {
        let Ok(name) = canonical_username(peer_username) else {
            return Ok(false);
        };
        let Some(peer) = self.storage.contact_identity_by_username(&name)? else {
            return Ok(false);
        };
        let Ok(peer) = <[u8; 32]>::try_from(peer.as_slice()).map(PublicKeyBytes::new) else {
            return Ok(false);
        };
        let (identity, _) = self.load_identity()?;
        let chat_id = derive_chat_id(identity.public().public(), &peer);

        Ok(self.storage.chat_request_state(&chat_id)? == Some(ChatRequest::Incoming))
    }

    /// Отмечает отправку: новый чат, начатый нами, ждёт ответа;
    /// собственное содержимое в чужой запрос — согласие.
    pub(super) fn note_outgoing(&self, chat_id: &ChatId, new_session: bool) -> Result<()> {
        match self.storage.chat_request_state(chat_id)? {
            None if new_session => self
                .storage
                .set_chat_request_state(chat_id, ChatRequest::Outgoing),
            Some(ChatRequest::Incoming) => self
                .storage
                .set_chat_request_state(chat_id, ChatRequest::Settled),
            _ => Ok(()),
        }
    }

    /// Передаёт свой ключ доступа собеседнику чата, если ещё не передан.
    fn share_access_key_in<R: RngCore + CryptoRng>(
        &self,
        chat_id: &ChatId,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let Some(contact) = self
            .contacts()?
            .into_iter()
            .find(|contact| contact.chat_id.as_ref() == Some(chat_id))
        else {
            return Ok(());
        };
        let Some(username) = contact.username else {
            return Ok(());
        };

        if self
            .storage
            .access_key_shared_with(&peer_account(&contact.identity))?
        {
            return Ok(());
        }

        let peer = self.api.discover(&username)?;
        let advertised = parse_public_key(&peer.identity_key)?;

        if advertised != contact.identity {
            return Ok(());
        }

        let peer_kem = verified_sealed_kem(&peer, &advertised)?;
        let Some(device) = peer.device_ids.first().cloned() else {
            return Ok(());
        };
        let Some(session) = self.storage.load_session(chat_id)? else {
            return Ok(());
        };
        let (identity, _) = self.load_identity()?;

        self.send_own_access_key(
            &identity,
            chat_id,
            Some(session),
            &advertised,
            &device,
            &peer_kem,
            now,
            rng,
        )?;

        Ok(())
    }
}
