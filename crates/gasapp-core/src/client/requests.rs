// SPDX-License-Identifier: Apache-2.0

//! Запросы на переписку: принять, отклонить, и что до этого нельзя.
//!
//! Состояние живёт в хранилище (`gasapp_storage::requests`). Здесь —
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

use gasapp_net::client::Transport;
use gasapp_protocol::content::Content;
use gasapp_types::{canonical_username, ChatId, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{
    derive_chat_id, parse_public_key, peer_account, verified_sealed_kem, ChatRequest, Client,
};

impl<T: Transport> Client<T> {
    /// Состояние запроса на переписку; `None` — чата ещё нет.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — чтение не удалось.
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
    /// [`gasapp_types::GasAppError::Storage`] — запись не удалась.
    pub fn accept_chat<R: RngCore + CryptoRng>(
        &self,
        chat_id: &ChatId,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        self.storage
            .set_chat_request_state(chat_id, ChatRequest::Settled)?;

        // Принять запрос — решить писать этому человеку (как нажатое @имя,
        // решение владельца 2026-11-27). Ключ — тот, которым он сам начал
        // переписку (сессия доказала владение им), а не названный сервером;
        // без этого ответить было нельзя: «сверьте код», и тот, кто добавил
        // по QR, видел молчание.
        if let Some(contact) = self
            .storage
            .list_contacts(u32::MAX)?
            .into_iter()
            .find(|contact| contact.chat_id.as_ref() == Some(chat_id))
        {
            if !contact.verified && !contact.confirmed_by_link && !contact.confirmed_by_kt {
                self.storage
                    .mark_contact_confirmed_by_link(&contact.account_id)?;
                self.storage
                    .log_security_event("contact_confirmed_by_acceptance", None, now)?;
            }
        }

        // Ключ доступа — только собеседнику этого чата и только если
        // сервер называет для его имени тот же ключ, что у сессии.
        // Иначе согласие ушло бы тому, кого назвал сервер.
        let _ = self.share_access_key_in(chat_id, now, rng);

        Ok(())
    }

    /// Чат открыт — входящие прочитаны (счётчик непрочитанных).
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — запись не удалась.
    pub fn mark_chat_read(&self, chat_id: &ChatId, now: Timestamp) -> Result<()> {
        self.storage.mark_chat_read(chat_id, now).map(|_| ())
    }

    /// Закрепляет сообщение чата у обоих (`None` — открепить). Сеть.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::SessionNotFound`] — сообщения нет или
    /// оно из другого чата; остальное — как у отправки сообщения.
    pub fn pin_message<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        target: Option<&gasapp_types::MessageId>,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let content = Content::Pin {
            target: target.map(|id| *id.as_uuid().as_bytes()),
        };
        let expected = match target {
            Some(id) => Some(
                self.storage
                    .message_origin(id)?
                    .map(|(chat, _)| chat)
                    .ok_or(gasapp_types::GasAppError::SessionNotFound)?,
            ),
            None => None,
        };
        // Сообщение из другого чата — до сети: собеседнику незачем знать
        // даже идентификатор чужого сообщения.
        let (identity, _) = self.load_identity()?;
        if let (Some(expected), Some(known)) = (
            expected,
            self.known_chat_of(&canonical_username(peer_username)?, &identity)?,
        ) {
            if expected != known {
                return Err(gasapp_types::GasAppError::SessionNotFound);
            }
        }
        let chat = self.send_content_with(peer_username, &content, false, now, rng)?;
        if expected.is_some_and(|expected| expected != chat) {
            return Err(gasapp_types::GasAppError::SessionNotFound);
        }
        self.note_pin(&chat, target)
    }

    /// Закреп пришёл (или поставлен своим): только сообщение этого чата.
    pub(crate) fn note_pin(
        &self,
        chat_id: &ChatId,
        target: Option<&gasapp_types::MessageId>,
    ) -> Result<()> {
        let key = pin_key(chat_id);
        match target {
            Some(id) => {
                if self.storage.message_origin(id)?.map(|(chat, _)| chat) == Some(*chat_id) {
                    self.storage.set_setting_text(&key, &id.to_string())?;
                }
                Ok(())
            }
            None => self.storage.delete_setting_text(&key),
        }
    }

    /// Закреплённое сообщение чата — если оно ещё есть. Без сети.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — чтение не удалось.
    pub fn pinned_message(&self, chat_id: &ChatId) -> Result<Option<gasapp_types::MessageId>> {
        let Some(text) = self.storage.setting_text(&pin_key(chat_id))? else {
            return Ok(None);
        };
        let Ok(uuid) = text.parse() else {
            return Ok(None);
        };
        let id = gasapp_types::MessageId::from_uuid(uuid);
        Ok(
            (self.storage.message_origin(&id)?.map(|(chat, _)| chat) == Some(*chat_id))
                .then_some(id),
        )
    }

    /// Закрепить чат наверху списка или открепить. Без сети.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — запись не удалась.
    pub fn set_chat_pinned(&self, chat_id: &ChatId, pinned: bool, now: Timestamp) -> Result<()> {
        self.storage.set_chat_pinned(chat_id, pinned.then_some(now))
    }

    /// Чат «без звука». Без сети.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — запись не удалась.
    pub fn set_chat_muted(&self, chat_id: &ChatId, muted: bool) -> Result<()> {
        self.storage.set_chat_muted(chat_id, muted)
    }

    /// Закреплённые и «без звука» чаты. Без сети.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — чтение не удалось.
    pub fn chat_prefs(&self) -> Result<Vec<gasapp_storage::chat_prefs::ChatPrefs>> {
        self.storage.chat_prefs()
    }

    /// Удаляет переписку у себя (собеседник ничего не узнаёт); писать
    /// можно сразу — сессия и контакт остаются. Без сети.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — удаление не удалось.
    pub fn clear_chat(&self, chat_id: &ChatId, now: Timestamp) -> Result<()> {
        self.storage.clear_chat(chat_id, now)
    }

    /// Убирает своё неотправленное сообщение (перед повтором: повтор —
    /// новое сообщение того же текста). Ушедшие и чужие — `false`.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — запись не удалась.
    pub fn discard_failed_message(
        &self,
        id: &gasapp_types::MessageId,
        now: Timestamp,
    ) -> Result<bool> {
        self.storage.discard_failed_message(id, now)
    }

    /// Свои сообщения, «отправляющиеся» дольше пяти минут (приложение
    /// выгрузили посреди отправки), — «не отправлено», с повтором.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — запись не удалась.
    pub fn fail_stale_sends(&self, now: Timestamp) -> Result<usize> {
        const STALE_MILLIS: i64 = 5 * 60 * 1000;
        self.storage.fail_stale_sends(
            Timestamp::from_millis(now.as_millis().saturating_sub(STALE_MILLIS)),
            now,
        )
    }

    /// Непрочитанные входящие по чатам (запросы незнакомцев — тоже).
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — чтение не удалось.
    pub fn unread_counts(&self) -> Result<Vec<(ChatId, u32)>> {
        self.storage.unread_counts()
    }

    /// Отклоняет запрос: переписка удаляется, в ответ не уходит ничего.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — удаление не удалось.
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
        let chat_id = derive_chat_id(&self.own_account(&identity)?, &peer);

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

        let peer_pq = self.verified_peer_pq(&peer, &advertised, now)?;
        let peer_kem = verified_sealed_kem(&peer, &advertised, &peer_pq)?;
        let targets = self.peer_targets(&peer, &advertised, &peer_pq, &peer_kem, now)?;
        let (identity, _) = self.load_identity()?;

        // Ключ доступа — каждому устройству, с которым уже есть сессия.
        for target in &targets {
            let session_id =
                crate::session::device_session_id(chat_id, &advertised, &target.identity);
            if let Some(session) = self.storage.load_session(&session_id)? {
                self.send_own_access_key(
                    &identity,
                    &advertised,
                    &session_id,
                    Some(session),
                    target,
                    now,
                    rng,
                )?;
            }
        }

        Ok(())
    }
}

/// Настройка: закреплённое сообщение чата.
fn pin_key(chat_id: &ChatId) -> String {
    format!("pinned_msg:{chat_id}")
}
