// SPDX-License-Identifier: Apache-2.0

//! Фото профиля, квитанции доставки и картинка аватара канала.
//!
//! **Фото профиля.** Своё фото уходит тем, с кем человек переписывается,
//! — внутри сквозного шифрования ([`Content::ProfilePhoto`]): перед первым
//! сообщением после смены (как общий таймер) и разом всем чатам по просьбе
//! интерфейса ([`Client::profile_photo_targets`]). 🔐 Сервер фото не видит;
//! незнакомцы его не получают, пока им не написали. Фото из непринятого
//! запроса на переписку не показывается: разбор картинки от незнакомца —
//! лишняя поверхность атаки.
//!
//! **Квитанции доставки.** Принятое сообщение подтверждается собеседнику
//! (две галочки) — кроме непринятых запросов и заблокированных. Копятся
//! при приёме и уходят следом ([`Client::send_delivery_receipts`]): приём
//! не ждёт отправки.
//!
//! **Аватар канала.** В описании канала — ссылка на зашифрованный файл,
//! а не картинка: файл качается и расшифровывается один раз и хранится в
//! зашифрованной базе.

use gasapp_net::client::Transport;
use gasapp_protocol::content::{Content, MAX_PROFILE_PHOTO_BYTES};
use gasapp_storage::requests::ChatRequest;
use gasapp_types::{ChatId, GasAppError, MessageId, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{derive_chat_id, Client};

/// Какая версия своего фото уже ушла в этот чат.
fn sent_key(chat_id: &ChatId) -> String {
    format!("photo_sent:{chat_id}")
}

impl<T: Transport> Client<T> {
    /// Свой чат с собой — под ним хранится своё фото.
    fn own_photo_chat(&self) -> Result<ChatId> {
        let (identity, _) = self.load_identity()?;
        let own = self.own_account(&identity)?;
        Ok(derive_chat_id(&own, &own))
    }

    /// Своё фото профиля (`None` — нет). Без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn own_profile_photo(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .storage
            .profile_photo(&self.own_photo_chat()?)?
            .map(|(image, _)| image)
            .filter(|image| !image.is_empty()))
    }

    /// Ставит своё фото; `None` — снимает. Собеседники получат его перед
    /// следующим сообщением либо сразу ([`Client::profile_photo_targets`]).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — картинка больше предела;
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_profile_photo(&self, image: Option<&[u8]>, now: Timestamp) -> Result<()> {
        if image.is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_PROFILE_PHOTO_BYTES) {
            return Err(GasAppError::Malformed);
        }
        let chat = self.own_photo_chat()?;
        // Версия растёт всегда, даже если часы отстали от прошлой смены.
        let previous = self.storage.profile_photo(&chat)?.map_or(0, |(_, v)| v);
        let version = now.as_millis().max(previous.saturating_add(1));
        self.storage.set_profile_photo(&chat, image, version)?;
        Ok(())
    }

    /// Фото собеседников по чатам — для списка чатов и шапок. Без сети.
    /// Фото из непринятых запросов не отдаётся.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn profile_photos(&self) -> Result<Vec<(ChatId, Vec<u8>)>> {
        let own = self.own_photo_chat().ok();
        let mut photos = Vec::new();
        for (chat, image) in self.storage.profile_photos()? {
            if Some(chat) == own
                || self.storage.chat_request_state(&chat)? == Some(ChatRequest::Incoming)
                || self.storage.is_chat_blocked(&chat)?
            {
                continue;
            }
            photos.push((chat, image));
        }
        Ok(photos)
    }

    /// Пришло фото собеседника.
    pub(crate) fn note_profile_photo(
        &self,
        chat_id: &ChatId,
        image: &[u8],
        version: u64,
    ) -> Result<()> {
        if self.storage.is_chat_blocked(chat_id)? {
            return Ok(());
        }
        let version = i64::try_from(version).map_err(|_| GasAppError::Malformed)?;
        let image = (!image.is_empty()).then_some(image);
        self.storage.set_profile_photo(chat_id, image, version)?;
        Ok(())
    }

    /// Нужно ли этому чату своё фото (не ушла последняя версия). `None` —
    /// не нужно: фото не ставилось вовсе либо уже отправлено.
    fn photo_due(&self, chat_id: &ChatId) -> Result<Option<(Vec<u8>, i64)>> {
        let Some((image, version)) = self.storage.profile_photo(&self.own_photo_chat()?)? else {
            return Ok(None);
        };
        let sent = self.storage.setting_int(&sent_key(chat_id), 0)?;
        Ok((sent != version).then_some((image, version)))
    }

    /// Своё фото — собеседнику, если он ещё не получил последнюю версию.
    /// Сбой не мешает сообщению: попробует следующее.
    pub(crate) fn announce_profile_photo<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        chat_id: &ChatId,
        now: Timestamp,
        rng: &mut R,
    ) {
        let Ok(Some((image, version))) = self.photo_due(chat_id) else {
            return;
        };
        let Ok(stamp) = u64::try_from(version) else {
            return;
        };
        let content = Content::ProfilePhoto {
            image,
            version: stamp,
        };
        if self
            .send_content_with(peer_username, &content, false, now, rng)
            .is_ok()
        {
            let _ = self.storage.set_setting_int(&sent_key(chat_id), version);
        }
    }

    /// Собеседники, которым своё фото ещё не ушло: переписка принята, не
    /// заблокирована. Платформа отправляет каждому ([`Client::share_profile_photo_with`])
    /// по одному — между ними ядро свободно для сообщений.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn profile_photo_targets(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for contact in self.storage.list_contacts(u32::MAX)? {
            let (Some(name), Some(chat)) = (contact.username, contact.chat_id) else {
                continue;
            };
            if contact.replaced
                || self.storage.is_chat_blocked(&chat)?
                || self.storage.chat_request_state(&chat)? == Some(ChatRequest::Incoming)
                // Переписки не было — фото незнакомцу не уходит.
                || self.storage.load_messages(&chat, 1)?.is_empty()
            {
                continue;
            }
            if self.photo_due(&chat)?.is_some() {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Своё фото — этому собеседнику (из [`Client::profile_photo_targets`]).
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — такого собеседника нет.
    pub fn share_profile_photo_with<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let chat = self
            .storage
            .list_contacts(u32::MAX)?
            .into_iter()
            .find(|contact| contact.username.as_deref() == Some(peer_username) && !contact.replaced)
            .and_then(|contact| contact.chat_id)
            .ok_or(GasAppError::SessionNotFound)?;
        self.announce_profile_photo(peer_username, &chat, now, rng);
        Ok(())
    }

    /// Принятое сообщение — в очередь квитанций доставки.
    pub(crate) fn queue_delivery(&self, chat_id: &ChatId, message_id: MessageId) {
        if let Ok(mut pending) = self.pending_deliveries.lock() {
            pending.insert(*chat_id, message_id);
        }
    }

    /// Отправляет накопленные квитанции доставки: по одной на чат — до
    /// последнего принятого. Возвращает число отправленных.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn send_delivery_receipts<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<u32> {
        let pending = std::mem::take(
            &mut *self
                .pending_deliveries
                .lock()
                .map_err(|_| GasAppError::Storage)?,
        );
        if pending.is_empty() {
            return Ok(0);
        }
        let contacts = self.storage.list_contacts(u32::MAX)?;
        let mut sent: u32 = 0;
        for (chat, until) in pending {
            // 🔐 Непринятому запросу и заблокированному — ничего.
            if self.storage.chat_request_state(&chat)? == Some(ChatRequest::Incoming)
                || self.storage.is_chat_blocked(&chat)?
            {
                continue;
            }
            let Some(name) = contacts
                .iter()
                .filter(|contact| !contact.replaced && contact.chat_id == Some(chat))
                .find_map(|contact| contact.username.clone())
            else {
                continue;
            };
            let receipt = Content::DeliveryReceipt {
                until: *until.as_uuid().as_bytes(),
            };
            match self.send_content_with(&name, &receipt, false, now, rng) {
                Ok(_) => sent = sent.saturating_add(1),
                // Сеть — вернуть в очередь (новее не затирая).
                Err(GasAppError::Network) => {
                    if let Ok(mut queue) = self.pending_deliveries.lock() {
                        queue.entry(chat).or_insert(until);
                    }
                }
                Err(_) => {}
            }
        }
        Ok(sent)
    }

    /// Картинка аватара канала: из базы, а нет — скачать, расшифровать и
    /// запомнить. `None` — аватара нет. Сеть только в первый раз.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен;
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn channel_avatar_image(
        &self,
        channel_id: &str,
        now: Timestamp,
    ) -> Result<Option<Vec<u8>>> {
        let stored = self.stored_channel(channel_id)?;
        let Some(descriptor) = stored.avatar.clone().filter(|bytes| !bytes.is_empty()) else {
            return Ok(None);
        };
        if let Some(image) = self
            .storage
            .cached_channel_avatar(&stored.channel_id, &descriptor)?
        {
            return Ok(Some(image));
        }
        let image = self.fetch_channel_media(channel_id, &descriptor, now)?;
        let _ = self
            .storage
            .cache_channel_avatar(&stored.channel_id, &descriptor, &image);
        Ok(Some(image))
    }

    /// Картинка аватара канала — только из базы, без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn cached_channel_avatar_image(&self, channel_id: &str) -> Result<Option<Vec<u8>>> {
        let stored = self.stored_channel(channel_id)?;
        let Some(descriptor) = stored.avatar.filter(|bytes| !bytes.is_empty()) else {
            return Ok(None);
        };
        self.storage
            .cached_channel_avatar(&stored.channel_id, &descriptor)
    }
}
