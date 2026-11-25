// SPDX-License-Identifier: Apache-2.0

//! Перенос истории на новое своё устройство (`docs/protocol/MULTI-DEVICE.md`,
//! этап 4б).
//!
//! Основное устройство при «Подключить» отмечает: новому нужна история.
//! Когда новое войдёт и опубликует ключи, основное отправляет ему последние
//! 30 дней переписки — текст, пачками [`Content::History`], обычной
//! сессией между своими устройствами. Сервер видит только шифротекст.
//!
//! 🔐 Новое устройство принимает историю только от основного (его ключ
//! устройства — ключ аккаунта) и только в первые полчаса после входа:
//! иначе любое своё устройство могло бы вписать другим «входящие» от
//! собеседников, а давно подключённое — переписать прошлое.

use std::collections::{HashMap, HashSet};

use gasapp_net::client::Transport;
use gasapp_protocol::content::{Content, HistoryItem, MAX_HISTORY_ITEMS};
use gasapp_protocol::keys::IdentityKeyPair;
use gasapp_storage::requests::ChatRequest;
use gasapp_storage::{MessageStatus, StoredMessage};
use gasapp_types::{
    AccountId, ChatId, Ciphertext, GasAppError, MessageId, Plaintext, PublicKeyBytes, Result,
    Timestamp,
};
use rand_core::{CryptoRng, RngCore};

use super::{derive_chat_id, Client};

/// Отметка «новому устройству нужна история»: ключ — префикс и устройство,
/// значение — до какого момента ждать его входа (0 — сделано).
const PENDING_PREFIX: &str = "history_for:";

/// Когда это устройство вошло в аккаунт по QR (миллисекунды Unix).
pub(crate) const LINKED_AT_SETTING: &str = "linked_at";

/// Глубина истории — 30 дней.
const HISTORY_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Сколько основное ждёт входа нового устройства.
const SEND_WINDOW_MILLIS: i64 = 10 * 60 * 1000;

/// Сколько новое устройство принимает историю после входа.
const ACCEPT_WINDOW_MILLIS: i64 = 30 * 60 * 1000;

/// Расхождение часов двух своих телефонов.
const CLOCK_SLACK_MILLIS: i64 = 5 * 60 * 1000;

/// Не больше стольких сообщений всего — самые новые.
const MAX_MESSAGES: usize = 5_000;

/// Не больше стольких сообщений из одного чата.
const PER_CHAT: u32 = 2_000;

/// Пачка по объёму: с запасом до наибольшего бакета padding (256 КиБ).
const BATCH_BYTES: usize = 120_000;

/// Служебные байты одного сообщения в пачке (ключ, id, время, длины).
const ITEM_OVERHEAD: usize = 72;

impl<T: Transport> Client<T> {
    /// Основное устройство, «Подключить»: новому устройству нужна история.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub(crate) fn schedule_history(&self, device_id: &str, now: Timestamp) -> Result<()> {
        self.storage.set_setting_int(
            &format!("{PENDING_PREFIX}{device_id}"),
            now.as_millis().saturating_add(SEND_WINDOW_MILLIS),
        )
    }

    /// Основное устройство: отправляет историю тем новым устройствам, что
    /// уже вошли. Вызывать вместе с приёмом сообщений; возвращает, сколько
    /// сообщений ушло.
    ///
    /// Новое устройство ещё не вошло — отметка остаётся до следующего раза
    /// (не дольше 10 минут). Сбой посреди отправки — повтор целиком:
    /// принятые раньше сообщения новое устройство узнаёт по идентификатору
    /// и не дублирует.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен; прочие — как у
    /// отправки.
    pub fn send_pending_history<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<usize> {
        // Свои устройства — заодно с приёмом (а не с отправкой: см.
        // `Client::own_targets`).
        if self.setting_bool(super::devices::MULTI_DEVICE_SETTING, false)? {
            let (identity, _) = self.load_identity()?;
            let _ = self.refresh_own_targets_if_old(&identity, now);
            // Основное — и переподпись своего списка раз в неделю.
            let _ = self.resign_own_list_if_old(now);
        }
        let pending: Vec<(String, i64)> = self
            .storage
            .list_settings()?
            .into_iter()
            .filter(|(_, deadline)| *deadline > 0)
            .filter_map(|(key, deadline)| {
                Some((key.strip_prefix(PENDING_PREFIX)?.to_owned(), deadline))
            })
            .collect();
        if pending.is_empty() {
            return Ok(0);
        }

        let (identity, _) = self.load_identity()?;
        let own = self.own_account(&identity)?;
        let self_chat = derive_chat_id(&own, &own);
        let mut sent = 0usize;
        for (device, deadline) in pending {
            let key = format!("{PENDING_PREFIX}{device}");
            if now.as_millis() > deadline {
                self.storage.set_setting_int(&key, 0)?;
                continue;
            }
            // Новое устройство в памяти ещё не знают — спрашиваем discovery
            // (это приём, не отправка).
            let Some(target) = self
                .refresh_own_targets(&identity, now)?
                .into_iter()
                .find(|target| target.device_id == device)
            else {
                continue;
            };
            for batch in self.history_batches(&identity, now)? {
                let count = batch.len();
                let plaintext = Plaintext::new(Content::History { items: batch }.to_bytes()?);
                self.send_to_devices(
                    &identity,
                    &self_chat,
                    &own,
                    std::slice::from_ref(&target),
                    &plaintext,
                    now,
                    rng,
                )?;
                sent = sent.saturating_add(count);
            }
            // Таймеры исчезающих и блокировки — тоже: без них новое
            // устройство хранило бы «исчезающие» вечно и показывало бы
            // заблокированных.
            for copy in self.chat_state_copies()? {
                self.send_to_devices(
                    &identity,
                    &self_chat,
                    &own,
                    std::slice::from_ref(&target),
                    &Plaintext::new(copy.to_bytes()?),
                    now,
                    rng,
                )?;
            }
            self.storage.set_setting_int(&key, 0)?;
            self.storage
                .log_security_event("device_history_sent", None, now)?;
        }
        Ok(sent)
    }

    /// Последние 30 дней — пачками по числу и объёму, от старых к новым.
    fn history_batches(
        &self,
        identity: &IdentityKeyPair,
        now: Timestamp,
    ) -> Result<Vec<Vec<HistoryItem>>> {
        let own_id = self
            .storage
            .get_account_id()?
            .ok_or(GasAppError::Uninitialized)?;
        let own = self.own_account(identity)?;
        let since = now.as_millis().saturating_sub(HISTORY_MILLIS);

        let mut items = Vec::new();
        for contact in self.storage.list_contacts(u32::MAX)? {
            let Some(chat_id) = contact.chat_id else {
                continue;
            };
            let Ok(peer) = <[u8; 32]>::try_from(contact.identity_key.as_slice()) else {
                continue;
            };
            if peer == *own.as_bytes() {
                continue;
            }
            for message in self.storage.load_messages(&chat_id, PER_CHAT)? {
                if let Some(item) =
                    history_item(&message, peer, contact.username.as_ref(), &own_id, since)
                {
                    items.push(item);
                }
            }
        }
        items.sort_by_key(|item| item.sent_at_millis);
        let surplus = items.len().saturating_sub(MAX_MESSAGES);
        items.drain(..surplus);

        let mut batches = Vec::new();
        let mut batch = Vec::new();
        let mut bytes = 0usize;
        for item in items {
            let size = item
                .body
                .len()
                .saturating_add(item.peer_username.as_ref().map_or(0, String::len))
                .saturating_add(ITEM_OVERHEAD);
            if !batch.is_empty()
                && (batch.len() >= MAX_HISTORY_ITEMS || bytes.saturating_add(size) > BATCH_BYTES)
            {
                batches.push(std::mem::take(&mut batch));
                bytes = 0;
            }
            bytes = bytes.saturating_add(size);
            batch.push(item);
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        Ok(batches)
    }

    /// Новое устройство: пачка истории от основного. Возвращает, появилось
    /// ли видимое.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub(crate) fn apply_history(
        &self,
        identity: &IdentityKeyPair,
        sender: &PublicKeyBytes,
        items: Vec<HistoryItem>,
        now: Timestamp,
    ) -> Result<bool> {
        let own = self.own_account(identity)?;
        // 🔐 Только от основного и только на подключённом устройстве.
        if *sender != own || self.is_primary_device()? {
            return Ok(false);
        }
        let linked_at = self.storage.setting_int(LINKED_AT_SETTING, 0)?;
        if linked_at == 0 || now.as_millis().saturating_sub(linked_at) > ACCEPT_WINDOW_MILLIS {
            return Ok(false);
        }
        let earliest = linked_at
            .saturating_sub(HISTORY_MILLIS)
            .saturating_sub(CLOCK_SLACK_MILLIS);
        let latest = now.as_millis().saturating_add(CLOCK_SLACK_MILLIS);
        let own_id = self
            .storage
            .get_account_id()?
            .ok_or(GasAppError::Uninitialized)?;

        let mut named = HashSet::new();
        let mut answered = HashSet::new();
        let mut newest: HashMap<ChatId, (i64, MessageId)> = HashMap::new();
        for item in items {
            let peer = PublicKeyBytes::new(item.peer);
            if peer == own || item.sent_at_millis < earliest || item.sent_at_millis > latest {
                continue;
            }
            let chat_id = derive_chat_id(&own, &peer);
            if let Some(name) = item.peer_username.as_deref() {
                // Имя — заявление: принимается, только если discovery
                // называет для него тот же ключ (раз на собеседника).
                if named.insert(item.peer) {
                    let _ = self.accept_claimed_username(&peer, name, &chat_id, now);
                }
            }
            let message_id = MessageId::from_uuid(uuid::Uuid::from_bytes(item.id));
            let stored = self.storage.insert_message(&StoredMessage {
                id: message_id,
                chat_id,
                sender_id: if item.outgoing {
                    own_id
                } else {
                    // Входящие помечаются идентификатором чата — как при приёме.
                    AccountId::from_uuid(*chat_id.as_uuid())
                },
                timestamp: Timestamp::from_millis(item.sent_at_millis),
                content: Ciphertext::new(item.body.into_bytes()),
                // Старые входящие прочитаны на основном устройстве.
                status: if item.outgoing {
                    MessageStatus::Sent
                } else {
                    MessageStatus::Read
                },
                message_type: 0,
                expires_at: None,
            })?;
            if item.outgoing {
                answered.insert(chat_id);
            }
            if stored {
                let entry = newest.entry(chat_id).or_insert((i64::MIN, message_id));
                if item.sent_at_millis >= entry.0 {
                    *entry = (item.sent_at_millis, message_id);
                }
            }
        }

        // Чат, где мы отвечали, — обычная переписка, а не запрос: иначе
        // первое же сообщение собеседника на новое устройство сделало бы
        // давний чат «запросом незнакомца». Только входящие — как было:
        // на основном это мог быть и неотвеченный запрос.
        for chat_id in &answered {
            if matches!(
                self.storage.chat_request_state(chat_id)?,
                None | Some(ChatRequest::Incoming)
            ) {
                self.storage
                    .set_chat_request_state(chat_id, ChatRequest::Settled)?;
            }
        }

        // Активность чата — только вперёд: живые сообщения, пришедшие
        // раньше истории, остаются последними.
        let current: HashMap<ChatId, i64> = self
            .storage
            .list_chats(u32::MAX)?
            .into_iter()
            .map(|row| (row.chat_id, row.last_activity))
            .collect();
        let shown = !newest.is_empty();
        for (chat_id, (at, message_id)) in newest {
            if current.get(&chat_id).is_none_or(|last| *last < at) {
                self.storage
                    .touch_chat(&chat_id, Some(&message_id), Timestamp::from_millis(at))?;
            }
        }
        Ok(shown)
    }
}

/// Сообщение для истории: текстовое, не исчезающее, не старше `since`.
fn history_item(
    message: &StoredMessage,
    peer: [u8; 32],
    username: Option<&String>,
    own_id: &AccountId,
    since: i64,
) -> Option<HistoryItem> {
    // Исчезающие не переносятся: их срок — договорённость с собеседником.
    if message.timestamp.as_millis() < since
        || message.expires_at.is_some()
        || message.message_type != 0
    {
        return None;
    }
    let body = String::from_utf8(message.content.as_bytes().to_vec()).ok()?;
    // Вложение без подписи: файлы не переносятся, пустое — незачем.
    if body.is_empty() {
        return None;
    }
    Some(HistoryItem {
        peer,
        peer_username: username.cloned(),
        id: *message.id.as_bytes(),
        outgoing: message.sender_id == *own_id,
        sent_at_millis: message.timestamp.as_millis(),
        body,
    })
}
