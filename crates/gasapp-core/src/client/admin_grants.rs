// SPDX-License-Identifier: Apache-2.0

//! Назначение администратором канала без заявки.
//!
//! Владелец выбирает собеседника — и всё: ядро заводит для него ключ
//! подписи, разрешает серверу принимать записи от его аккаунта, вписывает
//! ключ в описание канала и отправляет ключ с ссылкой на канал внутри
//! сквозного шифрования ([`Content::ChannelAdmin`]). У собеседника канал
//! появляется сам, уже с правом писать.
//!
//! Прежде нужна была заявка: читатель канала показывал владельцу QR со
//! своим ключом. Владелец 2026-11-27: «назначение админом без запроса,
//! запросы убрать».
//!
//! 🔐 Почему так можно:
//! * ключ уходит только сверенному собеседнику (тот же порог, что для
//!   сообщения: `check_advertised_identity`) и только ему — копий своим
//!   устройствам владельца нет;
//! * владелец ключ знает — но он и так подписывает канал целиком; читатели
//!   принимают записи по ключам из описания, подписанного владельцем;
//! * назначение от незнакомца (запрос на переписку) не применяется, пока
//!   переписку не приняли, и забывается через неделю; от заблокированного —
//!   отбрасывается.

use gasapp_net::client::Transport;
use gasapp_protocol::channel::{self, AdminRequest, ChannelAccess};
use gasapp_protocol::content::Content;
use gasapp_storage::requests::ChatRequest;
use gasapp_types::{ChatId, GasAppError, PrivateKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::channels::{parse_id, require_owner, role_of, ChannelAdminInfo, ChannelRole};
use super::{canonical_username, hex, parse_public_key, unhex, Client};

/// Назначения, ждущие применения: `admin_grant:<канал>` → чат, ссылка, ключ.
const GRANT_PREFIX: &str = "admin_grant:";

/// Сколько назначение из непринятой переписки ждёт её принятия.
const GRANT_TTL_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;

impl<T: Transport> Client<T> {
    /// Назначает собеседника администратором своего канала — без заявки.
    ///
    /// Сначала ключ уходит собеседнику (сбой — ничего не изменилось),
    /// потом сервер и описание канала. Не дошло до сервера — у собеседника
    /// лишь ненужный ключ, повтор назначит заново.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — человек не владелец канала;
    /// * [`GasAppError::PeerUnconfirmed`] / [`GasAppError::IdentityChanged`]
    ///   — ключ собеседника не сверен;
    /// * [`GasAppError::Malformed`] — администраторов уже предел;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn appoint_channel_admin<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        peer_username: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Vec<ChannelAdminInfo>> {
        let stored = self.stored_channel(channel_id)?;
        require_owner(&stored)?;
        let name = canonical_username(peer_username)?;

        let peer = self.discover_for_send(&name, now)?;
        let peer_identity = parse_public_key(&peer.identity_key)?;
        self.check_advertised_identity(
            &name,
            &peer_identity,
            peer.pq_identity_key.as_deref(),
            now,
        )?;
        // Сервер находит по устройству аккаунт: записи примет от любого
        // его устройства. Первое в списке — основное.
        let device = peer
            .device_ids
            .first()
            .ok_or(GasAppError::SessionNotFound)?;

        let (signing_key, verify_key) = channel::admin_keypair(rng);
        let request = AdminRequest {
            channel_id: stored.channel_id,
            verify_key,
            device_id: parse_id(device)?,
        }
        .to_uri();

        self.send_content_with(
            &name,
            &Content::ChannelAdmin {
                link: self.channel_link(channel_id)?,
                signing_key: *signing_key.expose_secret(),
            },
            false,
            now,
            rng,
        )?;

        self.add_channel_admin(channel_id, &request, &name, now, rng)
    }

    /// Пришло назначение администратором: запомнить до применения
    /// ([`Client::apply_admin_grants`] — сеть, не посреди приёма).
    pub(crate) fn note_admin_grant(
        &self,
        chat_id: &ChatId,
        link: &str,
        signing_key: &[u8; 32],
        now: Timestamp,
    ) -> Result<()> {
        // 🔐 От заблокированного — ничего.
        if self.storage.is_chat_blocked(chat_id)? {
            return Ok(());
        }
        let access = ChannelAccess::parse(link)?;
        // Ключ годный — иначе и запоминать нечего.
        channel::verify_key_of(PrivateKeyBytes::new(*signing_key))?;
        let (channel, at, uri, key) = (
            access.channel_uuid(),
            now.as_millis(),
            access.to_uri(),
            hex(signing_key),
        );
        self.storage.set_setting_text(
            &format!("{GRANT_PREFIX}{channel}"),
            &format!("{chat_id}\n{at}\n{uri}\n{key}"),
        )
    }

    /// Применяет пришедшие назначения: канал добавляется (если его ещё нет)
    /// и получает ключ подписи. Возвращает число применённых. Сеть.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение назначений не удалось.
    pub fn apply_admin_grants(&self, now: Timestamp) -> Result<u32> {
        let mut applied: u32 = 0;
        for (key, value) in self.storage.settings_text_with_prefix(GRANT_PREFIX)? {
            match self.apply_admin_grant(&value, now) {
                Ok(Grant::Applied) => {
                    applied = applied.saturating_add(1);
                    self.storage.delete_setting_text(&key)?;
                }
                // Сеть или непринятая переписка — в следующий раз.
                Ok(Grant::Later) | Err(GasAppError::Network) => {}
                Ok(Grant::Dropped) | Err(_) => self.storage.delete_setting_text(&key)?,
            }
        }
        Ok(applied)
    }

    fn apply_admin_grant(&self, value: &str, now: Timestamp) -> Result<Grant> {
        let mut parts = value.splitn(4, '\n');
        let (Some(chat), Some(at), Some(link), Some(key)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Ok(Grant::Dropped);
        };
        let chat = ChatId::from_uuid(chat.parse().map_err(|_| GasAppError::Malformed)?);
        let at: i64 = at.parse().map_err(|_| GasAppError::Malformed)?;
        let signing_key: [u8; 32] = unhex(key)?.try_into().map_err(|_| GasAppError::Malformed)?;

        if self.storage.is_chat_blocked(&chat)? {
            return Ok(Grant::Dropped);
        }
        // 🔐 Назначение от незнакомца — только после принятия переписки.
        if self.storage.chat_request_state(&chat)? == Some(ChatRequest::Incoming) {
            return Ok(if now.as_millis().saturating_sub(at) > GRANT_TTL_MILLIS {
                Grant::Dropped
            } else {
                Grant::Later
            });
        }

        let channel = self.join_channel(link, now)?;
        let stored = self.stored_channel(&channel.channel_id)?;
        // Свой канал ключом администратора не портится.
        if role_of(&stored) == ChannelRole::Owner {
            return Ok(Grant::Dropped);
        }
        self.storage
            .set_channel_signing_key(&stored.channel_id, &signing_key)?;
        self.storage
            .log_security_event("channel_admin_granted", None, now)?;
        // Свежее описание — с ключом в списке администраторов.
        let _ = self.sync_stored(&self.stored_channel(&channel.channel_id)?, false, now);
        Ok(Grant::Applied)
    }
}

/// Чем кончилась попытка применить назначение.
enum Grant {
    Applied,
    Later,
    Dropped,
}
