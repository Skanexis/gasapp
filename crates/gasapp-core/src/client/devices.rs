// SPDX-License-Identifier: Apache-2.0

//! Доставка всем устройствам собеседника (`docs/protocol/MULTI-DEVICE.md`, §4).
//!
//! Список устройств собеседника приходит с discovery подписанным ключом его
//! аккаунта — тем, что уже сверен (код безопасности, KT). Сообщение
//! шифруется отдельно для каждого устройства из **проверенного** списка:
//! своя сессия Double Ratchet, свой ключ sealed sender, своя доставка.
//!
//! 🔐 Правило версий ([`check_succession`]): список старше запомненного —
//! сервер отдаёт прошлое (например, с отключённым устройством); тогда
//! берётся запомненный. Та же версия с другим содержимым — подделка:
//! отправка отменяется, событие — в журнал.
//!
//! Нет списка (одно устройство либо прежний сервер) — как раньше: одно,
//! первое устройство, ключ устройства — ключ аккаунта.

use gasapp_net::api::DiscoveryResponse;
use gasapp_net::client::Transport;
use gasapp_protocol::device_list::{check_succession, SignedDeviceList};
use gasapp_protocol::keys::IdentityKeyPair;
use gasapp_storage::devices::{KnownDevice, StoredDeviceList};
use gasapp_types::{ChatId, GasAppError, Plaintext, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use gasapp_protocol::content::Content;
use gasapp_storage::MessageStatus;
use gasapp_types::MessageId;

use super::{derive_chat_id, parse_public_key, peer_account, unhex, verified_sealed_kem, Client};
use crate::session;

/// Есть ли у аккаунта другие устройства — копии отправленного идут только
/// тогда (иначе лишний запрос discovery на каждое сообщение).
pub(crate) const MULTI_DEVICE_SETTING: &str = "multi_device";

/// Устройство собеседника, которому доставляется сообщение.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// Устройство (UUID строкой) — им адресуются bundle и доставка.
    pub device_id: String,
    /// Identity-ключ устройства.
    pub identity: PublicKeyBytes,
    /// Пост-квантовая половина его identity.
    pub pq: Vec<u8>,
    /// Проверенный ключ ML-KEM sealed sender устройства.
    pub kem: Vec<u8>,
}

impl<T: Transport> Client<T> {
    /// Устройства собеседника для отправки.
    ///
    /// `account`, `account_pq`, `account_kem` — ключи аккаунта, уже
    /// проверенные вызывающим (`check_advertised_identity`,
    /// `verified_peer_pq`, `verified_sealed_kem`).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidSignature`] — список не подписан ключом
    ///   аккаунта;
    /// * [`GasAppError::IdentityChanged`] — две разные версии списка под
    ///   одним номером;
    /// * [`GasAppError::SessionNotFound`] — устройств для доставки нет.
    pub(crate) fn peer_targets(
        &self,
        peer: &DiscoveryResponse,
        account: &PublicKeyBytes,
        account_pq: &[u8],
        account_kem: &[u8],
        now: Timestamp,
    ) -> Result<Vec<Target>> {
        let Some(list_hex) = peer.device_list.as_deref() else {
            // Одно устройство: его ключ — ключ аккаунта.
            let device_id = peer
                .device_ids
                .first()
                .cloned()
                .ok_or(GasAppError::SessionNotFound)?;
            return Ok(vec![Target {
                device_id,
                identity: *account,
                pq: account_pq.to_vec(),
                kem: account_kem.to_vec(),
            }]);
        };

        let signed = SignedDeviceList::verify(&unhex(list_hex)?, account, account_pq)?;
        let devices = self.accept_device_list(account, &signed, now)?;

        let mut targets = Vec::with_capacity(devices.len());
        for device in devices {
            let device_id = uuid::Uuid::from_bytes(device.device_id).to_string();
            // Сервер не знает устройства — оно отключено либо ещё не
            // завершило связывание: доставлять некуда.
            if !peer.device_ids.contains(&device_id) {
                continue;
            }
            let kem = if device.identity == *account {
                Some(account_kem.to_vec())
            } else {
                device_kem(peer, &device_id, &device)
            };
            // Ключа sealed sender ещё нет — устройство только подключено и
            // не выложило ключи: ему — со следующим сообщением.
            if let Some(kem) = kem {
                targets.push(Target {
                    device_id,
                    identity: device.identity,
                    pq: device.pq_identity,
                    kem,
                });
            }
        }
        if targets.is_empty() {
            return Err(GasAppError::SessionNotFound);
        }
        Ok(targets)
    }

    /// Принимает проверенный список по правилу версий и запоминает его.
    /// Возвращает устройства, которым доставлять.
    fn accept_device_list(
        &self,
        account: &PublicKeyBytes,
        signed: &SignedDeviceList,
        now: Timestamp,
    ) -> Result<Vec<KnownDevice>> {
        let stored = self.storage.device_list(account)?;
        match check_succession(
            stored.as_ref().map(|list| (list.version, list.digest)),
            signed,
        ) {
            Ok(()) => {}
            // Сервер отдаёт прошлую версию — доставляем по запомненной.
            Err(GasAppError::InvalidSignature) => {
                self.storage
                    .log_security_event("device_list_rollback", None, now)?;
                return self.storage.known_devices(account);
            }
            Err(error) => {
                self.storage
                    .log_security_event("device_list_equivocation", None, now)?;
                return Err(error);
            }
        }

        let devices: Vec<KnownDevice> = signed
            .list
            .devices
            .iter()
            .map(|entry| KnownDevice {
                device_id: entry.device_id,
                identity: entry.identity,
                pq_identity: entry.pq_identity.clone(),
            })
            .collect();

        if stored.as_ref().map(|list| list.version) != Some(signed.list.version) {
            let before = self.storage.known_devices(account)?;
            if !before.is_empty() && devices.iter().any(|device| !before.contains(device)) {
                // Подключено новое устройство собеседника — в журнал; в чате
                // это покажет интерфейс (этап 5).
                self.storage
                    .log_security_event("contact_device_added", None, now)?;
            }
            self.storage.save_device_list(
                account,
                &StoredDeviceList {
                    version: signed.list.version,
                    digest: signed.digest(),
                    signed: signed.to_bytes(),
                },
                &devices,
                now,
            )?;
        }
        Ok(devices)
    }

    /// Шифрует и доставляет содержимое каждому устройству собеседника.
    ///
    /// С каждым устройством — своя сессия (`device_session_id`); новой
    /// сессии первым уходит ключ доступа, как прежде. Успех — если
    /// доставлено хотя бы одному устройству: недоступное устройство не
    /// должно лишать сообщения остальные.
    ///
    /// # Errors
    ///
    /// Первая ошибка, если не доставлено ни одному.
    pub(crate) fn send_to_devices<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        chat_id: &ChatId,
        account: &PublicKeyBytes,
        targets: &[Target],
        plaintext: &Plaintext,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let mut delivered = 0usize;
        let mut first_error = None;
        // Свои устройства ключ доступа аккаунта уже знают.
        let shared = *account == self.own_account(identity)?
            || self
                .storage
                .access_key_shared_with(&peer_account(account))?;

        for target in targets {
            let session_id = session::device_session_id(chat_id, account, &target.identity);
            let outcome = (|| {
                let existing = self.storage.load_session(&session_id)?;
                let state = match existing {
                    Some(state) if shared => state,
                    other => self.send_own_access_key(
                        identity,
                        account,
                        &session_id,
                        other,
                        target,
                        now,
                        rng,
                    )?,
                };
                let outgoing = session::continue_session(&state, plaintext)?;
                // Сессия сохраняется до отправки: см. порядок операций.
                self.storage
                    .save_session(&session_id, &outgoing.session, now)?;
                self.deliver(identity, account, target, &outgoing.envelope, now, rng)
            })();
            match outcome {
                Ok(()) => delivered = delivered.saturating_add(1),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }

        if delivered > 0 {
            Ok(())
        } else {
            Err(first_error.unwrap_or(GasAppError::SessionNotFound))
        }
    }
}

impl<T: Transport> Client<T> {
    /// Копия отправленного — остальным своим устройствам.
    ///
    /// Свои устройства — по своему же подписанному списку из discovery:
    /// ключ аккаунта и его половина сверяются со своими. Сбой не мешает
    /// самому сообщению (вызывающий его не пробрасывает).
    ///
    /// # Errors
    ///
    /// [`GasAppError::IdentityChanged`] — discovery называет для своего
    /// имени чужой ключ; прочие — как у отправки.
    pub(crate) fn copy_to_own_devices<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        peer: &PublicKeyBytes,
        peer_username: &str,
        content: &Content,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        if !self.setting_bool(MULTI_DEVICE_SETTING, false)? {
            return Ok(());
        }
        let own = self.own_account(identity)?;
        let targets = self.own_targets(identity, now)?;
        if targets.is_empty() {
            return Ok(());
        }
        let plaintext = Plaintext::new(
            Content::Sent {
                peer: *peer.as_bytes(),
                peer_username: Some(peer_username.to_owned()),
                content: Box::new(content.clone()),
            }
            .to_bytes()?,
        );
        let self_chat = derive_chat_id(&own, &own);
        self.send_to_devices(identity, &self_chat, &own, &targets, &plaintext, now, rng)
    }

    /// Свои другие устройства — по своему же подписанному списку из
    /// discovery: ключ аккаунта и его половина сверяются со своими.
    ///
    /// # Errors
    ///
    /// [`GasAppError::IdentityChanged`] — discovery называет для своего
    /// имени чужой ключ; [`GasAppError::Network`] — сервер недоступен.
    pub(crate) fn own_targets(
        &self,
        identity: &IdentityKeyPair,
        now: Timestamp,
    ) -> Result<Vec<Target>> {
        let own = self.own_account(identity)?;
        let username = self.own_username()?.ok_or(GasAppError::Uninitialized)?;
        let found = self.discover_for_send(&username, now)?;
        if parse_public_key(&found.identity_key)? != own {
            return Err(GasAppError::IdentityChanged);
        }
        let (Some(pq), Some(binding)) = (&found.pq_identity_key, &found.identity_binding) else {
            return Err(GasAppError::Uninitialized);
        };
        let pq = unhex(pq)?;
        gasapp_protocol::pq_identity::verify_binding(&own, &pq, &unhex(binding)?)?;
        if gasapp_protocol::pq_identity::pq_identity_hash(&pq) != self.own_pq_hash()? {
            return Err(GasAppError::IdentityChanged);
        }
        let kem = verified_sealed_kem(&found, &own, &pq)?;
        let me = self.own_device_id()?.unwrap_or_default();
        Ok(self
            .peer_targets(&found, &own, &pq, &kem, now)?
            .into_iter()
            .filter(|target| target.device_id != me)
            .collect())
    }

    /// Копия, пришедшая со своего устройства: сообщение — как отправленное
    /// отсюда, в чат с собеседником. Возвращает, появилось ли видимое.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub(crate) fn apply_sent(
        &self,
        identity: &IdentityKeyPair,
        peer: &PublicKeyBytes,
        peer_username: Option<&str>,
        content: Content,
        now: Timestamp,
    ) -> Result<bool> {
        let chat_id = derive_chat_id(&self.own_account(identity)?, peer);
        // Чат с именем: имя — заявление, принимается, только если
        // discovery называет для него тот же ключ.
        if let Some(name) = peer_username {
            let _ = self.accept_claimed_username(peer, name, &chat_id, now);
        }
        match content {
            Content::Text { body, id, .. } => {
                let message_id = MessageId::from_uuid(uuid::Uuid::from_bytes(id));
                let stored = self.store_message(
                    &chat_id,
                    message_id,
                    &body,
                    now,
                    true,
                    MessageStatus::Sent,
                )?;
                if stored {
                    self.storage.touch_chat(&chat_id, Some(&message_id), now)?;
                }
                Ok(stored)
            }
            Content::Attachments {
                body,
                descriptors,
                id,
                ..
            } => {
                let message_id = MessageId::from_uuid(uuid::Uuid::from_bytes(id));
                let stored = self.store_message(
                    &chat_id,
                    message_id,
                    &body,
                    now,
                    true,
                    MessageStatus::Sent,
                )?;
                if stored {
                    self.store_descriptors(&message_id, &descriptors, now)?;
                    self.storage.touch_chat(&chat_id, Some(&message_id), now)?;
                }
                Ok(stored)
            }
            // Правка и удаление — только своих сообщений этого чата.
            Content::Edit { target, body } => {
                let target = MessageId::from_uuid(uuid::Uuid::from_bytes(target));
                if self.written_by_us(&target, &chat_id)? {
                    self.storage.edit_message(&target, &body, now)?;
                }
                Ok(false)
            }
            Content::Delete { target } => {
                let target = MessageId::from_uuid(uuid::Uuid::from_bytes(target));
                if self.written_by_us(&target, &chat_id)? {
                    self.storage.delete_message(&target, now)?;
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

/// Ключ sealed sender подключённого устройства из discovery — только
/// с проверенной подписью ключей этого устройства.
fn device_kem(peer: &DiscoveryResponse, device_id: &str, device: &KnownDevice) -> Option<Vec<u8>> {
    let found = peer
        .devices
        .iter()
        .find(|entry| entry.device_id == device_id)?;
    let public = unhex(&found.sealed_kem_public).ok()?;
    let signature = unhex(&found.sealed_kem_signature).ok()?;
    gasapp_protocol::sealed_sender::verify_sealed_kem_key(
        &device.identity,
        &device.pq_identity,
        &public,
        &signature,
    )
    .ok()?;
    Some(public)
}
