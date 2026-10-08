// SPDX-License-Identifier: Apache-2.0

//! Закрытые каналы: ссылки-приглашения, заявки, одобрение, участники.
//!
//! Криптография — в `gasapp_protocol::channel_join`, там же честный
//! список того, чего закрытый канал не даёт. Здесь — связка с сервером
//! и базой:
//!
//! * **владелец** закрывает канал и снова открывает его;
//! * **тот, кто ведёт канал** (владелец либо администратор), заводит
//!   и отзывает ссылки-приглашения, одобряет и отклоняет заявки,
//!   удаляет подписчиков и возвращает удалённым право подать заявку;
//! * **читатель** подаёт заявку по ссылке и, когда её одобрили,
//!   получает секрет чтения — шифротекстом под свой одноразовый ключ.
//!
//! 🔐 Имена заявителей и подписчиков — слова сервера. Заявка подписана
//! ключом аккаунта, и если этот ключ совпадает с ключом известного
//! контакта с тем же именем, интерфейс это показывает; во всех прочих
//! случаях одобряющий доверяет серверу в том, чья это заявка.
//!
//! ⚠️ Удалённый подписчик секрет чтения помнит: сервер перестаёт
//! отдавать ему записи, но ключ у канала прежний.

use gasapp_net::api::{
    AnswerChannelJoinRequest, ChannelInviteRequest, ChannelMemberResponse, JoinChannelRequest,
    UpdateChannelRequest,
};
use gasapp_net::client::Transport;
use gasapp_protocol::channel;
use gasapp_protocol::channel_join::{self, JoinLink};
use gasapp_storage::channels::{PendingJoin, StoredChannel};
use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::channels::{access_of, new_stored, require_owner, role_of, Channel, ChannelRole};
use super::{hex, unhex, Client, DeviceSigner};

/// Заявка на вход глазами того, кто ведёт канал.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelJoinRequestInfo {
    /// Аккаунт заявителя, UUID, — им на заявку отвечают.
    pub account_id: String,
    /// Имя заявителя — со слов сервера.
    pub username: String,
    /// Заявка подписана ключом, который на этом устройстве уже известен
    /// как ключ контакта с таким именем. `false` — о заявителе известно
    /// только то, что сказал сервер.
    pub known_contact: bool,
}

/// Подписчик либо удалённый — глазами того, кто ведёт канал.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMember {
    /// Аккаунт, UUID.
    pub account_id: String,
    /// Имя — со слов сервера; пусто, если сервер назвал не имя.
    pub username: String,
}

/// Своя заявка, ждущая ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingChannelJoin {
    /// Канал, UUID.
    pub channel_id: String,
    /// Когда заявка подана.
    pub requested_at: Timestamp,
}

/// Вести канал — значит быть владельцем либо действующим администратором.
fn require_writer(stored: &StoredChannel) -> Result<()> {
    if matches!(role_of(stored), ChannelRole::Owner | ChannelRole::Admin) {
        Ok(())
    } else {
        Err(GasAppError::Forbidden)
    }
}

/// UUID от сервера в каноничном виде — либо ничего.
fn canonical_account(account_id: &str) -> Option<String> {
    channel::parse_channel_id(account_id)
        .ok()
        .map(|id| channel::format_uuid(&id))
}

/// 🔐 Имя приходит от сервера и попадает в интерфейс: принимается
/// только каноничное.
fn shown_username(username: String) -> String {
    if gasapp_types::is_canonical_username(&username) {
        username
    } else {
        String::new()
    }
}

fn members(list: Vec<ChannelMemberResponse>) -> Vec<ChannelMember> {
    list.into_iter()
        .filter_map(|member| {
            Some(ChannelMember {
                account_id: canonical_account(&member.account_id)?,
                username: shown_username(member.username),
            })
        })
        .collect()
}

impl<T: Transport> Client<T> {
    /// Делает канал закрытым либо снова открытым. Только владелец.
    ///
    /// Закрытый канал сервер отдаёт только участникам, а входят в него
    /// по заявке. Те, кто уже подписан, остаются участниками.
    ///
    /// ⚠️ Прежняя ссылка канала несёт секрет чтения, и он не меняется:
    /// у кого она есть, тот расшифрует записи, если добудет их
    /// шифротекст. Сервер ему их больше не отдаёт.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Malformed`] — у канала есть публичное `@имя`:
    ///   сначала его нужно убрать;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn set_channel_closed(
        &self,
        channel_id: &str,
        closed: bool,
        now: Timestamp,
    ) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;
        require_owner(&stored)?;

        let (device_id, identity) = self.own_device()?;

        self.api.update_channel(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &UpdateChannelRequest {
                closed: Some(closed),
                ..UpdateChannelRequest::default()
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .set_channel_closed(&stored.channel_id, closed)?;

        self.channel(channel_id)
    }

    /// Заводит ссылку-приглашение закрытого канала и возвращает её.
    ///
    /// Секрета чтения в ссылке нет: по ней подают заявку. Серверу
    /// уходит только хеш метки из ссылки.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Network`] — сервер недоступен либо у канала
    ///   предел действующих ссылок.
    pub fn create_channel_invite<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<String> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let link = JoinLink::new(&access_of(&stored), rng);
        let (device_id, identity) = self.own_device()?;

        self.api.set_channel_invite(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &ChannelInviteRequest {
                invite_hash: hex(&link.invite_hash()),
            },
            false,
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .add_channel_invite(&stored.channel_id, &link.invite, now)?;

        Ok(link.to_uri())
    }

    /// Свои действующие ссылки-приглашения канала — без сети.
    ///
    /// Ссылки хранятся только на устройстве, где их завели: сервер
    /// знает хеши, а в резервную копию они не входят.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn channel_invites(&self, channel_id: &str) -> Result<Vec<String>> {
        let stored = self.stored_channel(channel_id)?;

        Ok(self
            .storage
            .channel_invites(&stored.channel_id)?
            .into_iter()
            .map(|invite| {
                JoinLink {
                    channel_id: stored.channel_id,
                    verify_key: PublicKeyBytes::new(stored.verify_key),
                    invite,
                }
                .to_uri()
            })
            .collect())
    }

    /// Отзывает ссылку-приглашение: новые заявки по ней не принимаются.
    /// Уже поданные заявки и уже вошедшие участники остаются.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — это не ссылка этого канала;
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn revoke_channel_invite(
        &self,
        channel_id: &str,
        link: &str,
        now: Timestamp,
    ) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let link = JoinLink::parse(link)?;

        if link.channel_id != stored.channel_id {
            return Err(GasAppError::Malformed);
        }

        let (device_id, identity) = self.own_device()?;

        self.api.set_channel_invite(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &ChannelInviteRequest {
                invite_hash: hex(&link.invite_hash()),
            },
            true,
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .remove_channel_invite(&stored.channel_id, &link.invite)
    }

    /// Подаёт заявку в закрытый канал по ссылке-приглашению.
    ///
    /// Одноразовый ключ сохраняется **до** запроса: заявка, дошедшая до
    /// сервера, но не записанная здесь, осталась бы без ключа, которым
    /// открывается ответ.
    ///
    /// 🔐 Заявка называет серверу аккаунт и канал, а тем, кто ведёт
    /// канал, — имя аккаунта.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — не ссылка закрытого канала;
    /// * [`GasAppError::SessionNotFound`] — канала нет, он открытый
    ///   либо ссылка отозвана;
    /// * [`GasAppError::Forbidden`] — аккаунт удалён из этого канала;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn request_channel_join<R: RngCore + CryptoRng>(
        &self,
        link: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let link = JoinLink::parse(link)?;

        if self.storage.channel(&link.channel_id)?.is_some() {
            // Канал уже есть на устройстве — проситься некуда.
            return Ok(());
        }

        let (device_id, identity) = self.own_device()?;
        let request = channel_join::seal_request(
            &link,
            &PrivateKeyBytes::new(*identity.private().expose_secret()),
            rng,
        )?;

        self.storage.put_pending_join(&PendingJoin {
            channel_id: link.channel_id,
            verify_key: *link.verify_key.as_bytes(),
            invite: link.invite,
            secret: *request.secret.expose_secret(),
            requested_at: now,
        })?;

        let sent = self.api.request_channel_join(
            &device_id,
            &channel::format_uuid(&link.channel_id),
            &JoinChannelRequest {
                invite: hex(&link.invite),
                request: hex(&request.wire),
            },
            &DeviceSigner::new(&identity, now),
        );

        if let Err(error) = sent {
            // Сбой сети — заявка могла дойти, ключ к ответу остаётся.
            // Отказ сервера — заявки нет, и ждать нечего.
            if !matches!(error, GasAppError::Network) {
                self.storage.remove_pending_join(&link.channel_id)?;
            }

            return Err(error);
        }

        Ok(())
    }

    /// Свои заявки, ждущие ответа, — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn pending_channel_joins(&self) -> Result<Vec<PendingChannelJoin>> {
        Ok(self
            .storage
            .pending_joins()?
            .into_iter()
            .map(|join| PendingChannelJoin {
                channel_id: channel::format_uuid(&join.channel_id),
                requested_at: join.requested_at,
            })
            .collect())
    }

    /// Забывает свою заявку на этом устройстве. На сервере она остаётся,
    /// пока на неё не ответят; одобренную после этого открыть нечем.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID.
    pub fn forget_channel_join(&self, channel_id: &str) -> Result<()> {
        self.storage
            .remove_pending_join(&channel::parse_channel_id(channel_id)?)
    }

    /// Спрашивает сервер о своих заявках и входит в каналы, куда
    /// одобрили. Возвращает каналы, добавленные этим вызовом.
    ///
    /// Отклонённая заявка убирается; ответ, который не открывается либо
    /// несёт не тот секрет, — тоже: такой ответ годным уже не станет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы. Сбой сети по одной заявке
    /// остальным не мешает: она останется ждать.
    pub fn check_channel_joins(&self, now: Timestamp) -> Result<Vec<Channel>> {
        let pending = self.storage.pending_joins()?;

        if pending.is_empty() {
            return Ok(Vec::new());
        }

        let (device_id, identity) = self.own_device()?;
        let signer = DeviceSigner::new(&identity, now);
        let mut joined = Vec::new();

        for join in pending {
            let uuid = channel::format_uuid(&join.channel_id);

            let Ok(status) = self.api.channel_join_status(&device_id, &uuid, &signer) else {
                continue;
            };

            match status.status.as_str() {
                "pending" => {}
                "approved" => match self.accept_grant(&join, status.grant.as_deref(), now) {
                    Ok(channel) => {
                        self.storage.remove_pending_join(&join.channel_id)?;
                        joined.push(channel);
                    }
                    Err(GasAppError::Network) => {}
                    Err(_) => self.storage.remove_pending_join(&join.channel_id)?,
                },
                _ => self.storage.remove_pending_join(&join.channel_id)?,
            }
        }

        Ok(joined)
    }

    /// Открывает ответ на заявку и добавляет канал.
    ///
    /// 🔐 Секрет из ответа принимается, только если им расшифровывается
    /// описание канала, подписанное ключом владельца **из ссылки**:
    /// сервер, приславший свой «секрет», этой проверки не пройдёт.
    fn accept_grant(
        &self,
        join: &PendingJoin,
        grant: Option<&str>,
        now: Timestamp,
    ) -> Result<Channel> {
        let link = JoinLink {
            channel_id: join.channel_id,
            verify_key: PublicKeyBytes::new(join.verify_key),
            invite: join.invite,
        };
        let access = channel_join::open_grant(
            &link,
            &PrivateKeyBytes::new(join.secret),
            &unhex(grant.ok_or(GasAppError::Malformed)?)?,
        )?;
        let uuid = access.channel_uuid();

        let (device_id, identity) = self.own_device()?;
        let info =
            self.api
                .member_channel_info(&device_id, &uuid, &DeviceSigner::new(&identity, now))?;

        if unhex(&info.verify_key)? != access.verify_key.as_bytes() {
            return Err(GasAppError::InvalidSignature);
        }

        let meta = access.open_meta(&unhex(&info.meta)?)?;

        let mut stored = new_stored(&access, None, &meta, now);
        // Одобрение и есть подписка: её оформил сервер.
        stored.closed = true;
        stored.subscribed = true;
        self.storage.insert_channel(&stored)?;

        // Записи — сразу, но их сбой входу не мешает.
        let _ = self.sync_stored(&stored, true, now);

        self.channel(&uuid)
    }

    /// Заявки, ждущие ответа, — для того, кто ведёт канал. Сетевой
    /// вызов.
    ///
    /// Заявка с подписью, которая не сходится, в список не попадает.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn channel_join_requests(
        &self,
        channel_id: &str,
        now: Timestamp,
    ) -> Result<Vec<ChannelJoinRequestInfo>> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let (device_id, identity) = self.own_device()?;
        let list = self.api.channel_join_requests(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &DeviceSigner::new(&identity, now),
        )?;

        let mut requests = Vec::with_capacity(list.len());

        for item in list {
            let Some(account_id) = canonical_account(&item.account_id) else {
                continue;
            };
            let Ok(request) = unhex(&item.request)
                .and_then(|wire| channel_join::open_request(&stored.channel_id, &wire))
            else {
                continue;
            };

            if !gasapp_types::is_canonical_username(&item.username) {
                continue;
            }

            let known_contact = self
                .storage
                .contact_identity_by_username(&item.username)?
                .is_some_and(|known| known == request.identity.as_bytes());

            requests.push(ChannelJoinRequestInfo {
                account_id,
                username: item.username,
                known_contact,
            });
        }

        Ok(requests)
    }

    /// Одобряет заявку — шифрует секрет чтения под её ключ — либо
    /// отклоняет.
    ///
    /// Заявка перечитывается с сервера и проверяется заново: секрет
    /// шифруется под ключ из заявки, а не под то, что прислал интерфейс.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::SessionNotFound`] — заявки уже нет;
    /// * [`GasAppError::InvalidSignature`] — подпись заявки не сходится;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn answer_channel_join<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        account_id: &str,
        approve: bool,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let account_id = canonical_account(account_id).ok_or(GasAppError::Malformed)?;
        let uuid = channel::format_uuid(&stored.channel_id);
        let (device_id, identity) = self.own_device()?;
        let signer = DeviceSigner::new(&identity, now);

        let grant = if approve {
            let list = self.api.channel_join_requests(&device_id, &uuid, &signer)?;
            let item = list
                .iter()
                .find(|item| canonical_account(&item.account_id).as_ref() == Some(&account_id))
                .ok_or(GasAppError::SessionNotFound)?;
            let request = channel_join::open_request(&stored.channel_id, &unhex(&item.request)?)?;

            Some(hex(&channel_join::seal_grant(
                &access_of(&stored),
                &request,
                rng,
            )?))
        } else {
            None
        };

        self.api.answer_channel_join(
            &device_id,
            &uuid,
            &AnswerChannelJoinRequest { account_id, grant },
            &signer,
        )
    }

    /// Подписчики канала — страницей после аккаунта `after`. Сетевой
    /// вызов; пустая страница — список кончился.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn channel_subscribers(
        &self,
        channel_id: &str,
        after: Option<&str>,
        now: Timestamp,
    ) -> Result<Vec<ChannelMember>> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let (device_id, identity) = self.own_device()?;

        Ok(members(self.api.channel_subscribers(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            after,
            &DeviceSigner::new(&identity, now),
        )?))
    }

    /// Удалённые из канала: кому можно вернуть право подать заявку.
    /// Сетевой вызов.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn channel_banned(&self, channel_id: &str, now: Timestamp) -> Result<Vec<ChannelMember>> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let (device_id, identity) = self.own_device()?;

        Ok(members(self.api.channel_bans(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &DeviceSigner::new(&identity, now),
        )?))
    }

    /// Удаляет подписчика из канала (`restore == false`): сервер больше
    /// не отдаёт ему записи и не принимает от него заявок. С
    /// `restore == true` — снимает этот запрет; подписчиком человек
    /// от этого не становится, он может снова подать заявку.
    ///
    /// ⚠️ Секрет чтения удалённый помнит — см. описание модуля.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Malformed`] — удаляют владельца либо
    ///   администратора;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn remove_channel_subscriber(
        &self,
        channel_id: &str,
        account_id: &str,
        restore: bool,
        now: Timestamp,
    ) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let (device_id, identity) = self.own_device()?;

        self.api.remove_channel_subscriber(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            account_id,
            restore,
            &DeviceSigner::new(&identity, now),
        )
    }
}
