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
//! 🔐 Удаление подписчика меняет ключ канала: заводится новая эпоха,
//! её ключ раздаётся оставшимся (каждому — под его ключ доставки), и
//! новые записи шифруются им. Удалённый сохраняет то, что уже мог
//! прочесть: записи до удаления, название и описание канала.

use gasapp_net::api::{
    AnswerChannelJoinRequest, ChannelEpochGrant, ChannelInviteRequest, ChannelMemberKeyRequest,
    ChannelMemberKeyResponse, ChannelMemberResponse, JoinChannelRequest, RekeyChannelRequest,
    UpdateChannelRequest,
};
use gasapp_net::client::Transport;
use gasapp_protocol::channel::{self, ChannelAccess, ChannelAdmin};
use gasapp_protocol::channel_join::{self, JoinLink};
use gasapp_storage::channels::{PendingJoin, StoredChannel};
use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::channels::{
    access_of, admins_of, new_stored, require_owner, role_of, Channel, ChannelRole,
};
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
        let channel_id = join.channel_id;
        let owner = PublicKeyBytes::new(join.verify_key);
        let (epoch, granted) = channel_join::open_grant(
            &channel_id,
            &owner,
            &PrivateKeyBytes::new(join.secret),
            &unhex(grant.ok_or(GasAppError::Malformed)?)?,
        )?;
        let uuid = granted.channel_uuid();

        let (device_id, identity) = self.own_device()?;
        let signer = DeviceSigner::new(&identity, now);
        let info = self.api.member_channel_info(&device_id, &uuid, &signer)?;

        if unhex(&info.verify_key)? != owner.as_bytes() {
            return Err(GasAppError::InvalidSignature);
        }

        // От ключа из ответа — по звеньям к нулевой эпохе: её секретом
        // открывается описание. Кто подписал звенья, сверяется ниже,
        // когда из описания известны администраторы.
        let records = if epoch == 0 {
            Vec::new()
        } else {
            self.api.channel_epochs(&device_id, &uuid, 0, &signer)?
        };
        let mut keys = Vec::new();
        let mut signers = Vec::new();
        let mut secret = granted.secret;

        for number in (1..=epoch).rev() {
            let record = records
                .iter()
                .find(|record| record.epoch == number)
                .ok_or(GasAppError::Malformed)
                .and_then(|record| unhex(&record.record))?;
            let signed_by = channel_join::epoch_signer(&record)?;
            let anyone = [ChannelAdmin {
                verify_key: signed_by,
                until: None,
            }];

            keys.push((number, secret));
            signers.push(signed_by);
            secret =
                channel_join::open_epoch(&channel_id, &owner, &anyone, number, &secret, &record)?;
        }

        let access = ChannelAccess {
            channel_id,
            secret,
            verify_key: owner,
        };
        let meta = access.open_meta(&unhex(&info.meta)?)?;

        // 🔐 Звенья обязан подписать тот, кто вёл канал.
        if signers.iter().any(|signed_by| {
            *signed_by != owner
                && !meta
                    .admins
                    .iter()
                    .any(|admin| admin.verify_key == *signed_by)
        }) {
            return Err(GasAppError::InvalidSignature);
        }

        let mut stored = new_stored(&access, None, &meta, now);
        // Одобрение и есть подписка: её оформил сервер.
        stored.closed = true;
        stored.subscribed = true;
        self.storage.insert_channel(&stored)?;

        for (number, key) in keys {
            self.storage.put_channel_key(&channel_id, number, &key)?;
        }

        // Ключ из заявки остаётся ключом доставки: под него придёт ключ
        // следующей эпохи. Серверу он уже известен — из самой заявки.
        self.storage
            .set_channel_delivery(&channel_id, &join.secret, true)?;

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

            // Заявителю уходит ключ действующей эпохи: до прежних он
            // дойдёт по звеньям цепочки.
            let (epoch, access) = self.writer_access(&stored, now)?;

            Some(hex(&channel_join::seal_epoch_grant(
                &access, epoch, &request, rng,
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
    /// 🔐 После удаления ключ канала меняется: новые записи удалённый
    /// не прочтёт, даже добыв их шифротекст. Записи, вышедшие до
    /// удаления, он читал и читать может. Если сменить ключ сразу не
    /// вышло (нет сети), смена остаётся долгом —
    /// [`Client::channel_rekey_pending`].
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал ведёт не этот человек;
    /// * [`GasAppError::Malformed`] — удаляют владельца либо
    ///   администратора;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn remove_channel_subscriber<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        account_id: &str,
        restore: bool,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;
        require_writer(&stored)?;

        let (device_id, identity) = self.own_device()?;
        let uuid = channel::format_uuid(&stored.channel_id);

        self.api.remove_channel_subscriber(
            &device_id,
            &uuid,
            account_id,
            restore,
            &DeviceSigner::new(&identity, now),
        )?;

        if !restore && stored.closed {
            // 🔐 Удалённый знает ключ чтения — ключ меняется. Долг
            // записывается до попытки: не вышло сейчас (нет сети) —
            // смену повторит ближайшее обслуживание каналов.
            self.set_setting_bool(&rekey_due(&uuid), true)?;

            if self.rekey_channel(&stored, now, rng).is_ok() {
                self.set_setting_bool(&rekey_due(&uuid), false)?;
            }
        }

        Ok(())
    }

    /// Ждёт ли канал смены ключа: подписчик удалён, а новый ключ ещё
    /// не заведён (не было сети). Пока это так, новые записи удалённый
    /// прочёл бы, добудь он их шифротекст.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID.
    pub fn channel_rekey_pending(&self, channel_id: &str) -> Result<bool> {
        let uuid = channel::format_uuid(&channel::parse_channel_id(channel_id)?);

        self.setting_bool(&rekey_due(&uuid), false)
    }

    /// Обслуживание закрытых каналов, которые человек ведёт: довести
    /// отложенную смену ключа и выдать ключ действующей эпохи тем
    /// участникам, у кого его нет (не было ключа доставки, сменили
    /// устройство). Вызывается после синхронизации.
    ///
    /// Сбой по одному каналу остальным не мешает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn maintain_channel_keys<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        for stored in self.storage.channels()? {
            if !stored.closed || require_writer(&stored).is_err() {
                continue;
            }

            let uuid = channel::format_uuid(&stored.channel_id);

            if self.setting_bool(&rekey_due(&uuid), false)?
                && self.rekey_channel(&stored, now, rng).is_ok()
            {
                self.set_setting_bool(&rekey_due(&uuid), false)?;
            }

            let _ = self.issue_missing_keys(&stored, now, rng);
        }

        Ok(())
    }

    /// Доступ с ключом действующей эпохи — под ним пишутся новые записи
    /// и шифруются ответы на заявки.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен либо ключа
    /// действующей эпохи у этого устройства ещё нет.
    pub(super) fn writer_access(
        &self,
        stored: &StoredChannel,
        now: Timestamp,
    ) -> Result<(u32, ChannelAccess)> {
        if !stored.closed {
            return Ok((0, access_of(stored)));
        }

        let (device_id, identity) = self.own_device()?;
        let server = self
            .api
            .member_channel_info(
                &device_id,
                &channel::format_uuid(&stored.channel_id),
                &DeviceSigner::new(&identity, now),
            )?
            .key_epoch;

        // 🔐 Писать ключом, который сменили, нельзя: он есть у удалённого.
        if !self.catch_up_keys(stored, server, now)? {
            return Err(GasAppError::Network);
        }

        self.epoch_access(stored, server)?
            .map(|access| (server, access))
            .ok_or(GasAppError::Storage)
    }

    /// Секрет ключа доставки этого устройства для канала.
    ///
    /// У того, кто ведёт канал, он выводится из ключа подписи (и потому
    /// переживает восстановление из копии); у читателя — из ключа
    /// аккаунта. Вошедший по заявке пользуется ключом из заявки.
    fn delivery_secret(&self, stored: &StoredChannel) -> Result<([u8; 32], bool)> {
        if let Some(known) = self.storage.channel_delivery(&stored.channel_id)? {
            return Ok(known);
        }

        let (_, identity) = self.own_device()?;
        let source = stored
            .signing_key
            .unwrap_or(*identity.private().expose_secret());
        let secret =
            *channel_join::delivery_secret(&stored.channel_id, &PrivateKeyBytes::new(source))?
                .expose_secret();

        self.storage
            .set_channel_delivery(&stored.channel_id, &secret, false)?;

        Ok((secret, false))
    }

    /// Доводит локальные ключи до эпохи `server`. Возвращает, есть ли
    /// теперь ключ этой эпохи.
    ///
    /// Заодно называет серверу ключ доставки, если он ещё не назван.
    /// Нет ответа с ключом — не ошибка: его выдаст тот, кто ведёт
    /// канал, когда выйдет в сеть.
    pub(super) fn catch_up_keys(
        &self,
        stored: &StoredChannel,
        server: u32,
        now: Timestamp,
    ) -> Result<bool> {
        let id = &stored.channel_id;
        let uuid = channel::format_uuid(id);
        let owner = PublicKeyBytes::new(stored.verify_key);
        let (secret, sent) = self.delivery_secret(stored)?;
        let (device_id, identity) = self.own_device()?;
        let signer = DeviceSigner::new(&identity, now);
        let local = self.storage.channel_key_epoch(id)?;

        let granted = if local < server || !sent {
            self.api
                .channel_join_status(&device_id, &uuid, &signer)
                .ok()
                .and_then(|status| status.grant)
                .and_then(|grant| unhex(&grant).ok())
                .and_then(|grant| {
                    channel_join::open_grant(id, &owner, &PrivateKeyBytes::new(secret), &grant).ok()
                })
        } else {
            None
        };

        if !sent {
            // Ответ под этот ключ уже лежит на сервере — значит, ключ
            // серверу известен (вход по заявке, восстановление из копии).
            // Иначе ключ называется сейчас.
            if granted.is_none() {
                let wire = channel_join::request_wire(
                    id,
                    &PrivateKeyBytes::new(*identity.private().expose_secret()),
                    &PrivateKeyBytes::new(secret),
                )?;

                self.api.set_channel_member_key(
                    &device_id,
                    &uuid,
                    &ChannelMemberKeyRequest {
                        member_key: hex(&wire),
                    },
                    &signer,
                )?;
            }

            self.storage.set_channel_delivery(id, &secret, true)?;
        }

        if local >= server {
            return Ok(true);
        }

        let Some((epoch, access)) = granted.filter(|(epoch, _)| *epoch > local) else {
            return Ok(false);
        };

        // От нового ключа — по звеньям назад, до уже известного. Последнее
        // звено обязано привести ровно к нему: иначе это не продолжение
        // нашей цепочки.
        let records = self.api.channel_epochs(&device_id, &uuid, local, &signer)?;
        let admins = admins_of(stored);
        let mut keys = Vec::new();
        let mut current = access.secret;

        for number in (local.saturating_add(1)..=epoch).rev() {
            let record = records
                .iter()
                .find(|record| record.epoch == number)
                .ok_or(GasAppError::Malformed)
                .and_then(|record| unhex(&record.record))?;

            keys.push((number, current));
            current = channel_join::open_epoch(id, &owner, &admins, number, &current, &record)?;
        }

        let known = self
            .epoch_access(stored, local)?
            .ok_or(GasAppError::Storage)?
            .secret;

        if current != known {
            return Err(GasAppError::InvalidSignature);
        }

        for (number, key) in keys {
            self.storage.put_channel_key(id, number, &key)?;
        }

        Ok(epoch >= server)
    }

    /// Ответы с ключом эпохи `epoch` для страницы участников. Ключ
    /// доставки с подписью, которая не сходится, пропускается.
    fn seal_keys<R: RngCore + CryptoRng>(
        stored: &StoredChannel,
        access: &ChannelAccess,
        epoch: u32,
        members: &[ChannelMemberKeyResponse],
        rng: &mut R,
    ) -> Vec<ChannelEpochGrant> {
        members
            .iter()
            .filter_map(|member| {
                let request = unhex(&member.member_key)
                    .and_then(|wire| channel_join::open_request(&stored.channel_id, &wire))
                    .ok()?;
                let grant = channel_join::seal_epoch_grant(access, epoch, &request, rng).ok()?;

                Some(ChannelEpochGrant {
                    account_id: canonical_account(&member.account_id)?,
                    grant: hex(&grant),
                })
            })
            .collect()
    }

    /// Меняет ключ канала: новая эпоха, звено к прежней и ключ каждому
    /// оставшемуся участнику — под его ключ доставки.
    ///
    /// «Эпоха не та» от сервера — ключ только что сменил кто-то ещё:
    /// этого достаточно, вторая смена подряд не нужна.
    fn rekey_channel<R: RngCore + CryptoRng>(
        &self,
        stored: &StoredChannel,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        require_writer(stored)?;

        let signing_key = stored.signing_key.ok_or(GasAppError::Forbidden)?;
        let (current, access) = self.writer_access(stored, now)?;
        let epoch = current.checked_add(1).ok_or(GasAppError::Malformed)?;
        let uuid = channel::format_uuid(&stored.channel_id);
        let (device_id, identity) = self.own_device()?;
        let signer = DeviceSigner::new(&identity, now);

        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        let record = channel_join::seal_epoch(
            &stored.channel_id,
            epoch,
            &secret,
            &access.secret,
            PrivateKeyBytes::new(signing_key),
            rng,
        )?;
        let next = ChannelAccess {
            channel_id: stored.channel_id,
            secret,
            verify_key: access.verify_key,
        };

        // Первая страница участников уходит вместе с новой эпохой —
        // среди них и это устройство: его ключ доставки назван выше.
        let mut members = self
            .api
            .channel_member_keys(&device_id, &uuid, false, None, &signer)?;

        let started = self.api.rekey_channel(
            &device_id,
            &uuid,
            &RekeyChannelRequest {
                epoch,
                record: Some(hex(&record)),
                grants: Self::seal_keys(stored, &next, epoch, &members, rng),
            },
            &signer,
        );

        match started {
            Ok(()) => {}
            Err(GasAppError::UsernameTaken) => return Ok(()),
            Err(error) => return Err(error),
        }

        self.storage
            .put_channel_key(&stored.channel_id, epoch, &secret)?;

        // Остальные страницы — досылкой.
        while let Some(last) = members.last().map(|member| member.account_id.clone()) {
            members =
                self.api
                    .channel_member_keys(&device_id, &uuid, false, Some(&last), &signer)?;

            if members.is_empty() {
                break;
            }

            self.api.rekey_channel(
                &device_id,
                &uuid,
                &RekeyChannelRequest {
                    epoch,
                    record: None,
                    grants: Self::seal_keys(stored, &next, epoch, &members, rng),
                },
                &signer,
            )?;
        }

        Ok(())
    }

    /// Выдаёт ключ действующей эпохи участникам, у которых его нет.
    fn issue_missing_keys<R: RngCore + CryptoRng>(
        &self,
        stored: &StoredChannel,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let uuid = channel::format_uuid(&stored.channel_id);
        let (device_id, identity) = self.own_device()?;
        let signer = DeviceSigner::new(&identity, now);

        let members = self
            .api
            .channel_member_keys(&device_id, &uuid, true, None, &signer)?;

        if members.is_empty() {
            return Ok(());
        }

        let (epoch, access) = self.writer_access(stored, now)?;

        self.api.rekey_channel(
            &device_id,
            &uuid,
            &RekeyChannelRequest {
                epoch,
                record: None,
                grants: Self::seal_keys(stored, &access, epoch, &members, rng),
            },
            &signer,
        )
    }
}

/// Настройка «канал ждёт смены ключа».
fn rekey_due(uuid: &str) -> String {
    format!("channel.rekey_due.{uuid}")
}
