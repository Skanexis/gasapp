// SPDX-License-Identifier: Apache-2.0

//! Каналы: создать, вести, читать.
//!
//! Криптография — в `gasapp_protocol::channel`, там же честный список
//! того, чего канал не даёт. Здесь — связка с сервером и базой:
//!
//! * **создать** канал может только аккаунт с премиумом; право
//!   проверяет сервер, а премиум выдаёт оператор вручную;
//! * **читать** может любой, у кого есть ссылка: записи забираются без
//!   подписи запроса, и сервер не знает, кто читает;
//! * **вести** — писать записи с текстом и медиа, править, удалять,
//!   закреплять, менять название и аватар, дать каналу публичное
//!   `@имя` — может только автор: у него ключ подписи;
//! * **подписка** — от имени аккаунта, за подписью устройства: один
//!   аккаунт — один подписчик. Так счётчик подписчиков, просмотры
//!   и реакции нельзя накрутить; цена — сервер знает, на какие каналы
//!   подписан аккаунт (ADR-035). Читать канал по ссылке можно и без
//!   подписки: записи забираются без подписи запроса.
//!
//! * **закрытый канал** читают только участники: его записи
//!   забираются **за подписью** устройства, а входят в него по
//!   одобренной заявке (`channel_closed`).
//!
//! 🔐 Счётчики — подписчики, просмотры, реакции — это слова сервера,
//! ничем не подписанные. Интерфейс показывает их как статистику,
//! а не как факт.

use gasapp_media::descriptor::{AttachmentDescriptor, AttachmentKind};
use gasapp_net::api::{
    AddChannelAdminRequest, ChannelPostResponse, ChannelReactRequest, ChannelResponse,
    ChannelSeenRequest, CreateChannelRequest, PublishPostRequest, RemoveChannelAdminRequest,
    ReplacePostRequest, UpdateChannelRequest,
};
use gasapp_net::client::Transport;
use gasapp_protocol::channel::{
    self, AdminRequest, ChannelAccess, ChannelAdmin, ChannelAuthor, ChannelId, ChannelMeta,
    ChannelPost, ChannelTombstone,
};
use gasapp_protocol::keys::IdentityKeyPair;
use gasapp_storage::channels::{PostChange, StoredAdmin, StoredChannel, StoredMeta, StoredPost};
use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{hex, open_file, seal_file, unhex, AttachmentFile, Client, DeviceSigner};

/// Сколько записей запрашивается у сервера за один раз.
const PAGE: u32 = 100;

/// Сколько страниц изменений забирается за одну синхронизацию канала.
///
/// Предел нужен, чтобы канал с десятками тысяч записей не превращал
/// открытие экрана в минуты загрузки через Tor: остальное доедет при
/// следующей синхронизации.
const MAX_PAGES_PER_SYNC: u32 = 5;

/// У скольких свежих записей обновляются счётчики при открытии канала.
const COUNTERS_PAGE: u32 = 50;

/// Предел файла в канале, в байтах открытого содержимого.
///
/// Сервер принимает блоб до 32 МБ; дополнение Padmé добавляет до 12 %,
/// теги чанков — доли процента. 24 МБ укладываются с запасом.
pub const MAX_CHANNEL_MEDIA_BYTES: u64 = 24 * 1024 * 1024;

/// Предел шифроблоба на сервере.
const MAX_CHANNEL_BLOB_BYTES: usize = 32 * 1024 * 1024;

/// Предел имени файла в записи канала, в знаках.
///
/// Короче, чем в переписке: описание вложения обязано уложиться
/// в килобайт (`channel::MAX_ATTACHMENT_DESCRIPTOR_BYTES`).
const MAX_CHANNEL_FILE_NAME_CHARS: usize = 100;

/// Реакции, которые принимает сервер. Набор закрыт: произвольная
/// строка была бы способом писать в чужой канал.
pub const CHANNEL_REACTIONS: [&str; 8] = ["👍", "❤️", "🔥", "😂", "😮", "😢", "👏", "🎉"];

/// Наибольшее число от сервера, которое вмещает локальная база.
const MAX_COUNTER: u64 = i64::MAX.unsigned_abs();

/// Предел строки реакций от сервера: восемь эмодзи со счётчиками.
const MAX_REACTIONS_TEXT: usize = 256;

/// Канал в том виде, в каком его показывает интерфейс.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// Идентификатор, UUID.
    pub channel_id: String,
    /// Название.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Кто человек в этом канале.
    pub role: ChannelRole,
    /// Сколько записей ещё не прочитано.
    pub unread: u64,
    /// Текст последней записи — для списка.
    pub last_post: Option<String>,
    /// Время последней записи по часам автора.
    pub last_post_at: Option<Timestamp>,
    /// Сколько вложений у последней записи.
    pub last_post_attachments: u32,
    /// Публичное `@имя` — со слов сервера.
    pub handle: Option<String>,
    /// Число подписчиков — со слов сервера.
    pub subscribers: u64,
    /// «Без звука»: непрочитанное не идёт в общий счётчик.
    pub muted: bool,
    /// Номер закреплённой записи; `0` — закрепа нет.
    pub pinned_seq: u64,
    /// Описание вложения с аватаром — для [`Client::fetch_channel_media`].
    pub avatar: Option<Vec<u8>>,
    /// Закрытый ли канал: вход по одобренной заявке, записи — только
    /// участникам.
    pub closed: bool,
}

/// Вложение записи канала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAttachment {
    /// Описание как есть — для [`Client::fetch_channel_media`].
    pub descriptor: Vec<u8>,
    /// Тип вложения.
    pub kind: AttachmentKind,
    /// Размер открытого файла.
    pub size: u64,
    /// Имя файла, если автор его передал.
    pub name: Option<String>,
}

/// Реакция со счётчиком.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReaction {
    /// Эмодзи из [`CHANNEL_REACTIONS`].
    pub emoji: String,
    /// Сколько подписчиков её поставили — со слов сервера.
    pub count: u64,
}

/// Запись канала для интерфейса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEntry {
    /// Номер записи.
    pub seq: u64,
    /// Текст.
    pub text: String,
    /// Время публикации по часам автора.
    pub created_at: Timestamp,
    /// Время последней правки, если запись правили.
    pub edited_at: Option<Timestamp>,
    /// Просмотры — со слов сервера.
    pub views: u64,
    /// Реакции — со слов сервера.
    pub reactions: Vec<ChannelReaction>,
    /// Своя реакция.
    pub my_reaction: Option<String>,
    /// Вложения.
    pub attachments: Vec<ChannelAttachment>,
}

/// Администратор канала глазами владельца.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAdminInfo {
    /// Публичный ключ подписи, hex, — им администратора снимают.
    pub verify_key: String,
    /// Имя, которым владелец его подписал; пусто — не подписал.
    pub label: String,
    /// Действующий ли: снятый остаётся в списке, чтобы его прежние
    /// записи читались.
    pub active: bool,
}

impl Channel {
    /// Владелец ли человек канала: описание, закреп, аватар, имя,
    /// состав администраторов и удаление канала — только его.
    #[must_use]
    pub fn owned(&self) -> bool {
        self.role == ChannelRole::Owner
    }

    /// Можно ли писать, править и удалять записи.
    #[must_use]
    pub fn can_post(&self) -> bool {
        matches!(self.role, ChannelRole::Owner | ChannelRole::Admin)
    }

    /// Заявка на администрирование показана, но ключа человека в
    /// списке администраторов (пока или уже) нет.
    #[must_use]
    pub fn admin_pending(&self) -> bool {
        self.role == ChannelRole::Pending
    }
}

/// Кто человек в канале.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    /// Читает.
    Reader,
    /// Завёл ключ и показал заявку, но владелец его не назначил либо
    /// уже снял.
    Pending,
    /// Назначен владельцем: пишет, правит, удаляет записи.
    Admin,
    /// Владелец: его ключ лежит в ссылке канала.
    Owner,
}

pub(super) fn role_of(stored: &StoredChannel) -> ChannelRole {
    let Some(key) = stored.signing_key else {
        return ChannelRole::Reader;
    };
    let Ok(verify_key) = channel::verify_key_of(PrivateKeyBytes::new(key)) else {
        return ChannelRole::Reader;
    };

    if *verify_key.as_bytes() == stored.verify_key {
        ChannelRole::Owner
    } else if stored
        .admins
        .iter()
        .any(|admin| admin.verify_key == *verify_key.as_bytes() && admin.until.is_none())
    {
        ChannelRole::Admin
    } else {
        ChannelRole::Pending
    }
}

/// Список администраторов в том виде, в каком его проверяет протокол.
fn admins_of(stored: &StoredChannel) -> Vec<ChannelAdmin> {
    stored
        .admins
        .iter()
        .map(|admin| ChannelAdmin {
            verify_key: PublicKeyBytes::new(admin.verify_key),
            until: admin.until,
        })
        .collect()
}

/// Описание канала в том виде, в каком его хранит база.
fn stored_meta(meta: &ChannelMeta) -> StoredMeta {
    StoredMeta {
        title: meta.title.clone(),
        description: meta.description.clone(),
        pinned_seq: meta.pinned,
        avatar: (!meta.avatar.is_empty()).then(|| meta.avatar.clone()),
        admins: meta
            .admins
            .iter()
            .map(|admin| StoredAdmin {
                verify_key: *admin.verify_key.as_bytes(),
                until: admin.until,
            })
            .collect(),
        updated_at: meta.updated_at_millis,
    }
}

/// Предел имени администратора, в знаках.
const MAX_ADMIN_LABEL_CHARS: usize = 64;

/// Сколько раз публикация берёт следующий номер, если прежний заняли.
const PUBLISH_ATTEMPTS: u32 = 4;

/// Публичный канал, найденный по имени, — до подписки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPreview {
    /// Ссылка-приглашение: с ней канал добавляется.
    pub link: String,
    /// Идентификатор, UUID.
    pub channel_id: String,
    /// Название — расшифрованное и проверенное подписью автора.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Публичное имя.
    pub handle: String,
    /// Число подписчиков — со слов сервера.
    pub subscribers: u64,
    /// Есть ли канал уже на этом устройстве.
    pub joined: bool,
}

pub(super) fn access_of(stored: &StoredChannel) -> ChannelAccess {
    ChannelAccess {
        channel_id: stored.channel_id,
        secret: stored.secret,
        verify_key: PublicKeyBytes::new(stored.verify_key),
    }
}

pub(super) fn parse_id(channel_id: &str) -> Result<ChannelId> {
    channel::parse_channel_id(channel_id)
}

/// Разбирает строку реакций сервера `эмодзи:число,…`.
///
/// 🔐 Строка приходит от сервера и попадает в интерфейс: принимаются
/// только эмодзи из закрытого набора, всё прочее отбрасывается.
fn parse_reactions(text: &str) -> Vec<ChannelReaction> {
    if text.len() > MAX_REACTIONS_TEXT {
        return Vec::new();
    }

    text.split(',')
        .filter_map(|item| {
            let (emoji, count) = item.rsplit_once(':')?;
            let count: u64 = count.parse().ok()?;

            (count > 0 && CHANNEL_REACTIONS.contains(&emoji)).then(|| ChannelReaction {
                emoji: emoji.to_owned(),
                count,
            })
        })
        .collect()
}

fn entry_of(post: StoredPost) -> ChannelEntry {
    ChannelEntry {
        seq: post.seq,
        text: post.text,
        created_at: post.created_at,
        edited_at: (post.edited_at != 0).then(|| Timestamp::from_millis(post.edited_at)),
        views: post.views,
        reactions: parse_reactions(&post.reactions),
        my_reaction: (!post.my_reaction.is_empty()).then_some(post.my_reaction),
        // Описание, которое не разбирается, не показывается: открыть
        // по нему всё равно нечего.
        attachments: post
            .attachments
            .into_iter()
            .filter_map(|descriptor| {
                let parsed = AttachmentDescriptor::from_bytes(&descriptor).ok()?;

                Some(ChannelAttachment {
                    descriptor,
                    kind: parsed.kind,
                    size: parsed.size,
                    name: parsed.name,
                })
            })
            .collect(),
    }
}

/// Тот, кто пишет в канал, с ключом подписи из базы — владелец либо
/// действующий администратор.
///
/// Ключ без права (заявка не принята, администратор снят) автора не
/// даёт: подписанное им читатели всё равно отвергли бы.
fn author_of<'a>(access: &'a ChannelAccess, stored: &StoredChannel) -> Result<ChannelAuthor<'a>> {
    if !matches!(role_of(stored), ChannelRole::Owner | ChannelRole::Admin) {
        return Err(GasAppError::Forbidden);
    }

    let signing_key = stored.signing_key.ok_or(GasAppError::Forbidden)?;

    ChannelAuthor::new(access, PrivateKeyBytes::new(signing_key))
}

/// Отказ всем, кроме владельца канала.
pub(super) fn require_owner(stored: &StoredChannel) -> Result<()> {
    if role_of(stored) == ChannelRole::Owner {
        Ok(())
    } else {
        Err(GasAppError::Forbidden)
    }
}

impl<T: Transport> Client<T> {
    /// Спрашивает сервер, есть ли у аккаунта премиум.
    ///
    /// Ответ нужен интерфейсу, чтобы показать «Создать канал». Права он
    /// не даёт: сервер проверяет премиум при создании сам.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn refresh_premium(&self, now: Timestamp) -> Result<bool> {
        let (device_id, identity) = self.own_device()?;
        let status = self
            .api
            .account_status(&device_id, &DeviceSigner::new(&identity, now))?;

        // Последний известный ответ сохраняется: без сети интерфейс
        // показывает то, что было, а не прячет кнопку.
        self.set_setting_bool(PREMIUM_SETTING, status.premium)?;

        Ok(status.premium)
    }

    /// Последний известный ответ сервера о премиуме — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn premium_cached(&self) -> Result<bool> {
        self.setting_bool(PREMIUM_SETTING, false)
    }

    /// Создаёт канал. Только для аккаунта с премиумом.
    ///
    /// Ключи канала сохраняются **до** запроса к серверу: канал,
    /// созданный на сервере, но не записанный здесь, остался бы без
    /// автора навсегда — ключ подписи есть только на этом устройстве.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — у аккаунта нет премиума;
    /// * [`GasAppError::Malformed`] — название пустое либо слишком длинное;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn create_channel<R: RngCore + CryptoRng>(
        &self,
        title: &str,
        description: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Channel> {
        let title = title.trim();
        let description = description.trim();
        channel::validate_meta(title, description)?;

        let (device_id, identity) = self.own_device()?;
        let created = channel::create(rng);
        let signing_key = *created.signing_key.expose_secret();

        let meta = ChannelMeta {
            title: title.to_owned(),
            description: description.to_owned(),
            updated_at_millis: now.as_millis(),
            pinned: 0,
            avatar: Vec::new(),
            admins: Vec::new(),
        };
        let sealed_meta =
            ChannelAuthor::new(&created.access, created.signing_key)?.seal_meta(&meta, rng)?;

        let stored = new_stored(&created.access, Some(signing_key), &meta, now);
        self.storage.insert_channel(&stored)?;

        let request = CreateChannelRequest {
            channel_id: created.access.channel_uuid(),
            verify_key: hex(created.access.verify_key.as_bytes()),
            meta: hex(&sealed_meta),
        };

        if let Err(error) =
            self.api
                .create_channel(&device_id, &request, &DeviceSigner::new(&identity, now))
        {
            // Сервер канал не принял — локальная заготовка не нужна.
            // При сбое сети она тоже убирается: человек повторит
            // создание, и канал получит новые ключи.
            self.storage.delete_channel(&stored.channel_id)?;

            if matches!(error, GasAppError::Forbidden) {
                self.set_setting_bool(PREMIUM_SETTING, false)?;
            }

            return Err(error);
        }

        // Автор — тоже подписчик своего канала. Сбой не мешает: жетон
        // оформится при следующей синхронизации.
        let _ = self.ensure_subscribed(&stored, now);

        self.present(&self.stored_channel(&created.access.channel_uuid())?)
    }

    /// Добавляет канал по ссылке-приглашению и забирает его записи.
    ///
    /// 🔐 Ключ подписи автора берётся **из ссылки**, а не с сервера:
    /// сервер, назвавший другой ключ, отвергается. Иначе он подменил бы
    /// автора при первом же открытии канала.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — не ссылка на канал;
    /// * [`GasAppError::SessionNotFound`] — канала нет (удалён);
    /// * [`GasAppError::InvalidSignature`] — сервер отдаёт канал с другим
    ///   ключом автора либо описание подписано не автором;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn join_channel(&self, link: &str, now: Timestamp) -> Result<Channel> {
        let access = ChannelAccess::parse(link)?;

        if let Some(known) = self.storage.channel(&access.channel_id)? {
            // Канал уже есть — та же ссылка открывает его, а не заводит
            // второй раз.
            return self.present(&known);
        }

        let info = self.api.channel_info(&access.channel_uuid())?;

        if unhex(&info.verify_key)? != access.verify_key.as_bytes() {
            return Err(GasAppError::InvalidSignature);
        }

        let meta = access.open_meta(&unhex(&info.meta)?)?;

        let stored = new_stored(&access, None, &meta, now);
        self.storage.insert_channel(&stored)?;

        // Записи и подписка — сразу, но их сбой добавлению не мешает:
        // канал уже здесь, остальное доедет при следующей синхронизации.
        let _ = self.ensure_subscribed(&stored, now);
        let _ = self.sync_stored(&stored, true, now);

        self.present(&self.stored_channel(&access.channel_uuid())?)
    }

    /// Каналы на этом устройстве — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channels(&self) -> Result<Vec<Channel>> {
        self.storage
            .channels()?
            .iter()
            .map(|stored| self.present(stored))
            .collect()
    }

    /// Один канал — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn channel(&self, channel_id: &str) -> Result<Channel> {
        self.present(&self.stored_channel(channel_id)?)
    }

    /// Сколько непрочитанных записей во всех каналах, кроме тех, что
    /// «без звука».
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn unread_channel_posts(&self) -> Result<u64> {
        self.storage.count_unread_channel_posts()
    }

    /// Ссылка-приглашение канала — чтобы поделиться им.
    ///
    /// 🔐 Ссылка и есть доступ: кто её получил, читает весь канал.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn channel_link(&self, channel_id: &str) -> Result<String> {
        Ok(access_of(&self.stored_channel(channel_id)?).to_uri())
    }

    /// Забирает изменения канала с сервера: новые записи, правки,
    /// удаления, описание и свежие счётчики.
    ///
    /// Возвращает число новых записей. Запись, не прошедшая проверку
    /// (подпись не автора, чужой номер), пропускается и не сохраняется.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет на устройстве
    ///   либо он удалён с сервера;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn sync_channel(&self, channel_id: &str, now: Timestamp) -> Result<u32> {
        self.sync_stored(&self.stored_channel(channel_id)?, true, now)
    }

    /// Синхронизирует все каналы; возвращает число новых записей.
    ///
    /// Счётчики здесь не обновляются: это фоновый обход, и лишний
    /// запрос на каждый канал через Tor в нём ни к чему. Сбой одного
    /// канала (удалён, сеть оборвалась) остальным не мешает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn sync_channels(&self, now: Timestamp) -> Result<u32> {
        let mut fresh = 0u32;

        for stored in self.storage.channels()? {
            if let Ok(count) = self.sync_stored(&stored, false, now) {
                fresh = fresh.saturating_add(count);
            }
        }

        Ok(fresh)
    }

    /// Сведения о канале: открытого — без подписи, закрытого — за
    /// подписью, как участнику.
    ///
    /// Канал, который числится открытым, но без подписи не находится,
    /// спрашивается ещё раз как закрытый: владелец мог его закрыть, а
    /// канал из резервной копии признака не несёт.
    fn feed_info(&self, stored: &StoredChannel, now: Timestamp) -> Result<ChannelResponse> {
        let uuid = channel::format_uuid(&stored.channel_id);

        if !stored.closed {
            match self.api.channel_info(&uuid) {
                Err(GasAppError::SessionNotFound) => {}
                other => return other,
            }
        }

        let (device_id, identity) = self.own_device()?;

        self.api
            .member_channel_info(&device_id, &uuid, &DeviceSigner::new(&identity, now))
    }

    /// Страница ленты — см. [`Self::feed_info`].
    fn feed_page(
        &self,
        stored: &StoredChannel,
        before_seq: Option<u64>,
        limit: u32,
        now: Timestamp,
    ) -> Result<Vec<ChannelPostResponse>> {
        let uuid = channel::format_uuid(&stored.channel_id);

        if !stored.closed {
            return self.api.channel_page(&uuid, before_seq, limit);
        }

        let (device_id, identity) = self.own_device()?;

        self.api.member_channel_page(
            &device_id,
            &uuid,
            before_seq,
            limit,
            &DeviceSigner::new(&identity, now),
        )
    }

    /// Изменения после ревизии — см. [`Self::feed_info`].
    fn feed_changes(
        &self,
        stored: &StoredChannel,
        after_rev: u64,
        now: Timestamp,
    ) -> Result<Vec<ChannelPostResponse>> {
        let uuid = channel::format_uuid(&stored.channel_id);

        if !stored.closed {
            return self.api.channel_changes(&uuid, after_rev, PAGE);
        }

        let (device_id, identity) = self.own_device()?;

        self.api.member_channel_changes(
            &device_id,
            &uuid,
            after_rev,
            PAGE,
            &DeviceSigner::new(&identity, now),
        )
    }

    pub(super) fn sync_stored(
        &self,
        stored: &StoredChannel,
        refresh_counters: bool,
        now: Timestamp,
    ) -> Result<u32> {
        let access = access_of(stored);

        let info = self.feed_info(stored, now)?;

        // 🔐 Канал с другим ключом автора — не тот канал.
        if unhex(&info.verify_key)? != stored.verify_key {
            return Err(GasAppError::InvalidSignature);
        }

        self.accept_info(stored, &access, &info)?;

        // 🔐 Записи проверяются по списку администраторов из только что
        // принятого описания, а не по тому, что был до синхронизации:
        // иначе запись снятого администратора прошла бы по старому списку.
        let stored = &self
            .storage
            .channel(&stored.channel_id)?
            .ok_or(GasAppError::SessionNotFound)?;

        let mut fresh = 0u32;

        if stored.last_rev == 0 {
            // Первая синхронизация: свежая страница ленты, а не вся
            // история с начала. Старое догружается по запросу
            // ([`Client::load_older_channel_posts`]).
            for item in self.feed_page(stored, None, PAGE, now)? {
                if self.apply_item(stored, &access, &item)? {
                    fresh = fresh.saturating_add(1);
                }
            }

            // Ревизия взята до страницы: изменение, случившееся между
            // двумя запросами, придёт ещё раз, но не потеряется.
            self.storage
                .set_channel_last_rev(&stored.channel_id, info.last_rev.min(MAX_COUNTER))?;
        } else {
            fresh = self.pull_changes(stored, &access, info.last_rev, now)?;

            if refresh_counters {
                // Просмотры и реакции ревизию не двигают — их несёт
                // свежая страница.
                for item in self.feed_page(stored, None, COUNTERS_PAGE, now)? {
                    self.apply_item(stored, &access, &item)?;
                }
            }
        }

        // Канал, который человек ведёт, прочитан им по определению.
        if matches!(role_of(stored), ChannelRole::Owner | ChannelRole::Admin) {
            let last = self
                .storage
                .channel(&stored.channel_id)?
                .map_or(stored.last_seq, |fresh| fresh.last_seq);

            self.storage.mark_channel_read(&stored.channel_id, last)?;
        }

        Ok(fresh)
    }

    /// Забирает изменения после известной ревизии.
    fn pull_changes(
        &self,
        stored: &StoredChannel,
        access: &ChannelAccess,
        server_rev: u64,
        now: Timestamp,
    ) -> Result<u32> {
        let mut after = stored.last_rev;
        let mut fresh = 0u32;

        for _ in 0..MAX_PAGES_PER_SYNC {
            if after >= server_rev {
                break;
            }

            let page = self.feed_changes(stored, after, now)?;
            let full = u32::try_from(page.len()).is_ok_and(|len| len >= PAGE);

            for item in &page {
                // Ревизии обязаны расти: сервер, отдающий старое, не
                // должен зациклить синхронизацию.
                if item.rev <= after || item.rev > MAX_COUNTER {
                    return Ok(fresh);
                }
                after = item.rev;

                if self.apply_item(stored, access, item)? {
                    fresh = fresh.saturating_add(1);
                }
            }

            self.storage
                .set_channel_last_rev(&stored.channel_id, after)?;

            if !full {
                break;
            }
        }

        Ok(fresh)
    }

    /// Принимает то, что сервер говорит о канале: описание (подписанное
    /// автором), публичное имя и число подписчиков (слова сервера).
    fn accept_info(
        &self,
        stored: &StoredChannel,
        access: &ChannelAccess,
        info: &ChannelResponse,
    ) -> Result<()> {
        // Описание: принимается только подписанное автором и не старше
        // известного (второе проверяет хранилище).
        if let Ok(meta) = unhex(&info.meta).and_then(|wire| access.open_meta(&wire)) {
            self.storage
                .update_channel_meta(&stored.channel_id, &stored_meta(&meta))?;
        }

        // 🔐 Имя — со слов сервера, и в интерфейс попадает только
        // каноничное: строчная латиница, цифры, подчёркивание.
        let handle = info
            .handle
            .as_deref()
            .and_then(|handle| gasapp_net::client::canonical_handle(handle).ok());

        self.storage.set_channel_server_info(
            &stored.channel_id,
            handle.as_deref(),
            info.subscribers.min(MAX_COUNTER),
        )?;

        // Закрытый ли канал — слова сервера: от них зависит только то,
        // каким запросом забирать записи.
        if info.closed != stored.closed {
            self.storage
                .set_channel_closed(&stored.channel_id, info.closed)?;
        }

        Ok(())
    }

    /// Проверяет и сохраняет одну запись сервера. Возвращает, новая ли
    /// это запись.
    fn apply_item(
        &self,
        stored: &StoredChannel,
        access: &ChannelAccess,
        item: &ChannelPostResponse,
    ) -> Result<bool> {
        let id = &stored.channel_id;
        let admins = admins_of(stored);

        // 🔐 Номер, которого не бывает (больше `i64::MAX`), база не
        // сохранит. Такая запись пропускается молча: иначе один мусорный
        // элемент от сервера обрывал бы синхронизацию и не давал дойти
        // настоящим записям, стоящим за ним.
        if item.seq > MAX_COUNTER {
            return Ok(false);
        }

        let Ok(body) = unhex(&item.body) else {
            self.storage.skip_channel_seq(id, item.seq)?;
            return Ok(false);
        };

        if item.deleted {
            // 🔐 Слову сервера «удалено» веры нет: запись исчезает
            // только по отметке, подписанной автором.
            match access.open_tombstone(&body, item.seq, &admins) {
                Ok(tombstone) => {
                    self.storage
                        .tombstone_channel_post(id, item.seq, tombstone.revision)?;
                }
                Err(_) => self.storage.skip_channel_seq(id, item.seq)?,
            }

            return Ok(false);
        }

        let Ok(post) = access.open_post(&body, item.seq, &admins) else {
            // Не от автора или не на своём месте — пропустить, но не
            // запрашивать снова при каждой синхронизации.
            self.storage.skip_channel_seq(id, item.seq)?;
            return Ok(false);
        };

        let change = self.storage.upsert_channel_post(
            id,
            &StoredPost {
                seq: item.seq,
                revision: post.revision,
                text: post.text,
                created_at: Timestamp::from_millis(post.created_at_millis),
                edited_at: post.edited_at_millis,
                deleted: false,
                views: 0,
                reactions: String::new(),
                my_reaction: String::new(),
                attachments: post.attachments,
            },
        )?;

        let reactions = if item.reactions.len() <= MAX_REACTIONS_TEXT {
            item.reactions.as_str()
        } else {
            ""
        };
        // Счётчик сервера обрезается до того, что вмещает база: число
        // «больше некуда» — не повод оборвать синхронизацию.
        self.storage.set_channel_post_counters(
            id,
            item.seq,
            item.views.min(MAX_COUNTER),
            reactions,
        )?;

        Ok(change == PostChange::Inserted)
    }

    /// Догружает страницу истории — записи старше самой старой из
    /// сохранённых. Возвращает, сколько записей добавилось; ноль —
    /// история кончилась.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет на устройстве;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn load_older_channel_posts(&self, channel_id: &str, now: Timestamp) -> Result<u32> {
        let stored = self.stored_channel(channel_id)?;
        let access = access_of(&stored);

        let Some(oldest) = self.storage.min_channel_seq(&stored.channel_id)? else {
            return Ok(0);
        };

        if oldest <= 1 {
            return Ok(0);
        }

        let mut added = 0u32;

        for item in self.feed_page(&stored, Some(oldest), PAGE, now)? {
            // Сервер обязан отдать записи старше границы: всё прочее —
            // не история.
            if item.seq < oldest && self.apply_item(&stored, &access, &item)? {
                added = added.saturating_add(1);
            }
        }

        Ok(added)
    }

    /// Последние записи канала — без сети, от старых к новым.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID;
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_posts(&self, channel_id: &str, limit: u32) -> Result<Vec<ChannelEntry>> {
        self.channel_posts_before(channel_id, u64::MAX, limit)
    }

    /// Записи канала старше номера `before_seq` — без сети, от старых
    /// к новым.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID;
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_posts_before(
        &self,
        channel_id: &str,
        before_seq: u64,
        limit: u32,
    ) -> Result<Vec<ChannelEntry>> {
        Ok(self
            .storage
            .channel_posts_before(&parse_id(channel_id)?, before_seq, limit)?
            .into_iter()
            .map(entry_of)
            .collect())
    }

    /// Запись по номеру — без сети. Удалённой или неизвестной нет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID;
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_post(&self, channel_id: &str, seq: u64) -> Result<Option<ChannelEntry>> {
        Ok(self
            .storage
            .channel_post(&parse_id(channel_id)?, seq)?
            .filter(|post| !post.deleted)
            .map(entry_of))
    }

    /// Ищет подстроку в сохранённых записях канала: свежие — первыми.
    ///
    /// Поиск локальный: сервер текста записей не знает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — идентификатор не UUID;
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn search_channel_posts(
        &self,
        channel_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<ChannelEntry>> {
        Ok(self
            .storage
            .search_channel_posts(&parse_id(channel_id)?, query.trim(), limit)?
            .into_iter()
            .map(entry_of)
            .collect())
    }

    /// Отмечает канал прочитанным до последней сохранённой записи —
    /// без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn mark_channel_read(&self, channel_id: &str) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;

        self.storage
            .mark_channel_read(&stored.channel_id, stored.last_seq)
    }

    /// Сообщает серверу, до какой записи канал прочитан: из этих
    /// отметок складываются просмотры.
    ///
    /// 🔐 Отметка идёт с жетоном подписчика, без подписи устройства.
    /// Без жетона (подписка не оформилась) не отправляется ничего.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет на устройстве;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn report_channel_seen(&self, channel_id: &str, now: Timestamp) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;

        if !stored.subscribed || stored.last_read_seq <= stored.seen_sent_seq {
            return Ok(());
        }

        let (device_id, identity) = self.own_device()?;

        self.api.mark_channel_seen(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &ChannelSeenRequest {
                seq: stored.last_read_seq,
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .set_channel_seen_sent(&stored.channel_id, stored.last_read_seq)
    }

    /// Публикует запись в своём канале: текст, вложения или и то и
    /// другое.
    ///
    /// Номер записи автор назначает сам — следующий за последним на
    /// сервере — и кладёт внутрь шифротекста: читатели сверяют его
    /// с номером сервера (см. `gasapp_protocol::channel`).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой: ключа подписи нет;
    /// * [`GasAppError::Malformed`] — запись пуста, слишком длинна,
    ///   вложений больше предела либо файл слишком велик;
    /// * [`GasAppError::InvalidSignature`] — сервер поставил запись под
    ///   другим номером (в канал одновременно писали с другого места);
    ///   читатели такую запись не примут;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn publish_channel_post<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        text: &str,
        files: &[AttachmentFile],
        now: Timestamp,
        rng: &mut R,
    ) -> Result<ChannelEntry> {
        let stored = self.stored_channel(channel_id)?;
        let access = access_of(&stored);
        let author = author_of(&access, &stored)?;
        let uuid = access.channel_uuid();
        let (device_id, identity) = self.own_device()?;

        let text = text.trim();

        // Проверка до загрузки файлов: пустая или слишком длинная
        // запись не должна стоить мегабайтов трафика.
        if files.len() > channel::MAX_POST_ATTACHMENTS
            || text.len() > channel::MAX_POST_BYTES
            || (text.is_empty() && files.is_empty())
        {
            return Err(GasAppError::Malformed);
        }

        let mut attachments = Vec::with_capacity(files.len());
        let published = (|| {
            for file in files {
                attachments.push(
                    self.upload_channel_media(&uuid, &device_id, &identity, file, now, rng)?
                        .to_bytes()?,
                );
            }

            // Номер записи лежит внутри шифротекста, и сервер принимает
            // запись только под ним. В канал пишут несколько человек:
            // если номер успели занять, берётся следующий, и запись
            // подписывается заново.
            for _ in 0..PUBLISH_ATTEMPTS {
                let number = self
                    .feed_info(&stored, now)?
                    .last_seq
                    .checked_add(1)
                    .ok_or(GasAppError::Malformed)?;

                let sealed = author.seal_post(
                    &ChannelPost {
                        number,
                        revision: 0,
                        created_at_millis: now.as_millis(),
                        edited_at_millis: 0,
                        text: text.to_owned(),
                        attachments: attachments.clone(),
                    },
                    rng,
                )?;

                let outcome = self.api.publish_channel_post(
                    &device_id,
                    &uuid,
                    &PublishPostRequest {
                        body: hex(&sealed),
                        seq: Some(number),
                    },
                    &DeviceSigner::new(&identity, now),
                );

                match outcome {
                    Ok(published) if published.seq == number => return Ok(number),
                    // Сервер поставил запись не туда, куда просили.
                    Ok(_) => return Err(GasAppError::InvalidSignature),
                    // Номер занят (`409`) — ещё раз, со следующим.
                    Err(GasAppError::UsernameTaken) => {}
                    Err(error) => return Err(error),
                }
            }

            Err(GasAppError::Network)
        })();

        let number = match published {
            Ok(number) => number,
            Err(error) => {
                // Запись не вышла — её файлы на сервере никому не нужны.
                self.drop_channel_media(&uuid, &device_id, &identity, &attachments, now);

                return Err(error);
            }
        };

        let post = StoredPost {
            seq: number,
            revision: 0,
            text: text.to_owned(),
            created_at: now,
            edited_at: 0,
            deleted: false,
            views: 0,
            reactions: String::new(),
            my_reaction: String::new(),
            attachments,
        };
        self.storage
            .upsert_channel_post(&stored.channel_id, &post)?;
        self.storage.mark_channel_read(&stored.channel_id, number)?;

        Ok(entry_of(post))
    }

    /// Исправляет текст записи своего канала. Вложения остаются.
    ///
    /// Читатели увидят пометку «изменено». Прежний текст остаётся
    /// у тех, кто успел его загрузить.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::SessionNotFound`] — записи нет либо она удалена;
    /// * [`GasAppError::Malformed`] — запись стала бы пустой либо
    ///   слишком длинной;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn edit_channel_post<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        seq: u64,
        text: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<ChannelEntry> {
        let stored = self.stored_channel(channel_id)?;
        let access = access_of(&stored);
        let author = author_of(&access, &stored)?;
        let (device_id, identity) = self.own_device()?;
        let known = self.live_post(&stored, seq)?;

        let edited = StoredPost {
            revision: known
                .revision
                .checked_add(1)
                .ok_or(GasAppError::Malformed)?,
            text: text.trim().to_owned(),
            // Время правки обязано быть ненулевым: ноль значит «не
            // правили».
            edited_at: now.as_millis().max(1),
            ..known
        };

        let sealed = author.seal_post(
            &ChannelPost {
                number: seq,
                revision: edited.revision,
                created_at_millis: edited.created_at.as_millis(),
                edited_at_millis: edited.edited_at,
                text: edited.text.clone(),
                attachments: edited.attachments.clone(),
            },
            rng,
        )?;

        self.api.replace_channel_post(
            &device_id,
            &access.channel_uuid(),
            &ReplacePostRequest {
                seq,
                body: hex(&sealed),
                deleted: false,
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .upsert_channel_post(&stored.channel_id, &edited)?;

        self.live_post(&stored, seq).map(entry_of)
    }

    /// Удаляет запись своего канала — подписанной отметкой, которую
    /// проверят читатели, — и её файлы с сервера.
    ///
    /// ⚠️ У тех, кто запись уже загрузил, она останется до следующей
    /// синхронизации, а в чужих копиях и снимках экрана — навсегда.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::SessionNotFound`] — записи нет либо она уже
    ///   удалена;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn delete_channel_post<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        seq: u64,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;
        let access = access_of(&stored);
        let author = author_of(&access, &stored)?;
        let uuid = access.channel_uuid();
        let (device_id, identity) = self.own_device()?;
        let known = self.live_post(&stored, seq)?;

        let revision = known
            .revision
            .checked_add(1)
            .ok_or(GasAppError::Malformed)?;
        let sealed = author.seal_tombstone(
            &ChannelTombstone {
                number: seq,
                revision,
                deleted_at_millis: now.as_millis(),
            },
            rng,
        )?;

        self.api.replace_channel_post(
            &device_id,
            &uuid,
            &ReplacePostRequest {
                seq,
                body: hex(&sealed),
                deleted: true,
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .tombstone_channel_post(&stored.channel_id, seq, revision)?;

        // Файлы записи и закреп — вслед за ней. Сбой удалению не
        // мешает: запись уже удалена, а блобы зашифрованы.
        self.drop_channel_media(&uuid, &device_id, &identity, &known.attachments, now);

        // Закреп — в описании канала, а его подписывает только владелец.
        if stored.pinned_seq == seq && role_of(&stored) == ChannelRole::Owner {
            let _ = self.write_meta(&stored, now, rng, |meta| meta.pinned = 0);
        }

        Ok(())
    }

    /// Закрепляет запись своего канала; `seq == 0` — снимает закреп.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::SessionNotFound`] — записи нет либо она удалена;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn pin_channel_post<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        seq: u64,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;

        if seq != 0 {
            self.live_post(&stored, seq)?;
        }

        self.write_meta(&stored, now, rng, |meta| meta.pinned = seq)
    }

    /// Меняет название и описание своего канала.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::Malformed`] — название пустое либо слишком длинное;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn update_channel<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        title: &str,
        description: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;

        self.write_meta(&stored, now, rng, |meta| {
            title.trim().clone_into(&mut meta.title);
            description.trim().clone_into(&mut meta.description);
        })
    }

    /// Ставит аватар своего канала; `None` — убирает.
    ///
    /// Картинка шифруется и загружается как медиа канала — так же, как
    /// фото в записи: метаданные снимка удаляются до шифрования.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::Malformed`] — файл слишком велик либо не
    ///   разбирается;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn set_channel_avatar<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        image: Option<&[u8]>,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;
        // Право — до загрузки: чужому каналу файл не шлётся.
        require_owner(&stored)?;

        let uuid = channel::format_uuid(&stored.channel_id);
        let (device_id, identity) = self.own_device()?;

        let avatar = match image {
            Some(bytes) => self
                .upload_channel_media(
                    &uuid,
                    &device_id,
                    &identity,
                    &AttachmentFile {
                        kind: AttachmentKind::Image,
                        bytes: bytes.to_vec(),
                        name: None,
                        description: None,
                        duration_millis: None,
                        waveform: None,
                    },
                    now,
                    rng,
                )?
                .to_bytes()?,
            None => Vec::new(),
        };

        let written = self.write_meta(&stored, now, rng, |meta| meta.avatar.clone_from(&avatar));

        // Нужен один блоб: при успехе лишний — прежний, при сбое — новый.
        let stale = match &written {
            Ok(_) => stored.avatar.clone().unwrap_or_default(),
            Err(_) => avatar,
        };
        if !stale.is_empty() {
            self.drop_channel_media(&uuid, &device_id, &identity, &[stale], now);
        }

        written
    }

    /// Делает свой канал публичным под именем `handle` либо, с `None`,
    /// снова закрытым.
    ///
    /// # 🔐 Цена публичности
    ///
    /// Чтобы канал находился по `@имени`, серверу отдаётся
    /// ссылка-приглашение, а с ней — ключ чтения. Публичный канал
    /// сервер читает; подделать записи по-прежнему не может. Закрытие
    /// канала ключ у сервера не отзывает: что он успел узнать, то знает.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — канал чужой;
    /// * [`GasAppError::Malformed`] — это не имя канала;
    /// * [`GasAppError::UsernameTaken`] — имя занято;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn set_channel_handle(
        &self,
        channel_id: &str,
        handle: Option<&str>,
        now: Timestamp,
    ) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;
        require_owner(&stored)?;

        let access = access_of(&stored);
        let (device_id, identity) = self.own_device()?;
        let handle = handle
            .map(gasapp_net::client::canonical_handle)
            .transpose()?;

        self.api.update_channel(
            &device_id,
            &access.channel_uuid(),
            &UpdateChannelRequest {
                meta: None,
                set_public: true,
                public_link: handle.as_ref().map(|_| access.to_uri()),
                handle: handle.clone(),
                closed: None,
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage.set_channel_server_info(
            &stored.channel_id,
            handle.as_deref(),
            stored.subscribers,
        )?;

        self.channel(channel_id)
    }

    /// Включает либо выключает «без звука» — без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn set_channel_muted(&self, channel_id: &str, muted: bool) -> Result<Channel> {
        let stored = self.stored_channel(channel_id)?;

        self.storage.set_channel_muted(&stored.channel_id, muted)?;

        self.channel(channel_id)
    }

    /// Ставит, меняет либо (с `None`) снимает свою реакцию на запись.
    ///
    /// 🔐 Реакция идёт с жетоном подписчика, без подписи устройства:
    /// сервер видит, что жетон отреагировал, но не чей он.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — эмодзи не из набора;
    /// * [`GasAppError::SessionNotFound`] — записи нет либо она удалена;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn react_to_channel_post(
        &self,
        channel_id: &str,
        seq: u64,
        emoji: Option<&str>,
        now: Timestamp,
    ) -> Result<ChannelEntry> {
        let stored = self.stored_channel(channel_id)?;
        let access = access_of(&stored);
        let uuid = access.channel_uuid();

        if emoji.is_some_and(|emoji| !CHANNEL_REACTIONS.contains(&emoji)) {
            return Err(GasAppError::Malformed);
        }

        self.live_post(&stored, seq)?;
        self.ensure_subscribed(&stored, now)?;
        let (device_id, identity) = self.own_device()?;

        self.api.react_to_channel_post(
            &device_id,
            &uuid,
            &ChannelReactRequest {
                seq,
                emoji: emoji.map(str::to_owned),
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .set_channel_post_reaction(&stored.channel_id, seq, emoji.unwrap_or(""))?;

        // Свежий счётчик — тем же заходом; его сбой реакции не отменяет.
        if let Ok(page) = self.feed_page(&stored, Some(seq.saturating_add(1)), 1, now) {
            for item in page.iter().filter(|item| item.seq == seq) {
                self.apply_item(&stored, &access, item)?;
            }
        }

        self.live_post(&stored, seq).map(entry_of)
    }

    /// Скачивает и расшифровывает медиа канала по описанию из записи
    /// либо из описания канала (аватар).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — описание не разбирается либо
    ///   длина блоба с ним не сходится;
    /// * [`GasAppError::SessionNotFound`] — блоба нет (запись удалена);
    /// * [`GasAppError::Crypto`] — блоб подменён;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn fetch_channel_media(
        &self,
        channel_id: &str,
        descriptor: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        let descriptor = AttachmentDescriptor::from_bytes(descriptor)?;

        if descriptor.size > MAX_CHANNEL_MEDIA_BYTES {
            return Err(GasAppError::Malformed);
        }

        let id = parse_id(channel_id)?;
        let uuid = channel::format_uuid(&id);

        // Закрытый канал отдаёт медиа только участнику — за подписью.
        // Канала может не быть на устройстве: так показывается аватар
        // публичного канала до подписки.
        let payload = if self
            .storage
            .channel(&id)?
            .is_some_and(|stored| stored.closed)
        {
            let (device_id, identity) = self.own_device()?;

            self.api.member_download_channel_media(
                &device_id,
                &uuid,
                &descriptor.location,
                &DeviceSigner::new(&identity, now),
            )?
        } else {
            self.api
                .download_channel_media(&uuid, &descriptor.location)?
        };

        open_file(&descriptor, &payload)
    }

    /// Публичный канал по точному `@имени` — до подписки.
    ///
    /// 🔐 Название и описание расшифровываются ключом из ссылки и
    /// проверяются подписью автора из неё же. Какую ссылку отдать по
    /// имени, решает сервер: имя — его пространство, и гарантии, что
    /// `@имя` ведёт к тому же каналу, что вчера, нет.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — это не имя канала;
    /// * [`GasAppError::SessionNotFound`] — такого канала нет;
    /// * [`GasAppError::InvalidSignature`] — ссылка сервера не сходится
    ///   с каналом, который он отдаёт;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn find_public_channel(&self, handle: &str) -> Result<ChannelPreview> {
        self.preview_of(&self.api.channel_by_handle(handle)?)
    }

    /// Публичные каналы, чьё `@имя` начинается с `query`.
    ///
    /// Поиск только по имени: названий сервер не знает. Канал, чья
    /// ссылка не проходит проверку, в выдачу не попадает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn search_public_channels(&self, query: &str) -> Result<Vec<ChannelPreview>> {
        Ok(self
            .api
            .search_channels(query)?
            .iter()
            .filter_map(|info| self.preview_of(info).ok())
            .collect())
    }

    fn preview_of(&self, info: &ChannelResponse) -> Result<ChannelPreview> {
        let link = info.public_link.as_deref().ok_or(GasAppError::Malformed)?;
        let handle = gasapp_net::client::canonical_handle(
            info.handle.as_deref().ok_or(GasAppError::Malformed)?,
        )?;
        let access = ChannelAccess::parse(link)?;

        // 🔐 Ссылка обязана вести к каналу, который отдан: иначе под
        // одним именем показывалось бы описание другого канала.
        if access.channel_uuid() != info.channel_id.to_ascii_lowercase()
            || unhex(&info.verify_key)? != access.verify_key.as_bytes()
        {
            return Err(GasAppError::InvalidSignature);
        }

        let meta = access.open_meta(&unhex(&info.meta)?)?;

        Ok(ChannelPreview {
            link: access.to_uri(),
            channel_id: access.channel_uuid(),
            title: meta.title,
            description: meta.description,
            handle,
            subscribers: info.subscribers,
            joined: self.storage.channel(&access.channel_id)?.is_some(),
        })
    }

    /// Заявка на администрирование — строка, которую читатель канала
    /// показывает владельцу (QR-кодом или текстом).
    ///
    /// При первом вызове заводит ключ подписи для этого канала; при
    /// следующих называет тот же. В заявке нет секретов: публичный
    /// ключ и устройство, которому сервер разрешит публиковать.
    ///
    /// 🔐 Заявка называет владельцу устройство и, тем самым, серверу —
    /// аккаунт администратора. Читатель канала серверу неизвестен;
    /// администратор — известен, как и владелец.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет на устройстве;
    /// * [`GasAppError::Malformed`] — человек и так владелец канала.
    pub fn channel_admin_request<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        rng: &mut R,
    ) -> Result<String> {
        let stored = self.stored_channel(channel_id)?;

        if role_of(&stored) == ChannelRole::Owner {
            return Err(GasAppError::Malformed);
        }

        if stored.signing_key.is_none() {
            let (signing_key, _) = channel::admin_keypair(rng);

            self.storage
                .set_channel_signing_key(&stored.channel_id, signing_key.expose_secret())?;
        }

        // Ключ читается из базы заново: показывается тот, что сохранён.
        let key = self
            .stored_channel(channel_id)?
            .signing_key
            .ok_or(GasAppError::Storage)?;
        let (device_id, _) = self.own_device()?;

        Ok(AdminRequest {
            channel_id: stored.channel_id,
            verify_key: channel::verify_key_of(PrivateKeyBytes::new(key))?,
            device_id: parse_id(&device_id)?,
        }
        .to_uri())
    }

    /// Назначает администратора своего канала по его заявке.
    ///
    /// Два шага: сервер начинает принимать записи от его аккаунта,
    /// и в описание канала, подписанное владельцем, вписывается его
    /// ключ — по нему записи принимают читатели. `label` — имя для
    /// владельца; в описание канала оно не попадает.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — человек не владелец канала;
    /// * [`GasAppError::Malformed`] — это не заявка, она в другой
    ///   канал, список администраторов полон либо владелец назначает
    ///   себя;
    /// * [`GasAppError::SessionNotFound`] — устройства из заявки нет;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn add_channel_admin<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        request: &str,
        label: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Vec<ChannelAdminInfo>> {
        let stored = self.stored_channel(channel_id)?;
        require_owner(&stored)?;

        let request = AdminRequest::parse(request)?;
        let key = *request.verify_key.as_bytes();
        let known = stored.admins.iter().any(|admin| admin.verify_key == key);

        if request.channel_id != stored.channel_id
            || key == stored.verify_key
            || (!known && stored.admins.len() >= channel::MAX_ADMINS)
        {
            return Err(GasAppError::Malformed);
        }

        let (device_id, identity) = self.own_device()?;

        self.api.add_channel_admin(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &AddChannelAdminRequest {
                device_id: channel::format_uuid(&request.device_id),
                verify_key: hex(&key),
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.write_meta(&stored, now, rng, |meta| {
            match meta
                .admins
                .iter_mut()
                .find(|admin| admin.verify_key == request.verify_key)
            {
                // Снятого назначают снова: граница убирается.
                Some(admin) => admin.until = None,
                None => meta.admins.push(ChannelAdmin {
                    verify_key: request.verify_key,
                    until: None,
                }),
            }
        })?;

        let label: String = label.trim().chars().take(MAX_ADMIN_LABEL_CHARS).collect();
        self.storage
            .set_channel_admin_label(&stored.channel_id, &key, &label)?;

        self.channel_admins(channel_id)
    }

    /// Снимает администратора своего канала.
    ///
    /// Сервер перестаёт принимать от него записи, а в описании канала
    /// его ключу ставится граница — номер последней записи на этот
    /// момент. Прежние его записи читаются; новые под его ключом
    /// читатели не примут, даже если сервер их отдаст.
    ///
    /// ⚠️ Снятый администратор в сговоре с сервером мог бы переписать
    /// записи, вышедшие до снятия: для их номеров его ключ остаётся
    /// годным (см. `gasapp_protocol::channel`).
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — человек не владелец канала;
    /// * [`GasAppError::SessionNotFound`] — такого администратора нет;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn remove_channel_admin<R: RngCore + CryptoRng>(
        &self,
        channel_id: &str,
        verify_key: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Vec<ChannelAdminInfo>> {
        let stored = self.stored_channel(channel_id)?;
        require_owner(&stored)?;

        let key: [u8; 32] = unhex(verify_key)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)?;

        if !stored.admins.iter().any(|admin| admin.verify_key == key) {
            return Err(GasAppError::SessionNotFound);
        }

        let uuid = channel::format_uuid(&stored.channel_id);
        let (device_id, identity) = self.own_device()?;

        // Сначала сервер: с этого момента новых записей от него нет,
        // и граница ниже не окажется позади его последней записи.
        self.api.remove_channel_admin(
            &device_id,
            &uuid,
            &RemoveChannelAdminRequest {
                verify_key: hex(&key),
            },
            &DeviceSigner::new(&identity, now),
        )?;

        let last_seq = self.feed_info(&stored, now)?.last_seq;

        self.write_meta(&stored, now, rng, |meta| {
            for admin in &mut meta.admins {
                if *admin.verify_key.as_bytes() == key && admin.until.is_none() {
                    admin.until = Some(last_seq);
                }
            }
        })?;

        self.channel_admins(channel_id)
    }

    /// Администраторы своего канала — действующие и снятые. Без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::SessionNotFound`] — канала нет на устройстве.
    pub fn channel_admins(&self, channel_id: &str) -> Result<Vec<ChannelAdminInfo>> {
        let stored = self.stored_channel(channel_id)?;
        let labels = self.storage.channel_admin_labels(&stored.channel_id)?;

        Ok(stored
            .admins
            .iter()
            .map(|admin| ChannelAdminInfo {
                verify_key: hex(&admin.verify_key),
                label: labels
                    .iter()
                    .find(|(key, _)| *key == admin.verify_key)
                    .map(|(_, label)| label.clone())
                    .unwrap_or_default(),
                active: admin.until.is_none(),
            })
            .collect())
    }

    /// Убирает канал с устройства; свой — удаляет и с сервера.
    ///
    /// Чужой канал перестаёт читаться, а его жетон подписчика снимается
    /// с сервера вместе с реакциями. Свой удаляется с сервера вместе со
    /// всеми записями — у читателей останется то, что они уже загрузили.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — свой канал не удалось удалить
    /// с сервера; на устройстве он при этом остаётся, чтобы не потерять
    /// ключ подписи от канала, который всё ещё существует.
    pub fn leave_channel(&self, channel_id: &str, now: Timestamp) -> Result<()> {
        let stored = self.stored_channel(channel_id)?;
        let uuid = channel::format_uuid(&stored.channel_id);

        // Удаляет канал с сервера только владелец; администратор, уходя,
        // просто перестаёт его читать.
        if role_of(&stored) == ChannelRole::Owner {
            let (device_id, identity) = self.own_device()?;
            let removed =
                self.api
                    .delete_channel(&device_id, &uuid, &DeviceSigner::new(&identity, now));

            // «Не найден» — канал уже удалён с сервера: это и есть цель.
            match removed {
                Ok(()) | Err(GasAppError::SessionNotFound) => {}
                Err(error) => return Err(error),
            }
        } else if stored.subscribed {
            // Сбой отписки уходу не мешает: канал с устройства исчезает
            // в любом случае. Подписка на сервере при этом останется,
            // пока человек не отпишется снова либо не удалит аккаунт.
            if let Ok((device_id, identity)) = self.own_device() {
                let _ = self.api.unsubscribe_channel(
                    &device_id,
                    &uuid,
                    &DeviceSigner::new(&identity, now),
                );
            }
        }

        self.storage.delete_channel(&stored.channel_id)
    }

    /// Оформляет подписку аккаунта на канал, если её ещё нет.
    ///
    /// 🔐 Подписка — за подписью устройства: один аккаунт — один
    /// подписчик, и счётчик нельзя накрутить. Цена: сервер знает, на
    /// какие каналы подписан аккаунт. Сами записи забираются без
    /// подписи — читать канал по ссылке можно и не подписываясь.
    fn ensure_subscribed(&self, stored: &StoredChannel, now: Timestamp) -> Result<()> {
        if stored.subscribed {
            return Ok(());
        }

        let (device_id, identity) = self.own_device()?;

        self.api.subscribe_channel(
            &device_id,
            &channel::format_uuid(&stored.channel_id),
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .set_channel_subscribed(&stored.channel_id, true)
    }

    /// Собирает новое описание канала из известного, подписывает,
    /// отдаёт серверу и сохраняет.
    fn write_meta<R: RngCore + CryptoRng>(
        &self,
        stored: &StoredChannel,
        now: Timestamp,
        rng: &mut R,
        change: impl FnOnce(&mut ChannelMeta),
    ) -> Result<Channel> {
        // Описание подписывает только владелец: в нём список тех,
        // кому верят читатели.
        require_owner(stored)?;

        let access = access_of(stored);
        let author = author_of(&access, stored)?;
        let (device_id, identity) = self.own_device()?;

        // Время описания обязано расти: читатели не принимают описание
        // старше известного, а часы телефона могли уйти назад.
        let mut meta = ChannelMeta {
            title: stored.title.clone(),
            description: stored.description.clone(),
            updated_at_millis: now
                .as_millis()
                .max(stored.meta_updated_at.saturating_add(1)),
            pinned: stored.pinned_seq,
            avatar: stored.avatar.clone().unwrap_or_default(),
            admins: admins_of(stored),
        };
        change(&mut meta);

        let sealed = author.seal_meta(&meta, rng)?;

        self.api.update_channel(
            &device_id,
            &access.channel_uuid(),
            &UpdateChannelRequest {
                meta: Some(hex(&sealed)),
                ..UpdateChannelRequest::default()
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .update_channel_meta(&stored.channel_id, &stored_meta(&meta))?;

        self.present(
            &self
                .storage
                .channel(&stored.channel_id)?
                .ok_or(GasAppError::SessionNotFound)?,
        )
    }

    /// Шифрует файл и кладёт его в медиа своего канала.
    fn upload_channel_media<R: RngCore + CryptoRng>(
        &self,
        uuid: &str,
        device_id: &str,
        identity: &IdentityKeyPair,
        file: &AttachmentFile,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<AttachmentDescriptor> {
        let sealed = seal_file(file, MAX_CHANNEL_MEDIA_BYTES, rng)?;

        if sealed.payload.len() > MAX_CHANNEL_BLOB_BYTES {
            return Err(GasAppError::Malformed);
        }

        let location = self.api.upload_channel_media(
            device_id,
            uuid,
            sealed.payload,
            &DeviceSigner::new(identity, now),
        )?;

        let descriptor = AttachmentDescriptor {
            kind: file.kind,
            location,
            key: sealed.key,
            size: sealed.size,
            // 🔐 У фото, видео и звука имя не передаётся — в нём дата
            // съёмки и модель телефона (см. `Client::upload_attachment`).
            name: if sealed.is_media {
                None
            } else {
                file.name
                    .as_deref()
                    .map(|name| name.chars().take(MAX_CHANNEL_FILE_NAME_CHARS).collect())
            },
            description: None,
            duration_millis: file.duration_millis,
            waveform: file.waveform.clone(),
            preview: None,
        };

        descriptor.validate()?;

        Ok(descriptor)
    }

    /// Удаляет с сервера блобы по описаниям вложений — молча: это
    /// уборка, и её сбой ничего не ломает.
    fn drop_channel_media(
        &self,
        uuid: &str,
        device_id: &str,
        identity: &IdentityKeyPair,
        descriptors: &[Vec<u8>],
        now: Timestamp,
    ) {
        for descriptor in descriptors {
            if let Ok(parsed) = AttachmentDescriptor::from_bytes(descriptor) {
                let _ = self.api.delete_channel_media(
                    device_id,
                    uuid,
                    &parsed.location,
                    &DeviceSigner::new(identity, now),
                );
            }
        }
    }

    /// Сохранённая и не удалённая запись.
    fn live_post(&self, stored: &StoredChannel, seq: u64) -> Result<StoredPost> {
        self.storage
            .channel_post(&stored.channel_id, seq)?
            .filter(|post| !post.deleted)
            .ok_or(GasAppError::SessionNotFound)
    }

    pub(super) fn stored_channel(&self, channel_id: &str) -> Result<StoredChannel> {
        self.storage
            .channel(&parse_id(channel_id)?)?
            .ok_or(GasAppError::SessionNotFound)
    }

    /// Идентификатор своего устройства и ключ для подписи запросов.
    pub(super) fn own_device(&self) -> Result<(String, IdentityKeyPair)> {
        let device_id = self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id)
            .ok_or(GasAppError::SessionNotFound)?;
        let (identity, _) = self.load_identity()?;

        Ok((device_id, identity))
    }

    pub(super) fn present(&self, stored: &StoredChannel) -> Result<Channel> {
        let last = self.storage.channel_posts(&stored.channel_id, 1)?.pop();
        let role = role_of(stored);

        Ok(Channel {
            channel_id: channel::format_uuid(&stored.channel_id),
            title: stored.title.clone(),
            description: stored.description.clone(),
            role,
            unread: self
                .storage
                .count_channel_posts_after(&stored.channel_id, stored.last_read_seq)?,
            last_post_at: last.as_ref().map(|post| post.created_at),
            last_post_attachments: last
                .as_ref()
                .map_or(0, |post| u32::try_from(post.attachments.len()).unwrap_or(0)),
            last_post: last.map(|post| post.text),
            handle: stored.handle.clone(),
            subscribers: stored.subscribers,
            muted: stored.muted,
            pinned_seq: stored.pinned_seq,
            avatar: stored.avatar.clone(),
            closed: stored.closed,
        })
    }
}

/// Строка нового канала для базы.
pub(super) fn new_stored(
    access: &ChannelAccess,
    signing_key: Option<[u8; 32]>,
    meta: &ChannelMeta,
    now: Timestamp,
) -> StoredChannel {
    StoredChannel {
        channel_id: access.channel_id,
        secret: access.secret,
        verify_key: *access.verify_key.as_bytes(),
        signing_key,
        title: meta.title.clone(),
        description: meta.description.clone(),
        meta_updated_at: meta.updated_at_millis,
        pinned_seq: meta.pinned,
        avatar: (!meta.avatar.is_empty()).then(|| meta.avatar.clone()),
        handle: None,
        subscribers: 0,
        muted: false,
        last_seq: 0,
        last_rev: 0,
        last_read_seq: 0,
        seen_sent_seq: 0,
        subscribed: false,
        joined_at: now,
        admins: stored_meta(meta).admins,
        closed: false,
    }
}

/// Настройка с последним известным ответом сервера о премиуме.
const PREMIUM_SETTING: &str = "account.premium";

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 В интерфейс попадают только реакции из закрытого набора.
    #[test]
    fn reactions_from_the_server_are_filtered() {
        let parsed = parse_reactions("🔥:3,👍:1,<b>:9,🔥:x,😂:0,");

        assert_eq!(
            parsed,
            vec![
                ChannelReaction {
                    emoji: "🔥".to_owned(),
                    count: 3
                },
                ChannelReaction {
                    emoji: "👍".to_owned(),
                    count: 1
                },
            ]
        );
        assert!(parse_reactions(&"🔥:1,".repeat(200)).is_empty());
    }
}
