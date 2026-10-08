// SPDX-License-Identifier: Apache-2.0

//! Каналы и премиум на границе с платформой.
//!
//! Интерфейс не держит ключей каналов и не шифрует: наружу уходят
//! название, текст записей, описания вложений и ссылка-приглашение.
//! Ссылка — единственное место, где интерфейс видит секрет канала,
//! и это намеренно: ею человек делится сам.
//!
//! 🔐 Счётчики — подписчики, просмотры, реакции — это слова сервера,
//! ничем не подписанные: интерфейс показывает их как статистику.

use gasapp_core::client::{
    AttachmentFile, Channel, ChannelAdminInfo, ChannelAttachment, ChannelEntry, ChannelPreview,
    ChannelRole, CHANNEL_REACTIONS, MAX_CHANNEL_MEDIA_BYTES,
};
use gasapp_types::Timestamp;

use crate::messenger::{FfiAttachmentFile, FfiAttachmentKind, Messenger};
use crate::{guard, FfiError, FfiQrMatrix};

/// Кто человек в канале.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiChannelRole {
    /// Читает.
    Reader,
    /// Показал владельцу заявку на администрирование, но не назначен
    /// (либо уже снят): писать не может.
    AdminPending,
    /// Назначен владельцем: пишет, правит и удаляет записи.
    Admin,
    /// Владелец: кроме записей — описание, закреп, аватар, публичное
    /// имя, состав администраторов и удаление канала.
    Owner,
}

/// Канал для списка и экрана канала.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannel {
    /// Идентификатор, UUID.
    pub channel_id: String,
    /// Название.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Кто человек в этом канале.
    pub role: FfiChannelRole,
    /// Сколько записей не прочитано.
    pub unread: u64,
    /// Текст последней записи.
    pub last_post: Option<String>,
    /// Время последней записи по часам автора.
    pub last_post_at_millis: Option<i64>,
    /// Сколько вложений у последней записи.
    pub last_post_attachments: u32,
    /// Публичное `@имя` — со слов сервера.
    pub handle: Option<String>,
    /// Число подписчиков — со слов сервера.
    pub subscribers: u64,
    /// «Без звука».
    pub muted: bool,
    /// Номер закреплённой записи; `0` — закрепа нет.
    pub pinned_seq: u64,
    /// Описание вложения с аватаром — для
    /// [`Messenger::fetch_channel_media`].
    pub avatar: Option<Vec<u8>>,
}

impl From<Channel> for FfiChannel {
    fn from(channel: Channel) -> Self {
        Self {
            channel_id: channel.channel_id,
            title: channel.title,
            description: channel.description,
            role: match channel.role {
                ChannelRole::Reader => FfiChannelRole::Reader,
                ChannelRole::Pending => FfiChannelRole::AdminPending,
                ChannelRole::Admin => FfiChannelRole::Admin,
                ChannelRole::Owner => FfiChannelRole::Owner,
            },
            unread: channel.unread,
            last_post: channel.last_post,
            last_post_at_millis: channel.last_post_at.map(|at| at.as_millis()),
            last_post_attachments: channel.last_post_attachments,
            handle: channel.handle,
            subscribers: channel.subscribers,
            muted: channel.muted,
            pinned_seq: channel.pinned_seq,
            avatar: channel.avatar,
        }
    }
}

/// Вложение записи канала.
///
/// 🔐 Имя назвал автор канала: показывать его можно, доверять — нет.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannelAttachment {
    /// Описание как есть — для [`Messenger::fetch_channel_media`].
    pub descriptor: Vec<u8>,
    /// Тип вложения.
    pub kind: FfiAttachmentKind,
    /// Размер открытого файла в байтах.
    pub size: u64,
    /// Имя файла, если автор его передал.
    pub name: Option<String>,
}

impl From<ChannelAttachment> for FfiChannelAttachment {
    fn from(attachment: ChannelAttachment) -> Self {
        use gasapp_media::descriptor::AttachmentKind;

        Self {
            descriptor: attachment.descriptor,
            kind: match attachment.kind {
                AttachmentKind::Image => FfiAttachmentKind::Image,
                AttachmentKind::Video => FfiAttachmentKind::Video,
                AttachmentKind::Voice => FfiAttachmentKind::Voice,
                AttachmentKind::Document => FfiAttachmentKind::Document,
            },
            size: attachment.size,
            name: attachment.name,
        }
    }
}

/// Реакция со счётчиком.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannelReaction {
    /// Эмодзи из набора [`channel_reactions`].
    pub emoji: String,
    /// Сколько подписчиков её поставили — со слов сервера.
    pub count: u64,
}

/// Запись канала.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannelPost {
    /// Номер записи.
    pub seq: u64,
    /// Текст.
    pub text: String,
    /// Время публикации по часам автора.
    pub created_at_millis: i64,
    /// Время последней правки, если запись правили.
    pub edited_at_millis: Option<i64>,
    /// Просмотры — со слов сервера.
    pub views: u64,
    /// Реакции — со слов сервера.
    pub reactions: Vec<FfiChannelReaction>,
    /// Своя реакция.
    pub my_reaction: Option<String>,
    /// Вложения.
    pub attachments: Vec<FfiChannelAttachment>,
}

impl From<ChannelEntry> for FfiChannelPost {
    fn from(entry: ChannelEntry) -> Self {
        Self {
            seq: entry.seq,
            text: entry.text,
            created_at_millis: entry.created_at.as_millis(),
            edited_at_millis: entry.edited_at.map(|at| at.as_millis()),
            views: entry.views,
            reactions: entry
                .reactions
                .into_iter()
                .map(|reaction| FfiChannelReaction {
                    emoji: reaction.emoji,
                    count: reaction.count,
                })
                .collect(),
            my_reaction: entry.my_reaction,
            attachments: entry
                .attachments
                .into_iter()
                .map(FfiChannelAttachment::from)
                .collect(),
        }
    }
}

/// Администратор канала глазами владельца.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannelAdmin {
    /// Публичный ключ подписи, hex, — им администратора снимают.
    pub verify_key: String,
    /// Имя, которым владелец его подписал; пусто — не подписал.
    pub label: String,
    /// Действующий ли. Снятый остаётся в списке: по его ключу читаются
    /// записи, которые он успел написать.
    pub active: bool,
}

impl From<ChannelAdminInfo> for FfiChannelAdmin {
    fn from(admin: ChannelAdminInfo) -> Self {
        Self {
            verify_key: admin.verify_key,
            label: admin.label,
            active: admin.active,
        }
    }
}

/// Публичный канал, найденный по имени, — до подписки.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannelPreview {
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

impl From<ChannelPreview> for FfiChannelPreview {
    fn from(preview: ChannelPreview) -> Self {
        Self {
            link: preview.link,
            channel_id: preview.channel_id,
            title: preview.title,
            description: preview.description,
            handle: preview.handle,
            subscribers: preview.subscribers,
            joined: preview.joined,
        }
    }
}

/// Незавершённая регистрация: имя и адрес, на который ушёл код.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPendingRegistration {
    /// Имя, которое человек выбрал.
    pub username: String,
    /// Адрес почты, на который ушёл код.
    pub email: String,
}

/// Похожа ли строка на ссылку-приглашение канала.
///
/// Нужна сканеру QR и полю вставки, чтобы отличить канал от контакта,
/// не разбирая ссылку в интерфейсе.
#[uniffi::export]
#[must_use]
pub fn is_channel_link(text: String) -> bool {
    gasapp_protocol::channel::ChannelAccess::parse(&text).is_ok()
}

/// Похожа ли строка на заявку на администрирование канала.
///
/// Нужна сканеру QR и полю вставки у владельца канала.
#[uniffi::export]
#[must_use]
pub fn is_channel_admin_request(text: String) -> bool {
    gasapp_protocol::channel::AdminRequest::parse(&text).is_ok()
}

/// QR-код заявки на администрирование.
///
/// # Errors
///
/// [`FfiError::Core`] — строка не заявка либо не помещается в код;
/// [`FfiError::InvalidArgument`] — матрица не представима.
#[uniffi::export]
pub fn channel_admin_request_qr(request: String) -> Result<FfiQrMatrix, FfiError> {
    let matrix = guard(|| {
        // В код попадает только настоящая заявка.
        let parsed = gasapp_protocol::channel::AdminRequest::parse(&request)?;

        gasapp_protocol::qr::encode_text(&parsed.to_uri())
    })?;

    Ok(FfiQrMatrix {
        size: u32::try_from(matrix.size).map_err(|_| FfiError::InvalidArgument)?,
        modules: matrix.modules,
    })
}

/// Публичное имя канала в каноничном виде — без `@`, строчными, —
/// либо `None`, если строка именем быть не может.
///
/// Интерфейс проверяет имя этим же правилом, что и сервер, а не своим.
#[uniffi::export]
#[must_use]
pub fn canonical_channel_handle(text: String) -> Option<String> {
    gasapp_net::client::canonical_handle(&text).ok()
}

/// Реакции, которые можно поставить записи. Набор закрыт сервером.
#[uniffi::export]
#[must_use]
pub fn channel_reactions() -> Vec<String> {
    CHANNEL_REACTIONS
        .iter()
        .map(|&emoji| emoji.to_owned())
        .collect()
}

/// Предел файла в записи канала, в байтах.
#[uniffi::export]
#[must_use]
pub fn channel_media_limit() -> u64 {
    MAX_CHANNEL_MEDIA_BYTES
}

/// Сколько вложений может нести одна запись.
#[uniffi::export]
#[must_use]
pub fn channel_post_attachment_limit() -> u32 {
    u32::try_from(gasapp_protocol::channel::MAX_POST_ATTACHMENTS).unwrap_or(u32::MAX)
}

/// QR-код ссылки-приглашения канала.
///
/// # Errors
///
/// [`FfiError::Core`] — строка не ссылка на канал либо не помещается
/// в код; [`FfiError::InvalidArgument`] — матрица не представима.
#[uniffi::export]
pub fn channel_link_qr(uri: String) -> Result<FfiQrMatrix, FfiError> {
    let matrix = guard(|| {
        // В код попадает только настоящая ссылка на канал.
        let access = gasapp_protocol::channel::ChannelAccess::parse(&uri)?;

        gasapp_protocol::qr::encode_text(&access.to_uri())
    })?;

    Ok(FfiQrMatrix {
        size: u32::try_from(matrix.size).map_err(|_| FfiError::InvalidArgument)?,
        modules: matrix.modules,
    })
}

#[uniffi::export]
impl Messenger {
    /// Запоминает имя и адрес незавершённой регистрации — на случай,
    /// если приложение заблокируется, пока человек ходит за кодом.
    ///
    /// Хранится в зашифрованной базе и стирается при успешной
    /// регистрации.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — имя не по правилу;
    /// [`FfiError::InvalidEmail`] — строка не похожа на адрес.
    pub fn set_pending_registration(
        &self,
        username: String,
        email: String,
    ) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.set_pending_registration(&username, &email))
    }

    /// Незавершённая регистрация, если она есть, — без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn pending_registration(&self) -> Result<Option<FfiPendingRegistration>, FfiError> {
        let client = self.reader()?;

        Ok(
            guard(|| client.pending_registration())?.map(|pending| FfiPendingRegistration {
                username: pending.username,
                email: pending.email,
            }),
        )
    }

    /// Спрашивает сервер, есть ли у аккаунта премиум. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен либо аккаунта нет.
    pub fn refresh_premium(&self, now_millis: i64) -> Result<bool, FfiError> {
        let client = self.client()?;

        guard(|| client.refresh_premium(Timestamp::from_millis(now_millis)))
    }

    /// Последний известный ответ о премиуме — без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn premium_cached(&self) -> Result<bool, FfiError> {
        let client = self.reader()?;

        guard(|| client.premium_cached())
    }

    /// Создаёт канал. Только для аккаунта с премиумом.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — у аккаунта нет премиума;
    /// [`FfiError::InvalidArgument`] — название пустое либо слишком
    /// длинное; [`FfiError::Core`] — сервер недоступен.
    pub fn create_channel(
        &self,
        title: String,
        description: String,
        now_millis: i64,
    ) -> Result<FfiChannel, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.create_channel(
                &title,
                &description,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannel::from)
        .map_err(malformed_is_invalid)
    }

    /// Добавляет канал по ссылке-приглашению. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — не ссылка на канал;
    /// [`FfiError::Core`] — канал удалён, сервер недоступен либо
    /// отдаёт канал с другим ключом автора.
    pub fn join_channel(&self, link: String, now_millis: i64) -> Result<FfiChannel, FfiError> {
        // Форма ссылки проверяется до сети: «не ссылка» и «сервер
        // недоступен» интерфейс показывает по-разному.
        if !is_channel_link(link.clone()) {
            return Err(FfiError::InvalidArgument);
        }

        let client = self.client()?;

        guard(|| {
            client.join_channel(
                &link,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannel::from)
    }

    /// Каналы на этом устройстве — без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn channels(&self) -> Result<Vec<FfiChannel>, FfiError> {
        let client = self.reader()?;

        Ok(guard(|| client.channels())?
            .into_iter()
            .map(FfiChannel::from)
            .collect())
    }

    /// Один канал — без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn channel(&self, channel_id: String) -> Result<FfiChannel, FfiError> {
        let client = self.reader()?;

        guard(|| client.channel(&channel_id)).map(FfiChannel::from)
    }

    /// Сколько непрочитанных записей во всех каналах, кроме тех, что
    /// «без звука», — для счётчика на вкладке. Без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn unread_channel_posts(&self) -> Result<u64, FfiError> {
        let client = self.reader()?;

        guard(|| client.unread_channel_posts())
    }

    /// Ссылка-приглашение канала.
    ///
    /// 🔐 Ссылка и есть доступ: кто её получил, читает весь канал.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn channel_link(&self, channel_id: String) -> Result<String, FfiError> {
        let client = self.reader()?;

        guard(|| client.channel_link(&channel_id))
    }

    /// Забирает изменения канала — новые записи, правки, удаления,
    /// счётчики; возвращает число новых записей. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен либо канал удалён.
    pub fn sync_channel(&self, channel_id: String) -> Result<u32, FfiError> {
        let client = self.client()?;

        guard(|| client.sync_channel(&channel_id))
    }

    /// Забирает новые записи всех каналов. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn sync_channels(&self) -> Result<u32, FfiError> {
        let client = self.client()?;

        guard(|| client.sync_channels())
    }

    /// Догружает страницу истории канала; возвращает, сколько записей
    /// добавилось (ноль — история кончилась). Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn load_older_channel_posts(&self, channel_id: String) -> Result<u32, FfiError> {
        let client = self.client()?;

        guard(|| client.load_older_channel_posts(&channel_id))
    }

    /// Последние записи канала — без сети, от старых к новым.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn channel_posts(
        &self,
        channel_id: String,
        limit: u32,
    ) -> Result<Vec<FfiChannelPost>, FfiError> {
        let client = self.reader()?;

        Ok(guard(|| client.channel_posts(&channel_id, limit))?
            .into_iter()
            .map(FfiChannelPost::from)
            .collect())
    }

    /// Запись по номеру — без сети; удалённой или неизвестной нет.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn channel_post(
        &self,
        channel_id: String,
        seq: u64,
    ) -> Result<Option<FfiChannelPost>, FfiError> {
        let client = self.reader()?;

        Ok(guard(|| client.channel_post(&channel_id, seq))?.map(FfiChannelPost::from))
    }

    /// Ищет подстроку в сохранённых записях канала — без сети; свежие
    /// первыми.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn search_channel_posts(
        &self,
        channel_id: String,
        query: String,
        limit: u32,
    ) -> Result<Vec<FfiChannelPost>, FfiError> {
        let client = self.reader()?;

        Ok(
            guard(|| client.search_channel_posts(&channel_id, &query, limit))?
                .into_iter()
                .map(FfiChannelPost::from)
                .collect(),
        )
    }

    /// Отмечает канал прочитанным — без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn mark_channel_read(&self, channel_id: String) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.mark_channel_read(&channel_id))
    }

    /// Сообщает серверу, до какой записи канал прочитан: из этого
    /// складываются просмотры. Сетевой вызов, без подписи устройства.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn report_channel_seen(&self, channel_id: String) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.report_channel_seen(&channel_id))
    }

    /// Публикует запись в своём канале: текст, вложения или и то и
    /// другое. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::InvalidArgument`] — запись пуста, слишком длинна
    /// либо файл больше предела;
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn publish_channel_post(
        &self,
        channel_id: String,
        text: String,
        files: Vec<FfiAttachmentFile>,
        now_millis: i64,
    ) -> Result<FfiChannelPost, FfiError> {
        let client = self.client()?;
        let files: Vec<AttachmentFile> = files.into_iter().map(AttachmentFile::from).collect();

        guard(|| {
            client.publish_channel_post(
                &channel_id,
                &text,
                &files,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannelPost::from)
        .map_err(malformed_is_invalid)
    }

    /// Исправляет текст записи своего канала. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::InvalidArgument`] — запись стала бы пустой либо
    /// слишком длинной; [`FfiError::Core`] — сервер недоступен либо
    /// записи нет.
    pub fn edit_channel_post(
        &self,
        channel_id: String,
        seq: u64,
        text: String,
        now_millis: i64,
    ) -> Result<FfiChannelPost, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.edit_channel_post(
                &channel_id,
                seq,
                &text,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannelPost::from)
        .map_err(malformed_is_invalid)
    }

    /// Удаляет запись своего канала и её файлы. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::Core`] — сервер недоступен либо записи нет.
    pub fn delete_channel_post(
        &self,
        channel_id: String,
        seq: u64,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| {
            client.delete_channel_post(
                &channel_id,
                seq,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Закрепляет запись своего канала; `seq == 0` — снимает закреп.
    /// Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::Core`] — сервер недоступен либо записи нет.
    pub fn pin_channel_post(
        &self,
        channel_id: String,
        seq: u64,
        now_millis: i64,
    ) -> Result<FfiChannel, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.pin_channel_post(
                &channel_id,
                seq,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannel::from)
    }

    /// Меняет название и описание своего канала. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — название пустое либо слишком
    /// длинное; [`FfiError::Core`] — сервер недоступен.
    pub fn update_channel(
        &self,
        channel_id: String,
        title: String,
        description: String,
        now_millis: i64,
    ) -> Result<FfiChannel, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.update_channel(
                &channel_id,
                &title,
                &description,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannel::from)
        .map_err(malformed_is_invalid)
    }

    /// Ставит аватар своего канала; `None` — убирает. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::InvalidArgument`] — файл слишком велик либо не
    /// разбирается; [`FfiError::Core`] — сервер недоступен.
    pub fn set_channel_avatar(
        &self,
        channel_id: String,
        image: Option<Vec<u8>>,
        now_millis: i64,
    ) -> Result<FfiChannel, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.set_channel_avatar(
                &channel_id,
                image.as_deref(),
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannel::from)
        .map_err(malformed_is_invalid)
    }

    /// Делает свой канал публичным под именем `handle` либо, с `None`,
    /// снова закрытым. Сетевой вызов.
    ///
    /// 🔐 Публичному каналу сервер получает ссылку-приглашение и может
    /// его читать. Интерфейс обязан сказать об этом до вызова.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::InvalidArgument`] — это не имя канала;
    /// [`FfiError::UsernameTaken`] — имя занято;
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn set_channel_handle(
        &self,
        channel_id: String,
        handle: Option<String>,
        now_millis: i64,
    ) -> Result<FfiChannel, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.set_channel_handle(
                &channel_id,
                handle.as_deref(),
                Timestamp::from_millis(now_millis),
            )
        })
        .map(FfiChannel::from)
        .map_err(malformed_is_invalid)
    }

    /// Включает либо выключает «без звука» — без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn set_channel_muted(
        &self,
        channel_id: String,
        muted: bool,
    ) -> Result<FfiChannel, FfiError> {
        let client = self.client()?;

        guard(|| client.set_channel_muted(&channel_id, muted)).map(FfiChannel::from)
    }

    /// Ставит, меняет либо (с `None`) снимает свою реакцию на запись.
    /// Сетевой вызов, без подписи устройства.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — эмодзи не из набора;
    /// [`FfiError::Core`] — сервер недоступен либо записи нет.
    pub fn react_to_channel_post(
        &self,
        channel_id: String,
        seq: u64,
        emoji: Option<String>,
        now_millis: i64,
    ) -> Result<FfiChannelPost, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.react_to_channel_post(
                &channel_id,
                seq,
                emoji.as_deref(),
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannelPost::from)
        .map_err(malformed_is_invalid)
    }

    /// Скачивает и расшифровывает медиа канала по описанию из записи
    /// либо аватара. Сетевой вызов, без подписи устройства.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен, блоба нет (запись
    /// удалена) либо он подменён.
    pub fn fetch_channel_media(
        &self,
        channel_id: String,
        descriptor: Vec<u8>,
    ) -> Result<Vec<u8>, FfiError> {
        let client = self.client()?;

        guard(|| client.fetch_channel_media(&channel_id, &descriptor))
    }

    /// Публичный канал по точному `@имени` — до подписки. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — это не имя канала;
    /// [`FfiError::Core`] — такого канала нет либо сервер недоступен.
    pub fn find_public_channel(&self, handle: String) -> Result<FfiChannelPreview, FfiError> {
        if canonical_channel_handle(handle.clone()).is_none() {
            return Err(FfiError::InvalidArgument);
        }

        let client = self.client()?;

        guard(|| client.find_public_channel(&handle)).map(FfiChannelPreview::from)
    }

    /// Публичные каналы, чьё `@имя` начинается с `query`. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn search_public_channels(
        &self,
        query: String,
    ) -> Result<Vec<FfiChannelPreview>, FfiError> {
        let client = self.client()?;

        Ok(guard(|| client.search_public_channels(&query))?
            .into_iter()
            .map(FfiChannelPreview::from)
            .collect())
    }

    /// Пополняет запас пропусков — анонимных одноразовых прав на
    /// подписку, — если он на исходе. Сетевой вызов, за подписью
    /// устройства. Возвращает, сколько пропусков добавилось.
    ///
    /// Вызывается заранее, при открытии списка каналов: так сервер не
    /// видит рядом «аккаунт взял пропуск» и «кто-то подписался».
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен, суточный предел исчерпан
    /// либо сервер подписал пропуска не тем ключом, который объявил.
    pub fn refill_passes(&self, now_millis: i64) -> Result<u32, FfiError> {
        let client = self.client()?;

        guard(|| client.refill_passes(Timestamp::from_millis(now_millis), &mut rand_core::OsRng))
    }

    /// Заявка на администрирование канала — строка, которую читатель
    /// показывает владельцу. Без сети.
    ///
    /// 🔐 В заявке нет секретов, но она называет владельцу устройство,
    /// а серверу — аккаунт будущего администратора.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — человек и так владелец канала;
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn channel_admin_request(&self, channel_id: String) -> Result<String, FfiError> {
        let client = self.client()?;

        guard(|| client.channel_admin_request(&channel_id, &mut rand_core::OsRng))
            .map_err(malformed_is_invalid)
    }

    /// Назначает администратора своего канала по его заявке. Сетевой
    /// вызов. `label` — имя для владельца; читатели его не видят.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — человек не владелец канала;
    /// [`FfiError::InvalidArgument`] — это не заявка, она в другой
    /// канал либо список администраторов полон;
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn add_channel_admin(
        &self,
        channel_id: String,
        request: String,
        label: String,
        now_millis: i64,
    ) -> Result<Vec<FfiChannelAdmin>, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.add_channel_admin(
                &channel_id,
                &request,
                &label,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(|admins| admins.into_iter().map(FfiChannelAdmin::from).collect())
        .map_err(malformed_is_invalid)
    }

    /// Снимает администратора своего канала. Сетевой вызов.
    ///
    /// ⚠️ Записи, которые он уже написал, остаются. Новых под его
    /// ключом читатели не примут.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — человек не владелец канала;
    /// [`FfiError::Core`] — сервер недоступен либо администратора нет.
    pub fn remove_channel_admin(
        &self,
        channel_id: String,
        verify_key: String,
        now_millis: i64,
    ) -> Result<Vec<FfiChannelAdmin>, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.remove_channel_admin(
                &channel_id,
                &verify_key,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(|admins| admins.into_iter().map(FfiChannelAdmin::from).collect())
    }

    /// Администраторы своего канала — действующие и снятые. Без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn channel_admins(&self, channel_id: String) -> Result<Vec<FfiChannelAdmin>, FfiError> {
        let client = self.reader()?;

        Ok(guard(|| client.channel_admins(&channel_id))?
            .into_iter()
            .map(FfiChannelAdmin::from)
            .collect())
    }

    /// Убирает канал с устройства; свой — удаляет и с сервера.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — свой канал не удалось удалить с сервера;
    /// на устройстве он при этом остаётся.
    pub fn leave_channel(&self, channel_id: String, now_millis: i64) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.leave_channel(&channel_id, Timestamp::from_millis(now_millis)))
    }
}

/// «Не прошло проверку» для того, что ввёл человек, — это неверный
/// ввод, а не сбой ядра: интерфейс показывает правило.
fn malformed_is_invalid(error: FfiError) -> FfiError {
    match error {
        FfiError::Core(gasapp_types::GasAppError::Malformed) => FfiError::InvalidArgument,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_channel_links_are_recognised() {
        let channel = gasapp_protocol::channel::create(&mut rand_core::OsRng);
        let uri = channel.access.to_uri();

        assert!(is_channel_link(uri.clone()));
        assert!(!is_channel_link(uri.replace("channel", "contact")));
        assert!(!is_channel_link("https://example.org".to_owned()));
        assert!(!is_channel_link(String::new()));
    }

    #[test]
    fn a_channel_link_fits_a_qr_code() {
        let channel = gasapp_protocol::channel::create(&mut rand_core::OsRng);
        let matrix = channel_link_qr(channel.access.to_uri()).expect("код строится");

        assert!(matrix.size > 0);
        assert!(channel_link_qr("gasapp://channel/zz".to_owned()).is_err());
    }

    #[test]
    fn handles_are_canonicalised_by_one_rule() {
        assert_eq!(
            canonical_channel_handle(" @Gas_News ".to_owned()).as_deref(),
            Some("gas_news")
        );
        assert!(canonical_channel_handle("ab".to_owned()).is_none());
        assert!(canonical_channel_handle("1abc".to_owned()).is_none());
        assert!(canonical_channel_handle("новости".to_owned()).is_none());
        assert_eq!(channel_reactions().len(), 8);
    }
}
