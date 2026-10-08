// SPDX-License-Identifier: Apache-2.0

//! Каналы и премиум на границе с платформой.
//!
//! Интерфейс не держит ключей каналов и не шифрует: наружу уходят
//! название, текст записей и ссылка-приглашение. Ссылка — единственное
//! место, где интерфейс видит секрет канала, и это намеренно: ею
//! человек делится сам.

use gasapp_core::client::{Channel, ChannelEntry};
use gasapp_types::Timestamp;

use crate::messenger::Messenger;
use crate::{guard, FfiError, FfiQrMatrix};

/// Канал для списка и экрана канала.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChannel {
    /// Идентификатор, UUID.
    pub channel_id: String,
    /// Название.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Свой ли это канал: можно ли в него писать.
    pub owned: bool,
    /// Сколько записей не прочитано.
    pub unread: u64,
    /// Текст последней записи.
    pub last_post: Option<String>,
    /// Время последней записи по часам автора.
    pub last_post_at_millis: Option<i64>,
}

impl From<Channel> for FfiChannel {
    fn from(channel: Channel) -> Self {
        Self {
            channel_id: channel.channel_id,
            title: channel.title,
            description: channel.description,
            owned: channel.owned,
            unread: channel.unread,
            last_post: channel.last_post,
            last_post_at_millis: channel.last_post_at.map(|at| at.as_millis()),
        }
    }
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
}

impl From<ChannelEntry> for FfiChannelPost {
    fn from(entry: ChannelEntry) -> Self {
        Self {
            seq: entry.seq,
            text: entry.text,
            created_at_millis: entry.created_at.as_millis(),
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

        guard(|| client.join_channel(&link, Timestamp::from_millis(now_millis)))
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

    /// Забирает новые записи канала; возвращает их число. Сетевой вызов.
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

    /// Отмечает канал прочитанным.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — канала нет на устройстве.
    pub fn mark_channel_read(&self, channel_id: String) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.mark_channel_read(&channel_id))
    }

    /// Публикует запись в своём канале. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::PremiumRequired`] — канал чужой;
    /// [`FfiError::InvalidArgument`] — текст пустой либо слишком длинный;
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn publish_channel_post(
        &self,
        channel_id: String,
        text: String,
        now_millis: i64,
    ) -> Result<FfiChannelPost, FfiError> {
        let client = self.client()?;

        guard(|| {
            client.publish_channel_post(
                &channel_id,
                &text,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
        .map(FfiChannelPost::from)
        .map_err(malformed_is_invalid)
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

/// «Не прошло проверку» для текста, который ввёл человек, — это
/// неверный ввод, а не сбой ядра: интерфейс показывает правило.
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
}
