// SPDX-License-Identifier: Apache-2.0

//! Клиент серверного API.
//!
//! # Почему транспорт абстрактный
//!
//! Клиент не открывает TCP-соединений сам. Он формирует запрос, отдаёт
//! его [`Transport`] и разбирает ответ. Причина не в чистоте
//! архитектуры, а в пиннинге: на Android и iOS TLS ведёт платформенный
//! стек (`network_security_config.xml`, ATS), и проверка пина
//! включается именно там. Клиент со своим TLS-стеком обошёл бы
//! платформенные настройки — то есть отключил бы пиннинг, который
//! раздел 14.3 требует включить.
//!
//! Побочная выгода: логика запросов проверяется тестами без сети.
//!
//! # Что клиент не делает
//!
//! Не шифрует и не расшифровывает. В `SendRequest` уходит уже готовый
//! шифротекст, а из `EnvelopeResponse` приходит непрозрачный блоб.
//! Криптография живёт в `gasapp-protocol`, и смешивать её с сетевым
//! кодом нельзя (правило 1 раздела 4.1).

use gasapp_types::{GasAppError, Result};

use crate::api::{
    AccountDeletedResponse, AccountStatusResponse, AddChannelAdminRequest,
    AnswerChannelJoinRequest, BotNameRequest, BotResponse, BotTokenResponse, BundleResponse,
    CertificateResponse, ChannelEpochResponse, ChannelInviteRequest, ChannelJoinRequestResponse,
    ChannelJoinStatusResponse, ChannelMediaResponse, ChannelMemberKeyRequest,
    ChannelMemberKeyResponse, ChannelMemberRequest, ChannelMemberResponse, ChannelPostResponse,
    ChannelReactRequest, ChannelResponse, ChannelSeenRequest, CreateChannelRequest,
    DeleteChannelMediaRequest, DiscoveryResponse, EmailChallengeResponse, EmailCodeRequest,
    EnvelopeResponse, JoinChannelRequest, KtHeadsResponse, KtProofsRequest, KtProofsResponse,
    PublishKeysRequest, PublishPostRequest, PublishPostResponse, RecoverAccountRequest,
    RegisterBotRequest, RegisterRequest, RegisterResponse, RekeyChannelRequest,
    RemoveChannelAdminRequest, ReplacePostRequest, SealedAccessRequest, SealedReportRequest,
    SealedReportResponse, SealedSendRequest, UpdateChannelRequest,
};

/// Метод HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Чтение.
    Get,
    /// Создание.
    Post,
    /// Замена.
    Put,
    /// Удаление.
    Delete,
}

impl Method {
    /// Имя метода для протокола.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// Подготовленный запрос.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Метод.
    pub method: Method,
    /// Путь относительно базового URL, начиная со слэша.
    pub path: String,
    /// Тело в формате JSON. `None` для запросов без тела.
    pub body: Option<String>,
    /// Тело из сырых байтов — для вложений.
    ///
    /// Отдельное поле, а не hex в [`body`](Self::body): hex удваивает
    /// объём, и стомегабайтный файл занял бы двести мегабайт трафика
    /// и памяти на разбор с обеих сторон.
    ///
    /// Заполнено не более одного из двух полей. Оба сразу означали бы
    /// вопрос «какое отправлять», на который у транспорта нет ответа.
    pub binary_body: Option<Vec<u8>>,
    /// Дополнительные заголовки: имя и значение.
    ///
    /// Нужны для подписи запроса. Список, а не карта: заголовков
    /// два, и порядок их отправки значения не имеет — карта здесь
    /// была бы структурой ради структуры.
    pub headers: Vec<(String, String)>,
    /// Анонимный запрос — без подписи устройства.
    ///
    /// 🔐 Транспорт обязан отправить его **отдельной цепочкой Tor**
    /// (свой порт встроенного Tor, без переиспользования соединения):
    /// иначе он шёл бы той же цепочкой, что запросы за подписью, и
    /// сервер связал бы, например, запечатанное сообщение с отправителем
    /// по выходному узлу и времени — и sealed sender потерял бы смысл.
    pub anonymous: bool,
}

/// Ответ сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Код состояния.
    pub status: u16,
    /// Тело ответа.
    pub body: String,
    /// Тело ответа в сырых байтах — для скачанных вложений.
    ///
    /// Пусто для обычных ответов: они текстовые, и заводить копию
    /// каждого JSON в байтах значило бы удваивать память на ровном
    /// месте.
    pub binary_body: Vec<u8>,
}

/// Транспорт, выполняющий запрос.
///
/// Реализуется платформенным слоем: на Android поверх `OkHttp`
/// с пиннингом, на iOS — поверх `URLSession` с ATS.
pub trait Transport {
    /// Выполняет запрос.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения. Ошибки уровня
    /// приложения (4xx, 5xx) возвращаются как успешный [`HttpResponse`]
    /// с соответствующим кодом: сбой сети и отказ сервера — разные
    /// события, и клиент реагирует на них по-разному.
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

/// Заголовок с решением proof-of-work анонимной загрузки.
pub const UPLOAD_POW_HEADER: &str = "x-gasapp-upload-pow";

/// Клиент серверного API.
pub struct ApiClient<T: Transport> {
    transport: T,
}

impl<T: Transport> ApiClient<T> {
    /// Создаёт клиент поверх транспорта.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Регистрирует аккаунт.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidSignature`] — proof-of-work не принят.
    /// * [`GasAppError::UsernameTaken`] — имя занято.
    /// * [`GasAppError::EmailCodeRejected`] — код из письма не принят.
    /// * [`GasAppError::EmailTaken`] — на этот адрес уже есть аккаунт.
    /// * [`GasAppError::Malformed`] — запрос отвергнут.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn register(&self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let response = self
            .send(
                Method::Post,
                "/v1/accounts/register".to_owned(),
                Some(to_json(request)?),
            )
            // `403` при регистрации — только про код из письма.
            .map_err(|error| match error {
                GasAppError::Forbidden => GasAppError::EmailCodeRejected,
                other => other,
            })?;

        parse(&response)
    }

    /// Условия запроса письма: окно времени и цена, которая сейчас
    /// действует на узле. Без подписи — аккаунта ещё нет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn email_challenge(&self) -> Result<EmailChallengeResponse> {
        let response = self.send(Method::Get, "/v1/accounts/email/challenge".to_owned(), None)?;

        parse(&response)
    }

    /// Просит сервер отправить письмо с кодом подтверждения.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidEmail`] — сервер не принял адрес.
    /// * [`GasAppError::InvalidSignature`] — proof-of-work не принят.
    /// * [`GasAppError::Network`] — сбой соединения, слишком частые
    ///   запросы (письмо на адрес — не чаще раза в минуту) либо сервер
    ///   не смог отправить письмо.
    pub fn request_email_code(&self, request: &EmailCodeRequest) -> Result<()> {
        self.send(
            Method::Post,
            "/v1/accounts/email/code".to_owned(),
            Some(to_json(request)?),
        )
        .map_err(|error| match error {
            GasAppError::Malformed => GasAppError::InvalidEmail,
            other => other,
        })?;

        Ok(())
    }

    /// Состояние своего аккаунта: есть ли премиум.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidSignature`] — подпись не принята.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn account_status(
        &self,
        device_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<AccountStatusResponse> {
        let response = self.send_signed(
            Method::Get,
            format!("/v1/accounts/{device_id}/status"),
            None,
            signer,
        )?;

        parse(&response)
    }

    /// Создаёт канал.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — у аккаунта нет премиума.
    /// * [`GasAppError::InvalidSignature`] — подпись не принята.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn create_channel(
        &self,
        device_id: &str,
        request: &CreateChannelRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.send_signed(
            Method::Post,
            format!("/v1/channels/own/{device_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Меняет свой канал: описание и/или публичность.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет или он чужой.
    /// * [`GasAppError::UsernameTaken`] — публичное имя занято.
    /// * [`GasAppError::Malformed`] — сервер не принял имя.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn update_channel(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &UpdateChannelRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            Method::Put,
            format!("/v1/channels/own/{device_id}/{channel_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Удаляет свой канал вместе с записями.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет или он чужой.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn delete_channel(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            Method::Delete,
            format!("/v1/channels/own/{device_id}/{channel_id}"),
            None,
            signer,
        )?;

        Ok(())
    }

    /// Назначает администратора своего канала: сервер начнёт
    /// принимать записи от аккаунта этого устройства.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет, он чужой либо
    ///   такого устройства нет.
    /// * [`GasAppError::Malformed`] — это устройство самого владельца
    ///   либо у канала предел администраторов.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn add_channel_admin(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &AddChannelAdminRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;
        // Устройство из заявки приходит извне — только UUID.
        let request = AddChannelAdminRequest {
            device_id: canonical_uuid(&request.device_id)?,
            verify_key: request.verify_key.clone(),
        };

        self.send_signed(
            Method::Post,
            format!("/v1/channels/own/{device_id}/{channel_id}/admins"),
            Some(to_json(&request)?),
            signer,
        )?;

        Ok(())
    }

    /// Снимает администратора своего канала.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет или он чужой.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn remove_channel_admin(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &RemoveChannelAdminRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            Method::Delete,
            format!("/v1/channels/own/{device_id}/{channel_id}/admins"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Публикует запись в канале; возвращает её номер.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет либо аккаунт
    ///   в него не пишет.
    /// * [`GasAppError::UsernameTaken`] — номер записи занят: в канал
    ///   только что написал кто-то ещё (`409`). Запись не сохранена.
    /// * [`GasAppError::Network`] — сбой соединения либо слишком частые
    ///   публикации.
    pub fn publish_channel_post(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &PublishPostRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<PublishPostResponse> {
        let channel_id = canonical_uuid(channel_id)?;

        let response = self.send_signed(
            Method::Post,
            format!("/v1/channels/own/{device_id}/{channel_id}/posts"),
            Some(to_json(request)?),
            signer,
        )?;

        parse(&response)
    }

    /// Заменяет запись своего канала: правка либо отметка об удалении.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала или записи нет.
    /// * [`GasAppError::Network`] — сбой соединения либо слишком частые
    ///   правки.
    pub fn replace_channel_post(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &ReplacePostRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<PublishPostResponse> {
        let channel_id = canonical_uuid(channel_id)?;

        let response = self.send_signed(
            Method::Put,
            format!("/v1/channels/own/{device_id}/{channel_id}/posts"),
            Some(to_json(request)?),
            signer,
        )?;

        parse(&response)
    }

    /// Загружает зашифрованный медиаблоб своего канала; возвращает его
    /// адрес.
    ///
    /// За подписью устройства: место в канале — только владельцу.
    /// Блоб уходит сырыми байтами, и подпись покрывает его хеш.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет или он чужой.
    /// * [`GasAppError::Malformed`] — блоб больше предела либо в канале
    ///   кончилось место.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn upload_channel_media(
        &self,
        device_id: &str,
        channel_id: &str,
        payload: Vec<u8>,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<String> {
        let channel_id = canonical_uuid(channel_id)?;
        let path = format!("/v1/channels/own/{device_id}/{channel_id}/media");
        let headers =
            crate::auth::signature_headers(signer, Method::Post.as_str(), &path, &payload)?;

        let response = self.transport.execute(&HttpRequest {
            method: Method::Post,
            path,
            body: None,
            binary_body: Some(payload),
            headers,
            anonymous: false,
        })?;

        check_status(&response)?;

        let media: ChannelMediaResponse = parse(&response)?;

        canonical_uuid(&media.media_id)
    }

    /// Удаляет медиаблоб своего канала.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала или блоба нет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn delete_channel_media(
        &self,
        device_id: &str,
        channel_id: &str,
        media_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;
        let request = DeleteChannelMediaRequest {
            media_id: canonical_uuid(media_id)?,
        };

        self.send_signed(
            Method::Delete,
            format!("/v1/channels/own/{device_id}/{channel_id}/media"),
            Some(to_json(&request)?),
            signer,
        )?;

        Ok(())
    }

    /// Канал по идентификатору — **без подписи**: сервер не должен
    /// знать, кто читает канал.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет (удалён).
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_info(&self, channel_id: &str) -> Result<ChannelResponse> {
        let channel_id = canonical_uuid(channel_id)?;

        let response = self.send(Method::Get, format!("/v1/channels/feed/{channel_id}"), None)?;

        parse(&response)
    }

    /// Изменения канала после ревизии `after_rev`, по возрастанию
    /// ревизии — новые записи, правки и удаления. **Без подписи.**
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn channel_changes(
        &self,
        channel_id: &str,
        after_rev: u64,
        limit: u32,
    ) -> Result<Vec<ChannelPostResponse>> {
        let channel_id = canonical_uuid(channel_id)?;

        let response = self.send(
            Method::Get,
            format!("/v1/channels/feed/{channel_id}/posts?after_rev={after_rev}&limit={limit}"),
            None,
        )?;

        parse(&response)
    }

    /// Страница ленты от новых к старым: записи с номером меньше
    /// `before_seq`, а без него — самые свежие. **Без подписи.**
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn channel_page(
        &self,
        channel_id: &str,
        before_seq: Option<u64>,
        limit: u32,
    ) -> Result<Vec<ChannelPostResponse>> {
        let channel_id = canonical_uuid(channel_id)?;

        let path = match before_seq {
            Some(before) => {
                format!("/v1/channels/feed/{channel_id}/posts?before_seq={before}&limit={limit}")
            }
            None => format!("/v1/channels/feed/{channel_id}/posts?limit={limit}"),
        };

        parse(&self.send(Method::Get, path, None)?)
    }

    /// Скачивает медиаблоб канала — **без подписи**.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — блоба нет (запись удалена).
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn download_channel_media(&self, channel_id: &str, media_id: &str) -> Result<Vec<u8>> {
        // 🔐 Адрес блоба приходит из записи канала, то есть от автора:
        // в путь попадает только UUID (см. `download_attachment`).
        let channel_id = canonical_uuid(channel_id)?;
        let media_id = canonical_uuid(media_id)?;

        let response = self.send(
            Method::Get,
            format!("/v1/channels/feed/{channel_id}/media/{media_id}"),
            None,
        )?;

        Ok(response.binary_body)
    }

    /// Публичный канал по точному `@имени` — **без подписи**.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — такого канала нет.
    /// * [`GasAppError::Malformed`] — это не имя канала.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_by_handle(&self, handle: &str) -> Result<ChannelResponse> {
        let handle = canonical_handle(handle)?;

        let response = self.send(Method::Get, format!("/v1/channels/handle/{handle}"), None)?;

        parse(&response)
    }

    /// Публичные каналы, чьё `@имя` начинается с `prefix`. **Без
    /// подписи.** Негодный запрос даёт пустой список, как и на сервере.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn search_channels(&self, prefix: &str) -> Result<Vec<ChannelResponse>> {
        // 🔐 В строку запроса попадают только знаки имени: всё прочее
        // было бы способом дописать серверу свои параметры.
        let Ok(prefix) = canonical_handle_prefix(prefix) else {
            return Ok(Vec::new());
        };

        let response = self.send(Method::Get, format!("/v1/channels/search?q={prefix}"), None)?;

        parse(&response)
    }

    /// Подписывает аккаунт на канал — за подписью устройства.
    ///
    /// 🔐 Один аккаунт — один подписчик: анонимную подписку нечем было
    /// ограничить, и счётчик накручивался. Сервер знает, на какие
    /// каналы подписан аккаунт; читать канал по ссылке можно и без
    /// подписки — анонимно.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn subscribe_channel(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.reader_action(device_id, channel_id, "subscribe", None, signer)
    }

    /// Отписывает аккаунт от канала вместе с его реакциями.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn unsubscribe_channel(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.reader_action(device_id, channel_id, "unsubscribe", None, signer)
    }

    /// Отмечает, что подписчик дочитал до записи.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт не подписан.
    /// * [`GasAppError::Network`] — сбой соединения либо слишком частые
    ///   запросы.
    pub fn mark_channel_seen(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &ChannelSeenRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.reader_action(
            device_id,
            channel_id,
            "seen",
            Some(to_json(request)?),
            signer,
        )
    }

    /// Ставит, меняет или снимает реакцию подписчика на запись.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — эмодзи не из набора сервера.
    /// * [`GasAppError::SessionNotFound`] — аккаунт не подписан либо
    ///   записи нет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn react_to_channel_post(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &ChannelReactRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.reader_action(
            device_id,
            channel_id,
            "react",
            Some(to_json(request)?),
            signer,
        )
    }

    /// Действие подписчика канала — `POST` за подписью устройства.
    fn reader_action(
        &self,
        device_id: &str,
        channel_id: &str,
        action: &str,
        body: Option<String>,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            Method::Post,
            format!("/v1/channels/reader/{device_id}/{channel_id}/{action}"),
            body,
            signer,
        )?;

        Ok(())
    }

    /// Заводит (`revoke == false`) либо отзывает ссылку-приглашение
    /// закрытого канала. Серверу уходит хеш метки, не сама ссылка.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет.
    /// * [`GasAppError::Network`] — сбой соединения либо у канала предел
    ///   действующих ссылок.
    pub fn set_channel_invite(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &ChannelInviteRequest,
        revoke: bool,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            if revoke { Method::Delete } else { Method::Post },
            format!("/v1/channels/own/{device_id}/{channel_id}/invites"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Подаёт заявку на вход в закрытый канал.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет, он открытый либо
    ///   ссылка не действует.
    /// * [`GasAppError::Forbidden`] — аккаунт удалён из этого канала.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn request_channel_join(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &JoinChannelRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.reader_action(
            device_id,
            channel_id,
            "join",
            Some(to_json(request)?),
            signer,
        )
    }

    /// Что с заявкой: ждёт, одобрена (тогда — с ответом) либо её нет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn channel_join_status(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<ChannelJoinStatusResponse> {
        parse(&self.member_get(device_id, channel_id, "join", signer)?)
    }

    /// Заявки, ждущие ответа, — для того, кто ведёт канал.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_join_requests(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelJoinRequestResponse>> {
        let channel_id = canonical_uuid(channel_id)?;

        parse(&self.send_signed(
            Method::Get,
            format!("/v1/channels/own/{device_id}/{channel_id}/requests"),
            None,
            signer,
        )?)
    }

    /// Одобряет (с ответом) либо отклоняет заявку.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет либо
    ///   заявки уже нет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn answer_channel_join(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &AnswerChannelJoinRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;
        // Аккаунт приходит от сервера — в запрос уходит только UUID.
        let request = AnswerChannelJoinRequest {
            account_id: canonical_uuid(&request.account_id)?,
            grant: request.grant.clone(),
        };

        self.send_signed(
            Method::Post,
            format!("/v1/channels/own/{device_id}/{channel_id}/requests"),
            Some(to_json(&request)?),
            signer,
        )?;

        Ok(())
    }

    /// Подписчики канала, страницей после аккаунта `after`.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_subscribers(
        &self,
        device_id: &str,
        channel_id: &str,
        after: Option<&str>,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelMemberResponse>> {
        let channel_id = canonical_uuid(channel_id)?;
        let path = match after {
            Some(after) => format!(
                "/v1/channels/own/{device_id}/{channel_id}/subscribers?after={}",
                canonical_uuid(after)?
            ),
            None => format!("/v1/channels/own/{device_id}/{channel_id}/subscribers"),
        };

        parse(&self.send_signed(Method::Get, path, None, signer)?)
    }

    /// Удалённые из канала — кому можно вернуть право подать заявку.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_bans(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelMemberResponse>> {
        let channel_id = canonical_uuid(channel_id)?;

        parse(&self.send_signed(
            Method::Get,
            format!("/v1/channels/own/{device_id}/{channel_id}/bans"),
            None,
            signer,
        )?)
    }

    /// Удаляет подписчика из канала (`unban == false`) либо снимает с
    /// удалённого запрет на новую заявку.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет.
    /// * [`GasAppError::Malformed`] — удаляют того, кто сам ведёт канал.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn remove_channel_subscriber(
        &self,
        device_id: &str,
        channel_id: &str,
        account_id: &str,
        unban: bool,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;
        let request = ChannelMemberRequest {
            account_id: canonical_uuid(account_id)?,
        };
        let what = if unban { "bans" } else { "subscribers" };

        self.send_signed(
            Method::Delete,
            format!("/v1/channels/own/{device_id}/{channel_id}/{what}"),
            Some(to_json(&request)?),
            signer,
        )?;

        Ok(())
    }

    /// Закрытый канал — участнику, **за подписью**: сервер отдаёт его
    /// только тем, кого одобрили.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канала нет либо аккаунт не
    ///   участник (удалён).
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn member_channel_info(
        &self,
        device_id: &str,
        channel_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<ChannelResponse> {
        parse(&self.member_get(device_id, channel_id, "info", signer)?)
    }

    /// Изменения закрытого канала после ревизии — участнику.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт не участник.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn member_channel_changes(
        &self,
        device_id: &str,
        channel_id: &str,
        after_rev: u64,
        limit: u32,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelPostResponse>> {
        parse(&self.member_get(
            device_id,
            channel_id,
            &format!("posts?after_rev={after_rev}&limit={limit}"),
            signer,
        )?)
    }

    /// Страница ленты закрытого канала — участнику.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт не участник.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn member_channel_page(
        &self,
        device_id: &str,
        channel_id: &str,
        before_seq: Option<u64>,
        limit: u32,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelPostResponse>> {
        let what = match before_seq {
            Some(before) => format!("posts?before_seq={before}&limit={limit}"),
            None => format!("posts?limit={limit}"),
        };

        parse(&self.member_get(device_id, channel_id, &what, signer)?)
    }

    /// Медиаблоб закрытого канала — участнику.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — блоба нет либо аккаунт не
    ///   участник.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn member_download_channel_media(
        &self,
        device_id: &str,
        channel_id: &str,
        media_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<u8>> {
        let media_id = canonical_uuid(media_id)?;

        Ok(self
            .member_get(device_id, channel_id, &format!("media/{media_id}"), signer)?
            .binary_body)
    }

    /// Чтение от имени участника канала — `GET` за подписью устройства.
    fn member_get(
        &self,
        device_id: &str,
        channel_id: &str,
        what: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<HttpResponse> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            Method::Get,
            format!("/v1/channels/reader/{device_id}/{channel_id}/{what}"),
            None,
            signer,
        )
    }

    /// Просит токен под имя будущего бота. Только с премиумом.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — у аккаунта нет премиума.
    /// * [`GasAppError::UsernameTaken`] — имя занято.
    /// * [`GasAppError::Malformed`] — имя не годится боту.
    /// * [`GasAppError::Network`] — сбой соединения либо у владельца
    ///   предел ботов.
    pub fn create_bot(
        &self,
        device_id: &str,
        request: &BotNameRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<BotTokenResponse> {
        parse(&self.send_signed(
            Method::Post,
            format!("/v1/bots/own/{device_id}"),
            Some(to_json(request)?),
            signer,
        )?)
    }

    /// Боты аккаунта.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения.
    pub fn bots(
        &self,
        device_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<BotResponse>> {
        parse(&self.send_signed(
            Method::Get,
            format!("/v1/bots/own/{device_id}"),
            None,
            signer,
        )?)
    }

    /// Удаляет бота аккаунта вместе с его аккаунтом.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — такого бота у аккаунта нет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn delete_bot(
        &self,
        device_id: &str,
        request: &BotNameRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.send_signed(
            Method::Delete,
            format!("/v1/bots/own/{device_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Регистрирует бота по токену владельца. Без подписи: аккаунта у
    /// программы бота ещё нет.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Forbidden`] — токен не принят.
    /// * [`GasAppError::InvalidSignature`] — proof-of-work не принят.
    /// * [`GasAppError::UsernameTaken`] — имя успели занять.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn register_bot(&self, request: &RegisterBotRequest) -> Result<RegisterResponse> {
        parse(&self.send(
            Method::Post,
            "/v1/bots/register".to_owned(),
            Some(to_json(request)?),
        )?)
    }

    /// Называет серверу ключ доставки участника закрытого канала: под
    /// него тот, кто ведёт канал, зашифрует ключ следующей эпохи.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — канал открытый либо аккаунт
    ///   не участник.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn set_channel_member_key(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &ChannelMemberKeyRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.reader_action(
            device_id,
            channel_id,
            "key",
            Some(to_json(request)?),
            signer,
        )
    }

    /// Ключи доставки участников — страницей после аккаунта `after`;
    /// с `missing` — только тех, у кого нет ключа действующей эпохи.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_member_keys(
        &self,
        device_id: &str,
        channel_id: &str,
        missing: bool,
        after: Option<&str>,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelMemberKeyResponse>> {
        let channel_id = canonical_uuid(channel_id)?;
        let mut path = format!("/v1/channels/own/{device_id}/{channel_id}/keys?missing={missing}");

        if let Some(after) = after {
            path.push_str("&after=");
            path.push_str(&canonical_uuid(after)?);
        }

        parse(&self.send_signed(Method::Get, path, None, signer)?)
    }

    /// Меняет ключ канала (в запросе есть звено) либо досылает ключи
    /// действующей эпохи.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт в канал не пишет либо
    ///   канал открытый.
    /// * [`GasAppError::UsernameTaken`] — эпоха не та (`409`): ключ успел
    ///   сменить кто-то ещё.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn rekey_channel(
        &self,
        device_id: &str,
        channel_id: &str,
        request: &RekeyChannelRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let channel_id = canonical_uuid(channel_id)?;

        self.send_signed(
            Method::Post,
            format!("/v1/channels/own/{device_id}/{channel_id}/keys"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Звенья цепочки ключей с номером больше `after` — участнику.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — аккаунт не участник.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn channel_epochs(
        &self,
        device_id: &str,
        channel_id: &str,
        after: u32,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<ChannelEpochResponse>> {
        parse(&self.member_get(
            device_id,
            channel_id,
            &format!("epochs?after={after}"),
            signer,
        )?)
    }

    /// Перепривязывает аккаунт к новой identity (восстановление
    /// на новом устройстве). Без подписи устройства: право доказывает
    /// подпись ключа восстановления внутри запроса.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения либо отказ сервера
    /// (не тот ключ, нет такого имени, повтор запроса — одинаково).
    pub fn recover_account(&self, request: &RecoverAccountRequest) -> Result<RegisterResponse> {
        let response = self.send(
            Method::Post,
            "/v1/accounts/recover".to_owned(),
            Some(to_json(request)?),
        )?;

        parse(&response)
    }

    /// Ищет аккаунт по имени.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — имени нет.
    /// * [`GasAppError::Network`] — сбой соединения либо превышен лимит
    ///   частоты: повторить запрос имеет смысл позже, поэтому вариант
    ///   тот же, что у сетевого сбоя.
    pub fn discover(&self, username: &str) -> Result<DiscoveryResponse> {
        // 🔐 Неканоничное имя на сервер не уходит: такого аккаунта
        // нет и быть не может, а запрос выдал бы, кого искали.
        if !gasapp_types::is_canonical_username(username) {
            return Err(GasAppError::InvalidUsername);
        }

        let response = self.send(
            Method::Get,
            format!("/v1/discovery/username/{username}"),
            None,
        )?;

        parse(&response)
    }

    /// Публикует предключи устройства.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое, [`GasAppError::Malformed`]
    /// при отказе сервера.
    pub fn publish_keys(
        &self,
        device_id: &str,
        request: &PublishKeysRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let response = self.send_signed(
            Method::Put,
            format!("/v1/keys/{device_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        check_status(&response)
    }

    /// Забирает prekey bundle, расходуя одноразовый ключ получателя.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — устройства нет либо ключи
    ///   не опубликованы.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn fetch_bundle(&self, device_id: &str) -> Result<BundleResponse> {
        let response = self.send(Method::Get, format!("/v1/keys/{device_id}/bundle"), None)?;

        parse(&response)
    }

    /// Сколько одноразовых предключей осталось.
    ///
    /// Клиент опрашивает это, чтобы вовремя пополнить пул: ждать полного
    /// исчерпания значило бы оставить собеседников без forward secrecy
    /// первого сообщения.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения.
    pub fn prekey_count(&self, device_id: &str) -> Result<i64> {
        let response = self.send(Method::Get, format!("/v1/keys/{device_id}/count"), None)?;

        parse(&response)
    }

    /// Отправляет запечатанный конверт, не называя отправителя.
    ///
    /// # 🔐 Единственный путь отправки
    ///
    /// Запрос не подписывается: сервер не узнаёт, кто отправитель.
    /// Право на отправку доказывается ключом доступа получателя,
    /// который тот раздал своим собеседникам внутри переписки, а для
    /// первого сообщения — proof-of-work над конвертом. Подписанной
    /// отправки у сервера нет.
    ///
    /// Что сервер всё равно видит: IP отправителя и время. От этого
    /// защищает Tor или прокси (ADR-024), а не sealed sender.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — конверт превышает лимит;
    /// * [`GasAppError::Network`] — сбой соединения, лимит частоты
    ///   либо получатель не принимает анонимные сообщения.
    pub fn send_sealed(&self, request: &SealedSendRequest) -> Result<String> {
        let response = self.send(
            Method::Post,
            "/v1/sealed/messages".to_owned(),
            Some(to_json(request)?),
        )?;

        parse(&response)
    }

    /// Публикует ключ доступа sealed sender.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения.
    pub fn publish_sealed_access(
        &self,
        device_id: &str,
        request: &SealedAccessRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        self.send_signed(
            Method::Put,
            format!("/v1/sealed/access/{device_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        Ok(())
    }

    /// Забирает свежий сертификат отправителя.
    ///
    /// Вызывается раз в сутки: сертификат живёт 24 часа (раздел 15.2).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения.
    pub fn fetch_certificate(
        &self,
        device_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<CertificateResponse> {
        let response = self.send_signed(
            Method::Get,
            format!("/v1/sealed/certificate/{device_id}"),
            None,
            signer,
        )?;

        parse(&response)
    }

    /// Жалуется на отправителя, раскрытого из запечатанного конверта.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения.
    pub fn report_sealed_sender(
        &self,
        device_id: &str,
        request: &SealedReportRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<SealedReportResponse> {
        let response = self.send_signed(
            Method::Post,
            format!("/v1/sealed/report/{device_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        parse(&response)
    }

    /// Забирает ожидающие конверты.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения.
    pub fn fetch_envelopes(
        &self,
        device_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<Vec<EnvelopeResponse>> {
        let response = self.send_signed(
            Method::Get,
            format!("/v1/messages/{device_id}"),
            None,
            signer,
        )?;

        parse(&response)
    }

    /// Подтверждает доставку: сервер удаляет конверт немедленно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения.
    pub fn acknowledge(
        &self,
        device_id: &str,
        envelope_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<()> {
        let response = self.send_signed(
            Method::Delete,
            format!("/v1/messages/{device_id}/{envelope_id}"),
            None,
            signer,
        )?;

        check_status(&response)
    }

    /// Сколько одноразовых предключей осталось у устройства на сервере.
    ///
    /// # 🔐 Зачем спрашивать сервер, а не считать у себя
    ///
    /// Одноразовый ключ вычёркивается, когда его **забирает
    /// отправитель**. Владелец об этом не узнаёт: его локальный
    /// список не меняется. Значит единственный, кто знает настоящий
    /// остаток, — сервер.
    ///
    /// Без этого запроса вычерпанный чужими пул выглядит полным,
    /// и пополнение не срабатывает никогда.
    ///
    /// Маршрут требует подписи: остаток говорит о том, насколько
    /// активно с устройством начинают переписку.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidSignature`] — подпись не принята.
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn count_one_time_prekeys(
        &self,
        device_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<i64> {
        let response = self.send_signed(
            Method::Get,
            format!("/v1/keys/{device_id}/count"),
            None,
            signer,
        )?;

        parse(&response)
    }

    /// 🔐 Удаляет аккаунт целиком (MASVS PRIVACY-3.2).
    ///
    /// Адресуется устройством: право доказывается подписью, а
    /// подписывает устройство. Аккаунт сервер находит сам — иначе
    /// клиент назвал бы чужой.
    ///
    /// ⚠️ Уносит **все** устройства аккаунта, а не только это.
    /// Это и есть удаление аккаунта, а не выход с одного телефона.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidSignature`] — подпись не принята либо
    ///   аккаунт уже удалён: сервер не различает эти случаи, чтобы
    ///   не отвечать на вопрос «существовал ли такой аккаунт».
    /// * [`GasAppError::Network`] — сбой соединения.
    pub fn delete_account(
        &self,
        device_id: &str,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<AccountDeletedResponse> {
        let response = self.send_signed(
            Method::Delete,
            format!("/v1/accounts/{device_id}"),
            None,
            signer,
        )?;

        parse(&response)
    }

    /// Выполняет запрос и переводит код ответа в ошибку домена.
    fn send(&self, method: Method, path: String, body: Option<String>) -> Result<HttpResponse> {
        // Без подписи — значит, анонимно (см. `HttpRequest::anonymous`).
        self.execute(method, path, body, Vec::new(), true)
    }

    /// Выполняет запрос за подписью устройства.
    ///
    /// Подписываются ровно метод, путь и тело, которые уходят в сеть
    /// (см. [`crate::auth::RequestSigner`]). Приватного ключа здесь нет:
    /// подпись делает ядро.
    fn send_signed(
        &self,
        method: Method,
        path: String,
        body: Option<String>,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<HttpResponse> {
        // Сервер сверяет подпись с путём без строки запроса. Параметры
        // после `?` поэтому не подписаны: ими выбирают только страницу
        // выдачи, прав они не дают.
        let signed_path = path.split('?').next().unwrap_or(&path);
        let headers = crate::auth::signature_headers(
            signer,
            method.as_str(),
            signed_path,
            body.as_deref().unwrap_or("").as_bytes(),
        )?;

        self.execute(method, path, body, headers, false)
    }

    /// Выполняет запрос с готовыми заголовками.
    fn execute(
        &self,
        method: Method,
        path: String,
        body: Option<String>,
        headers: Vec<(String, String)>,
        anonymous: bool,
    ) -> Result<HttpResponse> {
        let response = self.transport.execute(&HttpRequest {
            method,
            path,
            body,
            binary_body: None,
            headers,
            anonymous,
        })?;

        check_status(&response)?;

        Ok(response)
    }

    /// Загружает зашифрованное вложение — **без подписи**.
    ///
    /// Возвращает адрес блоба: он уходит получателю внутри сообщения.
    ///
    /// # 🔐 Почему анонимно
    ///
    /// Прежде загрузка была подписана устройством, и сервер помнил,
    /// кто и в какой час прислал каждый файл. Теперь право на место
    /// доказывается proof-of-work над самим блобом
    /// (`pow::upload_challenge`), и загрузчик серверу неизвестен.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] при сбое соединения;
    /// [`GasAppError::Malformed`] — сервер вернул не адрес.
    pub fn upload_attachment(&self, payload: Vec<u8>, pow_nonce: u64) -> Result<String> {
        let response = self.transport.execute(&HttpRequest {
            method: Method::Post,
            path: "/v1/attachments/blob".to_owned(),
            body: None,
            binary_body: Some(payload),
            headers: vec![(UPLOAD_POW_HEADER.to_owned(), pow_nonce.to_string())],
            anonymous: true,
        })?;

        check_status(&response)?;

        parse(&response)
    }

    /// Скачивает шифроблоб вложения — **без подписи**.
    ///
    /// # 🔐 Почему анонимно
    ///
    /// Загружает вложение отправитель за своей подписью. Прежде и
    /// скачивал получатель за своей — по тому же идентификатору, и
    /// сервер видел пару «кто загрузил → кто скачал», то есть кто кому
    /// прислал файл. Sealed sender прятал отправителя сообщения,
    /// а вложение выдавало обоих.
    ///
    /// Идентификатор — случайные 128 бит, которые знает только тот,
    /// кому их передали внутри E2EE-сообщения, а содержимое зашифровано
    /// ключом из того же сообщения. Подпись скачивающего ничего не
    /// защищала, кроме этой связи.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — вложения нет или оно истекло.
    pub fn download_attachment(&self, attachment_id: &str) -> Result<Vec<u8>> {
        // 🔐 Адрес приходит от собеседника (описание вложения) и иначе
        // попадал бы в путь как есть: `../../v1/keys/…/bundle?x=` — и
        // устройство жертвы, открыв вложение, ходило бы туда, куда велел
        // собеседник (аудит 2026-10-02, N-1). Сервер выдаёт адреса UUID —
        // только их и принимаем.
        let attachment_id = canonical_attachment_id(attachment_id)?;

        let response = self.send(
            Method::Get,
            format!("/v1/attachments/blob/{attachment_id}"),
            None,
        )?;

        Ok(response.binary_body)
    }

    /// Вершины журнала ключей начиная с эпохи `from` (без неё — окно
    /// истории). Анонимно: сервер не должен знать, кто сверяет журнал.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения или отказ сервера.
    pub fn kt_heads(&self, from: Option<u64>) -> Result<KtHeadsResponse> {
        let path = match from {
            Some(from) => format!("/v1/kt/heads/{from}"),
            None => "/v1/kt/heads".to_owned(),
        };
        let response = self.send(Method::Get, path, None)?;

        parse(&response)
    }

    /// Доказательства журнала ключей для индекса в эпохах. Анонимно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сбой соединения или отказ сервера.
    pub fn kt_proofs(&self, request: &KtProofsRequest) -> Result<KtProofsResponse> {
        let response = self.send(
            Method::Post,
            "/v1/kt/proofs".to_owned(),
            Some(to_json(request)?),
        )?;

        parse(&response)
    }
}

/// Переводит код ответа в ошибку домена.
///
/// # Про выбор вариантов
///
/// `401` — это отказ аутентификации, а не сетевой сбой: повторять
/// запрос бессмысленно, нужно заново подписать челлендж. `429`
/// наоборот попадает в [`GasAppError::Network`], потому что лечится
/// именно повтором — очередь возьмётся за него по backoff.
fn check_status(response: &HttpResponse) -> Result<()> {
    match response.status {
        200..=299 => Ok(()),
        401 => Err(GasAppError::InvalidSignature),
        // 403 — права нет: код из письма не принят либо нет премиума.
        // Что именно, уточняет вызывающий метод.
        403 => Err(GasAppError::Forbidden),
        404 => Err(GasAppError::SessionNotFound),
        // 409 сервер отдаёт только на занятое имя при регистрации.
        409 => Err(GasAppError::UsernameTaken),
        // 422 сервер отдаёт только на занятый адрес почты.
        422 => Err(GasAppError::EmailTaken),
        // 429 и 5xx лечатся повтором, поэтому попадают в очередь.
        429 | 500..=599 => Err(GasAppError::Network),
        _ => Err(GasAppError::Malformed),
    }
}

/// Сериализует запрос.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| GasAppError::Malformed)
}

/// Разбирает тело ответа.
///
/// Ошибка разбора — [`GasAppError::Malformed`]: сервер прислал не то,
/// что обещает контракт, и продолжать на таком ответе нельзя.
fn parse<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T> {
    serde_json::from_str(&response.body).map_err(|_| GasAppError::Malformed)
}

/// Адрес вложения — UUID в каноническом виде (`8-4-4-4-12`, строчные), иначе отказ.
///
/// Так сервер и выдаёт адреса (`Json<Uuid>`). Всё прочее — не адрес,
/// а попытка собеседника вписать в путь что-то своё.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — не UUID.
fn canonical_attachment_id(raw: &str) -> Result<String> {
    canonical_uuid(raw)
}

/// UUID в каноничном виде (`8-4-4-4-12`, строчные), иначе отказ.
///
/// Идентификатор канала приходит из ссылки, то есть извне: в путь
/// запроса попадает только то, что выглядит как UUID.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — не UUID.
fn canonical_uuid(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let well_formed = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });

    if well_formed {
        Ok(raw.to_ascii_lowercase())
    } else {
        Err(GasAppError::Malformed)
    }
}

/// Публичное имя канала в каноничном виде: без `@`, строчные латинские
/// буквы, цифры и `_`, с буквы, 3–32 знака.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не имя канала.
pub fn canonical_handle(raw: &str) -> Result<String> {
    let handle = canonical_handle_prefix(raw)?;

    if handle.len() >= 3
        && handle
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
    {
        Ok(handle)
    } else {
        Err(GasAppError::Malformed)
    }
}

/// Начало публичного имени — для поиска: те же знаки, от двух.
fn canonical_handle_prefix(raw: &str) -> Result<String> {
    let handle = raw.trim().trim_start_matches('@').to_ascii_lowercase();

    let well_formed = (2..=32).contains(&handle.len())
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');

    if well_formed {
        Ok(handle)
    } else {
        Err(GasAppError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// 🔐 Адрес вложения от собеседника не попадает в путь как есть.
    #[test]
    fn attachment_id_must_be_a_uuid() {
        let api = ApiClient::new(FakeTransport::with(200, ""));

        for hostile in [
            "../../v1/keys/00000000-0000-0000-0000-000000000000/bundle",
            "00000000-0000-0000-0000-000000000000/../../health",
            "00000000-0000-0000-0000-000000000000?x=1",
            "00000000-0000-0000-0000-00000000000%",
            "",
            "blob-1",
        ] {
            assert!(
                matches!(
                    api.download_attachment(hostile),
                    Err(GasAppError::Malformed)
                ),
                "принят адрес {hostile:?}"
            );
        }
        assert!(api.transport.seen.borrow().is_empty(), "запрос ушёл");

        api.download_attachment("3F2504E0-4F89-11D3-9A0C-0305E82C3301")
            .expect("канонический UUID");
        assert_eq!(
            api.transport.last_request().path,
            "/v1/attachments/blob/3f2504e0-4f89-11d3-9a0c-0305e82c3301"
        );
    }

    /// Транспорт-двойник: записывает запросы и отдаёт заданные ответы.
    ///
    /// Существует, потому что клиент проверяется **без сети**: важно,
    /// какой запрос он формирует и как разбирает ответ, а не то, умеет
    /// ли платформа открывать сокеты.
    struct FakeTransport {
        responses: RefCell<Vec<HttpResponse>>,
        seen: RefCell<Vec<HttpRequest>>,
    }

    impl FakeTransport {
        fn with(status: u16, body: &str) -> Self {
            Self {
                responses: RefCell::new(vec![HttpResponse {
                    binary_body: Vec::new(),
                    status,
                    body: body.to_owned(),
                }]),
                seen: RefCell::new(Vec::new()),
            }
        }

        fn last_request(&self) -> HttpRequest {
            self.seen.borrow().last().cloned().expect("запрос выполнен")
        }
    }

    impl Transport for FakeTransport {
        fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
            self.seen.borrow_mut().push(request.clone());

            self.responses
                .borrow_mut()
                .pop()
                .ok_or(GasAppError::Network)
        }
    }

    /// Подписывающая сторона для тестов: подпись — само сообщение.
    ///
    /// По ней видно, что именно подписано: метод, путь, время и хеш тела.
    struct TestSigner;

    impl crate::auth::RequestSigner for TestSigner {
        fn issued_at(&self) -> i64 {
            1_700_000_000_000
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            Ok(message.to_vec())
        }
    }

    fn header<'a>(request: &'a HttpRequest, name: &str) -> &'a str {
        request
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map_or_else(
                || panic!("нет заголовка {name}"),
                |(_, value)| value.as_str(),
            )
    }

    fn register_request() -> RegisterRequest {
        RegisterRequest {
            username: "alice".to_owned(),
            identity_key: "aa".to_owned(),
            device_identity_key: "bb".to_owned(),
            pq_identity_key: "dd".to_owned(),
            identity_binding: "ee".to_owned(),
            recovery_key: None,
            recovery_pq_key: None,
            email: "alice@example.org".to_owned(),
            email_code: "123456".to_owned(),
            pow_challenge: "cc".to_owned(),
            pow_nonce: 7,
        }
    }

    #[test]
    fn register_builds_expected_request() {
        let transport = FakeTransport::with(200, r#"{"account_id":"acc-1","device_id":"dev-1"}"#);
        let client = ApiClient::new(transport);

        let response = client.register(&register_request()).unwrap();

        assert_eq!(response.account_id, "acc-1");
        assert_eq!(response.device_id, "dev-1");

        let sent = client.transport.last_request();
        assert_eq!(sent.method, Method::Post);
        assert_eq!(sent.path, "/v1/accounts/register");
        assert!(sent.body.unwrap_or_default().contains("alice"));
    }

    #[test]
    fn discovery_encodes_username_in_path() {
        let transport = FakeTransport::with(200, r#"{"account_id":"acc-1","identity_key":"aa"}"#);
        let client = ApiClient::new(transport);

        client.discover("bob").unwrap();

        assert_eq!(
            client.transport.last_request().path,
            "/v1/discovery/username/bob"
        );
    }

    /// Занятое имя — своей ошибкой, а не «запрос отвергнут»: интерфейс
    /// показывал его как сбой сети, и человек регистрировался снова
    /// с тем же именем.
    #[test]
    fn a_taken_username_is_not_a_generic_refusal() {
        let client = ApiClient::new(FakeTransport::with(409, ""));

        assert!(matches!(
            client.register(&register_request()),
            Err(GasAppError::UsernameTaken)
        ));
    }

    /// 🔐 Неизвестное имя — не сетевой сбой.
    ///
    /// Разница важна для очереди: отсутствующий контакт повторным
    /// запросом не появится, а сетевой сбой лечится именно повтором.
    #[test]
    fn missing_account_is_not_a_network_error() {
        let client = ApiClient::new(FakeTransport::with(404, ""));

        assert!(matches!(
            client.discover("ghost"),
            Err(GasAppError::SessionNotFound)
        ));
    }

    /// 🔐 Отказ аутентификации не отправляется в очередь на повтор.
    #[test]
    fn unauthorized_is_reported_as_signature_failure() {
        let client = ApiClient::new(FakeTransport::with(401, ""));

        assert!(matches!(
            client.discover("bob"),
            Err(GasAppError::InvalidSignature)
        ));
    }

    /// Лимит частоты лечится повтором, поэтому это сетевая ошибка.
    #[test]
    fn rate_limit_is_retryable() {
        let client = ApiClient::new(FakeTransport::with(429, ""));

        assert!(matches!(client.discover("bob"), Err(GasAppError::Network)));
    }

    /// Сбой сервера тоже лечится повтором.
    #[test]
    fn server_error_is_retryable() {
        let client = ApiClient::new(FakeTransport::with(503, ""));

        assert!(matches!(client.discover("bob"), Err(GasAppError::Network)));
    }

    /// Ответ не по контракту отвергается, а не разбирается частично.
    #[test]
    fn malformed_response_is_rejected() {
        let client = ApiClient::new(FakeTransport::with(200, "не json"));

        assert!(matches!(
            client.discover("bob"),
            Err(GasAppError::Malformed)
        ));
    }

    #[test]
    fn bundle_is_parsed_with_degraded_flag() {
        let body = r#"{
            "device_id":"dev-1","identity_key":"aa",
            "signed_key_id":1,"signed_public":"bb","signed_signature":"cc",
            "kem_key_id":2,"kem_public":"dd","kem_signature":"ee",
            "one_time":null,"one_time_kem":null,"degraded":true
        }"#;
        let client = ApiClient::new(FakeTransport::with(200, body));

        let bundle = client.fetch_bundle("dev-1").unwrap();

        assert!(bundle.degraded, "исчерпание пула должно быть видно клиенту");
        assert!(bundle.one_time.is_none());
    }

    #[test]
    fn envelopes_are_fetched_as_list() {
        let body =
            r#"[{"envelope_id":"env-1","ciphertext":"aabb","queued_at_bucketed":1700000000}]"#;
        let client = ApiClient::new(FakeTransport::with(200, body));

        let envelopes = client.fetch_envelopes("dev-1", &TestSigner).unwrap();

        assert_eq!(envelopes.len(), 1);
        assert_eq!(
            envelopes.first().map(|e| e.ciphertext.as_str()),
            Some("aabb")
        );
    }

    /// Метка времени приходит округлённой — клиент её не уточняет.
    #[test]
    fn queued_time_stays_bucketed() {
        let body = r#"[{"envelope_id":"e","ciphertext":"aa","queued_at_bucketed":1699999200}]"#;
        let client = ApiClient::new(FakeTransport::with(200, body));

        let envelopes = client.fetch_envelopes("dev-1", &TestSigner).unwrap();
        let bucketed = envelopes.first().map_or(1, |e| e.queued_at_bucketed);

        assert_eq!(bucketed % 3600, 0);
    }

    #[test]
    fn acknowledge_uses_delete_with_both_ids() {
        let client = ApiClient::new(FakeTransport::with(204, ""));

        client.acknowledge("dev-1", "env-1", &TestSigner).unwrap();

        let sent = client.transport.last_request();
        assert_eq!(sent.method, Method::Delete);
        assert_eq!(sent.path, "/v1/messages/dev-1/env-1");
        assert!(sent.body.is_none());
    }

    #[test]
    fn publish_keys_sends_put_with_body() {
        let client = ApiClient::new(FakeTransport::with(204, ""));
        let request = PublishKeysRequest {
            signed_key_id: 1,
            signed_public: "aa".to_owned(),
            signed_signature: "bb".to_owned(),
            kem_key_id: 2,
            kem_public: "cc".to_owned(),
            kem_signature: "dd".to_owned(),
            one_time: vec![(10, "ee".to_owned())],
            one_time_kem: Vec::new(),
            sealed_kem_public: None,
            sealed_kem_signature: None,
            pq_identity_key: None,
            identity_binding: None,
        };

        client.publish_keys("dev-1", &request, &TestSigner).unwrap();

        let sent = client.transport.last_request();
        assert_eq!(sent.method, Method::Put);
        assert_eq!(sent.path, "/v1/keys/dev-1");
        assert!(sent.body.is_some());
    }

    /// 🔐 Подписано ровно отправленное тело: хеш в заголовке и в подписи —
    /// от тех байтов, что ушли в сеть. В v1 тела в подписи не было,
    /// и подпись `PUT` предключей подходила к любым предключам.
    #[test]
    fn a_signed_request_covers_the_body_it_sends() {
        let client = ApiClient::new(FakeTransport::with(204, ""));
        let request = PublishKeysRequest {
            signed_key_id: 1,
            signed_public: "aa".to_owned(),
            signed_signature: "bb".to_owned(),
            kem_key_id: 2,
            kem_public: "cc".to_owned(),
            kem_signature: "dd".to_owned(),
            one_time: Vec::new(),
            one_time_kem: Vec::new(),
            sealed_kem_public: None,
            sealed_kem_signature: None,
            pq_identity_key: None,
            identity_binding: None,
        };

        client.publish_keys("dev-1", &request, &TestSigner).unwrap();

        let sent = client.transport.last_request();
        let body = sent.body.clone().expect("тело");
        let digest = crate::auth::body_sha256(body.as_bytes());
        let expected =
            crate::auth::signed_message("PUT", "/v1/keys/dev-1", 1_700_000_000_000, &digest);

        let hex = crate::auth::to_hex;

        assert_eq!(header(&sent, crate::auth::BODY_SHA256_HEADER), hex(&digest));
        assert_eq!(header(&sent, crate::auth::SIGNATURE_HEADER), hex(&expected));
        assert_eq!(
            header(&sent, crate::auth::ISSUED_AT_HEADER),
            "1700000000000"
        );
    }

    /// Сбой транспорта доходит до вызывающего как сетевая ошибка.
    #[test]
    fn transport_failure_propagates() {
        struct Failing;

        impl Transport for Failing {
            fn execute(&self, _: &HttpRequest) -> Result<HttpResponse> {
                Err(GasAppError::Network)
            }
        }

        let client = ApiClient::new(Failing);

        assert!(matches!(client.discover("bob"), Err(GasAppError::Network)));
    }

    #[test]
    fn method_names_match_protocol() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Method::Put.as_str(), "PUT");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }

    /// Загрузка медиа канала подписана и покрывает сырое тело.
    #[test]
    fn channel_media_upload_is_signed_over_the_blob() {
        let transport = FakeTransport::with(
            200,
            r#"{"media_id":"6F9619FF-8B86-D011-B42D-00C04FC964FF"}"#,
        );
        let client = ApiClient::new(transport);

        let media_id = client
            .upload_channel_media(
                "dev",
                "6f9619ff-8b86-d011-b42d-00c04fc964ff",
                vec![1, 2, 3],
                &TestSigner,
            )
            .expect("upload");

        assert_eq!(media_id, "6f9619ff-8b86-d011-b42d-00c04fc964ff");

        let request = client.transport.last_request();
        assert!(!request.anonymous);
        assert_eq!(request.binary_body.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(
            header(&request, crate::auth::BODY_SHA256_HEADER),
            crate::auth::to_hex(&crate::auth::body_sha256(&[1, 2, 3]))
        );
    }

    /// 🔐 Имя канала и адрес блоба приходят извне: в путь попадает
    /// только каноничный вид.
    #[test]
    fn channel_paths_take_only_canonical_parts() {
        let client = ApiClient::new(FakeTransport::with(200, "[]"));

        assert!(client.channel_by_handle("../v1/keys").is_err());
        assert!(client.channel_by_handle("ab").is_err());
        assert!(client.channel_by_handle("1news").is_err());
        assert!(client
            .download_channel_media("6f9619ff-8b86-d011-b42d-00c04fc964ff", "../x")
            .is_err());

        // Негодный поиск до сети не доходит.
        assert!(client
            .search_channels("a&limit=9")
            .expect("empty")
            .is_empty());
        assert!(client.transport.seen.borrow().is_empty());

        client.search_channels(" @Gas_News ").expect("search");
        assert_eq!(
            client.transport.last_request().path,
            "/v1/channels/search?q=gas_news"
        );
    }

    /// 🔐 Подписчик — аккаунт: его действия подписаны устройством.
    #[test]
    fn reader_actions_are_signed() {
        let client = ApiClient::new(FakeTransport::with(204, ""));

        client
            .mark_channel_seen(
                "dev",
                "6f9619ff-8b86-d011-b42d-00c04fc964ff",
                &ChannelSeenRequest { seq: 7 },
                &TestSigner,
            )
            .expect("seen");

        let request = client.transport.last_request();
        assert!(!request.anonymous);
        assert!(!header(&request, crate::auth::SIGNATURE_HEADER).is_empty());
        assert_eq!(
            request.path,
            "/v1/channels/reader/dev/6f9619ff-8b86-d011-b42d-00c04fc964ff/seen"
        );
    }
}
