// SPDX-License-Identifier: Apache-2.0

//! Граница FFI мессенджера: регистрация, отправка, приём.
//!
//! # Почему HTTP делает платформа, а не Rust
//!
//! Транспорт объявлен колбэком ([`HttpTransport`]), который реализует
//! Kotlin или Swift. Свой TLS-стек внутри Rust обошёл бы платформенные
//! настройки — то есть отключил бы и пиннинг из
//! `network_security_config.xml`, и системные отзывы сертификатов,
//! и корпоративные политики. Пиннинг, который можно обойти изнутри
//! приложения, не защищает ни от чего.
//!
//! # Что пересекает границу
//!
//! Только публичные данные и открытый текст сообщений, который UI
//! обязан показать. Приватные ключи не пересекают её **никогда**:
//! они рождаются в ядре, живут в зашифрованном хранилище и там же
//! используются.

use std::sync::Mutex;

use aegis_core::client::Client;
use aegis_net::client::{HttpRequest, HttpResponse, Transport};
use aegis_storage::Storage;
use aegis_types::{AegisError, ChatId, Timestamp};

use crate::{guard, FfiError};

/// Транспорт HTTP, реализуемый платформой.
///
/// # Что обязана делать реализация
///
/// Выполнить запрос по базовому URL, вернуть код и тело. Сбой сети —
/// это ошибка; ответ 4xx/5xx — **не** ошибка, а успешный результат
/// с соответствующим кодом: клиент различает недоступность сервера
/// и его отказ, и реагирует на них по-разному.
#[uniffi::export(with_foreign)]
pub trait HttpTransport: Send + Sync {
    /// Выполняет запрос.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] при сбое соединения.
    fn execute(
        &self,
        method: String,
        path: String,
        body: Option<String>,
        headers: Vec<FfiHeader>,
    ) -> Result<FfiHttpResponse, FfiError>;
}


/// Заголовок HTTP.
///
/// Отдельная запись, а не карта: UniFFI не переносит `HashMap`
/// с произвольными ключами так же дёшево, а заголовков здесь два —
/// подпись и время выпуска.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiHeader {
    /// Имя заголовка.
    pub name: String,
    /// Значение.
    pub value: String,
}
/// Ответ HTTP, пришедший от платформы.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiHttpResponse {
    /// Код состояния.
    pub status: u16,
    /// Тело ответа.
    pub body: String,
}

/// Мост между колбэком платформы и внутренним трейтом транспорта.
struct ForeignTransport {
    inner: std::sync::Arc<dyn HttpTransport>,
}

impl Transport for ForeignTransport {
    fn execute(&self, request: &HttpRequest) -> aegis_types::Result<HttpResponse> {
        let response = self
            .inner
            .execute(
                request.method.as_str().to_owned(),
                request.path.clone(),
                request.body.clone(),
                request
                    .headers
                    .iter()
                    .map(|(name, value)| FfiHeader {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect(),
            )
            // Ошибка платформы означает недоступность сети. Различать
            // её причины здесь нельзя: текст исключения Kotlin в лог
            // ядра не пойдёт.
            .map_err(|_| AegisError::Network)?;

        Ok(HttpResponse {
            status: response.status,
            body: response.body,
        })
    }
}

/// Сведения о зарегистрированном аккаунте.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAccount {
    /// Идентификатор аккаунта.
    pub account_id: String,
    /// Идентификатор устройства: по нему адресуется доставка.
    pub device_id: String,
    /// Занятое имя пользователя.
    pub username: String,
}

/// Сообщение для показа в интерфейсе.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMessage {
    /// Идентификатор сообщения.
    pub message_id: String,
    /// Расшифрованный текст.
    pub text: String,
    /// Время в миллисекундах.
    pub timestamp: i64,
    /// Наше сообщение или входящее.
    pub outgoing: bool,
    /// Статус доставки.
    pub status: FfiDeliveryStatus,
}

/// Статус доставки сообщения.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiDeliveryStatus {
    /// Ждёт отправки.
    Pending,
    /// Отправлено на сервер.
    Sent,
    /// Доставлено получателю.
    Delivered,
    /// Прочитано.
    Read,
    /// Отправка не удалась.
    Failed,
}

impl From<aegis_storage::MessageStatus> for FfiDeliveryStatus {
    fn from(status: aegis_storage::MessageStatus) -> Self {
        match status {
            aegis_storage::MessageStatus::Pending => Self::Pending,
            aegis_storage::MessageStatus::Sent => Self::Sent,
            aegis_storage::MessageStatus::Delivered => Self::Delivered,
            aegis_storage::MessageStatus::Read => Self::Read,
            aegis_storage::MessageStatus::Failed => Self::Failed,
        }
    }
}

/// Мессенджер: то, чем пользуется приложение.
///
/// Владеет открытым хранилищем и транспортом. Создаётся после ввода
/// PIN — до него хранилище зашифровано и открыть его нечем.
#[derive(uniffi::Object)]
pub struct Messenger {
    // Mutex, а не RwLock: операции клиента изменяют состояние сессий,
    // и параллельная отправка двух сообщений в один чат провернула бы
    // храповик дважды из одного состояния, потеряв одно из них.
    client: Mutex<Client<ForeignTransport>>,
}

#[uniffi::export]
impl Messenger {
    /// Открывает мессенджер поверх зашифрованного хранилища.
    ///
    /// `database_key` — 32 байта, полученные растягиванием PIN через
    /// Argon2id. Ключ приходит готовым: растягивание живёт в
    /// `aegis-keystore`, где к нему привязано аппаратное хранилище.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — ключ не той длины;
    /// [`FfiError::Core`] — хранилище не открылось (неверный ключ
    /// или повреждение).
    #[uniffi::constructor]
    pub fn open(
        database_path: String,
        database_key: Vec<u8>,
        transport: std::sync::Arc<dyn HttpTransport>,
    ) -> Result<Self, FfiError> {
        let key: [u8; 32] = database_key
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::InvalidArgument)?;

        let storage = guard(|| Storage::new(&database_path, &key))?;

        Ok(Self {
            client: Mutex::new(Client::new(ForeignTransport { inner: transport }, storage)),
        })
    }

    /// Регистрирует новый аккаунт.
    ///
    /// Операция долгая: включает подбор proof-of-work. Вызывать её
    /// следует в фоновом потоке.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен либо имя занято.
    pub fn register(&self, username: String, now_millis: i64) -> Result<FfiAccount, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let account = guard(|| {
            client.register(
                &username,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })?;

        Ok(FfiAccount {
            account_id: account.account_id.to_string(),
            device_id: account.device_id.to_string(),
            username: account.username,
        })
    }

    /// Отправляет сообщение контакту по имени.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — контакт не найден, сервер недоступен либо
    /// подписи в prekey bundle не сходятся с identity-ключом владельца.
    pub fn send_message(
        &self,
        peer_username: String,
        text: String,
        now_millis: i64,
    ) -> Result<String, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let message_id = guard(|| {
            client.send_message(
                &peer_username,
                &text,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })?;

        Ok(message_id.to_string())
    }

    /// Забирает входящие сообщения и возвращает их число.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен либо аккаунт не
    /// зарегистрирован.
    pub fn receive_messages(
        &self,
        device_id: String,
        now_millis: i64,
    ) -> Result<u32, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let count = guard(|| {
            client.receive_messages(&device_id, Timestamp::from_millis(now_millis))
        })?;

        u32::try_from(count).map_err(|_| FfiError::InvalidArgument)
    }

    /// Перечисляет чаты в порядке последней активности.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn chats(&self) -> Result<Vec<String>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let chats = guard(|| client.chats())?;

        Ok(chats.iter().map(ToString::to_string).collect())
    }

    /// Возвращает сообщения чата.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор чата не разбирается;
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn messages(&self, chat_id: String, limit: u32) -> Result<Vec<FfiMessage>, FfiError> {
        let parsed = uuid::Uuid::parse_str(&chat_id).map_err(|_| FfiError::InvalidArgument)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let messages = guard(|| client.messages(&ChatId::from_uuid(parsed), limit))?;

        Ok(messages
            .into_iter()
            .map(|message| FfiMessage {
                message_id: message.message_id.to_string(),
                text: message.text,
                timestamp: message.timestamp.as_millis(),
                outgoing: message.outgoing,
                status: message.status.into(),
            })
            .collect())
    }
}
