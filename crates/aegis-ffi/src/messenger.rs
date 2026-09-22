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
use aegis_types::{AccountId, AegisError, ChatId, MessageId, Timestamp};

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
        binary_body: Option<Vec<u8>>,
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
/// Что исчезло вместе с аккаунтом.
///
/// 🔐 Показывается человеку после удаления. «Готово» без чисел ничем
/// не отличается от «готово» при запросе, который ничего не удалил,
/// а здесь проверить самому уже нечем: аккаунта, которым можно было бы
/// спросить, больше нет.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAccountDeletion {
    /// Сколько устройств было у аккаунта.
    pub devices: u64,
    /// Сколько недоставленных конвертов удалено.
    pub envelopes: u64,
    /// Сколько загруженных вложений удалено.
    ///
    /// ⚠️ Только загруженных этим аккаунтом. Присланные ему остаются:
    /// сервер не знает, кому они предназначались.
    pub attachments: u64,
}

/// Что сделало обслуживание предключей.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPreKeyMaintenance {
    /// Подписанный предключ заменён новым.
    pub rotated_signed: bool,
    /// Сколько одноразовых предключей добавлено.
    pub added_one_time: u32,
    /// Сколько их у сервера после обслуживания.
    pub remaining_one_time: u32,
}

/// Ответ HTTP, пришедший от платформы.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiHttpResponse {
    /// Код состояния.
    pub status: u16,
    /// Тело ответа.
    pub body: String,
    /// Тело ответа в сырых байтах — для скачанных вложений.
    ///
    /// Пусто для обычных ответов: они текстовые, и держать копию
    /// каждого JSON в байтах значило бы удваивать память на ровном
    /// месте.
    ///
    /// 🔐 Для вложений передаётся именно так, а не в hex: hex удваивает
    /// объём, и стомегабайтный файл занял бы двести мегабайт памяти
    /// на границе FFI.
    pub binary_body: Vec<u8>,
}

/// Мост между колбэком платформы и внутренним трейтом транспорта.
pub(crate) struct ForeignTransport {
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
                request.binary_body.clone(),
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
            binary_body: response.binary_body,
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

/// Контакт для показа в интерфейсе.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiContact {
    /// Идентификатор аккаунта.
    pub account_id: String,
    /// Identity-ключ, 32 байта.
    ///
    /// 🔐 Единственное, что определяет собеседника. Имя ниже —
    /// подсказка: его выбирает сам контакт.
    pub identity: Vec<u8>,
    /// Имя, если известно.
    pub username: Option<String>,
    /// Чат с контактом, если он заведён.
    pub chat_id: Option<String>,
    /// Подтверждён ли контакт сверкой safety number.
    pub verified: bool,
    /// 🔐 Это имя уже известно под **другим** ключом.
    ///
    /// Либо собеседник переустановил приложение или восстановился
    /// из копии, либо кто-то занял его имя, либо подсунутая ссылка
    /// выдаёт чужой ключ за его. Отличить может только сверка
    /// safety number вживую.
    ///
    /// ⚠️ Приложение обязано это показать. Добавление не отменяется
    /// и прежний контакт остаётся на месте: смена ключа заводит
    /// новую запись, а верификация старой на неё не переносится.
    pub key_changed: bool,
}

/// Найденное сообщение вместе с его чатом.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSearchHit {
    /// Чат, в котором найдено сообщение.
    pub chat_id: String,
    /// Само сообщение.
    pub message: FfiMessage,
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

impl Messenger {
    /// Берёт клиент под замком.
    ///
    /// Вынесено отдельным методом, потому что модуль `backup`
    /// обращается к клиенту так же часто, как этот: повторять
    /// `lock().map_err(...)` в каждой точке входа значит однажды
    /// написать иначе и получить панику через границу FFI.
    pub(crate) fn client(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Client<ForeignTransport>>, FfiError> {
        self.client.lock().map_err(|_| FfiError::Panic)
    }
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
    pub fn receive_messages(&self, device_id: String, now_millis: i64) -> Result<u32, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let count =
            guard(|| client.receive_messages(&device_id, Timestamp::from_millis(now_millis)))?;

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

/// Дополнительные операции хранилища.
#[uniffi::export]
impl Messenger {
    /// Удаляет истёкшие сообщения.
    ///
    /// 🔐 Вызывать **сразу после открытия** хранилища и затем
    /// периодически. Таймер в приложении работает, только пока оно
    /// запущено: сообщение с часовым сроком, полученное перед тем,
    /// как телефон убрали на неделю, пережило бы свой срок в семь раз.
    /// Изъятие устройства показало бы переписку, которую пользователь
    /// считает исчезнувшей.
    ///
    /// Возвращает число удалённых сообщений.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — удаление не удалось.
    pub fn purge_expired(&self, now_millis: i64) -> Result<u32, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let removed = guard(|| client.purge_expired(Timestamp::from_millis(now_millis)))?;

        u32::try_from(removed).map_err(|_| FfiError::InvalidArgument)
    }

    /// Задаёт таймер исчезающих сообщений для чата.
    ///
    /// `seconds` равное нулю выключает таймер.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор чата не разбирается;
    /// [`FfiError::Core`] — запись не удалась.
    pub fn set_disappearing_timer(&self, chat_id: String, seconds: u32) -> Result<(), FfiError> {
        let parsed = uuid::Uuid::parse_str(&chat_id).map_err(|_| FfiError::InvalidArgument)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.set_disappearing_timer(
                &ChatId::from_uuid(parsed),
                // Ноль означает «выключить»: отдельный флаг здесь был бы
                // лишним состоянием, которое можно рассогласовать.
                if seconds == 0 { None } else { Some(seconds) },
            )
        })
    }
}

/// Контакты и поиск.
#[uniffi::export]
impl Messenger {
    /// Добавляет контакт по ссылке `aegis://contact/...`.
    ///
    /// # 🔐 Про доверие к ссылке
    ///
    /// Ссылка не подписана и подписана быть не может — ключ как раз
    /// и передаётся. Если в ней есть имя, ядро сверяет его с тем,
    /// что зарегистрировано на сервере, и отказывает при расхождении.
    /// Это не делает сервер доверенным: ключ пришёл со ссылки, то есть
    /// из канала, которого сервер не видел.
    ///
    /// Приложение обязано показать пользователю, кого добавляет,
    /// **до** добавления.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — ссылка не разбирается, имя принадлежит
    /// другому ключу, контакт уже известен с другим ключом либо
    /// проверка через сервер не удалась.
    pub fn add_contact_from_link(
        &self,
        uri: String,
        now_millis: i64,
    ) -> Result<FfiContact, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let contact =
            guard(|| client.add_contact_from_link(&uri, Timestamp::from_millis(now_millis)))?;

        Ok(contact_to_ffi(&contact))
    }

    /// Safety number с контактом.
    ///
    /// 🔴 Прежде экран сверки считал цифры по двум **случайным** ключам
    /// (`generate_identity_public_key` дважды). Настоящих ключей
    /// в расчёте не было, и совпасть у собеседников цифры не могли.
    ///
    /// ⚠️ Контакт задаётся счётом, а не именем. Имя неоднозначно:
    /// после смены ключа под одним именем живут две записи, и поиск
    /// по имени мог бы показать цифры **прежнего** ключа — ровно
    /// в тот момент, когда сверка нужнее всего.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — счёт не разбирается;
    /// [`FfiError::Core`] — такого контакта нет либо свои ключи
    /// не прочитались.
    pub fn safety_number_with(&self, account_id: String) -> Result<String, FfiError> {
        let account = parse_account_id(&account_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.safety_number(&account))
    }

    /// Отмечает контакт сверенным или снимает отметку.
    ///
    /// 🔴 Прежде кнопка «Отметить сверенным» закрывала экран, и только.
    /// Отметку в продукте не ставил никто.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — счёт не разбирается;
    /// [`FfiError::Core`] — такого контакта нет либо запись не удалась.
    pub fn set_contact_verified(
        &self,
        account_id: String,
        verified: bool,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let account = parse_account_id(&account_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.set_contact_verified(&account, verified, Timestamp::from_millis(now_millis))
        })
    }

    /// Возвращает ссылку на собственный профиль.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — свои ключи не читаются либо имя не подходит
    /// для ссылки.
    pub fn own_contact_link(&self) -> Result<String, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.own_contact_link())
    }

    /// Читает булеву настройку приложения.
    ///
    /// 🔐 Умолчание указывает приложение: оно разное у разных
    /// настроек, и общий ответ означал бы, что какая-то из них
    /// защищает не так, как задумано.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn setting_bool(&self, key: String, default: bool) -> Result<bool, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.setting_bool(&key, default))
    }

    /// Записывает булеву настройку приложения.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — запись не удалась.
    pub fn set_setting_bool(&self, key: String, enabled: bool) -> Result<(), FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.set_setting_bool(&key, enabled))
    }

    /// Читает числовую настройку приложения.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn setting_int(&self, key: String, default: i64) -> Result<i64, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.setting_int(&key, default))
    }

    /// Записывает числовую настройку приложения.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — запись не удалась.
    pub fn set_setting_int(&self, key: String, value: i64) -> Result<(), FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.set_setting_int(&key, value))
    }

    /// Возвращает идентификатор этого устройства.
    ///
    /// [`None`] означает, что регистрация ещё не проходила.
    ///
    /// Нужен приложению для приёма сообщений и работы с вложениями:
    /// обе ручки адресуются по устройству. Читается из хранилища,
    /// а не держится в памяти приложения: после перезапуска память
    /// пуста, и очередь сообщений осталась бы незабранной.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn own_device_id(&self) -> Result<Option<String>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.own_device_id())
    }

    /// Перешифровывает базу новым ключом.
    ///
    /// Нужен ровно для одного: перевести базу, созданную схемой
    /// «ключ из одного PIN», на ключ, связанный с аппаратным
    /// хранилищем ([`crate::derive_storage_key_bound`], находка P-5 раздела
    /// 23.6). Выбросить старую базу значило бы стереть переписку при
    /// обновлении приложения.
    ///
    /// 🔐 Вызывается на **открытой** базе: перешифровать можно только
    /// то, что удалось расшифровать. Отсюда и порядок на платформе —
    /// открыть старым ключом, затем сменить.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — ключ не 32 байта либо смена не удалась.
    pub fn rekey_storage(&self, new_key: Vec<u8>) -> Result<(), FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.rekey_storage(&new_key))
    }

    /// 🔐 Пополняет одноразовые предключи и ротирует подписанный.
    ///
    /// Одноразовый предключ расходуется при каждом первом контакте:
    /// сервер отдаёт его тому, кто начинает переписку, и вычёркивает.
    /// Без пополнения пул кончается, и каждая новая переписка
    /// заводится **без** одноразового ключа — теряя и классическую,
    /// и пост-квантовую половину вклада в forward secrecy. Сервер
    /// при этом отвечает успехом, и никто ничего не замечает.
    ///
    /// ⚠️ Вызывать после открытия хранилища и после приёма
    /// сообщений. Когда делать нечего, вызов ограничивается одним
    /// запросом остатка и в сеть за публикацией не ходит.
    ///
    /// Возвращает, сколько ключей добавлено и сколько осталось
    /// на сервере, — это показывает центр безопасности.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — аккаунт не зарегистрирован либо
    /// публикация не удалась. Секреты в последнем случае
    /// не сохраняются: иначе клиент считал бы опубликованным то,
    /// чего сервер не видел.
    pub fn maintain_prekeys(&self, now_millis: i64) -> Result<FfiPreKeyMaintenance, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let report = guard(|| {
            client.maintain_prekeys(
                aegis_types::Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })?;

        Ok(FfiPreKeyMaintenance {
            rotated_signed: report.rotated_signed,
            added_one_time: report.added_one_time,
            remaining_one_time: report.remaining_one_time,
        })
    }

    /// 🔐 Собирает выгрузку данных пользователя (MASVS PRIVACY-3.1).
    ///
    /// Возвращает JSON: имя аккаунта, контакты, переписка и настройки.
    ///
    /// # ⚠️ Ключей в выгрузке нет
    ///
    /// Ни приватного identity-ключа, ни состояния ратчета, ни ключа
    /// восстановления. Выгрузка — файл, который человек кладёт
    /// в облако и забывает в загрузках; ключ в нём означал бы, что
    /// всю защиту переписки обходит один этот файл.
    ///
    /// Восстановиться из выгрузки поэтому нельзя: для этого есть
    /// [`Messenger::create_backup`], и она зашифрована.
    ///
    /// # ⚠️ Файл не зашифрован
    ///
    /// Иначе он не переносим. Интерфейс обязан сказать это **до**
    /// того, как человек выберет, куда сохранять: получивший файл
    /// получил всю переписку.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — аккаунта нет либо чтение не удалось.
    pub fn export_data(&self, now_millis: i64) -> Result<String, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.export_data(aegis_types::Timestamp::from_millis(now_millis)))
    }

    /// 🔐 Удаляет аккаунт на сервере (MASVS PRIVACY-3.2).
    ///
    /// # Что делает и чего не делает
    ///
    /// Делает один подписанный запрос и возвращает то, что сервер
    /// сообщил об удалённом. **Локальные данные остаются**: файл базы,
    /// аппаратный секрет и настройки убирает платформа — ядро не знает
    /// ни пути к файлу, ни имени ключа в хранилище устройства.
    ///
    /// ⚠️ Порядок на платформе обязателен именно такой: сначала этот
    /// вызов, и только по его успеху — стирание локального. Наоборот —
    /// и при обрыве сети человек остался бы без переписки, но с живым
    /// аккаунтом на сервере, а повторить удаление стало бы нечем:
    /// подпись требует ключа, который только что стёрли.
    ///
    /// ⚠️ Уносит все устройства аккаунта. Это удаление аккаунта,
    /// а не выход с одного телефона.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — аккаунт не зарегистрирован, сервер не принял
    /// подпись (в том числе если аккаунт уже удалён) либо не удалось
    /// соединиться. В последнем случае аккаунт цел и попытку можно
    /// повторить.
    pub fn delete_account(&self, now_millis: i64) -> Result<FfiAccountDeletion, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let report =
            guard(|| client.delete_account(aegis_types::Timestamp::from_millis(now_millis)))?;

        Ok(FfiAccountDeletion {
            devices: report.devices,
            envelopes: report.envelopes,
            attachments: report.attachments,
        })
    }

    /// Заголовки подписи для рукопожатия сокета уведомлений.
    ///
    /// Возвращает пары «имя заголовка — значение», которые платформа
    /// обязана добавить в запрос апгрейда `GET /v1/ws/{device_id}`.
    ///
    /// 🔐 Подпись привязана к пути и к времени: воспользоваться ею
    /// для другого запроса нельзя. Приватный ключ остаётся в ядре.
    ///
    /// Понадобилось потому, что сокет ведёт платформа: рукопожатие
    /// WebSocket на Android собрано руками поверх сырого сокета,
    /// и поставить заголовок изнутри ядра неоткуда.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — аккаунт не зарегистрирован либо подпись
    /// не построилась.
    pub fn socket_auth_headers(
        &self,
        device_id: String,
        now_millis: i64,
    ) -> Result<Vec<FfiHeader>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let headers = guard(|| {
            client.socket_auth_headers(&device_id, aegis_types::Timestamp::from_millis(now_millis))
        })?;

        Ok(headers
            .into_iter()
            .map(|(name, value)| FfiHeader { name, value })
            .collect())
    }

    /// Возвращает собственное имя пользователя.
    ///
    /// [`None`] означает, что регистрация ещё не прошла.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn own_username(&self) -> Result<Option<String>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.own_username())
    }

    /// Перечисляет контакты, недавно добавленные первыми.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn contacts(&self) -> Result<Vec<FfiContact>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let contacts = guard(|| client.contacts())?;

        Ok(contacts.iter().map(contact_to_ffi).collect())
    }

    /// Ищет по расшифрованной переписке.
    ///
    /// 🔐 Поиск идёт по самим сообщениям, а не по отдельному индексу:
    /// индекс был бы второй копией переписки, которую тоже пришлось бы
    /// стирать при удалении, — и о которой легко забыть.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn search(&self, query: String, limit: u32) -> Result<Vec<FfiSearchHit>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let hits = guard(|| client.search(&query, limit))?;

        Ok(hits
            .into_iter()
            .map(|hit| FfiSearchHit {
                chat_id: hit.chat_id.to_string(),
                message: FfiMessage {
                    message_id: hit.message.message_id.to_string(),
                    text: hit.message.text,
                    timestamp: hit.message.timestamp.as_millis(),
                    outgoing: hit.message.outgoing,
                    status: hit.message.status.into(),
                },
            })
            .collect())
    }
}

/// Действия над сообщениями.
#[uniffi::export]
impl Messenger {
    /// Отправляет реакцию на сообщение.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор сообщения
    /// не разбирается;
    /// [`FfiError::Core`] — отправка не удалась.
    pub fn send_reaction(
        &self,
        peer_username: String,
        target_message_id: String,
        emoji: String,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let target = parse_message_id(&target_message_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.send_reaction(
                &peer_username,
                &target,
                &emoji,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Правит ранее отправленное сообщение.
    ///
    /// 🔐 Правка не скрывает исходный текст: получатель уже видел его.
    /// Интерфейс обязан помечать правленые сообщения, иначе отправитель
    /// мог бы переписать разговор задним числом.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор сообщения
    /// не разбирается;
    /// [`FfiError::Core`] — отправка не удалась.
    pub fn edit_message(
        &self,
        peer_username: String,
        target_message_id: String,
        text: String,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let target = parse_message_id(&target_message_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.edit_message(
                &peer_username,
                &target,
                &text,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Удаляет сообщение у обеих сторон.
    ///
    /// 🔐 Своё удаляется сразу, не дожидаясь сети: если связи нет,
    /// пользователь всё равно должен перестать видеть сообщение
    /// у себя. Удаление у собеседника — просьба, а не гарантия: он уже
    /// видел текст и мог его запомнить.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор сообщения
    /// не разбирается;
    /// [`FfiError::Core`] — отправка не удалась.
    pub fn delete_for_everyone(
        &self,
        peer_username: String,
        target_message_id: String,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let target = parse_message_id(&target_message_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.delete_for_everyone(
                &peer_username,
                &target,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Сообщает, что пользователь печатает.
    ///
    /// 🔐 Молча ничего не делает, если передача присутствия выключена:
    /// иначе пользователь получал бы ошибку за то, что сознательно
    /// оставил функцию выключенной.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — отправка не удалась.
    pub fn send_typing(
        &self,
        peer_username: String,
        active: bool,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.send_typing(
                &peer_username,
                active,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Отправляет квитанцию о прочтении.
    ///
    /// Квитанция указывает последнее прочитанное сообщение, а не
    /// каждое: открытие чата с сотней непрочитанных иначе породило бы
    /// сто сообщений, и по их числу собеседник узнал бы, сколько
    /// накопилось.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор сообщения
    /// не разбирается;
    /// [`FfiError::Core`] — отправка не удалась.
    pub fn send_read_receipt(
        &self,
        peer_username: String,
        until_message_id: String,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let until = parse_message_id(&until_message_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            client.send_read_receipt(
                &peer_username,
                &until,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Включает или выключает передачу присутствия.
    ///
    /// 🔐 Выключено по умолчанию. Индикатор набора и квитанции
    /// о прочтении сообщают собеседнику, когда пользователь у телефона:
    /// это данные о распорядке дня, и включать их за пользователя
    /// нельзя.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — запись не удалась.
    pub fn set_presence_sharing(&self, enabled: bool) -> Result<(), FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.set_presence_sharing(enabled))
    }

    /// Сообщает, включена ли передача присутствия.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось.
    pub fn presence_sharing_enabled(&self) -> Result<bool, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| client.presence_sharing_enabled())
    }
}

/// Переводит контакт через границу.
fn contact_to_ffi(contact: &aegis_core::client::Contact) -> FfiContact {
    FfiContact {
        account_id: contact.account_id.to_string(),
        identity: contact.identity.as_bytes().to_vec(),
        username: contact.username.clone(),
        chat_id: contact.chat_id.map(|id| id.to_string()),
        verified: contact.verified,
        key_changed: contact.key_changed,
    }
}

/// Разбирает идентификатор аккаунта, пришедший с платформы.
fn parse_account_id(raw: &str) -> Result<AccountId, FfiError> {
    let uuid = uuid::Uuid::parse_str(raw).map_err(|_| FfiError::InvalidArgument)?;

    Ok(AccountId::from_uuid(uuid))
}

/// Разбирает идентификатор сообщения, пришедший с платформы.
///
/// За границей FFI это строка: разбор здесь, а не в ядре, потому что
/// битый идентификатор — ошибка вызывающего кода, и отличать её
/// от ошибок хранилища полезно.
fn parse_message_id(raw: &str) -> Result<MessageId, FfiError> {
    let uuid = uuid::Uuid::parse_str(raw).map_err(|_| FfiError::InvalidArgument)?;

    Ok(MessageId::from_uuid(uuid))
}

/// Вложения: голосовые, фото, видео, документы.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiAttachmentKind {
    /// Изображение.
    Image,
    /// Видео.
    Video,
    /// Голосовое сообщение.
    Voice,
    /// Произвольный файл.
    Document,
}

impl From<FfiAttachmentKind> for aegis_media::descriptor::AttachmentKind {
    fn from(kind: FfiAttachmentKind) -> Self {
        match kind {
            FfiAttachmentKind::Image => Self::Image,
            FfiAttachmentKind::Video => Self::Video,
            FfiAttachmentKind::Voice => Self::Voice,
            FfiAttachmentKind::Document => Self::Document,
        }
    }
}

/// Файл, который пользователь отправляет вложением.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAttachmentFile {
    /// Тип: от него зависит поведение получателя.
    ///
    /// Определяется приложением, а не расширением имени: имя выбирает
    /// отправитель, и «отчёт.jpg», который на деле исполняемый файл,
    /// не должен открываться как картинка.
    pub kind: FfiAttachmentKind,
    /// Содержимое файла в открытом виде.
    pub bytes: Vec<u8>,
    /// Имя файла.
    ///
    /// 🔐 Уходит зашифрованным вместе с описанием: «результаты
    /// анализов.jpg» говорит о человеке больше, чем сам факт отправки.
    pub name: Option<String>,
    /// Описание для незрячих пользователей.
    pub description: Option<String>,
    /// Длительность — для голосовых и видео.
    pub duration_millis: Option<u32>,
    /// Огибающая громкости — для голосовых.
    pub waveform: Option<Vec<u8>>,
}

impl From<FfiAttachmentFile> for aegis_core::client::AttachmentFile {
    fn from(file: FfiAttachmentFile) -> Self {
        Self {
            kind: file.kind.into(),
            bytes: file.bytes,
            name: file.name,
            description: file.description,
            duration_millis: file.duration_millis,
            waveform: file.waveform,
        }
    }
}

/// Разобранное описание вложения.
///
/// 🔐 Всё здесь пришло от собеседника внутри сообщения. Ядро уже
/// проверило границы каждого поля при разборе, но имя остаётся тем,
/// что назвал отправитель: показывать его можно, доверять — нет.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAttachmentInfo {
    /// Тип вложения.
    pub kind: FfiAttachmentKind,
    /// Имя файла, если отправитель его передал.
    pub name: Option<String>,
    /// Размер открытого файла в байтах.
    pub size: u64,
    /// Описание для незрячих пользователей.
    pub description: Option<String>,
    /// Длительность в миллисекундах — у голосовых и видео.
    pub duration_millis: Option<u32>,
}

/// Разбирает описание вложения для показа.
///
/// Принимает те же байты, что отдаёт [`Messenger::attachments_of`].
///
/// # Errors
///
/// [`FfiError::Core`] — описание не разбирается либо какое-то поле
/// вне допустимых границ.
#[uniffi::export]
pub fn parse_attachment_descriptor(descriptor: Vec<u8>) -> Result<FfiAttachmentInfo, FfiError> {
    let parsed = guard(|| aegis_media::descriptor::AttachmentDescriptor::from_bytes(&descriptor))?;

    Ok(FfiAttachmentInfo {
        kind: match parsed.kind {
            aegis_media::descriptor::AttachmentKind::Image => FfiAttachmentKind::Image,
            aegis_media::descriptor::AttachmentKind::Video => FfiAttachmentKind::Video,
            aegis_media::descriptor::AttachmentKind::Voice => FfiAttachmentKind::Voice,
            aegis_media::descriptor::AttachmentKind::Document => FfiAttachmentKind::Document,
        },
        name: parsed.name,
        size: parsed.size,
        description: parsed.description,
        duration_millis: parsed.duration_millis,
    })
}

#[uniffi::export]
impl Messenger {
    /// Отправляет файл вложением.
    ///
    /// # Что происходит внутри
    ///
    /// Файл шифруется случайным ключом, режется на чанки по 64 КБ
    /// и уходит на сервер. Описание — адрес, ключ, имя, тип —
    /// отправляется **внутри сообщения**, под сквозным шифрованием.
    ///
    /// 🔐 Сервер получает только байты и их длину. Ни имени файла,
    /// ни получателя, ни ключа он не видит.
    ///
    /// # Про поток
    ///
    /// Вызывать в фоне: шифрование стомегабайтного файла и его
    /// загрузка занимают секунды, и держать на них главный поток
    /// нельзя.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — файл больше предела, описание не проходит
    /// проверку либо отправка не удалась.
    pub fn send_attachment(
        &self,
        peer_username: String,
        device_id: String,
        file: FfiAttachmentFile,
        body: String,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;
        let file = aegis_core::client::AttachmentFile::from(file);

        guard(|| {
            client.send_attachment(
                &peer_username,
                &device_id,
                &file,
                &body,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }

    /// Возвращает описания вложений сообщения.
    ///
    /// Каждое — те самые байты, что принимает [`Self::fetch_attachment`].
    /// Пусто, если вложений нет.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор сообщения
    /// не разбирается;
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn attachments_of(&self, message_id: String) -> Result<Vec<Vec<u8>>, FfiError> {
        let parsed = parse_message_id(&message_id)?;
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        let descriptors = guard(|| client.attachments_of(&parsed))?;

        descriptors
            .iter()
            .map(|descriptor| descriptor.to_bytes().map_err(FfiError::from))
            .collect()
    }

    /// Скачивает и расшифровывает вложение по его описанию.
    ///
    /// `descriptor` — те самые байты, что пришли внутри сообщения.
    ///
    /// 🔐 Расшифровка проверяет тег каждого чанка: подменённый сервером
    /// файл вернёт ошибку, а не покажется пользователю содержимым.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — описание не разбирается, скачивание
    /// не удалось либо блоб подменён.
    pub fn fetch_attachment(
        &self,
        device_id: String,
        descriptor: Vec<u8>,
        now_millis: i64,
    ) -> Result<Vec<u8>, FfiError> {
        let client = self.client.lock().map_err(|_| FfiError::Panic)?;

        guard(|| {
            let descriptor =
                aegis_media::descriptor::AttachmentDescriptor::from_bytes(&descriptor)?;

            client.fetch_attachment(&device_id, &descriptor, Timestamp::from_millis(now_millis))
        })
    }
}
