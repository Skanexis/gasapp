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
//! Криптография живёт в `aegis-protocol`, и смешивать её с сетевым
//! кодом нельзя (правило 1 раздела 4.1).

use aegis_types::{AegisError, Result};

use crate::api::{
    AccountDeletedResponse, BundleResponse, CertificateResponse, DiscoveryResponse,
    EnvelopeResponse, PublishKeysRequest, RegisterRequest, RegisterResponse, SealedAccessRequest,
    SealedReportRequest, SealedReportResponse, SealedSendRequest, SendRequest,
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
    /// [`AegisError::Network`] при сбое соединения. Ошибки уровня
    /// приложения (4xx, 5xx) возвращаются как успешный [`HttpResponse`]
    /// с соответствующим кодом: сбой сети и отказ сервера — разные
    /// события, и клиент реагирует на них по-разному.
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

/// Заголовок с решением proof-of-work анонимной загрузки.
pub const UPLOAD_POW_HEADER: &str = "x-aegis-upload-pow";

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
    /// * [`AegisError::InvalidSignature`] — proof-of-work не принят.
    /// * [`AegisError::Malformed`] — имя занято либо запрос отвергнут.
    /// * [`AegisError::Network`] — сбой соединения.
    pub fn register(&self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let response = self.send(
            Method::Post,
            "/v1/accounts/register".to_owned(),
            Some(to_json(request)?),
        )?;

        parse(&response)
    }

    /// Ищет аккаунт по имени.
    ///
    /// # Errors
    ///
    /// * [`AegisError::SessionNotFound`] — имени нет.
    /// * [`AegisError::Network`] — сбой соединения либо превышен лимит
    ///   частоты: повторить запрос имеет смысл позже, поэтому вариант
    ///   тот же, что у сетевого сбоя.
    pub fn discover(&self, username: &str) -> Result<DiscoveryResponse> {
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
    /// [`AegisError::Network`] при сбое, [`AegisError::Malformed`]
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
    /// * [`AegisError::SessionNotFound`] — устройства нет либо ключи
    ///   не опубликованы.
    /// * [`AegisError::Network`] — сбой соединения.
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
    /// [`AegisError::Network`] при сбое соединения.
    pub fn prekey_count(&self, device_id: &str) -> Result<i64> {
        let response = self.send(Method::Get, format!("/v1/keys/{device_id}/count"), None)?;

        parse(&response)
    }

    /// Отправляет конверт — за подписью своего устройства.
    ///
    /// 🔐 Анонимно писать можно только тому, кто раздал ключ доступа
    /// ([`ApiClient::send_sealed`]). Сюда клиент уходит, пока ключа
    /// собеседника у него нет, то есть с первым сообщением, — а
    /// начальный конверт и так несёт identity-ключ открыто. Прежде
    /// маршрут был без подписи, и любой клал конверты в любую очередь.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Malformed`] — конверт превышает лимит 256 КБ.
    /// * [`AegisError::Network`] — сбой соединения либо лимит частоты.
    pub fn send_envelope(
        &self,
        sender_device_id: &str,
        request: &SendRequest,
        signer: &dyn crate::auth::RequestSigner,
    ) -> Result<String> {
        let response = self.send_signed(
            Method::Post,
            format!("/v1/messages/{sender_device_id}"),
            Some(to_json(request)?),
            signer,
        )?;

        parse(&response)
    }

    /// Отправляет запечатанный конверт, не называя отправителя.
    ///
    /// # 🔐 Чем это отличается от [`ApiClient::send_envelope`]
    ///
    /// Запрос не подписывается: сервер не узнаёт, кто отправитель.
    /// Право на отправку доказывается ключом доступа получателя,
    /// который тот раздал своим собеседникам внутри переписки.
    ///
    /// Что сервер всё равно видит: IP отправителя и время. От этого
    /// защищает Tor или прокси (ADR-024), а не sealed sender.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Malformed`] — конверт превышает лимит;
    /// * [`AegisError::Network`] — сбой соединения, лимит частоты
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
    /// [`AegisError::Network`] при сбое соединения.
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
    /// [`AegisError::Network`] при сбое соединения.
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
    /// [`AegisError::Network`] при сбое соединения.
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
    /// [`AegisError::Network`] при сбое соединения.
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
    /// [`AegisError::Network`] при сбое соединения.
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
    /// * [`AegisError::InvalidSignature`] — подпись не принята.
    /// * [`AegisError::Network`] — сбой соединения.
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
    /// * [`AegisError::InvalidSignature`] — подпись не принята либо
    ///   аккаунт уже удалён: сервер не различает эти случаи, чтобы
    ///   не отвечать на вопрос «существовал ли такой аккаунт».
    /// * [`AegisError::Network`] — сбой соединения.
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
        self.execute(method, path, body, Vec::new())
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
        let headers = crate::auth::signature_headers(
            signer,
            method.as_str(),
            &path,
            body.as_deref().unwrap_or("").as_bytes(),
        )?;

        self.execute(method, path, body, headers)
    }

    /// Выполняет запрос с готовыми заголовками.
    fn execute(
        &self,
        method: Method,
        path: String,
        body: Option<String>,
        headers: Vec<(String, String)>,
    ) -> Result<HttpResponse> {
        let response = self.transport.execute(&HttpRequest {
            method,
            path,
            body,
            binary_body: None,
            headers,
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
    /// [`AegisError::Network`] при сбое соединения;
    /// [`AegisError::Malformed`] — сервер вернул не адрес.
    pub fn upload_attachment(&self, payload: Vec<u8>, pow_nonce: u64) -> Result<String> {
        let response = self.transport.execute(&HttpRequest {
            method: Method::Post,
            path: "/v1/attachments/blob".to_owned(),
            body: None,
            binary_body: Some(payload),
            headers: vec![(UPLOAD_POW_HEADER.to_owned(), pow_nonce.to_string())],
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
    /// [`AegisError::Network`] — вложения нет или оно истекло.
    pub fn download_attachment(&self, attachment_id: &str) -> Result<Vec<u8>> {
        let response = self.send(
            Method::Get,
            format!("/v1/attachments/blob/{attachment_id}"),
            None,
        )?;

        Ok(response.binary_body)
    }
}

/// Переводит код ответа в ошибку домена.
///
/// # Про выбор вариантов
///
/// `401` — это отказ аутентификации, а не сетевой сбой: повторять
/// запрос бессмысленно, нужно заново подписать челлендж. `429`
/// наоборот попадает в [`AegisError::Network`], потому что лечится
/// именно повтором — очередь возьмётся за него по backoff.
fn check_status(response: &HttpResponse) -> Result<()> {
    match response.status {
        200..=299 => Ok(()),
        401 => Err(AegisError::InvalidSignature),
        404 => Err(AegisError::SessionNotFound),
        // 429 и 5xx лечатся повтором, поэтому попадают в очередь.
        429 | 500..=599 => Err(AegisError::Network),
        _ => Err(AegisError::Malformed),
    }
}

/// Сериализует запрос.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| AegisError::Malformed)
}

/// Разбирает тело ответа.
///
/// Ошибка разбора — [`AegisError::Malformed`]: сервер прислал не то,
/// что обещает контракт, и продолжать на таком ответе нельзя.
fn parse<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T> {
    serde_json::from_str(&response.body).map_err(|_| AegisError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

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

            self.responses.borrow_mut().pop().ok_or(AegisError::Network)
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

    /// 🔐 Неизвестное имя — не сетевой сбой.
    ///
    /// Разница важна для очереди: отсутствующий контакт повторным
    /// запросом не появится, а сетевой сбой лечится именно повтором.
    #[test]
    fn missing_account_is_not_a_network_error() {
        let client = ApiClient::new(FakeTransport::with(404, ""));

        assert!(matches!(
            client.discover("ghost"),
            Err(AegisError::SessionNotFound)
        ));
    }

    /// 🔐 Отказ аутентификации не отправляется в очередь на повтор.
    #[test]
    fn unauthorized_is_reported_as_signature_failure() {
        let client = ApiClient::new(FakeTransport::with(401, ""));

        assert!(matches!(
            client.discover("bob"),
            Err(AegisError::InvalidSignature)
        ));
    }

    /// Лимит частоты лечится повтором, поэтому это сетевая ошибка.
    #[test]
    fn rate_limit_is_retryable() {
        let client = ApiClient::new(FakeTransport::with(429, ""));

        assert!(matches!(client.discover("bob"), Err(AegisError::Network)));
    }

    /// Сбой сервера тоже лечится повтором.
    #[test]
    fn server_error_is_retryable() {
        let client = ApiClient::new(FakeTransport::with(503, ""));

        assert!(matches!(client.discover("bob"), Err(AegisError::Network)));
    }

    /// Ответ не по контракту отвергается, а не разбирается частично.
    #[test]
    fn malformed_response_is_rejected() {
        let client = ApiClient::new(FakeTransport::with(200, "не json"));

        assert!(matches!(client.discover("bob"), Err(AegisError::Malformed)));
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
                Err(AegisError::Network)
            }
        }

        let client = ApiClient::new(Failing);

        assert!(matches!(client.discover("bob"), Err(AegisError::Network)));
    }

    #[test]
    fn method_names_match_protocol() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
        assert_eq!(Method::Put.as_str(), "PUT");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }
}
