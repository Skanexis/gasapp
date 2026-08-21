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
    BundleResponse, DiscoveryResponse, EnvelopeResponse, PublishKeysRequest, RegisterRequest,
    RegisterResponse, SendRequest,
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
        auth: Vec<(String, String)>,
    ) -> Result<()> {
        let response = self.send_signed(
            Method::Put,
            format!("/v1/keys/{device_id}"),
            Some(to_json(request)?),
            auth,
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

    /// Отправляет конверт.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Malformed`] — конверт превышает лимит 256 КБ.
    /// * [`AegisError::Network`] — сбой соединения либо лимит частоты.
    pub fn send_envelope(&self, request: &SendRequest) -> Result<String> {
        let response = self.send(
            Method::Post,
            "/v1/messages".to_owned(),
            Some(to_json(request)?),
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
        auth: Vec<(String, String)>,
    ) -> Result<Vec<EnvelopeResponse>> {
        let response = self.send_signed(
            Method::Get,
            format!("/v1/messages/{device_id}"),
            None,
            auth,
        )?;

        parse(&response)
    }

    /// Подтверждает доставку: сервер удаляет конверт немедленно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Network`] при сбое соединения.
pub fn acknowledge(        &self,        device_id: &str,        envelope_id: &str,        auth: Vec<(String, String)>,    ) -> Result<()> {        let response = self.send_signed(            Method::Delete,            format!("/v1/messages/{device_id}/{envelope_id}"),            None,            auth,        )?;

        check_status(&response)
    }

    /// Выполняет запрос и переводит код ответа в ошибку домена.
    fn send(&self, method: Method, path: String, body: Option<String>) -> Result<HttpResponse> {
        self.send_signed(method, path, body, Vec::new())
    }

    /// Выполняет запрос с дополнительными заголовками.
    ///
    /// Заголовки собирает вызывающая сторона: подпись требует
    /// приватного ключа, а сетевой клиент его не видит и видеть
    /// не должен — ключи живут в ядре и не покидают его.
    fn send_signed(
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
            headers,
        })?;

        check_status(&response)?;

        Ok(response)
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

        let envelopes = client.fetch_envelopes("dev-1", Vec::new()).unwrap();

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

        let envelopes = client.fetch_envelopes("dev-1", Vec::new()).unwrap();
        let bucketed = envelopes.first().map_or(1, |e| e.queued_at_bucketed);

        assert_eq!(bucketed % 3600, 0);
    }

    #[test]
    fn acknowledge_uses_delete_with_both_ids() {
        let client = ApiClient::new(FakeTransport::with(204, ""));

        client.acknowledge("dev-1", "env-1", Vec::new()).unwrap();

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
        };

        client.publish_keys("dev-1", &request, Vec::new()).unwrap();

        let sent = client.transport.last_request();
        assert_eq!(sent.method, Method::Put);
        assert_eq!(sent.path, "/v1/keys/dev-1");
        assert!(sent.body.is_some());
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
