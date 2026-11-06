// SPDX-License-Identifier: AGPL-3.0-only

//! Отправщик пустых пуш-уведомлений: `gasapp-server-admin push`.
//!
//! # Как работает
//!
//! Узел API, положив конверт в очередь устройства, шлёт в базу
//! `NOTIFY gasapp_envelope '<устройство>'` (так он будит соседние узлы).
//! Этот процесс слушает тот же канал и, если у устройства есть токен
//! (`push_tokens`), просит Apple (APNs) или Google (FCM) показать на нём
//! «Новое сообщение».
//!
//! # Почему отдельным процессом, а не в узле
//!
//! 🔐 Узлам API интернет запрещён (`IPAddressAllow` в юните): взломанный
//! узел не должен уметь выгрузить данные наружу. Отправщику нужны только
//! база (через сокет) и два адреса провайдеров, и живёт он на машине базы
//! рядом с админ-центром. Ключи Apple и Google — только здесь.
//!
//! # 🔐 Что уходит провайдеру
//!
//! Токен устройства и **постоянная** нагрузка: ключ строки
//! «Новое сообщение», которую телефон переводит сам. Ни текста, ни
//! отправителя, ни чата, ни счётчика. Провайдер видит лишь, что
//! устройству что-то пришло, и когда.
//!
//! Чаще раза в [`MIN_INTERVAL`] одно устройство не будится: серия
//! сообщений — одно уведомление, и провайдер не видит её ритма.
//!
//! # Что не пишется в журнал
//!
//! Ни идентификаторы устройств, ни токены: журнал отправщика не должен
//! становиться журналом того, кому и когда приходили сообщения.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sqlx::PgPool;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

/// Канал, в который узлы пишут о новых конвертах (`hub::NOTIFY_CHANNEL`).
pub const CHANNEL: &str = "gasapp_envelope";

/// Не чаще одного пуша на устройство за это время.
pub const MIN_INTERVAL: Duration = Duration::from_mins(1);

/// Одновременных отправок не больше.
const MAX_IN_FLIGHT: usize = 16;

/// Ключ строки уведомления на iOS (`Localizable.strings`).
pub const APNS_LOC_KEY: &str = "PUSH_NEW_MESSAGE";

/// Ресурсы строк уведомления на Android (`values/strings.xml`) и канал.
pub const FCM_TITLE_KEY: &str = "notify_title";
/// Текст уведомления на Android.
pub const FCM_BODY_KEY: &str = "notify_body";
/// Канал уведомлений Android (`Notifier.CHANNEL`).
pub const FCM_CHANNEL: &str = "messages";

/// Сколько живёт непоказанный пуш у провайдера: сутки — телефон мог быть
/// выключен.
const TTL_SECS: u64 = 86_400;

/// Ошибка отправщика.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Настройка неполна или ключ не читается.
    #[error("настройка: {0}")]
    Config(&'static str),
    /// Сеть, TLS, HTTP/2.
    #[error("связь с провайдером")]
    Transport,
    /// Провайдер отказал (не из-за токена).
    #[error("провайдер ответил {0}")]
    Rejected(u16),
}

/// Итог одной отправки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Принято провайдером.
    Sent,
    /// 🔐 Токен мёртв (приложение удалено, токен сменился): забыть.
    DeadToken,
}

// --- JWT ----------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Тело PEM (PKCS#8) без заголовков → DER.
///
/// # Errors
///
/// [`SendError::Config`] — не PEM.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, SendError> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----") && !line.is_empty())
        .collect();
    STANDARD
        .decode(body)
        .map_err(|_| SendError::Config("ключ не PEM"))
}

/// `base64url(header).base64url(claims)` и подпись поверх — компактный JWT.
fn jwt(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, SendError>,
) -> Result<String, SendError> {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = sign(signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

// --- HTTP/2 ----------------------------------------------------------------------

/// Одно HTTP/2-соединение с хостом провайдера; переоткрывается при обрыве.
struct H2 {
    host: &'static str,
    sender: Mutex<Option<SendRequest<Full<Bytes>>>>,
}

impl H2 {
    fn new(host: &'static str) -> Self {
        Self {
            host,
            sender: Mutex::new(None),
        }
    }

    async fn connect(host: &str) -> Result<SendRequest<Full<Bytes>>, SendError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| SendError::Transport)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        // APNs принимает только HTTP/2.
        config.alpn_protocols = vec![b"h2".to_vec()];

        let tcp = tokio::net::TcpStream::connect((host, 443))
            .await
            .map_err(|_| SendError::Transport)?;
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| SendError::Transport)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|_| SendError::Transport)?;

        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|_| SendError::Transport)?;
        tokio::spawn(async move {
            // Конец соединения — штатно: следующая отправка откроет новое.
            let _ = connection.await;
        });

        Ok(sender)
    }

    /// Отправляет запрос; ответ — код и тело (до 64 КБ).
    async fn send(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<(StatusCode, Vec<u8>), SendError> {
        let mut guard = self.sender.lock().await;
        let usable = match guard.as_mut() {
            Some(sender) => sender.ready().await.is_ok(),
            None => false,
        };
        if !usable {
            *guard = Some(Self::connect(self.host).await?);
        }
        let sender = guard.as_mut().ok_or(SendError::Transport)?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|_| SendError::Transport)?;
        drop(guard);

        let status = response.status();
        let body = http_body_util::Limited::new(response.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|_| SendError::Transport)?
            .to_bytes();

        Ok((status, body.to_vec()))
    }
}

// --- APNs ------------------------------------------------------------------------

/// Настройка Apple: ключ `.p8` из developer.apple.com → Keys.
pub struct Apns {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    token: Mutex<Option<(String, Instant)>>,
    production: H2,
    sandbox: H2,
}

impl Apns {
    /// Ключ — PEM (PKCS#8) `.p8`; `topic` — bundle id приложения.
    ///
    /// # Errors
    ///
    /// [`SendError::Config`] — ключ не читается или поля пусты.
    pub fn new(p8_pem: &str, key_id: &str, team_id: &str, topic: &str) -> Result<Self, SendError> {
        if key_id.is_empty() || team_id.is_empty() || topic.is_empty() {
            return Err(SendError::Config(
                "APNs: нужны GASAPP_APNS_KEY_ID, GASAPP_APNS_TEAM_ID, GASAPP_APNS_TOPIC",
            ));
        }
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pem_to_der(p8_pem)?)
            .map_err(|_| SendError::Config("APNs: ключ .p8 не P-256 PKCS#8"))?;
        Ok(Self {
            key,
            key_id: key_id.to_owned(),
            team_id: team_id.to_owned(),
            topic: topic.to_owned(),
            token: Mutex::new(None),
            production: H2::new("api.push.apple.com"),
            sandbox: H2::new("api.sandbox.push.apple.com"),
        })
    }

    /// JWT провайдера: Apple принимает его до часа, обновляем раз в 40 минут.
    async fn bearer(&self) -> Result<String, SendError> {
        let mut cached = self.token.lock().await;
        if let Some((token, made)) = cached.as_ref() {
            if made.elapsed() < Duration::from_mins(40) {
                return Ok(token.clone());
            }
        }
        let token = self.sign_jwt(unix_now())?;
        *cached = Some((token.clone(), Instant::now()));
        Ok(token)
    }

    /// JWT ES256 c `kid` ключа и `iss` команды.
    ///
    /// # Errors
    ///
    /// [`SendError::Config`] — подпись не удалась.
    pub fn sign_jwt(&self, iat: u64) -> Result<String, SendError> {
        jwt(
            &serde_json::json!({ "alg": "ES256", "kid": self.key_id }),
            &serde_json::json!({ "iss": self.team_id, "iat": iat }),
            |input| {
                self.key
                    .sign(&SystemRandom::new(), input)
                    .map(|signature| signature.as_ref().to_vec())
                    .map_err(|_| SendError::Config("APNs: подпись JWT"))
            },
        )
    }

    /// 🔐 Нагрузка — постоянная: ключ строки, звук, группа.
    #[must_use]
    pub fn payload() -> serde_json::Value {
        serde_json::json!({
            "aps": {
                "alert": { "loc-key": APNS_LOC_KEY },
                "sound": "default",
                "thread-id": "gasapp"
            }
        })
    }

    async fn send(&self, token: &str, sandbox: bool) -> Result<Outcome, SendError> {
        let host = if sandbox {
            &self.sandbox
        } else {
            &self.production
        };
        let request = Request::post(format!("https://{}/3/device/{token}", host.host))
            .header("authorization", format!("bearer {}", self.bearer().await?))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-collapse-id", "gasapp")
            .header(
                "apns-expiration",
                unix_now().saturating_add(TTL_SECS).to_string(),
            )
            .body(Full::new(Bytes::from(Self::payload().to_string())))
            .map_err(|_| SendError::Transport)?;

        let (status, body) = host.send(request).await?;
        let reason = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|json| {
                json.get("reason")
                    .and_then(|r| r.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_default();

        match status.as_u16() {
            200 => Ok(Outcome::Sent),
            410 => Ok(Outcome::DeadToken),
            400 if matches!(reason.as_str(), "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                Ok(Outcome::DeadToken)
            }
            code => Err(SendError::Rejected(code)),
        }
    }
}

// --- FCM -------------------------------------------------------------------------

/// Настройка Google: JSON сервисного аккаунта Firebase.
pub struct Fcm {
    key: RsaKeyPair,
    client_email: String,
    project_id: String,
    access: Mutex<Option<(String, Instant)>>,
    oauth: H2,
    messages: H2,
}

/// Поля сервисного аккаунта, которые нужны отправщику.
#[derive(serde::Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
}

impl Fcm {
    /// Из JSON сервисного аккаунта (Firebase → Project settings →
    /// Service accounts → Generate new private key).
    ///
    /// # Errors
    ///
    /// [`SendError::Config`] — JSON или ключ не читаются.
    pub fn new(service_account_json: &str) -> Result<Self, SendError> {
        let account: ServiceAccount = serde_json::from_str(service_account_json)
            .map_err(|_| SendError::Config("FCM: JSON сервисного аккаунта не читается"))?;
        let key = RsaKeyPair::from_pkcs8(&pem_to_der(&account.private_key)?)
            .map_err(|_| SendError::Config("FCM: ключ сервисного аккаунта не RSA PKCS#8"))?;
        Ok(Self {
            key,
            client_email: account.client_email,
            project_id: account.project_id,
            access: Mutex::new(None),
            oauth: H2::new("oauth2.googleapis.com"),
            messages: H2::new("fcm.googleapis.com"),
        })
    }

    /// JWT RS256 для обмена на токен доступа OAuth.
    ///
    /// # Errors
    ///
    /// [`SendError::Config`] — подпись не удалась.
    pub fn sign_assertion(&self, iat: u64) -> Result<String, SendError> {
        jwt(
            &serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
            &serde_json::json!({
                "iss": self.client_email,
                "scope": "https://www.googleapis.com/auth/firebase.messaging",
                "aud": "https://oauth2.googleapis.com/token",
                "iat": iat,
                "exp": iat.saturating_add(3600),
            }),
            |input| {
                let mut signature = vec![0u8; self.key.public_modulus_len()];
                self.key
                    .sign(
                        &RSA_PKCS1_SHA256,
                        &SystemRandom::new(),
                        input,
                        &mut signature,
                    )
                    .map_err(|_| SendError::Config("FCM: подпись JWT"))?;
                Ok(signature)
            },
        )
    }

    async fn bearer(&self) -> Result<String, SendError> {
        let mut cached = self.access.lock().await;
        if let Some((token, until)) = cached.as_ref() {
            if Instant::now() < *until {
                return Ok(token.clone());
            }
        }

        let form = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            self.sign_assertion(unix_now())?
        );
        let request = Request::post("https://oauth2.googleapis.com/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(form)))
            .map_err(|_| SendError::Transport)?;
        let (status, body) = self.oauth.send(request).await?;
        if status != StatusCode::OK {
            return Err(SendError::Rejected(status.as_u16()));
        }

        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| SendError::Transport)?;
        let token = json
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or(SendError::Transport)?
            .to_owned();
        let lifetime = json
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3600);
        // Минуту запаса: токен не должен истечь по дороге.
        let until = Instant::now()
            .checked_add(Duration::from_secs(lifetime.saturating_sub(60)))
            .unwrap_or_else(Instant::now);
        *cached = Some((token.clone(), until));
        Ok(token)
    }

    /// 🔐 Сообщение — постоянное: ключи строк приложения, канал, метка
    /// замены. Ни данных, ни текста.
    #[must_use]
    pub fn message(token: &str) -> serde_json::Value {
        serde_json::json!({
            "message": {
                "token": token,
                "android": {
                    "priority": "HIGH",
                    "ttl": format!("{TTL_SECS}s"),
                    "collapse_key": "gasapp",
                    "notification": {
                        "title_loc_key": FCM_TITLE_KEY,
                        "body_loc_key": FCM_BODY_KEY,
                        "channel_id": FCM_CHANNEL,
                        "tag": "gasapp",
                        "icon": "ic_bell"
                    }
                }
            }
        })
    }

    async fn send(&self, token: &str) -> Result<Outcome, SendError> {
        let request = Request::post(format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        ))
        .header("authorization", format!("Bearer {}", self.bearer().await?))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(Self::message(token).to_string())))
        .map_err(|_| SendError::Transport)?;

        let (status, body) = self.messages.send(request).await?;
        let text = String::from_utf8_lossy(&body);

        match status.as_u16() {
            200 => Ok(Outcome::Sent),
            404 if text.contains("UNREGISTERED") => Ok(Outcome::DeadToken),
            400 if text.contains("registration token is not a valid FCM registration token") => {
                Ok(Outcome::DeadToken)
            }
            code => Err(SendError::Rejected(code)),
        }
    }
}

// --- Цикл --------------------------------------------------------------------------

/// Отправщик: провайдеры, какие настроены.
pub struct Pusher {
    /// Apple.
    pub apns: Option<Apns>,
    /// Google.
    pub fcm: Option<Fcm>,
}

impl Pusher {
    async fn wake(&self, pool: &PgPool, device_id: Uuid) {
        let Ok(Some(token)) = gasapp_server_db::repo::find_push_token(pool, device_id).await else {
            return;
        };

        let outcome = match (token.provider.as_str(), &self.apns, &self.fcm) {
            ("apns", Some(apns), _) => apns.send(&token.token, false).await,
            ("apns-sandbox", Some(apns), _) => apns.send(&token.token, true).await,
            ("fcm", _, Some(fcm)) => fcm.send(&token.token).await,
            // Провайдер не настроен на этой установке — молча: токен
            // не мёртв, просто будить нечем.
            _ => return,
        };

        match outcome {
            Ok(Outcome::Sent) => {}
            Ok(Outcome::DeadToken) => {
                // 🔐 Мёртвый токен — лишняя связь устройства с посредником.
                let _ =
                    gasapp_server_db::repo::forget_dead_push_token(pool, device_id, &token.token)
                        .await;
            }
            // Без идентификаторов: только что и сколько.
            Err(error) => tracing::warn!(provider = %token.provider, %error, "пуш не отправлен"),
        }
    }

    /// Слушает канал конвертов и будит устройства — до остановки процесса.
    pub async fn run(self, pool: PgPool) {
        let this = Arc::new(self);
        let limiter = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let mut last: HashMap<Uuid, Instant> = HashMap::new();

        loop {
            let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::warn!(%error, "нет связи с базой, повтор через секунду");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            if let Err(error) = listener.listen(CHANNEL).await {
                tracing::warn!(%error, "LISTEN не удался");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            tracing::info!("отправщик пушей слушает канал конвертов");

            while let Ok(notification) = listener.recv().await {
                let Ok(device_id) = Uuid::parse_str(notification.payload()) else {
                    continue;
                };

                let now = Instant::now();
                if last
                    .get(&device_id)
                    .is_some_and(|at| now.duration_since(*at) < MIN_INTERVAL)
                {
                    continue;
                }
                last.insert(device_id, now);
                // Память — не журнал: старые отметки уходят.
                if last.len() > 100_000 {
                    last.retain(|_, at| now.duration_since(*at) < MIN_INTERVAL);
                }

                let Ok(permit) = Arc::clone(&limiter).acquire_owned().await else {
                    continue;
                };
                let this = Arc::clone(&this);
                let pool = pool.clone();
                tokio::spawn(async move {
                    this.wake(&pool, device_id).await;
                    drop(permit);
                });
            }

            tracing::warn!("слушатель канала оборвался, переподключение");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    fn test_p8() -> String {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(pkcs8.as_ref())
        )
    }

    #[test]
    fn apns_jwt_is_es256_and_verifies() {
        let pem = test_p8();
        let apns = Apns::new(&pem, "ABC123DEFG", "TEAM123456", "org.gasapp.messenger").unwrap();
        let token = apns.sign_jwt(1_700_000_000).unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "ABC123DEFG");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");

        // Подпись — 64 байта r‖s и проверяется открытым ключом.
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64);
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pem_to_der(&pem).unwrap())
                .unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("подпись JWT проверяется");
    }

    /// 🔐 Нагрузка не зависит ни от чего: ни текста, ни отправителя.
    #[test]
    fn payloads_are_constant_and_empty_of_content() {
        assert_eq!(
            Apns::payload().to_string(),
            r#"{"aps":{"alert":{"loc-key":"PUSH_NEW_MESSAGE"},"sound":"default","thread-id":"gasapp"}}"#
        );
        let message = Fcm::message("tok");
        assert_eq!(message["message"]["token"], "tok");
        assert!(
            message["message"].get("data").is_none(),
            "в FCM ушли бы данные"
        );
        assert!(
            message["message"].get("notification").is_none(),
            "текст уведомления — только ключами строк"
        );
        assert_eq!(
            message["message"]["android"]["notification"]["title_loc_key"],
            "notify_title"
        );
    }

    #[test]
    fn bad_keys_are_config_errors() {
        assert!(Apns::new("not a key", "K", "T", "org.gasapp.messenger").is_err());
        assert!(Apns::new(&test_p8(), "", "T", "org.gasapp.messenger").is_err());
        assert!(Fcm::new("{}").is_err());
    }
}
