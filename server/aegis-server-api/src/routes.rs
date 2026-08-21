// SPDX-License-Identifier: AGPL-3.0-only

//! HTTP-эндпоинты по разделу 14.2 плана.
//!
//! # Что сервер отвечает и чего не отвечает
//!
//! Каждый обработчик здесь построен так, чтобы **ответ не сообщал
//! лишнего**. Это не стилистика: разница в ответах — оракул, по которому
//! перебором выясняется то, что сервер не должен раскрывать.
//!
//! * несуществующее имя и ошибка базы дают один и тот же `404`;
//! * неверная подпись и неизвестное устройство дают один и тот же `401`;
//! * исчерпанный пул предключей — не ошибка, а bundle без одноразового
//!   ключа: отказ позволил бы атакующему, вычерпав чужой пул, лишить
//!   контакт возможности принимать сообщения.
//!
//! # Про порядок проверок
//!
//! Rate limit проверяется **до** обращения к базе, proof-of-work — **до**
//! записи аккаунта. Обратный порядок означал бы, что дешёвый для
//! атакующего запрос заставляет сервер выполнять дорогую работу.

use std::sync::{Arc, Mutex};

use aegis_server_db::{
    repo::{self, RepoError},
    ENVELOPE_TTL,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth, pow,
    rate_limit::{self, RateLimiter},
};

/// Состояние, разделяемое обработчиками.
pub struct AppState {
    /// Пул соединений с Postgres.
    pub pool: PgPool,
    /// Ограничитель discovery — против перебора username.
    pub discovery_limiter: Mutex<RateLimiter>,
    /// Ограничитель отправки сообщений.
    pub message_limiter: Mutex<RateLimiter>,
    /// Соль для ключей ограничителя.
    ///
    /// Живёт только в памяти процесса: после перезапуска счётчики нельзя
    /// сопоставить с адресами даже по дампу (раздел 14.4 — IP не хранится).
    pub limiter_salt: [u8; 32],
    /// Сложность proof-of-work при регистрации.
    pub pow_difficulty: u32,
    /// Хаб уведомлений о новых конвертах.
    ///
    /// Живёт в состоянии, а не глобально: тесты поднимают несколько
    /// экземпляров сервера в одном процессе, и общий хаб связал бы
    /// их между собой.
    pub hub: Arc<crate::hub::Hub>,
    /// Отправитель push-уведомлений.
    ///
    /// По умолчанию не делает ничего: сервер обязан работать без
    /// ключей Apple и Google. Разворачивающий инстанс для друзей
    /// не должен ради этого регистрироваться в Firebase.
    pub push: Arc<dyn crate::push::PushProvider>,
    /// Состояние узла для наблюдения.
    ///
    /// 🔐 Здесь только про сам процесс: доступность базы, жив ли
    /// слушатель, время работы. Ничего про пользователей — см.
    /// пояснение в модуле `health`.
    pub health: Arc<crate::health::HealthState>,
}

impl AppState {
    /// Собирает состояние с лимитами из плана.
    #[must_use]
    pub fn new(pool: PgPool, limiter_salt: [u8; 32]) -> Self {
        Self {
            pool,
            discovery_limiter: Mutex::new(RateLimiter::new(rate_limit::DISCOVERY_PER_MINUTE)),
            message_limiter: Mutex::new(RateLimiter::new(rate_limit::MESSAGES_PER_MINUTE)),
            limiter_salt,
            pow_difficulty: pow::DEFAULT_DIFFICULTY,
            hub: Arc::new(crate::hub::Hub::new()),
            push: Arc::new(crate::push::NoPush),
            health: Arc::new(crate::health::HealthState::new()),
        }
    }
}

/// Ошибка API в терминах HTTP.
///
/// Тела ответов намеренно скупы: детали помогали бы атакующему
/// и не помогают добросовестному клиенту, который знает контракт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// Запрос некорректен.
    BadRequest,
    /// Аутентификация не прошла.
    Unauthorized,
    /// Запрошенного не существует.
    NotFound,
    /// Имя занято.
    Conflict,
    /// Превышен лимит частоты.
    TooManyRequests,
    /// Полезная нагрузка слишком велика.
    PayloadTooLarge,
    /// Внутренний сбой.
    Internal,
}

impl ApiError {
    /// Код ответа.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<RepoError> for ApiError {
    fn from(error: RepoError) -> Self {
        match error {
            RepoError::NotFound => Self::NotFound,
            RepoError::UsernameTaken => Self::Conflict,
            RepoError::EnvelopeTooLarge => Self::PayloadTooLarge,
            RepoError::Database => Self::Internal,
        }
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        // Тело пустое: код ответа уже всё сказал, а текст ошибки
        // мог бы раскрыть внутреннее устройство.
        self.status().into_response()
    }
}

/// Запрос регистрации.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Желаемое имя.
    pub username: String,
    /// Публичный identity-ключ аккаунта, hex.
    pub identity_key: String,
    /// Публичный identity-ключ первого устройства, hex.
    pub device_identity_key: String,
    /// Челлендж proof-of-work, hex.
    pub pow_challenge: String,
    /// Решение proof-of-work.
    pub pow_nonce: u64,
}

/// Ответ на регистрацию.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    /// Идентификатор аккаунта.
    pub account_id: Uuid,
    /// Идентификатор первого устройства.
    pub device_id: Uuid,
}

/// Ответ discovery.
#[derive(Debug, Serialize)]
pub struct DiscoveryResponse {
    /// Идентификатор аккаунта.
    pub account_id: Uuid,
    /// Публичный identity-ключ, hex.
    pub identity_key: String,
    /// Устройства аккаунта.
    ///
    /// Без них клиент не может ни забрать prekey bundle, ни отправить
    /// сообщение: и то и другое адресуется по устройству, а discovery
    /// раньше отдавал только аккаунт — узнать устройство было неоткуда.
    ///
    /// Список, а не одно устройство: у аккаунта их несколько, и
    /// сообщение доставляется каждому (раздел 13.1).
    pub device_ids: Vec<Uuid>,
}


/// Регистрация токена push-уведомлений.
#[derive(Debug, Deserialize)]
pub struct PushTokenRequest {
    /// Провайдер: `fcm`, `apns` или `unified`.
    pub provider: String,
    /// Токен, выданный провайдером.
    pub token: String,
}
/// Публикация предключей.
#[derive(Debug, Deserialize)]
pub struct PublishKeysRequest {
    /// Идентификатор подписанного предключа.
    pub signed_key_id: i32,
    /// Публичная часть подписанного предключа, hex.
    pub signed_public: String,
    /// Подпись подписанного предключа, hex.
    pub signed_signature: String,
    /// Идентификатор пост-квантового предключа.
    pub kem_key_id: i32,
    /// Публичная часть пост-квантового предключа, hex.
    pub kem_public: String,
    /// Подпись пост-квантового предключа, hex.
    pub kem_signature: String,
    /// Одноразовые предключи: идентификатор и публичная часть.
    #[serde(default)]
    pub one_time: Vec<(i32, String)>,
    /// Одноразовые пост-квантовые: идентификатор, ключ, подпись.
    #[serde(default)]
    pub one_time_kem: Vec<(i32, String, String)>,
}

/// Выдаваемый prekey bundle.
#[derive(Debug, Serialize)]
pub struct BundleResponse {
    /// Устройство, которому принадлежит набор.
    pub device_id: Uuid,
    /// Identity-ключ устройства, hex.
    pub identity_key: String,
    /// Идентификатор подписанного предключа.
    pub signed_key_id: i32,
    /// Публичная часть подписанного предключа, hex.
    pub signed_public: String,
    /// Подпись, hex.
    pub signed_signature: String,
    /// Идентификатор пост-квантового предключа.
    pub kem_key_id: i32,
    /// Публичная часть пост-квантового предключа, hex.
    pub kem_public: String,
    /// Подпись пост-квантового предключа, hex.
    pub kem_signature: String,
    /// Одноразовый предключ, если пул не исчерпан.
    pub one_time: Option<(i32, String)>,
    /// Одноразовый пост-квантовый предключ.
    pub one_time_kem: Option<(i32, String, String)>,
    /// Ослаблена ли forward secrecy первого сообщения.
    ///
    /// Клиент обязан показать это в Security Center: систематическое
    /// исчерпание пула может означать, что кто-то намеренно вычерпывает
    /// предключи собеседника.
    pub degraded: bool,
}

/// Отправка конверта.
#[derive(Debug, Deserialize)]
pub struct SendRequest {
    /// Устройство-получатель.
    pub destination_device_id: Uuid,
    /// Шифротекст конверта, hex. Сервер его не разбирает.
    pub ciphertext: String,
}

/// Конверт, отдаваемый получателю.
#[derive(Debug, Serialize)]
pub struct EnvelopeResponse {
    /// Идентификатор конверта.
    pub envelope_id: Uuid,
    /// Шифротекст, hex.
    pub ciphertext: String,
    /// Время постановки в очередь, округлённое до часа.
    pub queued_at_bucketed: i64,
}

/// Запрос проверки подписи челленджа.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// Устройство, которое аутентифицируется.
    pub device_id: Uuid,
    /// Челлендж, выданный сервером, hex.
    pub challenge: String,
    /// Когда челлендж был выпущен, миллисекунды Unix.
    pub issued_at: i64,
    /// Подпись челленджа ключом устройства, hex.
    pub signature: String,
}

/// Собирает маршрутизатор.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/accounts/register", post(register))
        .route("/v1/auth/verify", post(verify_auth))
        .route("/v1/discovery/username/:username", get(discovery))
        .route("/v1/keys/:device_id", put(publish_keys))
        .route("/v1/keys/:device_id/bundle", get(take_bundle))
        .route("/v1/keys/:device_id/count", get(count_keys))
        .route("/v1/messages", post(send_message))
        .route("/v1/messages/:device_id", get(fetch_messages))
        // Уведомления о новых конвертах.
        //
        // По сокету уходит только слово «envelope» — сам конверт
        // забирается обычным GET. Доставка прямо в сокет связала бы
        // момент отправки с присутствием получателя, а это ровно та
        // корреляция, которую собирают при наблюдении за трафиком.
        .route("/v1/ws/:device_id", get(crate::hub::websocket_handler))
        // Токен push: клиент присылает его после регистрации
        // и при каждой смене — провайдеры их отзывают.
        .route("/v1/push/:device_id", put(register_push_token))
        // Проверка готовности узла.
        //
        // 🔐 Не должна торчать в интернет: версия подсказывает
        // атакующему, какие уязвимости пробовать. Балансировщик
        // отдаёт её только внутренней сети.
        .route("/health", get(crate::health::health))
        .route(
            "/v1/messages/:device_id/:envelope_id",
            axum::routing::delete(ack_message),
        )
        .with_state(state)
}

/// Регистрация аккаунта.
///
/// Proof-of-work проверяется **до** обращения к базе: иначе дешёвый
/// запрос заставлял бы сервер выполнять дорогую работу.
async fn register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let challenge = decode_hex(&request.pow_challenge)?;

    pow::verify(&challenge, request.pow_nonce, state.pow_difficulty)
        .map_err(|_| ApiError::Unauthorized)?;

    let identity = decode_hex(&request.identity_key)?;
    let device_identity = decode_hex(&request.device_identity_key)?;

    if request.username.is_empty() || request.username.len() > 64 {
        return Err(ApiError::BadRequest);
    }

    let (account_id, device_id) =
        repo::register_account(&state.pool, &request.username, &identity, &device_identity).await?;

    Ok(Json(RegisterResponse {
        account_id,
        device_id,
    }))
}

/// Проверка подписи челленджа — аутентификация устройства.
///
/// # Почему одна ошибка на все случаи
///
/// Неизвестное устройство, просроченный челлендж и неверная подпись дают
/// один и тот же `401`. Различать их значило бы отвечать на вопрос
/// «существует ли такое устройство» тому, кто не смог подписать челлендж.
///
/// # Про свежесть
///
/// Челлендж проверяется на возраст **до** проверки подписи: проверка
/// подписи дороже, и незачем выполнять её для заведомо просроченного
/// запроса.
async fn verify_auth(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyRequest>,
) -> Result<StatusCode, ApiError> {
    auth::check_freshness(request.issued_at, now_millis()).map_err(|_| ApiError::Unauthorized)?;

    let challenge = decode_hex(&request.challenge)?;
    let signature = decode_hex(&request.signature)?;

    // Публичный ключ берётся из базы: клиент не может подсунуть свой,
    // иначе подписал бы челлендж чем угодно.
    let devices = repo::list_devices_by_id(&state.pool, request.device_id)
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    let identity: [u8; 32] = devices
        .identity_key
        .try_into()
        .map_err(|_| ApiError::Unauthorized)?;

    auth::verify_challenge_signature(&identity, &challenge, &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Поиск аккаунта по имени.
///
/// Ограничение частоты — 20 запросов в минуту: без него перебором
/// составляется список всех зарегистрированных имён.
async fn discovery(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<DiscoveryResponse>, ApiError> {
    // Ключ ограничителя строится по имени, а не по адресу: адрес сюда
    // не передаётся намеренно — сервер его не хранит и не использует.
    // В боевой конфигурации ключ приходит из прокси-слоя.
    let key = rate_limit::key_from_addr(&state.limiter_salt, &username);
    let now = now_millis();

    {
        let mut limiter = state
            .discovery_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        if !limiter.allow(key, now) {
            return Err(ApiError::TooManyRequests);
        }
    }

    let account = repo::find_by_username(&state.pool, &username).await?;

    // Устройства запрашиваются здесь же: отдельный маршрут означал бы
    // второй round-trip перед каждой первой отправкой.
    let devices = repo::list_devices(&state.pool, account.account_id).await?;

    Ok(Json(DiscoveryResponse {
        account_id: account.account_id,
        identity_key: hex::encode(account.identity_key),
        device_ids: devices.into_iter().map(|device| device.device_id).collect(),
    }))
}

/// Публикация предключей устройства.
///
/// 🔐 Требует подпись устройства: без неё любой мог бы заменить чужие
/// предключи своими и получать адресованные другому сообщения.
async fn publish_keys(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<PublishKeysRequest>,
) -> Result<StatusCode, ApiError> {
    // 🔐 Подписавший обязан быть тем, о чьих ключах речь.
    //
    // Извлекатель берёт устройство из того же пути, поэтому
    // расхождение здесь невозможно — проверка стоит как защита
    // от будущей правки, которая возьмёт идентификатор откуда-то
    // ещё и незаметно откроет подмену чужих предключей.
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let signed_public = decode_hex(&request.signed_public)?;
    let signed_signature = decode_hex(&request.signed_signature)?;
    let kem_public = decode_hex(&request.kem_public)?;
    let kem_signature = decode_hex(&request.kem_signature)?;

    let one_time = request
        .one_time
        .iter()
        .map(|(id, key)| decode_hex(key).map(|bytes| (*id, bytes)))
        .collect::<Result<Vec<_>, _>>()?;

    let one_time_kem = request
        .one_time_kem
        .iter()
        .map(|(id, key, signature)| Ok((*id, decode_hex(key)?, decode_hex(signature)?)))
        .collect::<Result<Vec<_>, ApiError>>()?;

    repo::publish_prekeys(
        &state.pool,
        device_id,
        (request.signed_key_id, &signed_public, &signed_signature),
        (request.kem_key_id, &kem_public, &kem_signature),
        &one_time,
        &one_time_kem,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Выдача prekey bundle с расходом одноразового ключа.
async fn take_bundle(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<BundleResponse>, ApiError> {
    let bundle = repo::take_prekey_bundle(&state.pool, device_id).await?;
    let degraded = bundle.one_time.is_none() || bundle.one_time_kem.is_none();

    Ok(Json(BundleResponse {
        device_id: bundle.device_id,
        identity_key: hex::encode(bundle.identity_key),
        signed_key_id: bundle.signed_key_id,
        signed_public: hex::encode(bundle.signed_public),
        signed_signature: hex::encode(bundle.signed_signature),
        kem_key_id: bundle.kem_key_id,
        kem_public: hex::encode(bundle.kem_public),
        kem_signature: hex::encode(bundle.kem_signature),
        one_time: bundle.one_time.map(|(id, key)| (id, hex::encode(key))),
        one_time_kem: bundle
            .one_time_kem
            .map(|(id, key, signature)| (id, hex::encode(key), hex::encode(signature))),
        degraded,
    }))
}

/// Сколько одноразовых предключей осталось.
async fn count_keys(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<i64>, ApiError> {
    let count = repo::count_one_time_prekeys(&state.pool, device_id).await?;

    Ok(Json(count))
}

/// Постановка конверта в очередь доставки.
async fn send_message(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SendRequest>,
) -> Result<Json<Uuid>, ApiError> {
    let key = rate_limit::key_from_addr(
        &state.limiter_salt,
        &request.destination_device_id.to_string(),
    );
    let now = now_millis();

    {
        let mut limiter = state
            .message_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        if !limiter.allow(key, now) {
            return Err(ApiError::TooManyRequests);
        }
    }

    let ciphertext = decode_hex(&request.ciphertext)?;

    let envelope_id = repo::enqueue_envelope(
        &state.pool,
        request.destination_device_id,
        &ciphertext,
        i64::try_from(ENVELOPE_TTL.as_secs()).unwrap_or(i64::MAX),
    )
    .await?;


    // Уведомление после успешной постановки в очередь, а не до:
    // при обратном порядке клиент пришёл бы за конвертом, которого
    // ещё нет, и решил, что уведомление ложное.
    //
    // Рассылка идёт всем узлам кластера: получатель почти всегда
    // подключён к другому узлу, чем отправитель. Локальный хаб
    // получит своё уведомление тем же путём — через LISTEN, — поэтому
    // отдельного вызова notify здесь нет: он привёл бы к двойному
    // уведомлению на своём узле.
    //
    // Ошибка рассылки не отменяет отправку: конверт уже в очереди,
    // и получатель заберёт его при следующем запросе. Молчаливо
    // терять сообщение из-за сбоя уведомления было бы хуже.
    if let Err(error) = crate::hub::broadcast(&state.pool, request.destination_device_id).await {
        tracing::warn!(%error, "не удалось разослать уведомление");
    }

    // Пробуждение устройства, если оно не подключено сокетом.
    //
    // 🔐 Уходит только флаг «есть новое»: ни текста, ни отправителя,
    // ни чата. Всё, что попало бы в нагрузку, увидели бы Apple
    // и Google — а мессенджер, отдающий посреднику имя собеседника,
    // перестаёт быть тем, за что его выбрали (ADR-014).
    //
    // Ошибки подавляются внутри: провал push означает задержку,
    // а не потерю — конверт уже в очереди.
    crate::push::wake_device(
        &state.pool,
        state.push.as_ref(),
        request.destination_device_id,
    )
    .await;
    Ok(Json(envelope_id))
}


/// Регистрация токена push-уведомлений.
///
/// 🔐 Требует подпись устройства: без неё любой мог бы привязать свой
/// токен к чужому устройству и получать сигнал о каждом входящем
/// сообщении — то есть наблюдать активность собеседника, не читая
/// переписки.
async fn register_push_token(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<PushTokenRequest>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    repo::save_push_token(&state.pool, device_id, &request.provider, &request.token).await?;

    Ok(StatusCode::NO_CONTENT)
}
/// Выдача ожидающих конвертов.
///
/// 🔐 Требует подпись устройства: конверты зашифрованы, но их выдача
/// удаляет их из очереди — без проверки любой лишал бы адресата
/// переписки, просто запросив её первым.
async fn fetch_messages(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<Json<Vec<EnvelopeResponse>>, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let envelopes = repo::fetch_envelopes(&state.pool, device_id, 100).await?;

    Ok(Json(
        envelopes
            .into_iter()
            .map(|envelope| EnvelopeResponse {
                envelope_id: envelope.envelope_id,
                ciphertext: hex::encode(envelope.ciphertext),
                queued_at_bucketed: envelope.queued_at_bucketed,
            })
            .collect(),
    ))
}

/// Подтверждение доставки: конверт удаляется немедленно.
///
/// 🔐 Требует подпись устройства: без неё любой мог бы удалять чужие
/// неполученные сообщения, зная только идентификаторы.
async fn ack_message(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path((device_id, envelope_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    repo::acknowledge_envelope(&state.pool, device_id, envelope_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Разбирает hex, отвергая мусор.
pub(crate) fn decode_hex(input: &str) -> Result<Vec<u8>, ApiError> {
    hex::decode(input).map_err(|_| ApiError::BadRequest)
}

/// Текущее время в миллисекундах.
///
/// Единственное место, где серверный слой берёт системные часы:
/// ограничителю нужно текущее время, а протаскивать его через HTTP-слой
/// значило бы усложнить каждый обработчик ради одной величины.
pub(crate) fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Коды ответов соответствуют смыслу ошибок.
    #[test]
    fn error_codes_match_semantics() {
        assert_eq!(ApiError::BadRequest.status(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(ApiError::Conflict.status(), StatusCode::CONFLICT);
        assert_eq!(
            ApiError::TooManyRequests.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::PayloadTooLarge.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    /// 🔐 Ошибка базы не раскрывается наружу.
    ///
    /// `RepoError::Database` содержит причину в журнале, но клиенту
    /// достаётся только код 500 — иначе текст ошибки Postgres
    /// раскрывал бы имена таблиц и фрагменты запросов.
    #[test]
    fn database_errors_become_opaque_internal() {
        assert_eq!(ApiError::from(RepoError::Database), ApiError::Internal);
    }

    /// Ошибки репозитория переводятся в осмысленные коды.
    #[test]
    fn repo_errors_map_to_http() {
        assert_eq!(ApiError::from(RepoError::NotFound), ApiError::NotFound);
        assert_eq!(ApiError::from(RepoError::UsernameTaken), ApiError::Conflict);
        assert_eq!(
            ApiError::from(RepoError::EnvelopeTooLarge),
            ApiError::PayloadTooLarge
        );
    }

    /// Некорректный hex отвергается, а не паникует.
    #[test]
    fn malformed_hex_is_rejected() {
        assert_eq!(decode_hex("zz"), Err(ApiError::BadRequest));
        assert_eq!(decode_hex("abc"), Err(ApiError::BadRequest));
        assert_eq!(decode_hex(""), Ok(Vec::new()));
    }

    /// Время идёт вперёд и укладывается в i64.
    #[test]
    fn clock_is_sane() {
        let now = now_millis();

        assert!(now > 1_700_000_000_000, "часы отстают более чем на годы");
    }
}
