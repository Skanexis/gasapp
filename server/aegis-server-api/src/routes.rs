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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aegis_server_db::{
    repo::{self, RepoError},
    ATTACHMENT_TTL, ENVELOPE_TTL, MAX_ATTACHMENT_BYTES,
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
    auth, certificate, pow,
    rate_limit::{self, RateLimiter},
};

/// Состояние, разделяемое обработчиками.
pub struct AppState {
    /// Пул соединений с Postgres.
    pub pool: PgPool,
    /// Ограничитель discovery — против перебора username.
    pub discovery_limiter: Mutex<RateLimiter>,
    /// Последние ответы discovery по имени — их получает запрашивающий
    /// сверх бюджета имени (см. `discovery`).
    pub discovery_cache: Mutex<HashMap<String, (i64, DiscoveryResponse)>>,
    /// Ограничитель запечатанной отправки — по получателю.
    ///
    /// Считаются только принятые конверты: мусор без ключа доступа
    /// и без работы идёт в [`AppState::sealed_rejected_limiter`].
    pub sealed_limiter: Mutex<RateLimiter>,
    /// Ограничитель первых контактов (по proof-of-work) — по получателю;
    /// свой, чтобы незнакомцы не тратили бюджет собеседников.
    pub sealed_first_contact_limiter: Mutex<RateLimiter>,
    /// Ограничитель отвергнутых запечатанных попыток — по получателю.
    ///
    /// Попытки без верного ключа доступа считаются здесь, а не в бюджете
    /// получателя: чужой мусор не должен тратить то, что принадлежит
    /// его собеседникам.
    pub sealed_rejected_limiter: Mutex<RateLimiter>,
    /// Ограничитель выдачи prekey bundle.
    ///
    /// 🔐 Отдельный от остальных: выдача расходует одноразовый предключ,
    /// то есть тратит ресурс получателя, а не пропускную способность.
    pub bundle_limiter: Mutex<RateLimiter>,
    /// Неудачные попытки перепривязки аккаунта, по имени.
    ///
    /// 🔐 Считаются **только отказы**: верная подпись ключа
    /// восстановления проходит всегда. Прежде перепривязка делила
    /// ограничитель с discovery, и посторонний, зная имя, двадцатью
    /// бесплатными запросами в минуту не давал владельцу вернуть
    /// аккаунт — а подделать подпись ключа восстановления нельзя,
    /// так что ограничитель ничего не защищал, только мешал.
    pub recovery_failures_limiter: Mutex<RateLimiter>,
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

    /// Приватный ключ, которым сервер подписывает сертификаты
    /// отправителя (раздел 15.2).
    ///
    /// 🔐 Ключ узла, а не пользователя: им подписывается утверждение
    /// «этот identity-ключ принадлежит этому аккаунту». Утечка ключа
    /// позволяет выписывать поддельные сертификаты — то есть выдавать
    /// чужие сообщения за сообщения другого аккаунта. От этого
    /// защищает не он, а safety number, но менять его при подозрении
    /// всё равно нужно.
    ///
    /// В кластере ключ обязан быть одним на все узлы: сертификат,
    /// выданный одним узлом, проверяется клиентом независимо от того,
    /// через какой узел пришло сообщение. Задаётся переменной
    /// окружения, а не генерируется при старте.
    pub certificate_key: [u8; 32],

    /// Места для одновременных загрузок вложений (см. [`limit_uploads`]).
    pub upload_slots: Arc<tokio::sync::Semaphore>,
}

/// Сколько вложений узел принимает одновременно.
///
/// 🔐 Тело загрузки буферизуется целиком (до 101 МБ): работа считается
/// над всем блобом. Без предела десяток медленных загрузок через
/// onion-сервис — где нет ни nginx, ни ограничения по адресу — занимал
/// бы гигабайт памяти узла (аудит 2026-10-02, S-3).
pub const MAX_CONCURRENT_UPLOADS: usize = 8;

/// Сколько может длиться одна загрузка вложения.
///
/// Сто мегабайт через Tor — десять-пятнадцать минут; дольше место
/// держит уже не человек, а тот, кто занимает его нарочно.
pub const UPLOAD_DEADLINE: std::time::Duration = std::time::Duration::from_mins(20);

impl AppState {
    /// Собирает состояние с лимитами из плана.
    #[must_use]
    /// Собирает состояние для одиночного узла.
    ///
    /// Лимиты применяются целиком: узел один, делить не на что.
    pub fn new(pool: PgPool, limiter_salt: [u8; 32]) -> Self {
        Self::with_nodes(pool, limiter_salt, rate_limit::DEFAULT_CLUSTER_NODES)
    }

    /// Собирает состояние с учётом числа узлов кластера.
    ///
    /// 🔐 Лимиты делятся на `nodes`: счётчики живут в памяти процесса,
    /// и без деления заявленные 20 запросов в минуту превратились бы
    /// в 60 на трёх узлах — то есть заявление перестало бы быть
    /// правдой.
    ///
    /// Число узлов задаётся конфигурацией, а не определяется само:
    /// автоопределение потребовало бы, чтобы узлы знали друг о друге,
    /// то есть ещё одного механизма, который может сломаться молча.
    #[must_use]
    pub fn with_nodes(pool: PgPool, limiter_salt: [u8; 32], nodes: u32) -> Self {
        Self::with_certificate_key(pool, limiter_salt, nodes, certificate_key_from_env())
    }

    /// Собирает состояние с явно заданным ключом подписи сертификатов.
    ///
    /// Нужен тестам: они поднимают сервер в процессе и должны знать
    /// ключ, чтобы проверять выданные сертификаты.
    #[must_use]
    pub fn with_certificate_key(
        pool: PgPool,
        limiter_salt: [u8; 32],
        nodes: u32,
        certificate_key: [u8; 32],
    ) -> Self {
        Self {
            certificate_key,
            pool,
            discovery_limiter: Mutex::new(RateLimiter::new(rate_limit::per_node(
                rate_limit::DISCOVERY_PER_MINUTE,
                nodes,
            ))),
            discovery_cache: Mutex::new(HashMap::new()),
            bundle_limiter: Mutex::new(RateLimiter::new(rate_limit::per_node(
                rate_limit::BUNDLE_PER_MINUTE,
                nodes,
            ))),
            recovery_failures_limiter: Mutex::new(RateLimiter::new(rate_limit::per_node(
                rate_limit::DISCOVERY_PER_MINUTE,
                nodes,
            ))),
            sealed_limiter: Mutex::new(RateLimiter::new(rate_limit::per_node(
                rate_limit::MESSAGES_PER_MINUTE,
                nodes,
            ))),
            sealed_rejected_limiter: Mutex::new(RateLimiter::new(rate_limit::per_node(
                rate_limit::MESSAGES_PER_MINUTE,
                nodes,
            ))),
            sealed_first_contact_limiter: Mutex::new(RateLimiter::new(rate_limit::per_node(
                rate_limit::FIRST_CONTACTS_PER_MINUTE,
                nodes,
            ))),
            limiter_salt,
            pow_difficulty: pow::DEFAULT_DIFFICULTY,
            hub: Arc::new(crate::hub::Hub::new()),
            push: Arc::new(crate::push::NoPush),
            health: Arc::new(crate::health::HealthState::new()),
            upload_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
        }
    }
}

/// 🔐 Ограничивает одновременные загрузки вложений и их длительность.
///
/// Место занимается до чтения тела: тело и есть то, что занимает память.
/// Мест нет — `429`, клиент повторит через очередь. Загрузка дольше
/// [`UPLOAD_DEADLINE`] обрывается, и место освобождается.
async fn limit_uploads(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let Ok(_slot) = Arc::clone(&state.upload_slots).try_acquire_owned() else {
        return ApiError::TooManyRequests.into_response();
    };

    tokio::time::timeout(UPLOAD_DEADLINE, next.run(request))
        .await
        .unwrap_or_else(|_| ApiError::TooManyRequests.into_response())
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
    /// Место, отведённое устройству, исчерпано.
    InsufficientStorage,
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
            Self::InsufficientStorage => StatusCode::INSUFFICIENT_STORAGE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<RepoError> for ApiError {
    fn from(error: RepoError) -> Self {
        match error {
            RepoError::NotFound => Self::NotFound,
            RepoError::UsernameTaken => Self::Conflict,
            // Повтор перепривязки — отказ авторизации, а не «конфликт»:
            // отличать их вслух незачем.
            RepoError::Conflict => Self::Unauthorized,
            // Чужой ключ identity — испорченный запрос, а не «имя занято»:
            // настоящему владельцу свежего ключа сюда не попасть.
            RepoError::IdentityInUse => Self::BadRequest,
            RepoError::EnvelopeTooLarge | RepoError::AttachmentTooLarge => Self::PayloadTooLarge,
            // Исчерпанная квота — не «слишком большой файл»: тот же
            // файл пройдёт, когда прежние вложения истекут. 507 говорит
            // именно это, а 413 заставил бы клиента сжимать заново
            // и упереться снова.
            RepoError::QuotaExceeded => Self::InsufficientStorage,
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
    /// 🔐 Пост-квантовая половина identity — ключ ML-DSA-65, hex.
    #[serde(default)]
    pub pq_identity_key: Option<String>,
    /// Гибридная привязка половин identity, hex.
    #[serde(default)]
    pub identity_binding: Option<String>,
    /// Ключ восстановления аккаунта — классическая половина, hex.
    #[serde(default)]
    pub recovery_key: Option<String>,
    /// Ключ восстановления аккаунта — ML-DSA-65, hex.
    #[serde(default)]
    pub recovery_pq_key: Option<String>,
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

/// Сколько живёт снимок ответа discovery, отдаваемый сверх бюджета имени.
const DISCOVERY_SNAPSHOT_MILLIS: i64 = 5 * 60 * 1000;

/// Предел числа снимков discovery в памяти узла.
const DISCOVERY_CACHE_ENTRIES: usize = 1024;

/// Ответ discovery.
#[derive(Debug, Clone, Serialize)]
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
    /// Ключ ML-KEM-1024 sealed sender первого устройства, hex.
    ///
    /// 🔐 Без него отправитель не может запечатать конверт гибридно,
    /// и имя отправителя защищала бы одна кривая X25519. Подписан
    /// identity-ключом владельца — подпись проверяет отправитель.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_kem_public: Option<String>,
    /// Подпись ключа ML-KEM sealed sender, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_kem_signature: Option<String>,
    /// Пост-квантовая половина identity, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_identity_key: Option<String>,
    /// Гибридная привязка половин identity, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<String>,
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
    /// Ключ ML-KEM-1024 sealed sender устройства, hex.
    #[serde(default)]
    pub sealed_kem_public: Option<String>,
    /// Подпись ключа ML-KEM sealed sender identity-ключом, hex.
    #[serde(default)]
    pub sealed_kem_signature: Option<String>,
    /// Пост-квантовая половина identity — у аккаунтов, заведённых без неё.
    #[serde(default)]
    pub pq_identity_key: Option<String>,
    /// Гибридная привязка половин identity.
    #[serde(default)]
    pub identity_binding: Option<String>,
}

/// Выдаваемый prekey bundle.
#[derive(Debug, Serialize)]
pub struct BundleResponse {
    /// Устройство, которому принадлежит набор.
    pub device_id: Uuid,
    /// Identity-ключ устройства, hex.
    pub identity_key: String,
    /// Пост-квантовая половина identity владельца, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_identity_key: Option<String>,
    /// Гибридная привязка половин identity, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<String>,
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
        // 🔐 Перепривязка аккаунта к новой identity — без подписи
        // устройства (старых устройств у человека уже нет): право
        // доказывает подпись ключа восстановления (см. `recovery`).
        .route("/v1/accounts/recover", post(recover_account))
        // 🔐 Удаление аккаунта (MASVS PRIVACY-3.2).
        //
        // Адресуется устройством, а не аккаунтом: право доказывается
        // подписью, а подписывает устройство. Аккаунт сервер находит
        // сам — иначе клиент назвал бы чужой.
        .route(
            "/v1/accounts/:device_id",
            axum::routing::delete(delete_account),
        )
        .route("/v1/auth/verify", post(verify_auth))
        .route("/v1/discovery/username/:username", get(discovery))
        // 🔐 Журнал ключей (§9.7): без аутентификации — сервер не должен
        // знать, кто проверяет, иначе показал бы проверяющему своё дерево.
        .route("/v1/kt/heads", get(crate::kt::heads_all))
        .route("/v1/kt/heads/:from", get(crate::kt::heads_from))
        .route("/v1/kt/proofs", post(crate::kt::proofs))
        .route("/v1/keys/:device_id", put(publish_keys))
        .route("/v1/keys/:device_id/bundle", get(take_bundle))
        .route("/v1/keys/:device_id/count", get(count_keys))
        // Очередь устройства: только чтение, за подписью владельца.
        //
        // 🔐 Отправки здесь нет. Прежде `POST` принимал конверт за
        // подписью отправителя — для первого сообщения, пока ключа
        // доступа ещё нет. Первый контакт давно запечатан (proof-of-work),
        // клиент маршрутом не пользовался, а сервер, который его держит,
        // мог бы принять подписанный конверт от изменённого клиента —
        // и узнать, кто кому пишет. Единственный путь отправки —
        // `/v1/sealed/messages`.
        .route("/v1/messages/:device_id", get(fetch_messages))
        // Sealed sender (раздел 15.2).
        //
        // 🔐 Отправка идёт по отдельному маршруту без аутентификации
        // отправителя: подпись и была бы той меткой, которую sealed
        // sender убирает. Право на отправку доказывается ключом
        // доступа получателя, а не личностью отправителя.
        .route("/v1/sealed/messages", post(send_sealed_message))
        .route("/v1/sealed/access/:device_id", put(publish_sealed_access))
        .route("/v1/sealed/certificate/:device_id", get(issue_certificate))
        .route("/v1/sealed/report/:device_id", post(report_sealed_sender))
        // Уведомления о новых конвертах.
        //
        // По сокету уходит только слово «envelope» — сам конверт
        // забирается обычным GET. Доставка прямо в сокет связала бы
        // момент отправки с присутствием получателя, а это ровно та
        // корреляция, которую собирают при наблюдении за трафиком.
        //
        // 🔐 Маршрут требует подпись устройства. Без неё та же
        // корреляция раздавалась даром: `discovery` отдаёт `device_ids`
        // по имени пользователя без аутентификации, а сокет открывал
        // по этому идентификатору поток уведомлений кому угодно.
        // Время прихода «envelope» и есть метаданные — см. `hub`.
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
        // Вложения: шифроблоб внутрь, шифроблоб наружу.
        //
        // 🔐 Тело — сырые байты, а не JSON с hex: hex удваивает объём,
        // и стомегабайтный файл занял бы двести мегабайт трафика
        // и памяти на разбор.
        //
        // Предел тела поднят отдельно для этих двух маршрутов:
        // умолчание axum в 2 МБ отвергло бы любое вложение крупнее
        // короткого голосового, а поднимать его для всего сервера
        // значило бы разрешить стомегабайтную регистрацию.
        // 🔐 Загрузка и скачивание — без подписи: сервер не знает ни
        // загрузчика, ни получателя (см. `upload_attachment`).
        .route(
            "/v1/attachments/blob",
            post(upload_attachment)
                .layer(axum::extract::DefaultBodyLimit::max(MAX_ATTACHMENT_BYTES))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    limit_uploads,
                )),
        )
        .route(
            "/v1/attachments/blob/:attachment_id",
            get(download_attachment),
        )
        // 🔐 Подписанные запросы — через проверку подписи и тела
        // (`authz::verify_signed_request`). `route_layer`, а не `layer`:
        // слой работает после маршрутизации, когда устройство из пути
        // известно. Надет на все маршруты выше — неподписанные проходят
        // его насквозь.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::authz::verify_signed_request,
        ))
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
    let identity = decode_hex(&request.identity_key)?;
    let device_identity = decode_hex(&request.device_identity_key)?;

    // 🔐 Ключи — ровно 32 байта, как при перепривязке. Прежде длина
    // не проверялась: сервер хранил и раздавал ключ любой длины, а журнал
    // ключей такой аккаунт молча пропускал.
    if identity.len() != 32 || device_identity.len() != 32 {
        return Err(ApiError::BadRequest);
    }

    // 🔐 Челлендж обязан быть выведен из этой самой регистрации.
    //
    // Прежде сервер проверял работу над любым челленджем, который
    // прислал клиент, и одно решение регистрировало сколько угодно
    // аккаунтов. Теперь решение привязано к имени и ключам: для нового
    // имени его надо искать заново (см. `pow::registration_challenge`).
    if challenge != pow::registration_challenge(&request.username, &identity, &device_identity) {
        return Err(ApiError::Unauthorized);
    }

    pow::verify(&challenge, request.pow_nonce, state.pow_difficulty)
        .map_err(|_| ApiError::Unauthorized)?;

    // 🔐 Только каноничное имя: иначе «alice» и «аlice» с кириллической
    // «а» были бы разными аккаунтами с одинаковым видом.
    if !aegis_server_db::is_canonical_username(&request.username) {
        return Err(ApiError::BadRequest);
    }

    // 🔐 Пост-квантовая половина identity обязательна: без неё гибридные
    // подписи клиентов не проверить. Сервер проверяет только длины —
    // подлинность проверяют клиенты.
    let (pq_public, binding) = decode_pq_identity(
        request.pq_identity_key.as_deref(),
        request.identity_binding.as_deref(),
    )?
    .ok_or(ApiError::BadRequest)?;

    let (account_id, device_id) =
        repo::register_account(&state.pool, &request.username, &identity, &device_identity).await?;
    repo::set_pq_identity(&state.pool, account_id, &pq_public, &binding).await?;

    // Ключ восстановления аккаунта: без него имя не пережило бы
    // переустановку. Необязателен для запроса — клиенты прежних
    // сборок его не присылают.
    if let (Some(public), Some(pq_public)) = (&request.recovery_key, &request.recovery_pq_key) {
        let public = decode_hex(public)?;
        let pq_public = decode_hex(pq_public)?;

        if public.len() != 32 || pq_public.len() != PQ_IDENTITY_KEY_LEN {
            return Err(ApiError::BadRequest);
        }

        repo::set_recovery_key(&state.pool, account_id, &public, &pq_public).await?;
    }

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
    // ⚠️ Ключ ограничителя строится по **искомому имени**, а не по
    // тому, кто спрашивает. Адрес сюда не передаётся намеренно:
    // сервер его не хранит и не использует (раздел 14.4).
    //
    // Отсюда прямое следствие, которое надо понимать: этот
    // ограничитель **не мешает перебору**. Каждое новое имя — новый
    // ключ со своим бюджетом, и словарь из тысячи имён проходит
    // тысячей запросов, ни один из которых не будет отклонён.
    // Измерено: шестьдесят запросов к разным именам — ноль отказов;
    // шестьдесят к одному имени — сорок отказов.
    //
    // Он защищает от другого: от долбёжки по одному имени, то есть
    // от попытки следить за конкретным человеком — появился ли,
    // сменил ли устройства.
    //
    // 🔐 От перебора защищает ограничение **по клиенту**, и ему
    // место на балансировщике: там адрес уже есть, там он никуда
    // не пишется и дальше не передаётся. Настройка `limit_req` —
    // в `deploy/РАЗВЁРТЫВАНИЕ.md`. Прежде здесь стояло «в боевой
    // конфигурации ключ приходит из прокси-слоя», и это было
    // неправдой: ни механизма приёма такого ключа, ни настройки
    // в руководстве не существовало.
    // Неканоничного имени нет и быть не может — тот же ответ, что
    // у отсутствующего, и до ограничителя: бюджет им не тратится.
    if !aegis_server_db::is_canonical_username(&username) {
        return Err(ApiError::NotFound);
    }

    let key = rate_limit::key_from_addr(&state.limiter_salt, &username);
    let now = now_millis();

    let within_budget = {
        let mut limiter = state
            .discovery_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        limiter.allow(key, now)
    };

    // 🔐 Сверх бюджета имени — недавний снимок, а не отказ.
    //
    // Отправка идёт через discovery на каждое сообщение, и прежде
    // посторонний, бесплатно выбирая двадцать запросов в минуту по имени,
    // не давал **никому** писать этому человеку (429 на каждую отправку).
    // Снимок сохраняет то, ради чего ограничитель стоит: за человеком
    // нельзя следить частыми запросами — сверх бюджета ответ не меняется
    // пять минут.
    if !within_budget {
        let cache = state
            .discovery_cache
            .lock()
            .map_err(|_| ApiError::Internal)?;

        return match cache.get(&username) {
            Some((at, cached)) if now.saturating_sub(*at) <= DISCOVERY_SNAPSHOT_MILLIS => {
                Ok(Json(cached.clone()))
            }
            _ => Err(ApiError::TooManyRequests),
        };
    }

    let account = repo::find_by_username(&state.pool, &username).await?;

    // Устройства запрашиваются здесь же: отдельный маршрут означал бы
    // второй round-trip перед каждой первой отправкой.
    let devices = repo::list_devices(&state.pool, account.account_id).await?;

    let sealed_kem = match devices.first() {
        Some(first) => repo::sealed_kem_of(&state.pool, first.device_id).await?,
        None => None,
    };
    let pq = repo::pq_identity_of(&state.pool, account.account_id).await?;

    let response = DiscoveryResponse {
        account_id: account.account_id,
        identity_key: hex::encode(account.identity_key),
        device_ids: devices.into_iter().map(|device| device.device_id).collect(),
        sealed_kem_public: sealed_kem.as_ref().map(|(public, _)| hex::encode(public)),
        sealed_kem_signature: sealed_kem
            .as_ref()
            .map(|(_, signature)| hex::encode(signature)),
        pq_identity_key: pq.as_ref().map(|(public, _)| hex::encode(public)),
        identity_binding: pq.as_ref().map(|(_, binding)| hex::encode(binding)),
    };

    {
        let mut cache = state
            .discovery_cache
            .lock()
            .map_err(|_| ApiError::Internal)?;
        if cache.len() >= DISCOVERY_CACHE_ENTRIES {
            // Вытесняется самый старый снимок: предел держит память,
            // а не полноту.
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(name, _)| name.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(username, (now, response.clone()));
    }

    Ok(Json(response))
}

/// Запрос перепривязки аккаунта к новой identity.
#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    /// Имя аккаунта.
    pub username: String,
    /// Новый identity-ключ, hex.
    pub identity_key: String,
    /// Identity-ключ нового устройства, hex.
    pub device_identity_key: String,
    /// Пост-квантовая половина новой identity, hex.
    pub pq_identity_key: String,
    /// Её привязка, hex.
    pub identity_binding: String,
    /// Момент подписи, мс.
    pub issued_at: i64,
    /// Гибридная подпись ключа восстановления, hex.
    pub signature: String,
}

/// Перепривязывает аккаунт к новой identity (см. модуль `recovery`).
///
/// # 🔐 Что проверяется
///
/// * имя каноническое и аккаунт существует;
/// * у аккаунта есть ключ восстановления, и гибридная подпись запроса
///   сходится обеими половинами;
/// * момент подписи — в пределах пяти минут от часов сервера и новее
///   прошлой перепривязки: перехваченный запрос не повторить.
///
/// Любой отказ — `401`, одинаково: «нет такого имени», «нет ключа»
/// и «подпись не та» наружу не различаются.
async fn recover_account(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RecoverRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    if !aegis_server_db::is_canonical_username(&request.username) {
        return Err(ApiError::Unauthorized);
    }

    // Отказ считается в бюджет имени; сверх бюджета — 429 вместо 401.
    // Верную подпись бюджет не задерживает (см. `recovery_failures_limiter`).
    let refuse = |state: &AppState| -> ApiError {
        let key = rate_limit::key_from_addr(&state.limiter_salt, &request.username);
        match state.recovery_failures_limiter.lock() {
            Ok(mut limiter) => {
                if limiter.allow(key, now_millis()) {
                    ApiError::Unauthorized
                } else {
                    ApiError::TooManyRequests
                }
            }
            Err(_) => ApiError::Internal,
        }
    };

    let identity = decode_hex(&request.identity_key)?;
    let device_identity = decode_hex(&request.device_identity_key)?;
    let signature = decode_hex(&request.signature)?;
    let (pq_public, binding) = decode_pq_identity(
        Some(&request.pq_identity_key),
        Some(&request.identity_binding),
    )?
    .ok_or(ApiError::BadRequest)?;

    if identity.len() != 32 || device_identity.len() != 32 {
        return Err(ApiError::BadRequest);
    }

    if now_millis().abs_diff(request.issued_at) > crate::recovery::MAX_SKEW_MILLIS.unsigned_abs() {
        return Err(refuse(&state));
    }

    let Ok(account) = repo::find_by_username(&state.pool, &request.username).await else {
        return Err(refuse(&state));
    };
    let Some((recovery_key, recovery_pq_key)) =
        repo::recovery_key_of(&state.pool, account.account_id).await?
    else {
        return Err(refuse(&state));
    };

    let message = crate::recovery::message(
        &request.username,
        &identity,
        &device_identity,
        &pq_public,
        &binding,
        request.issued_at,
    );

    if !crate::recovery::verify(&recovery_key, &recovery_pq_key, &message, &signature) {
        return Err(refuse(&state));
    }

    let device_id = repo::rebind_account(
        &state.pool,
        account.account_id,
        repo::Rebind {
            identity_key: &identity,
            device_identity_key: &device_identity,
            pq_identity_key: &pq_public,
            identity_binding: &binding,
            issued_at_millis: request.issued_at,
        },
    )
    .await?;

    Ok(Json(RegisterResponse {
        account_id: account.account_id,
        device_id,
    }))
}

/// Длина ключа ML-DSA-65.
const PQ_IDENTITY_KEY_LEN: usize = 1952;

/// Наибольшая длина токена push: у FCM и APNs — сотни символов.
const MAX_PUSH_TOKEN_CHARS: usize = 4096;

/// Наибольшая длина открытого предключа: ML-KEM-1024 (1568) с запасом.
const MAX_PREKEY_PUBLIC_BYTES: usize = 2048;

/// Наибольшая длина подписи предключа: гибридная (3373) с запасом.
const MAX_PREKEY_SIGNATURE_BYTES: usize = 4096;

/// Разбирает hex с пределом длины: сверх предела — отказ, а не запись.
fn decode_key(hex_text: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    if hex_text.len() > max_bytes.saturating_mul(2) {
        return Err(ApiError::BadRequest);
    }

    decode_hex(hex_text)
}

/// Длина гибридной подписи: XEdDSA (64) ‖ ML-DSA-65 (3309).
const HYBRID_SIGNATURE_LEN: usize = 3373;

/// Разбирает пост-квантовую половину identity; `None` — не прислана.
///
/// Прислана наполовину или не той длины — отказ: неполная половина
/// выглядела бы у клиентов подменой.
fn decode_pq_identity(
    public: Option<&str>,
    binding: Option<&str>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, ApiError> {
    match (public, binding) {
        (None, None) => Ok(None),
        (Some(public), Some(binding)) => {
            let public = decode_hex(public)?;
            let binding = decode_hex(binding)?;

            if public.len() != PQ_IDENTITY_KEY_LEN || binding.len() != HYBRID_SIGNATURE_LEN {
                return Err(ApiError::BadRequest);
            }

            Ok(Some((public, binding)))
        }
        _ => Err(ApiError::BadRequest),
    }
}

/// Длина открытого ключа ML-KEM-1024.
const SEALED_KEM_PUBLIC_LEN: usize = 1568;

/// Длина подписи XEdDSA.
const SEALED_KEM_SIGNATURE_LEN: usize = HYBRID_SIGNATURE_LEN;

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

    // 🔐 Пределы до разбора: число ключей и длина каждого. Прежде
    // сервер хранил и раздавал другим ключи любой длины — мегабайт
    // на ключ, — и загрузка ничем не ограничивалась.
    let max_keys = usize::try_from(repo::MAX_ONE_TIME_PREKEYS).unwrap_or(usize::MAX);
    if request.one_time.len() > max_keys || request.one_time_kem.len() > max_keys {
        return Err(ApiError::BadRequest);
    }

    let signed_public = decode_key(&request.signed_public, MAX_PREKEY_PUBLIC_BYTES)?;
    let signed_signature = decode_key(&request.signed_signature, MAX_PREKEY_SIGNATURE_BYTES)?;
    let kem_public = decode_key(&request.kem_public, MAX_PREKEY_PUBLIC_BYTES)?;
    let kem_signature = decode_key(&request.kem_signature, MAX_PREKEY_SIGNATURE_BYTES)?;

    let one_time = request
        .one_time
        .iter()
        .map(|(id, key)| decode_key(key, MAX_PREKEY_PUBLIC_BYTES).map(|bytes| (*id, bytes)))
        .collect::<Result<Vec<_>, _>>()?;

    let one_time_kem = request
        .one_time_kem
        .iter()
        .map(|(id, key, signature)| {
            Ok((
                *id,
                decode_key(key, MAX_PREKEY_PUBLIC_BYTES)?,
                decode_key(signature, MAX_PREKEY_SIGNATURE_BYTES)?,
            ))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    // Ключ sealed sender: длины проверяются до базы — неверная длина
    // означает испорченный запрос, а не сбой сервера.
    let sealed_kem = match (&request.sealed_kem_public, &request.sealed_kem_signature) {
        (Some(public), Some(signature)) => {
            let public = decode_hex(public)?;
            let signature = decode_hex(signature)?;

            if public.len() != SEALED_KEM_PUBLIC_LEN || signature.len() != SEALED_KEM_SIGNATURE_LEN
            {
                return Err(ApiError::BadRequest);
            }

            Some((public, signature))
        }
        (None, None) => None,
        _ => return Err(ApiError::BadRequest),
    };

    // Разбирается до записи: неверная половина не должна оставить
    // опубликованными предключи без неё.
    let pq_update = decode_pq_identity(
        request.pq_identity_key.as_deref(),
        request.identity_binding.as_deref(),
    )?;

    repo::publish_prekeys(
        &state.pool,
        device_id,
        (request.signed_key_id, &signed_public, &signed_signature),
        (request.kem_key_id, &kem_public, &kem_signature),
        &one_time,
        &one_time_kem,
    )
    .await?;

    if let Some((public, signature)) = sealed_kem {
        repo::set_sealed_kem(&state.pool, device_id, &public, &signature).await?;
    }

    // Пост-квантовая половина identity — у аккаунтов, заведённых без неё.
    if let Some((public, binding)) = pq_update {
        let account = repo::account_of_device(&state.pool, device_id).await?;
        repo::set_pq_identity(&state.pool, account, &public, &binding).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Выдача prekey bundle с расходом одноразового ключа.
///
/// # Почему без подписи
///
/// Bundle берёт тот, кто хочет **начать** переписку, — то есть, как
/// правило, человек, которого получатель ещё не знает. Требовать здесь
/// подпись значило бы разрешать первый контакт только знакомым.
///
/// # 🔐 Почему с ограничителем
///
/// Каждый вызов **расходует** одноразовый предключ. Без ограничителя
/// любой желающий вычерпывал запас жертвы в один цикл запросов
/// (находка внутреннего пентеста, раздел 23.6): маршрут был единственным
/// из расходующих ресурс, где ограничителя не стояло вовсе, при том что
/// он стоял на поиске по имени и на отправке.
///
/// Последствие не отказ, а тихое ухудшение: `take_prekey_bundle`
/// отдаёт bundle с `degraded = true`, и все новые сессии с жертвой
/// заводятся **без** одноразового предключа. Пострадавшая при этом
/// сторона ничего не замечает — у неё просто «кто-то написал».
///
/// Ключ ограничителя — устройство-получатель, а не адрес: адрес сервер
/// не хранит.
///
/// 🔐 Ограничитель бережёт **пул**, а не закрывает дверь: сверх бюджета
/// выдаётся bundle без одноразовых предключей (`degraded = true`), а не
/// 429. Прежде был отказ — и посторонний, бесплатно выбирая десять
/// запросов в минуту, не давал никому новому начать переписку с жертвой.
/// Сессия на подписанных предключах остаётся стойкой; одноразовый ключ
/// добавляет только прямую секретность первого сообщения.
async fn take_bundle(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<BundleResponse>, ApiError> {
    let key = rate_limit::key_from_addr(&state.limiter_salt, &device_id.to_string());
    let now = now_millis();

    let within_budget = {
        let mut limiter = state
            .bundle_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        limiter.allow(key, now)
    };

    let bundle = if within_budget {
        repo::take_prekey_bundle(&state.pool, device_id).await?
    } else {
        repo::signed_prekey_bundle(&state.pool, device_id).await?
    };
    let degraded = bundle.one_time.is_none() || bundle.one_time_kem.is_none();

    let account = repo::account_of_device(&state.pool, bundle.device_id).await?;
    let pq = repo::pq_identity_of(&state.pool, account).await?;

    Ok(Json(BundleResponse {
        device_id: bundle.device_id,
        identity_key: hex::encode(bundle.identity_key),
        pq_identity_key: pq.as_ref().map(|(public, _)| hex::encode(public)),
        identity_binding: pq.as_ref().map(|(_, binding)| hex::encode(binding)),
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
///
/// 🔐 Требует подпись устройства. Прежде маршрут был открыт, и это
/// был оракул использования (находка внутреннего пентеста, раздел 23.6):
/// расход одноразовых предключей равен числу новых сессий, начатых
/// с этим устройством. Опрашивая счётчик раз в минуту, посторонний
/// строил график того, как часто с человеком начинают переписку —
/// не читая ни одного сообщения.
///
/// Ограничение никому не мешает: число нужно самому устройству, чтобы
/// решить, когда пополнять запас. Отправителю оно не нужно — он берёт
/// bundle и получает `degraded`, если одноразового ключа не нашлось.
async fn count_keys(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<Json<i64>, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let count = repo::count_one_time_prekeys(&state.pool, device_id).await?;

    Ok(Json(count))
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

    // 🔐 Только известные провайдеры и токен разумной длины из печатных
    // ASCII. Прежде принималось что угодно до двух мегабайт. Особенно
    // важно для будущего UnifiedPush: там токен — адрес, куда сервер
    // сам пойдёт запросом, и без списка разрешённых адресов это был бы
    // запрос во внутреннюю сеть оператора по указке клиента (SSRF).
    // Поэтому UnifiedPush здесь не принимается, пока такой защиты нет.
    let known_provider = matches!(request.provider.as_str(), "fcm" | "apns");
    let sane_token = !request.token.is_empty()
        && request.token.len() <= MAX_PUSH_TOKEN_CHARS
        && request.token.bytes().all(|byte| byte.is_ascii_graphic());
    if !known_provider || !sane_token {
        return Err(ApiError::BadRequest);
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

    // Активность аккаунта — месяцем (миграция 0011): год без входа
    // удаляет аккаунт и освобождает имя. Приложение забирает очередь
    // при каждом открытии, так что этого места достаточно.
    repo::touch_account_activity(&state.pool, device_id).await?;

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

/// Ответ на удаление аккаунта: что именно исчезло.
#[derive(Debug, Serialize)]
pub struct AccountDeletedResponse {
    /// Сколько устройств удалено.
    pub devices: u64,
    /// Сколько недоставленных конвертов удалено.
    pub envelopes: u64,
    /// Сколько загруженных вложений удалено.
    pub attachments: u64,
}

/// 🔐 Удаление аккаунта (MASVS PRIVACY-3.2).
///
/// # Почему это отдельный маршрут, а не «перестань пользоваться»
///
/// До его появления политика приватности была вынуждена признавать,
/// что права на удаление у пользователя нет: снос приложения убирал
/// локальные данные, а на сервере оставались имя, identity-ключ,
/// предключи и недоставленные конверты. Обещанное право без ручки,
/// которая его исполняет, — это то самое расхождение документа
/// со сборкой, ради которого заведено правило 0.1.
///
/// # Что делает
///
/// Удаляет строку аккаунта; всё остальное уносят каскады схемы
/// ([`repo::delete_account`]). Затем закрывает сокет устройства:
/// подпись проверяется один раз, при апгрейде, и открытое соединение
/// пережило бы удаление.
///
/// # Почему ответ сообщает числа
///
/// «Готово» без чисел неотличимо от «готово» при пустом запросе.
/// Всё, что здесь названо, — данные самого запрашивающего.
///
/// # ⚠️ Чего этот маршрут не делает
///
/// Не удаляет сообщения, уже доставленные собеседникам: они лежат
/// на их устройствах, и сервер до них не дотянется. Не удаляет
/// присланные этому аккаунту вложения — сервер не знает, кому они
/// предназначались, и узнать это значило бы хранить граф отправок
/// (`0003_attachments.sql`). Они исчезают по сроку в тридцать суток.
async fn delete_account(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<Json<AccountDeletedResponse>, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let report = repo::delete_account(&state.pool, device_id).await?;

    state.hub.evict(device_id).await;

    Ok(Json(AccountDeletedResponse {
        devices: report.devices,
        envelopes: report.envelopes,
        attachments: report.attachments,
    }))
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

/// Загружает зашифрованное вложение.
///
/// # 🔐 Что сервер получает и чего не узнаёт
///
/// Получает: непрозрачные байты. Не узнаёт: кто их прислал, кому
/// файл предназначен, как он называется, что в нём.
///
/// Прежде загрузка была подписана устройством, и сервер помнил, кто
/// и в какой час прислал каждый файл. Теперь право на место — работа
/// над самим блобом (`pow::upload_challenge`), растущая с размером.
/// Описание вложения — имя, тип, ключ, превью — уходит получателю
/// **внутри сообщения**, под сквозным шифрованием.
///
/// Получателя ручка не принимает намеренно. Знай сервер, кому
/// адресован файл, оператор строил бы граф «кто кому шлёт файлы»,
/// не расшифровав ни байта.
///
/// # Ограничение объёма
///
/// Квоты на устройство больше нет — считать по загрузчику нечего.
/// Её заменяют работа, растущая с размером, общий потолок хранилища
/// (`repo::store_attachment`) и лимит частоты на балансировщике.
///
/// # Errors
///
/// * [`ApiError::PayloadTooLarge`] — блоб больше предела.
/// * [`ApiError::Unauthorized`] — нет решения proof-of-work или оно неверно.
/// * [`ApiError::InsufficientStorage`] — общий потолок хранилища исчерпан.
/// * [`ApiError::TooManyRequests`] — превышена частота.
/// * [`ApiError::Internal`] — сбой базы.
async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    payload: axum::body::Bytes,
) -> Result<Json<Uuid>, ApiError> {
    // Пустое вложение — ошибка вызывающего, а не файл нулевой длины:
    // описание, ссылающееся на пустой блоб, у получателя всё равно
    // не откроется.
    if payload.is_empty() {
        return Err(ApiError::BadRequest);
    }

    // 🔐 Работа над этим блобом — вместо подписи устройства.
    let nonce: u64 = headers
        .get(UPLOAD_POW_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or(ApiError::Unauthorized)?;

    crate::pow::verify(
        &crate::pow::upload_challenge(&payload),
        nonce,
        crate::pow::upload_difficulty(payload.len()),
    )
    .map_err(|_| ApiError::Unauthorized)?;

    let attachment_id = repo::store_attachment(
        &state.pool,
        &payload,
        i64::try_from(ATTACHMENT_TTL.as_secs()).unwrap_or(i64::MAX),
    )
    .await?;

    Ok(Json(attachment_id))
}

/// Заголовок с решением proof-of-work загрузки.
const UPLOAD_POW_HEADER: &str = "x-aegis-upload-pow";

/// Отдаёт зашифрованное вложение.
///
/// # 🔐 Почему нет проверки прав
///
/// Проверить право на скачивание нельзя, не зная, кому файл
/// предназначен, — а этого сервер не знает намеренно. Защита здесь
/// не в проверке доступа, а в том, что адрес — случайный UUID
/// (122 бита), а содержимое зашифровано ключом, которого у сервера нет.
/// Угадавший адрес получит шифроблоб без ключа.
///
/// # 🔐 Почему без подписи
///
/// Прежде скачивание требовало подписи устройства. Загружает вложение
/// отправитель за своей подписью, и подпись скачивающего по тому же
/// адресу давала серверу пару «кто кому прислал файл» — при том что
/// sealed sender прятал отправителя самого сообщения. Перебор адресов
/// подпись не останавливала (адрес — 122 случайных бита), а от объёма
/// трафика защищает ограничитель на балансировщике.
///
/// # Errors
///
/// * [`ApiError::NotFound`] — вложения нет либо срок истёк.
/// * [`ApiError::Internal`] — сбой базы.
async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Path(attachment_id): Path<Uuid>,
) -> Result<Vec<u8>, ApiError> {
    let payload = repo::fetch_attachment(&state.pool, attachment_id).await?;

    Ok(payload)
}

// --- Sealed sender (раздел 15.2) ---

/// Запрос на публикацию ключа доступа sealed sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedAccessRequest {
    /// SHA-256 от ключа доступа, hex.
    ///
    /// 🔐 Именно хеш: сам ключ сервер знать не должен. Иначе утечка
    /// дампа позволила бы писать анонимно любому пользователю.
    pub access_key_hash: String,
    /// Принимать ли анонимные конверты вообще без ключа.
    pub allow_from_anyone: bool,
}

/// Ответ с сертификатом отправителя.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// Сертификат целиком, hex.
    pub certificate: String,
    /// Момент истечения, миллисекунды.
    pub expires_at_millis: i64,
    /// Публичный ключ сервера, hex — им клиент проверяет подпись.
    pub server_key: String,
}

/// Запрос на анонимную отправку.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSendRequest {
    /// Устройство-получатель.
    pub destination_device_id: Uuid,
    /// Запечатанный конверт, hex. Сервер его не разбирает.
    pub sealed: String,
    /// Ключ доступа получателя, hex.
    ///
    /// Получатель раздаёт его своим собеседникам внутри E2EE-переписки.
    /// Сервер сверяет его с хешем, не узнавая, кто предъявил.
    pub access_key: Option<String>,
    /// Решение proof-of-work первого контакта — вместо ключа доступа,
    /// которого у отправителя ещё нет (`pow::first_contact_challenge`).
    #[serde(default)]
    pub pow_nonce: Option<u64>,
}

/// Жалоба на спам, отправленный через sealed sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedReportRequest {
    /// Сертификат отправителя, извлечённый получателем из конверта, hex.
    pub certificate: String,
}

/// Ответ на жалобу.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedReportResponse {
    /// Учтена ли жалоба (повторная от того же жалобщика — нет).
    pub recorded: bool,
    /// Сколько разных людей пожаловались на этот аккаунт.
    pub total_reporters: i64,
}

/// Выдаёт сертификат отправителя.
///
/// 🔐 Требует подпись устройства: сертификат утверждает, кому
/// принадлежит ключ, и выдавать его кому попало значит позволить
/// выписать его на чужой аккаунт.
async fn issue_certificate(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<Json<CertificateResponse>, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let subject = repo::device_subject(&state.pool, device_id)
        .await
        .map_err(|_| ApiError::NotFound)?;

    let identity: [u8; certificate::KEY_LEN] = subject
        .identity_key
        .try_into()
        .map_err(|_| ApiError::Internal)?;

    let expires_at_millis = now_millis().saturating_add(certificate::VALIDITY_MILLIS);

    let payload = certificate::signed_payload(
        subject.account_id.as_bytes(),
        device_id.as_bytes(),
        &identity,
        expires_at_millis,
    );
    let signature = certificate::sign(&state.certificate_key, &payload);

    Ok(Json(CertificateResponse {
        certificate: hex::encode(certificate::encode(&payload, &signature)),
        expires_at_millis,
        server_key: hex::encode(certificate::public_key(&state.certificate_key)),
    }))
}

/// Публикует ключ доступа sealed sender.
///
/// 🔐 Требует подпись устройства: иначе посторонний заменил бы чужой
/// ключ доступа своим и открыл бы себе анонимную отправку.
async fn publish_sealed_access(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<SealedAccessRequest>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let hash = decode_hex(&request.access_key_hash)?;

    // Длина проверяется здесь, а не только схемой: ошибка клиента
    // должна давать понятный 400, а не нарушение CHECK.
    if hash.len() != 32 {
        return Err(ApiError::BadRequest);
    }

    repo::set_sealed_sender_access(&state.pool, device_id, &hash, request.allow_from_anyone)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Принимает запечатанный конверт без аутентификации отправителя.
///
/// # 🔐 Что сервер знает и чего не знает
///
/// Знает: кому доставить, размер конверта, время и IP. Не знает:
/// кто отправитель. Подписи здесь нет и быть не может — она и была бы
/// той самой меткой, которую sealed sender убирает.
///
/// # Чем это не открытая дверь для спама
///
/// Отправитель обязан предъявить **ключ доступа получателя**.
/// Получатель раздаёт его только тем, с кем согласен переписываться,
/// и делает это внутри E2EE-переписки — сервер раздачу не видит.
/// Итог: писать анонимно можно, писать анонимно кому угодно — нет.
///
/// Плюс к этому действует общий ограничитель частоты по получателю:
/// он не различает отправителей и потому не даёт им признака.
async fn send_sealed_message(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SealedSendRequest>,
) -> Result<Json<Uuid>, ApiError> {
    let key = rate_limit::key_from_addr(
        &state.limiter_salt,
        &request.destination_device_id.to_string(),
    );
    let now = now_millis();

    let access_key = match &request.access_key {
        None => None,
        Some(encoded) => Some(decode_hex(encoded)?),
    };

    let sealed = decode_hex(&request.sealed)?;

    let by_key = repo::check_sealed_sender_access(
        &state.pool,
        request.destination_device_id,
        access_key.as_deref(),
    )
    .await?;

    // 🔐 Первый контакт: ключа доступа у отправителя ещё нет, и право
    // на анонимную отправку доказывается работой над этим конвертом
    // этому получателю. Прежде такое сообщение шло за подписью
    // отправителя. Устройство проверяется на существование: очередь
    // несуществующего дала бы сбой базы, отличимый от отказа, — оракул
    // «кто зарегистрирован».
    let by_work = !by_key
        && match request.pow_nonce {
            None => false,
            Some(nonce) => {
                let challenge = crate::pow::first_contact_challenge(
                    &request.destination_device_id.to_string(),
                    &sealed,
                );

                crate::pow::verify(&challenge, nonce, crate::pow::FIRST_CONTACT_DIFFICULTY).is_ok()
                    && repo::device_subject(&state.pool, request.destination_device_id)
                        .await
                        .is_ok()
            }
        };

    // 🔐 Ключ проверяется до расхода бюджета получателя.
    //
    // Прежде бюджет тратился первым, и мусор без ключа выжигал его:
    // собеседник с верным ключом доступа получал 429. Отказы теперь
    // считаются отдельно — ограничены, но чужого не тратят.
    let allowed = by_key || by_work;

    // 🔐 Три бюджета: собеседники с ключом, незнакомцы с работой и отказы.
    // Работа первого контакта дешёвая, и общий бюджет с собеседниками
    // позволял постороннему выбрать его и отрезать получателя от своих.
    let limiter = if by_key {
        &state.sealed_limiter
    } else if by_work {
        &state.sealed_first_contact_limiter
    } else {
        &state.sealed_rejected_limiter
    };

    {
        let mut limiter = limiter.lock().map_err(|_| ApiError::Internal)?;

        if !limiter.allow(key, now) {
            return Err(ApiError::TooManyRequests);
        }
    }

    if !allowed {
        // 🔐 Тот же код, что у неверной подписи, и по той же причине:
        // разница между «получателя нет» и «ключ не тот» — оракул,
        // по которому перебором выясняется, кто зарегистрирован.
        return Err(ApiError::Unauthorized);
    }

    let envelope_id = repo::enqueue_envelope(
        &state.pool,
        request.destination_device_id,
        &sealed,
        i64::try_from(ENVELOPE_TTL.as_secs()).unwrap_or(i64::MAX),
    )
    .await?;

    if let Err(error) = crate::hub::broadcast(&state.pool, request.destination_device_id).await {
        tracing::warn!(%error, "не удалось разослать уведомление");
    }

    crate::push::wake_device(
        &state.pool,
        state.push.as_ref(),
        request.destination_device_id,
    )
    .await;

    Ok(Json(envelope_id))
}

/// Принимает жалобу на отправителя, раскрытого получателем.
///
/// # Как жалоба доказывает то, что утверждает
///
/// Сервер при доставке отправителя не знает. Узнать его он может
/// только от получателя: тот расшифровывает конверт, достаёт оттуда
/// сертификат — подписанный самим же сервером — и предъявляет его.
///
/// 🔐 Подпись проверяется здесь. Без неё жалоба была бы просто
/// утверждением жалобщика, и любой мог бы навесить спам на неугодного.
async fn report_sealed_sender(
    State(state): State<Arc<AppState>>,
    device: crate::authz::AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<SealedReportRequest>,
) -> Result<Json<SealedReportResponse>, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let raw = decode_hex(&request.certificate)?;

    let (payload, signature) = certificate::split(&raw).ok_or(ApiError::BadRequest)?;

    // 🔐 Проверка подписи — до того, как из сертификата что-либо
    // прочитано. До неё это байты жалобщика, а не утверждение сервера.
    let server_public = certificate::public_key(&state.certificate_key);
    if !certificate::verify(&server_public, payload, &signature) {
        return Err(ApiError::BadRequest);
    }

    let (account_bytes, device_bytes) =
        certificate::subject(payload).ok_or(ApiError::BadRequest)?;

    let reported_account = Uuid::from_bytes(account_bytes);
    let reported_device = Uuid::from_bytes(device_bytes);

    // Жалоба на себя — либо ошибка клиента, либо попытка накрутить
    // счётчик. И то и другое не должно попадать в статистику.
    if reported_device == device_id {
        return Err(ApiError::BadRequest);
    }

    // 🔐 Каким сертификатом доказана жалоба: он предъявительский, и
    // десяток жалоб с одним сертификатом — скорее один человек с десятком
    // аккаунтов, чем десять пострадавших (аудит 2026-10-02, S-4).
    let certificate_hash: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&raw).into()
    };

    let recorded = repo::record_sealed_sender_report(
        &state.pool,
        reported_account,
        reported_device,
        device_id,
        &certificate_hash,
    )
    .await?;

    let total_reporters = repo::sealed_sender_report_count(&state.pool, reported_account).await?;

    Ok(Json(SealedReportResponse {
        recorded,
        total_reporters,
    }))
}

/// Читает ключ подписи сертификатов из окружения.
///
/// # Почему из окружения, а не генерируется при старте
///
/// 🔐 Сгенерированный при старте ключ менялся бы при каждом
/// перезапуске, и все выданные сертификаты разом переставали бы
/// проверяться. В кластере было бы хуже: узлы выдавали бы
/// сертификаты, которые не проверяются клиентами, сходившими
/// к другому узлу.
///
/// # Что происходит, если переменной нет
///
/// Берётся ключ из нулей и пишется предупреждение. Это осознанно:
/// сервер обязан подниматься без настройки, иначе разворачивающий
/// инстанс для друзей упрётся в неё на первом же шаге. Но такой
/// ключ **публично известен**, то есть сертификаты подделывает кто
/// угодно, — и предупреждение об этом обязано быть громким.
#[must_use]
pub fn certificate_key_from_env() -> [u8; 32] {
    let Ok(encoded) = std::env::var("AEGIS_CERTIFICATE_KEY") else {
        tracing::warn!(
            "AEGIS_CERTIFICATE_KEY не задан: сертификаты отправителя \
             подписываются известным ключом и подделываются кем угодно"
        );

        return [0u8; 32];
    };

    let Ok(bytes) = hex::decode(&encoded) else {
        tracing::warn!("AEGIS_CERTIFICATE_KEY не является hex — ключ не применён");

        return [0u8; 32];
    };

    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        tracing::warn!("AEGIS_CERTIFICATE_KEY не 32 байта — ключ не применён");

        [0u8; 32]
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
