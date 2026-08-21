// SPDX-License-Identifier: AGPL-3.0-only

//! Интеграционные тесты HTTP-слоя против живого Postgres.
//!
//! # Что здесь проверяется
//!
//! Сценарий M3 целиком: **регистрация → публикация ключей → получение
//! bundle**, а также отправка и приём конверта. Не отдельные функции,
//! а связка — то, что ломается при рассогласовании слоёв и не ловится
//! модульными тестами.
//!
//! # Как запускать
//!
//! ```text
//! docker compose -f server/deploy/docker-compose.yml up -d
//!
//! AEGIS_TEST_DATABASE_URL=postgres://aegis:aegis-dev@localhost:5433/aegis \
//!     cargo test -p aegis-server-api
//! ```
//!
//! Без переменной окружения тесты пропускаются, а не падают.

// Индексация JSON-значений (`body["field"]`) — штатный способ работы
// с `serde_json::Value`: отсутствующее поле даёт `Value::Null`, а не
// панику. Приведение времени в тесте ограничено заведомо малой величиной.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use std::sync::Arc;

use aegis_server_api::{pow, routes::AppState};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Малая сложность: боевые 18 бит считались бы секундами на каждый тест.
const TEST_DIFFICULTY: u32 = 4;

async fn state() -> Option<Arc<AppState>> {
    use std::sync::OnceLock;
    use tokio::sync::Mutex;

    static MIGRATED: OnceLock<Mutex<bool>> = OnceLock::new();

    let url = std::env::var("AEGIS_TEST_DATABASE_URL").ok()?;
    let pool = PgPool::connect(&url).await.ok()?;

    let guard = MIGRATED.get_or_init(|| Mutex::new(false));
    let mut applied = guard.lock().await;

    if !*applied {
        let _ = sqlx::raw_sql(
            "DROP TABLE IF EXISTS attachments, push_tokens, envelopes, one_time_prekeys,              signed_prekeys, devices, accounts CASCADE",
        )
        .execute(&pool)
        .await;

        // Все миграции по порядку, а не только первая: тест, знающий
        // лишь про начальную схему, зелен на таблицах, которых в бою
        // уже нет, и слеп к тем, что появились.
        for migration in [
            include_str!("../../migrations/0001_initial.sql"),
            include_str!("../../migrations/0002_push_tokens.sql"),
            include_str!("../../migrations/0003_attachments.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&pool)
                .await
                .expect("миграция применяется");
        }
        *applied = true;
    }

    let mut state = AppState::new(pool, [0x5Au8; 32]);
    state.pow_difficulty = TEST_DIFFICULTY;

    Some(Arc::new(state))
}

macro_rules! require_state {
    () => {
        match state().await {
            Some(state) => state,
            None => {
                eprintln!("AEGIS_TEST_DATABASE_URL не задан — тест пропущен");
                return;
            }
        }
    };
}

/// Выполняет запрос и возвращает код со телом.
async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = aegis_server_api::router(Arc::clone(state));

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    let request = match body {
        Some(value) => request.body(Body::from(value.to_string())).unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();

    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

    (status, json)
}

/// Подбирает решение proof-of-work — то, чем занят клиент.
fn solve(challenge: &[u8]) -> u64 {
    (0u64..100_000)
        .find(|nonce| pow::verify(challenge, *nonce, TEST_DIFFICULTY).is_ok())
        .expect("решение находится")
}

/// Регистрирует аккаунт, возвращая идентификаторы.
async fn register(state: &Arc<AppState>, username: &str) -> (Uuid, Uuid) {
    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);

    let (status, body) = call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode([1u8; 32]),
            "device_identity_key": hex::encode([2u8; 32]),
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "регистрация не прошла: {body:?}");

    (
        body["account_id"].as_str().unwrap().parse().unwrap(),
        body["device_id"].as_str().unwrap().parse().unwrap(),
    )
}

fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

/// 🧪 Задача M3: регистрация → публикация ключей → получение bundle.
#[tokio::test]
async fn full_registration_and_key_exchange_flow() {
    let state = require_state!();
    let username = unique_name("alice");

    // 1. Регистрация.
    let (account_id, device_id) = register(&state, &username).await;

    // 2. Discovery находит аккаунт.
    let (status, body) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["account_id"].as_str().unwrap(), account_id.to_string());

    // 3. Публикация предключей.
    let (status, _) = call(
        &state,
        "PUT",
        &format!("/v1/keys/{device_id}"),
        Some(serde_json::json!({
            "signed_key_id": 1,
            "signed_public": hex::encode([0x11u8; 32]),
            "signed_signature": hex::encode([0xAAu8; 64]),
            "kem_key_id": 2,
            "kem_public": hex::encode([0x22u8; 1568]),
            "kem_signature": hex::encode([0xBBu8; 64]),
            "one_time": [[10, hex::encode([0x33u8; 32])]],
            "one_time_kem": [[20, hex::encode([0x44u8; 1568]), hex::encode([0xCCu8; 64])]],
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    // 4. Получение bundle — с расходом одноразового ключа.
    let (status, bundle) = call(&state, "GET", &format!("/v1/keys/{device_id}/bundle"), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(bundle["signed_key_id"].as_i64(), Some(1));
    assert!(!bundle["one_time"].is_null(), "одноразовый ключ не выдан");
    assert_eq!(
        bundle["degraded"].as_bool(),
        Some(false),
        "полный bundle помечен ослабленным"
    );

    // 5. Повторный запрос — пул исчерпан, bundle всё равно выдаётся.
    let (status, second) = call(&state, "GET", &format!("/v1/keys/{device_id}/bundle"), None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(second["one_time"].is_null(), "ключ выдан дважды");
    assert_eq!(
        second["degraded"].as_bool(),
        Some(true),
        "исчерпание пула не отмечено"
    );
}

/// 🔐 Регистрация без proof-of-work отвергается.
#[tokio::test]
async fn registration_without_valid_pow_is_rejected() {
    let state = require_state!();

    let (status, _) = call(
        &state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": unique_name("mallory"),
            "identity_key": hex::encode([1u8; 32]),
            "device_identity_key": hex::encode([2u8; 32]),
            "pow_challenge": hex::encode([0x42u8; 32]),
            // Заведомо неверное решение.
            "pow_nonce": u64::MAX,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// 🔐 Занятое имя даёт конфликт, а не подмену аккаунта.
#[tokio::test]
async fn duplicate_username_conflicts() {
    let state = require_state!();
    let username = unique_name("bob");

    register(&state, &username).await;

    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);
    let (status, _) = call(
        &state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode([9u8; 32]),
            "device_identity_key": hex::encode([9u8; 32]),
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
}

/// 🔐 Неизвестное имя — 404 без подробностей.
#[tokio::test]
async fn unknown_username_returns_not_found() {
    let state = require_state!();

    let (status, _) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{}", unique_name("ghost")),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// 🔐 Перебор имён упирается в лимит частоты.
///
/// Без него список всех зарегистрированных имён составляется за сутки.
#[tokio::test]
async fn discovery_is_rate_limited() {
    let state = require_state!();
    let username = unique_name("carol");
    register(&state, &username).await;

    let mut limited = false;
    // Лимит 20/мин; запас на случай, если часть запросов уйдёт в другую
    // минуту, невелик — окно скользящее.
    for _ in 0..25 {
        let (status, _) = call(
            &state,
            "GET",
            &format!("/v1/discovery/username/{username}"),
            None,
        )
        .await;

        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }

    assert!(limited, "лимит discovery не сработал");
}

/// Отправка и приём конверта по HTTP.
#[tokio::test]
async fn envelope_delivery_round_trip() {
    let state = require_state!();
    let (_account, device_id) = register(&state, &unique_name("dave")).await;

    let (status, envelope_id) = call(
        &state,
        "POST",
        "/v1/messages",
        Some(serde_json::json!({
            "destination_device_id": device_id,
            "ciphertext": hex::encode(b"opaque"),
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let (status, waiting) = call(&state, "GET", &format!("/v1/messages/{device_id}"), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(waiting.as_array().map(Vec::len), Some(1));

    // Метка времени округлена до часа — раздел 15.
    let bucketed = waiting[0]["queued_at_bucketed"].as_i64().unwrap();
    assert_eq!(bucketed % 3600, 0, "метка не округлена");

    // Подтверждение удаляет конверт немедленно.
    let envelope = envelope_id.as_str().unwrap();
    let (status, _) = call(
        &state,
        "DELETE",
        &format!("/v1/messages/{device_id}/{envelope}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, empty) = call(&state, "GET", &format!("/v1/messages/{device_id}"), None).await;

    assert_eq!(empty.as_array().map(Vec::len), Some(0), "конверт не удалён");
}

/// 🔐 Некорректный hex отвергается как плохой запрос, а не роняет сервер.
#[tokio::test]
async fn malformed_hex_is_rejected() {
    let state = require_state!();
    let (_account, device_id) = register(&state, &unique_name("erin")).await;

    let (status, _) = call(
        &state,
        "POST",
        "/v1/messages",
        Some(serde_json::json!({
            "destination_device_id": device_id,
            "ciphertext": "не hex",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Счётчик оставшихся предключей доступен по HTTP.
#[tokio::test]
async fn prekey_count_is_exposed() {
    let state = require_state!();
    let (_account, device_id) = register(&state, &unique_name("frank")).await;

    call(
        &state,
        "PUT",
        &format!("/v1/keys/{device_id}"),
        Some(serde_json::json!({
            "signed_key_id": 1,
            "signed_public": hex::encode([0x11u8; 32]),
            "signed_signature": hex::encode([0xAAu8; 64]),
            "kem_key_id": 2,
            "kem_public": hex::encode([0x22u8; 1568]),
            "kem_signature": hex::encode([0xBBu8; 64]),
            "one_time": [[10, hex::encode([0x33u8; 32])], [11, hex::encode([0x34u8; 32])]],
            "one_time_kem": [],
        })),
    )
    .await;

    let (status, count) = call(&state, "GET", &format!("/v1/keys/{device_id}/count"), None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.as_i64(), Some(2));
}

/// 🔐 Аутентификация с просроченным челленджем отвергается.
#[tokio::test]
async fn expired_challenge_is_rejected() {
    let state = require_state!();
    let (_account, device_id) = register(&state, &unique_name("grace")).await;

    let (status, _) = call(
        &state,
        "POST",
        "/v1/auth/verify",
        Some(serde_json::json!({
            "device_id": device_id,
            "challenge": hex::encode([0x42u8; 32]),
            // Выпущен в 1970-м — заведомо просрочен.
            "issued_at": 0,
            "signature": hex::encode([0u8; 64]),
        })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// 🔐 Неизвестное устройство и неверная подпись неразличимы.
#[tokio::test]
async fn unknown_device_and_bad_signature_look_alike() {
    let state = require_state!();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let (unknown_status, _) = call(
        &state,
        "POST",
        "/v1/auth/verify",
        Some(serde_json::json!({
            "device_id": Uuid::new_v4(),
            "challenge": hex::encode([0x42u8; 32]),
            "issued_at": now,
            "signature": hex::encode([0u8; 64]),
        })),
    )
    .await;

    let (_account, device_id) = register(&state, &unique_name("heidi")).await;
    let (bad_signature_status, _) = call(
        &state,
        "POST",
        "/v1/auth/verify",
        Some(serde_json::json!({
            "device_id": device_id,
            "challenge": hex::encode([0x42u8; 32]),
            "issued_at": now,
            "signature": hex::encode([0u8; 64]),
        })),
    )
    .await;

    assert_eq!(
        unknown_status, bad_signature_status,
        "ответы различаются — это оракул для перебора устройств"
    );
    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
}

/// 🔐 Уведомление проходит между узлами через базу.
///
/// Главная проверка распределённого хаба: без неё сообщение, отправленное
/// через один узел, не разбудило бы получателя на другом — и приходило бы
/// только при следующем открытии чата.
///
/// Два хаба здесь изображают два узла: они не знают друг о друге и
/// связаны только каналом `LISTEN/NOTIFY`.
#[tokio::test]
async fn notification_crosses_nodes_through_postgres() {
    let Some(state) = state().await else {
        eprintln!("пропущено: нет DATABASE_URL");

        return;
    };

    let device = uuid::Uuid::new_v4();

    // Узел B: слушает канал и держит соединение устройства.
    let node_b = std::sync::Arc::new(aegis_server_api::hub::Hub::new());
    let mut receiver = node_b.connect_for_test(device).await;

    let pool = state.pool.clone();
    let listener = tokio::spawn(aegis_server_api::hub::listen(
        pool.clone(),
        std::sync::Arc::clone(&node_b),
        std::sync::Arc::new(aegis_server_api::health::HealthState::new()),
    ));

    // Слушателю нужно время на подписку: NOTIFY до LISTEN теряется.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Узел A: рассылает уведомление, ничего не зная о узле B.
    aegis_server_api::hub::broadcast(&pool, device)
        .await
        .expect("рассылка");

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .expect("уведомление не дошло между узлами за пять секунд");

    assert!(delivered.is_some(), "канал закрылся вместо доставки");

    listener.abort();
}

/// 🔐 Ручка здоровья не выдаёт метаданных о пользователях.
///
/// Главная проверка мониторинга. Число подключённых устройств, размер
/// очереди или количество аккаунтов выглядят безобидными метриками,
/// а на деле описывают поведение людей: когда сообщество активно,
/// растёт ли оно, когда случаются всплески. Собранные за месяц, они
/// дают ровно то, ради чего наблюдают за мессенджерами.
///
/// Тест перечисляет запрещённые поля явно, а не проверяет «нет лишнего»:
/// так видно, что именно решено не отдавать, и добавление такого поля
/// потребует осознанной правки теста.
#[tokio::test]
async fn health_reveals_no_user_metadata() {
    let Some(state) = state().await else {
        eprintln!("пропущено: нет DATABASE_URL");

        return;
    };

    let app = aegis_server_api::routes::router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("запрос"),
        )
        .await
        .expect("ответ");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("тело");
    let text = String::from_utf8_lossy(&body);

    for forbidden in [
        "devices",       // сколько людей сейчас в сети
        "connections",   // то же самое другими словами
        "accounts",      // размер сообщества и его рост
        "envelopes",     // сколько сейчас переписываются
        "queue",         // то же самое
        "messages",      // объём трафика
        "requests",      // суточный ритм активности
    ] {
        assert!(
            !text.contains(forbidden),
            "ручка здоровья отдаёт «{forbidden}» — это метаданные о пользователях, \
             а не о работоспособности узла"
        );
    }
}

/// Регистрирует устройство и возвращает его идентификатор вместе
/// с секретным ключом подписи.
///
/// Обычный [`register`] кладёт в базу фиксированный публичный ключ,
/// к которому нет секретного, — подписать им ничего нельзя. Здесь
/// пара настоящая, поэтому запросы к защищённым ручкам проходят
/// проверку.
async fn register_signing_device(
    state: &Arc<AppState>,
    username: &str,
) -> (Uuid, ed25519_dalek::SigningKey) {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
    let verifying = signing.verifying_key().to_bytes();

    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);

    let (status, body) = call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode([1u8; 32]),
            "device_identity_key": hex::encode(verifying),
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "регистрация не прошла: {body:?}");

    (
        body["device_id"].as_str().unwrap().parse().unwrap(),
        signing,
    )
}

/// Выполняет подписанный запрос с сырым телом.
async fn call_signed(
    state: &Arc<AppState>,
    signing: &ed25519_dalek::SigningKey,
    method: &str,
    uri: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    use ed25519_dalek::Signer as _;

    // Время берётся так же, как его берёт сервер. Внутренняя
    // now_millis намеренно pub(crate): расширять публичный API ради
    // теста значило бы делать частью контракта то, что им не является.
    let issued_at = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("часы после 1970")
            .as_millis(),
    )
    .expect("время помещается в i64");
    let message = aegis_server_api::authz::signed_message(method, uri, issued_at);
    let signature = signing.sign(&message).to_bytes();

    let router = aegis_server_api::router(Arc::clone(state));

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-aegis-signature", hex::encode(signature))
        .header("x-aegis-issued-at", issued_at.to_string())
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();

    // Предел чтения выше предела вложения: иначе тест на слишком
    // большой ответ упирался бы в собственное ограничение, а не
    // в серверное.
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024 * 1024)
        .await
        .unwrap();

    (status, bytes.to_vec())
}

/// Вложение загружается и скачивается без изменений.
#[tokio::test]
async fn attachment_round_trips() {
    let state = require_state!();
    let (device_id, signing) = register_signing_device(&state, &unique_name("uploader")).await;

    let payload = vec![0xABu8; 4096];

    let (status, body) = call_signed(
        &state,
        &signing,
        "POST",
        &format!("/v1/attachments/{device_id}"),
        payload.clone(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "загрузка не прошла");

    let attachment_id: Uuid = serde_json::from_slice::<Uuid>(&body).expect("адрес вложения");

    let (status, downloaded) = call_signed(
        &state,
        &signing,
        "GET",
        &format!("/v1/attachments/{device_id}/{attachment_id}"),
        Vec::new(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "скачивание не прошло");
    assert_eq!(downloaded, payload, "вложение изменилось при хранении");
}

/// 🔐 Без подписи вложение не загрузить и не скачать.
///
/// Подпись не защищает конкретный файл — адрес случаен, а содержимое
/// зашифровано, — но не даёт анонимно перебирать адреса и качать
/// чужой трафик.
#[tokio::test]
async fn attachment_requires_authentication() {
    let state = require_state!();
    let (device_id, signing) = register_signing_device(&state, &unique_name("anon")).await;

    let (status, body) = call_signed(
        &state,
        &signing,
        "POST",
        &format!("/v1/attachments/{device_id}"),
        vec![0x11u8; 128],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let attachment_id: Uuid = serde_json::from_slice::<Uuid>(&body).expect("адрес вложения");

    // Те же запросы без заголовков подписи.
    for (method, uri) in [
        ("POST", format!("/v1/attachments/{device_id}")),
        (
            "GET",
            format!("/v1/attachments/{device_id}/{attachment_id}"),
        ),
    ] {
        let router = aegis_server_api::router(Arc::clone(&state));

        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .body(Body::from(vec![0x11u8; 128]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} прошёл без подписи"
        );
    }
}

/// 🔐 Чужой подписью загрузить в чужую квоту нельзя.
#[tokio::test]
async fn attachment_upload_checks_signer_matches_path() {
    let state = require_state!();
    let (_, signing) = register_signing_device(&state, &unique_name("mallory")).await;
    let victim = Uuid::new_v4();

    let (status, _) = call_signed(
        &state,
        &signing,
        "POST",
        &format!("/v1/attachments/{victim}"),
        vec![0x22u8; 128],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "загрузка в чужую квоту прошла"
    );
}

/// Пустое вложение отвергается.
///
/// Описание, ссылающееся на пустой блоб, у получателя всё равно
/// не откроется.
#[tokio::test]
async fn empty_attachment_is_rejected() {
    let state = require_state!();
    let (device_id, signing) = register_signing_device(&state, &unique_name("empty")).await;

    let (status, _) = call_signed(
        &state,
        &signing,
        "POST",
        &format!("/v1/attachments/{device_id}"),
        Vec::new(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Несуществующее вложение — 404, а не пустое тело.
#[tokio::test]
async fn missing_attachment_returns_not_found() {
    let state = require_state!();
    let (device_id, signing) = register_signing_device(&state, &unique_name("seeker")).await;

    let (status, _) = call_signed(
        &state,
        &signing,
        "GET",
        &format!("/v1/attachments/{device_id}/{}", Uuid::new_v4()),
        Vec::new(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}
