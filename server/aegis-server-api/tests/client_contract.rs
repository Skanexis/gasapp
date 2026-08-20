// SPDX-License-Identifier: AGPL-3.0-only

//! Сверка клиентского контракта с настоящим сервером.
//!
//! # Что здесь проверяется
//!
//! Клиентские типы (`aegis-net::api`) продублированы вручную, потому
//! что связать крейты зависимостью нельзя: клиент под Apache-2.0,
//! сервер под AGPL-3.0 (ADR-006). Дублирование безопасно ровно до
//! первого расхождения — и обнаружить его должен тест, а не пользователь.
//!
//! Здесь **клиентский JSON скармливается серверу**: если поле
//! переименовано или изменён тип, сервер ответит `400`, и тест упадёт.
//!
//! Зависимость на `aegis-net` тут не нужна: воспроизводится точная
//! проволочная форма, зафиксированная в `crates/aegis-net/tests/
//! wire_contract.rs`. Так серверный workspace остаётся независимым
//! от клиентского в обе стороны.
//!
//! # Как запускать
//!
//! ```text
//! docker compose -f server/deploy/docker-compose.yml up -d
//!
//! AEGIS_TEST_DATABASE_URL=postgres://aegis:aegis-dev@localhost:5433/aegis \
//!     cargo test -p aegis-server-api --test client_contract
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
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

/// Малая сложность: боевые 18 бит считались бы секундами на тест.
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
            "DROP TABLE IF EXISTS envelopes, one_time_prekeys, signed_prekeys, devices, accounts CASCADE",
        )
        .execute(&pool)
        .await;
        sqlx::raw_sql(include_str!("../../migrations/0001_initial.sql"))
            .execute(&pool)
            .await
            .expect("миграция применяется");
        *applied = true;
    }

    let mut state = AppState::new(pool, [0x7Au8; 32]);
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

/// Отправляет **сырую строку** тела, как её сформировал бы клиент.
async fn call_raw(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let router = aegis_server_api::router(Arc::clone(state));

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    let request = match body {
        Some(text) => request.body(Body::from(text)).unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();

    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn solve(challenge: &[u8]) -> u64 {
    (0u64..100_000)
        .find(|nonce| pow::verify(challenge, *nonce, TEST_DIFFICULTY).is_ok())
        .expect("решение находится")
}

fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

/// 🔐 Клиентская форма регистрации принимается сервером.
///
/// Тело собрано ровно так, как его сериализует `aegis_net::api::
/// RegisterRequest`. Переименованное поле дало бы `400`.
#[tokio::test]
async fn client_register_shape_is_accepted() {
    let state = require_state!();
    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);

    // Точная форма клиентского запроса: порядок полей неважен,
    // важны имена и типы.
    let body = format!(
        r#"{{"username":"{}","identity_key":"{}","device_identity_key":"{}","pow_challenge":"{}","pow_nonce":{}}}"#,
        unique_name("wire"),
        hex::encode([1u8; 32]),
        hex::encode([2u8; 32]),
        hex::encode(challenge),
        nonce,
    );

    let (status, response) = call_raw(&state, "POST", "/v1/accounts/register", Some(body)).await;

    assert_eq!(status, StatusCode::OK, "сервер отверг клиентскую форму");

    // Ответ обязан содержать поля, которые ждёт клиент.
    assert!(response["account_id"].is_string());
    assert!(response["device_id"].is_string());
}

/// 🔐 Клиентская форма публикации предключей принимается.
///
/// Одноразовые ключи передаются массивами массивов: сервер разбирает
/// их как кортежи, и объекты вместо массивов дали бы `400`.
#[tokio::test]
async fn client_publish_keys_shape_is_accepted() {
    let state = require_state!();

    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);
    let register = format!(
        r#"{{"username":"{}","identity_key":"{}","device_identity_key":"{}","pow_challenge":"{}","pow_nonce":{}}}"#,
        unique_name("keys"),
        hex::encode([1u8; 32]),
        hex::encode([2u8; 32]),
        hex::encode(challenge),
        nonce,
    );
    let (_, account) = call_raw(&state, "POST", "/v1/accounts/register", Some(register)).await;
    let device_id = account["device_id"].as_str().unwrap();

    let body = format!(
        r#"{{"signed_key_id":1,"signed_public":"{}","signed_signature":"{}","kem_key_id":2,"kem_public":"{}","kem_signature":"{}","one_time":[[10,"{}"]],"one_time_kem":[[20,"{}","{}"]]}}"#,
        hex::encode([0x11u8; 32]),
        hex::encode([0xAAu8; 64]),
        hex::encode([0x22u8; 1568]),
        hex::encode([0xBBu8; 64]),
        hex::encode([0x33u8; 32]),
        hex::encode([0x44u8; 1568]),
        hex::encode([0xCCu8; 64]),
    );

    let (status, _) = call_raw(&state, "PUT", &format!("/v1/keys/{device_id}"), Some(body)).await;

    assert_eq!(status, StatusCode::NO_CONTENT, "сервер отверг форму ключей");

    // Ответ bundle обязан разбираться клиентскими типами.
    let (status, bundle) =
        call_raw(&state, "GET", &format!("/v1/keys/{device_id}/bundle"), None).await;

    assert_eq!(status, StatusCode::OK);
    for field in [
        "device_id",
        "identity_key",
        "signed_key_id",
        "signed_public",
        "signed_signature",
        "kem_key_id",
        "kem_public",
        "kem_signature",
        "degraded",
    ] {
        assert!(
            !bundle[field].is_null(),
            "в ответе нет поля {field}, которое ждёт клиент"
        );
    }

    // Одноразовые ключи приходят массивами, как ждёт клиентский кортеж.
    assert!(bundle["one_time"].is_array());
}

/// 🔐 Клиентская форма отправки конверта принимается.
#[tokio::test]
async fn client_send_shape_is_accepted() {
    let state = require_state!();

    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);
    let register = format!(
        r#"{{"username":"{}","identity_key":"{}","device_identity_key":"{}","pow_challenge":"{}","pow_nonce":{}}}"#,
        unique_name("send"),
        hex::encode([1u8; 32]),
        hex::encode([2u8; 32]),
        hex::encode(challenge),
        nonce,
    );
    let (_, account) = call_raw(&state, "POST", "/v1/accounts/register", Some(register)).await;
    let device_id = account["device_id"].as_str().unwrap();

    let body = format!(
        r#"{{"destination_device_id":"{device_id}","ciphertext":"{}"}}"#,
        hex::encode(b"opaque envelope"),
    );

    let (status, _) = call_raw(&state, "POST", "/v1/messages", Some(body)).await;

    assert_eq!(status, StatusCode::OK, "сервер отверг форму отправки");

    // Ответ со списком конвертов обязан разбираться клиентом.
    let (status, envelopes) =
        call_raw(&state, "GET", &format!("/v1/messages/{device_id}"), None).await;

    assert_eq!(status, StatusCode::OK);
    let first = &envelopes[0];
    assert!(first["envelope_id"].is_string());
    assert!(first["ciphertext"].is_string());
    assert!(first["queued_at_bucketed"].is_i64());
}

/// 🔐 Форма discovery совпадает с клиентской.
#[tokio::test]
async fn client_discovery_shape_matches() {
    let state = require_state!();
    let username = unique_name("disco");

    let challenge = [0x42u8; 32];
    let nonce = solve(&challenge);
    let register = format!(
        r#"{{"username":"{username}","identity_key":"{}","device_identity_key":"{}","pow_challenge":"{}","pow_nonce":{}}}"#,
        hex::encode([1u8; 32]),
        hex::encode([2u8; 32]),
        hex::encode(challenge),
        nonce,
    );
    call_raw(&state, "POST", "/v1/accounts/register", Some(register)).await;

    let (status, response) = call_raw(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["account_id"].is_string());
    assert!(response["identity_key"].is_string());
}
