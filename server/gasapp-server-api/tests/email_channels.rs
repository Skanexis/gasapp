// SPDX-License-Identifier: AGPL-3.0-only

//! Регистрация по адресу почты, премиум и каналы — против живого Postgres.
//!
//! # Что здесь проверяется
//!
//! * без кода из письма аккаунт не создаётся; один адрес — один аккаунт;
//! * код перебором не подбирается: после пяти неверных вводов он сгорает;
//! * канал создаёт только премиум-аккаунт, публикует только владелец;
//! * читатель забирает записи без подписи.
//!
//! Запуск — как у `http.rs`: нужен `GASAPP_TEST_DATABASE_URL`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use gasapp_server_api::{pow, routes::AppState};
use tower::ServiceExt as _;
use uuid::Uuid;

mod common;

use common::{public_key, signed_request, DeviceKey};

macro_rules! require_state {
    () => {
        match common::state_with_mailer().await {
            Some(pair) => pair,
            None => {
                eprintln!("GASAPP_TEST_DATABASE_URL не задан — тест пропущен");
                return;
            }
        }
    };
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let router = gasapp_server_api::router(Arc::clone(state));
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();

    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn post(
    state: &Arc<AppState>,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    send(state, request).await
}

async fn get(state: &Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    send(state, request).await
}

async fn signed(
    state: &Arc<AppState>,
    private: &DeviceKey,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let bytes = body.map(|value| value.to_string().into_bytes());
    let request = signed_request(
        private,
        method,
        uri,
        "application/json",
        bytes.unwrap_or_default(),
    );

    send(state, request).await
}

fn solve(challenge: &[u8]) -> u64 {
    (0u64..100_000)
        .find(|nonce| pow::verify(challenge, *nonce, common::TEST_DIFFICULTY).is_ok())
        .expect("решение находится")
}

fn key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    key
}

fn unique_name(prefix: &str) -> String {
    format!("{prefix}_{}", &Uuid::new_v4().simple().to_string()[..16])
}

fn unique_email() -> String {
    format!("{}@mail.example", Uuid::new_v4().simple())
}

/// Просит письмо с кодом так, как это делает клиент.
async fn request_code(state: &Arc<AppState>, email: &str) -> StatusCode {
    let challenge = pow::email_code_challenge(email);

    post(
        state,
        "/v1/accounts/email/code",
        serde_json::json!({ "email": email, "pow_nonce": solve(&challenge) }),
    )
    .await
    .0
}

/// Тело регистрации с настоящим ключом устройства.
fn registration(username: &str, private: &DeviceKey, email: &str, code: &str) -> serde_json::Value {
    let identity = key();
    let device = public_key(private);
    let challenge = pow::registration_challenge(username, &identity, &device);

    serde_json::json!({
        "username": username,
        "identity_key": hex::encode(identity),
        "device_identity_key": hex::encode(device),
        "pq_identity_key": hex::encode([0x51u8; 1952]),
        "identity_binding": hex::encode([0x52u8; 3373]),
        "email": email,
        "email_code": code,
        "pow_challenge": hex::encode(challenge),
        "pow_nonce": solve(&challenge),
    })
}

/// Регистрирует аккаунт с подтверждённой почтой; возвращает устройство.
async fn register(state: &Arc<AppState>, username: &str, private: &DeviceKey) -> Uuid {
    let email = common::confirmed_email(state).await;
    let (status, body) = post(
        state,
        "/v1/accounts/register",
        registration(username, private, &email, common::TEST_EMAIL_CODE),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "регистрация не прошла: {body:?}");

    body["device_id"].as_str().unwrap().parse().unwrap()
}

fn device_key() -> DeviceKey {
    key()
}

// ---------------------------------------------------------------------------
//  Почта
// ---------------------------------------------------------------------------

/// Полный путь: письмо → код → аккаунт.
#[tokio::test]
async fn code_from_the_letter_registers_an_account() {
    let (state, mailer) = require_state!();
    let email = unique_email();

    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);

    let code = mailer.code_for(&email).expect("письмо ушло");
    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&unique_name("mail"), &device_key(), &email, &code),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

/// 🔐 Адрес приводится к каноничному виду: регистр и пробелы не дают
/// второго аккаунта на тот же ящик.
#[tokio::test]
async fn address_case_does_not_make_a_second_account() {
    let (state, mailer) = require_state!();
    let email = unique_email();

    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);
    let code = mailer.code_for(&email).unwrap();

    let (first, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&unique_name("first"), &device_key(), &email, &code),
    )
    .await;
    assert_eq!(first, StatusCode::OK);

    // Тот же адрес заглавными: код кладётся напрямую, чтобы не ждать
    // паузы между письмами.
    let shouted = email.to_uppercase();
    let email_hash = gasapp_server_api::email::hash_email(&state.email_key, &email);
    let code_hash = gasapp_server_api::email::hash_code(&email_hash, "111111");
    sqlx::query(
        "INSERT INTO email_codes (email_hash, code_hash, expires_at)
         VALUES ($1, $2, now() + interval '5 minutes')",
    )
    .bind(email_hash.as_slice())
    .bind(code_hash.as_slice())
    .execute(&state.pool)
    .await
    .unwrap();

    let (second, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&unique_name("second"), &device_key(), &shouted, "111111"),
    )
    .await;

    assert_eq!(
        second,
        StatusCode::UNPROCESSABLE_ENTITY,
        "один адрес — один аккаунт"
    );
}

/// Без верного кода аккаунт не создаётся.
#[tokio::test]
async fn wrong_code_is_refused() {
    let (state, _mailer) = require_state!();
    let email = unique_email();

    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);

    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&unique_name("guess"), &device_key(), &email, "000000x"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Адрес, на который код не запрашивали, не регистрируется.
#[tokio::test]
async fn address_without_a_code_is_refused() {
    let (state, _mailer) = require_state!();

    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(
            &unique_name("nocode"),
            &device_key(),
            &unique_email(),
            "123456",
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// 🔐 Код не подбирается перебором: пять неверных вводов сжигают его,
/// и верный код после этого уже не принимается.
#[tokio::test]
async fn five_wrong_guesses_burn_the_code() {
    let (state, mailer) = require_state!();
    let email = unique_email();

    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);
    let code = mailer.code_for(&email).unwrap();
    let wrong = if code == "000000" { "000001" } else { "000000" };

    for _ in 0..5 {
        let (status, _) = post(
            &state,
            "/v1/accounts/register",
            registration(&unique_name("brute"), &device_key(), &email, wrong),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&unique_name("late"), &device_key(), &email, &code),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "сгоревший код не принимается"
    );
}

/// Занятое имя не сжигает код: человек пробует другое имя с тем же
/// письмом.
#[tokio::test]
async fn taken_username_keeps_the_code() {
    let (state, mailer) = require_state!();
    let taken = unique_name("taken");
    register(&state, &taken, &device_key()).await;

    let email = unique_email();
    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);
    let code = mailer.code_for(&email).unwrap();

    let (conflict, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&taken, &device_key(), &email, &code),
    )
    .await;
    assert_eq!(conflict, StatusCode::CONFLICT);

    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&unique_name("free"), &device_key(), &email, &code),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

/// Второе письмо на тот же адрес раньше чем через минуту не уходит.
#[tokio::test]
async fn a_second_letter_waits() {
    let (state, mailer) = require_state!();
    let email = unique_email();

    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);
    assert_eq!(
        request_code(&state, &email).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(mailer.letters_to(&email), 1);
}

/// Письмо стоит работы: без решения proof-of-work оно не уходит.
#[tokio::test]
async fn a_letter_costs_work() {
    let (state, mailer) = require_state!();
    let email = unique_email();
    let challenge = pow::email_code_challenge(&email);
    let wrong = (0..u64::MAX)
        .find(|nonce| pow::verify(&challenge, *nonce, common::TEST_DIFFICULTY).is_err())
        .unwrap();

    let (status, _) = post(
        &state,
        "/v1/accounts/email/code",
        serde_json::json!({ "email": email, "pow_nonce": wrong }),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(mailer.letters_to(&email), 0);
}

/// 🔐 Адрес в базе не лежит — только его хеш.
#[tokio::test]
async fn the_address_itself_is_not_stored() {
    let (state, mailer) = require_state!();
    let email = unique_email();
    let username = unique_name("hashed");

    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);
    let code = mailer.code_for(&email).unwrap();
    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&username, &device_key(), &email, &code),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let stored: Vec<u8> = sqlx::query_scalar("SELECT email_hash FROM accounts WHERE username = $1")
        .bind(&username)
        .fetch_one(&state.pool)
        .await
        .unwrap();

    assert_eq!(
        stored,
        gasapp_server_api::email::hash_email(&state.email_key, &email)
    );

    // Код израсходован: строки с ним больше нет.
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM email_codes WHERE email_hash = $1")
        .bind(&stored)
        .fetch_one(&state.pool)
        .await
        .unwrap();

    assert_eq!(left, 0);
}

// ---------------------------------------------------------------------------
//  Премиум и каналы
// ---------------------------------------------------------------------------

fn channel_body(channel_id: Uuid) -> serde_json::Value {
    serde_json::json!({
        "channel_id": channel_id,
        "verify_key": hex::encode([0x77u8; 32]),
        "meta": hex::encode(b"encrypted-meta"),
    })
}

/// Регистрирует аккаунт и выдаёт ему премиум — как оператор.
async fn premium_account(state: &Arc<AppState>, private: &DeviceKey) -> Uuid {
    let username = unique_name("premium");
    let device_id = register(state, &username, private).await;

    assert!(
        gasapp_server_db::channels::set_premium(&state.pool, &username, true)
            .await
            .unwrap()
    );

    device_id
}

/// Канал создаёт только премиум-аккаунт.
#[tokio::test]
async fn only_premium_creates_a_channel() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let username = unique_name("plain");
    let device_id = register(&state, &username, &private).await;

    let (status, body) = signed(
        &state,
        &private,
        "GET",
        &format!("/v1/accounts/{device_id}/status"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["premium"], false);

    let uri = format!("/v1/channels/own/{device_id}");
    let (refused, _) = signed(
        &state,
        &private,
        "POST",
        &uri,
        Some(channel_body(Uuid::new_v4())),
    )
    .await;
    assert_eq!(refused, StatusCode::FORBIDDEN, "без премиума канала нет");

    gasapp_server_db::channels::set_premium(&state.pool, &username, true)
        .await
        .unwrap();

    let (status, body) = signed(
        &state,
        &private,
        "GET",
        &format!("/v1/accounts/{device_id}/status"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["premium"], true);

    let (created, _) = signed(
        &state,
        &private,
        "POST",
        &uri,
        Some(channel_body(Uuid::new_v4())),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);
}

/// Создание канала требует подписи устройства.
#[tokio::test]
async fn creating_a_channel_needs_a_signature() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let device_id = premium_account(&state, &private).await;

    let (status, _) = post(
        &state,
        &format!("/v1/channels/own/{device_id}"),
        channel_body(Uuid::new_v4()),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Запись публикуется владельцем и читается без подписи, по порядку.
#[tokio::test]
async fn posts_are_published_by_the_owner_and_read_by_anyone() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let device_id = premium_account(&state, &private).await;
    let channel_id = Uuid::new_v4();

    let (created, _) = signed(
        &state,
        &private,
        "POST",
        &format!("/v1/channels/own/{device_id}"),
        Some(channel_body(channel_id)),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);

    let posts_uri = format!("/v1/channels/own/{device_id}/{channel_id}/posts");

    for (index, text) in [b"first".as_slice(), b"second", b"third"]
        .iter()
        .enumerate()
    {
        let (status, body) = signed(
            &state,
            &private,
            "POST",
            &posts_uri,
            Some(serde_json::json!({ "body": hex::encode(text) })),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["seq"], index + 1);
    }

    // Читатель: никакой подписи.
    let (status, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["last_seq"], 3);
    assert_eq!(info["verify_key"], hex::encode([0x77u8; 32]));
    assert_eq!(info["meta"], hex::encode(b"encrypted-meta"));

    let (status, all) = get(&state, &format!("/v1/channels/feed/{channel_id}/posts")).await;
    assert_eq!(status, StatusCode::OK);
    let all = all.as_array().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0]["body"], hex::encode(b"first"));
    assert_eq!(all[2]["seq"], 3);

    let (_, tail) = get(
        &state,
        &format!("/v1/channels/feed/{channel_id}/posts?after=2"),
    )
    .await;
    let tail = tail.as_array().unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0]["body"], hex::encode(b"third"));
}

/// 🔐 Чужой аккаунт — даже с премиумом — в канал не пишет, не меняет
/// его и не удаляет.
#[tokio::test]
async fn a_stranger_cannot_touch_the_channel() {
    let (state, _mailer) = require_state!();
    let owner_key = device_key();
    let owner = premium_account(&state, &owner_key).await;
    let stranger_key = device_key();
    let stranger = premium_account(&state, &stranger_key).await;
    let channel_id = Uuid::new_v4();

    let (created, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("/v1/channels/own/{owner}"),
        Some(channel_body(channel_id)),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);

    // Своей подписью, со своим устройством в пути — но канал чужой.
    let (status, _) = signed(
        &state,
        &stranger_key,
        "POST",
        &format!("/v1/channels/own/{stranger}/{channel_id}/posts"),
        Some(serde_json::json!({ "body": hex::encode(b"forged") })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = signed(
        &state,
        &stranger_key,
        "PUT",
        &format!("/v1/channels/own/{stranger}/{channel_id}"),
        Some(serde_json::json!({ "meta": hex::encode(b"defaced") })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = signed(
        &state,
        &stranger_key,
        "DELETE",
        &format!("/v1/channels/own/{stranger}/{channel_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Своей подписью, с устройством владельца в пути — подпись не та.
    let (status, _) = signed(
        &state,
        &stranger_key,
        "POST",
        &format!("/v1/channels/own/{owner}/{channel_id}/posts"),
        Some(serde_json::json!({ "body": hex::encode(b"forged") })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["last_seq"], 0);
    assert_eq!(info["meta"], hex::encode(b"encrypted-meta"));
}

/// Владелец меняет описание и удаляет канал; записи уходят вместе с ним.
#[tokio::test]
async fn the_owner_edits_and_deletes_the_channel() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let device_id = premium_account(&state, &private).await;
    let channel_id = Uuid::new_v4();
    let own = format!("/v1/channels/own/{device_id}/{channel_id}");

    signed(
        &state,
        &private,
        "POST",
        &format!("/v1/channels/own/{device_id}"),
        Some(channel_body(channel_id)),
    )
    .await;
    signed(
        &state,
        &private,
        "POST",
        &format!("{own}/posts"),
        Some(serde_json::json!({ "body": hex::encode(b"note") })),
    )
    .await;

    let (status, _) = signed(
        &state,
        &private,
        "PUT",
        &own,
        Some(serde_json::json!({ "meta": hex::encode(b"renamed") })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["meta"], hex::encode(b"renamed"));

    let (status, _) = signed(&state, &private, "DELETE", &own, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM channel_posts WHERE channel_id = $1")
        .bind(channel_id)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// Слишком большая запись отвергается.
#[tokio::test]
async fn an_oversized_post_is_refused() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let device_id = premium_account(&state, &private).await;
    let channel_id = Uuid::new_v4();

    signed(
        &state,
        &private,
        "POST",
        &format!("/v1/channels/own/{device_id}"),
        Some(channel_body(channel_id)),
    )
    .await;

    let (status, _) = signed(
        &state,
        &private,
        "POST",
        &format!("/v1/channels/own/{device_id}/{channel_id}/posts"),
        Some(serde_json::json!({ "body": hex::encode(vec![0u8; 65_537]) })),
    )
    .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Удаление аккаунта уносит его каналы.
#[tokio::test]
async fn deleting_the_account_removes_its_channels() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let device_id = premium_account(&state, &private).await;
    let channel_id = Uuid::new_v4();

    signed(
        &state,
        &private,
        "POST",
        &format!("/v1/channels/own/{device_id}"),
        Some(channel_body(channel_id)),
    )
    .await;

    let (status, _) = signed(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{device_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
