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
    // Как клиент: сначала условия, затем решение по ним.
    let (_, terms) = get(state, "/v1/accounts/email/challenge").await;
    let window = terms["window"].as_u64().unwrap();
    let difficulty = u32::try_from(terms["difficulty"].as_u64().unwrap()).unwrap();
    let challenge = pow::email_code_challenge(email, window);
    let nonce = (0..u64::MAX)
        .find(|nonce| pow::verify(&challenge, *nonce, difficulty).is_ok())
        .unwrap();

    post(
        state,
        "/v1/accounts/email/code",
        serde_json::json!({ "email": email, "pow_nonce": nonce, "window": window }),
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
    let window = pow::email_window(common::now_millis());
    let challenge = pow::email_code_challenge(&email, window);
    let wrong = (0..u64::MAX)
        .find(|nonce| pow::verify(&challenge, *nonce, common::TEST_DIFFICULTY).is_err())
        .unwrap();

    let (status, _) = post(
        &state,
        "/v1/accounts/email/code",
        serde_json::json!({ "email": email, "pow_nonce": wrong, "window": window }),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(mailer.letters_to(&email), 0);
}

/// 🔐 Решение, заготовленное впрок, не годится: оно привязано к окну
/// времени, и ни прошлое, ни будущее окно не принимается.
#[tokio::test]
async fn a_stale_solution_buys_no_letter() {
    let (state, mailer) = require_state!();
    let now = pow::email_window(common::now_millis());

    for window in [now - 2, now + 1] {
        let email = unique_email();
        let challenge = pow::email_code_challenge(&email, window);
        let (status, _) = post(
            &state,
            "/v1/accounts/email/code",
            serde_json::json!({ "email": email, "pow_nonce": solve(&challenge), "window": window }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "окно {window}");
        assert_eq!(mailer.letters_to(&email), 0);
    }
}

/// 🔐 Чем больше писем узел отправил за минуту, тем дороже следующее:
/// решение по вчерашней цене перестаёт приниматься, по новой — проходит.
#[tokio::test]
async fn letters_get_dearer_as_the_node_fills_up() {
    let (state, _mailer) = require_state!();

    let (_, calm) = get(&state, "/v1/accounts/email/challenge").await;
    assert_eq!(calm["difficulty"], common::TEST_DIFFICULTY);

    // Четверть минутного бюджета писем узла.
    let budget = gasapp_server_api::email::CODES_PER_MINUTE;
    for _ in 0..budget / 4 {
        assert_eq!(
            request_code(&state, &unique_email()).await,
            StatusCode::NO_CONTENT
        );
    }

    let (_, busy) = get(&state, "/v1/accounts/email/challenge").await;
    assert_eq!(busy["difficulty"], common::TEST_DIFFICULTY + 2);

    // Решение по прежней цене, которое новой не удовлетворяет.
    let email = unique_email();
    let window = pow::email_window(common::now_millis());
    let challenge = pow::email_code_challenge(&email, window);
    let cheap = (0..u64::MAX)
        .find(|nonce| {
            pow::verify(&challenge, *nonce, common::TEST_DIFFICULTY).is_ok()
                && pow::verify(&challenge, *nonce, common::TEST_DIFFICULTY + 2).is_err()
        })
        .unwrap();
    let (status, _) = post(
        &state,
        "/v1/accounts/email/code",
        serde_json::json!({ "email": email, "pow_nonce": cheap, "window": window }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Клиент, спросивший цену заново, письмо получает.
    assert_eq!(request_code(&state, &email).await, StatusCode::NO_CONTENT);
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
    assert_eq!(info["last_rev"], 3);
    assert_eq!(info["verify_key"], hex::encode([0x77u8; 32]));
    assert_eq!(info["meta"], hex::encode(b"encrypted-meta"));

    // Лента — от новых к старым.
    let (status, all) = get(&state, &format!("/v1/channels/feed/{channel_id}/posts")).await;
    assert_eq!(status, StatusCode::OK);
    let all = all.as_array().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0]["body"], hex::encode(b"third"));
    assert_eq!(all[2]["seq"], 1);

    // История — страницами назад.
    let (_, older) = get(
        &state,
        &format!("/v1/channels/feed/{channel_id}/posts?before_seq=3&limit=1"),
    )
    .await;
    let older = older.as_array().unwrap();
    assert_eq!(older.len(), 1);
    assert_eq!(older[0]["body"], hex::encode(b"second"));

    // Изменения — после ревизии, по возрастанию.
    let (_, tail) = get(
        &state,
        &format!("/v1/channels/feed/{channel_id}/posts?after_rev=2"),
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

// ---------------------------------------------------------------------------
//  Каналы: правка, удаление, медиа, публичность, подписчики, реакции
// ---------------------------------------------------------------------------

/// Создаёт канал премиум-аккаунта с `count` записями.
async fn channel_with_posts(state: &Arc<AppState>, count: usize) -> (DeviceKey, Uuid, Uuid) {
    let private = device_key();
    let device_id = premium_account(state, &private).await;
    let channel_id = Uuid::new_v4();

    let (created, _) = signed(
        state,
        &private,
        "POST",
        &format!("/v1/channels/own/{device_id}"),
        Some(channel_body(channel_id)),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);

    for index in 0..count {
        let (status, _) = signed(
            state,
            &private,
            "POST",
            &format!("/v1/channels/own/{device_id}/{channel_id}/posts"),
            Some(serde_json::json!({ "body": hex::encode(format!("post-{index}")) })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    (private, device_id, channel_id)
}

/// Подписчик: ключ устройства и само устройство.
type Subscriber = (DeviceKey, Uuid);

/// Действие подписчика над каналом — за подписью его устройства.
async fn reader(
    state: &Arc<AppState>,
    who: &Subscriber,
    channel_id: Uuid,
    action: &str,
    body: Option<serde_json::Value>,
) -> StatusCode {
    signed(
        state,
        &who.0,
        "POST",
        &format!("/v1/channels/reader/{}/{channel_id}/{action}", who.1),
        body,
    )
    .await
    .0
}

/// Заводит аккаунт и подписывает его на канал.
async fn subscriber(state: &Arc<AppState>, channel_id: Uuid) -> Subscriber {
    let private = device_key();
    let device_id = register(state, &unique_name("reader"), &private).await;
    let who = (private, device_id);

    assert_eq!(
        reader(state, &who, channel_id, "subscribe", None).await,
        StatusCode::NO_CONTENT
    );

    who
}

/// Правка и удаление видны читателю как изменения: у каждой свой номер
/// ревизии, а удалённая запись исчезает из ленты.
#[tokio::test]
async fn edits_and_deletions_reach_readers_as_changes() {
    let (state, _mailer) = require_state!();
    let (private, device_id, channel_id) = channel_with_posts(&state, 3).await;
    let posts_uri = format!("/v1/channels/own/{device_id}/{channel_id}/posts");

    let (status, edited) = signed(
        &state,
        &private,
        "PUT",
        &posts_uri,
        Some(serde_json::json!({ "seq": 1, "body": hex::encode(b"post-0 edited") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(edited["rev"], 4);

    let (status, removed) = signed(
        &state,
        &private,
        "PUT",
        &posts_uri,
        Some(serde_json::json!({ "seq": 2, "body": hex::encode(b"tombstone"), "deleted": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["rev"], 5);

    // Читатель, остановившийся на ревизии 3, получает оба изменения.
    let (_, changes) = get(
        &state,
        &format!("/v1/channels/feed/{channel_id}/posts?after_rev=3"),
    )
    .await;
    let changes = changes.as_array().unwrap();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["seq"], 1);
    assert_eq!(changes[0]["deleted"], false);
    assert_eq!(changes[0]["body"], hex::encode(b"post-0 edited"));
    assert_eq!(changes[1]["seq"], 2);
    assert_eq!(changes[1]["deleted"], true);

    // В ленте удалённой записи нет.
    let (_, feed) = get(&state, &format!("/v1/channels/feed/{channel_id}/posts")).await;
    let seqs: Vec<i64> = feed
        .as_array()
        .unwrap()
        .iter()
        .map(|post| post["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![3, 1]);

    // Удаление окончательно: удалённую запись не исправить.
    let (status, _) = signed(
        &state,
        &private,
        "PUT",
        &posts_uri,
        Some(serde_json::json!({ "seq": 2, "body": hex::encode(b"undelete") })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Несостоявшаяся правка номер ревизии не тратит.
    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["last_rev"], 5);
    assert_eq!(info["last_seq"], 3);
}

/// 🔐 Чужой аккаунт запись не правит и не удаляет.
#[tokio::test]
async fn a_stranger_cannot_edit_posts() {
    let (state, _mailer) = require_state!();
    let (_owner_key, _owner, channel_id) = channel_with_posts(&state, 1).await;
    let stranger_key = device_key();
    let stranger = premium_account(&state, &stranger_key).await;

    let (status, _) = signed(
        &state,
        &stranger_key,
        "PUT",
        &format!("/v1/channels/own/{stranger}/{channel_id}/posts"),
        Some(serde_json::json!({ "seq": 1, "body": hex::encode(b"defaced"), "deleted": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, feed) = get(&state, &format!("/v1/channels/feed/{channel_id}/posts")).await;
    assert_eq!(feed[0]["body"], hex::encode(b"post-0"));
}

/// Медиа: загружает владелец, скачивает любой, удаляет владелец.
#[tokio::test]
async fn media_round_trips() {
    let (state, _mailer) = require_state!();
    let (private, device_id, channel_id) = channel_with_posts(&state, 0).await;
    let uri = format!("/v1/channels/own/{device_id}/{channel_id}/media");
    let blob = vec![0xABu8; 300_000];

    let request = signed_request(
        &private,
        "POST",
        &uri,
        "application/octet-stream",
        blob.clone(),
    );
    let (status, uploaded) = send(&state, request).await;
    assert_eq!(status, StatusCode::OK);
    let media_id = uploaded["media_id"].as_str().unwrap().to_owned();

    // Скачивание — без подписи.
    let router = gasapp_server_api::router(Arc::clone(&state));
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/v1/channels/feed/{channel_id}/media/{media_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), blob.as_slice());

    // Чужой — даже с премиумом — в канал не загружает.
    let stranger_key = device_key();
    let stranger = premium_account(&state, &stranger_key).await;
    let foreign = signed_request(
        &stranger_key,
        "POST",
        &format!("/v1/channels/own/{stranger}/{channel_id}/media"),
        "application/octet-stream",
        vec![1, 2, 3],
    );
    assert_eq!(send(&state, foreign).await.0, StatusCode::NOT_FOUND);

    // Без подписи загрузки нет.
    let unsigned = Request::builder()
        .method("POST")
        .uri(&uri)
        .body(Body::from(vec![1u8, 2, 3]))
        .unwrap();
    assert_eq!(send(&state, unsigned).await.0, StatusCode::UNAUTHORIZED);

    let (status, _) = signed(
        &state,
        &private,
        "DELETE",
        &uri,
        Some(serde_json::json!({ "media_id": media_id })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = get(
        &state,
        &format!("/v1/channels/feed/{channel_id}/media/{media_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Ссылка-приглашение канала по форме — какой её ждёт сервер.
fn link_to(channel_id: Uuid) -> String {
    format!(
        "gasapp://channel/{}.ABCDEFGH234567.ZYXWVUTS765432",
        channel_id.simple()
    )
}

/// Публичный канал находится по имени и поиском; закрытый — нет.
#[tokio::test]
async fn a_public_channel_is_found_by_handle() {
    let (state, _mailer) = require_state!();
    let (private, device_id, channel_id) = channel_with_posts(&state, 0).await;
    let (_other_key, _other, hidden) = channel_with_posts(&state, 0).await;
    let handle = unique_name("gasnews");
    let own = format!("/v1/channels/own/{device_id}/{channel_id}");
    let link = link_to(channel_id);

    // 🔐 Под своим именем владелец не раздаст ссылку на чужой канал
    // и не раздаст не-ссылку.
    for foreign in [link_to(hidden), "https://example.org/".to_owned()] {
        let (status, _) = signed(
            &state,
            &private,
            "PUT",
            &own,
            Some(serde_json::json!({
                "set_public": true,
                "handle": handle,
                "public_link": foreign,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{foreign}");
    }

    let (status, _) = signed(
        &state,
        &private,
        "PUT",
        &own,
        Some(serde_json::json!({
            "set_public": true,
            "handle": handle,
            "public_link": link,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, found) = get(&state, &format!("/v1/channels/handle/{handle}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found["channel_id"], channel_id.to_string());
    assert_eq!(found["public_link"], link);

    let prefix = &handle[..handle.len() - 4];
    let (_, results) = get(&state, &format!("/v1/channels/search?q={prefix}")).await;
    let ids: Vec<&str> = results
        .as_array()
        .unwrap()
        .iter()
        .map(|channel| channel["channel_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&channel_id.to_string().as_str()));
    assert!(!ids.contains(&hidden.to_string().as_str()));

    // 🔐 У закрытого канала ссылки на сервере нет.
    let (_, closed) = get(&state, &format!("/v1/channels/feed/{hidden}")).await;
    assert!(closed["public_link"].is_null());
    assert!(closed["handle"].is_null());

    // Снова закрытый: по имени больше не находится.
    let (status, _) = signed(
        &state,
        &private,
        "PUT",
        &own,
        Some(serde_json::json!({ "set_public": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = get(&state, &format!("/v1/channels/handle/{handle}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Занятое имя канала второму каналу не достаётся; негодное — не принимается.
#[tokio::test]
async fn a_taken_or_malformed_handle_is_refused() {
    let (state, _mailer) = require_state!();
    let (first_key, first_device, first) = channel_with_posts(&state, 0).await;
    let (second_key, second_device, second) = channel_with_posts(&state, 0).await;
    let handle = unique_name("taken");
    let body = |name: &str, channel: Uuid| serde_json::json!({ "set_public": true, "handle": name, "public_link": link_to(channel) });

    let (status, _) = signed(
        &state,
        &first_key,
        "PUT",
        &format!("/v1/channels/own/{first_device}/{first}"),
        Some(body(&handle, first)),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let second_uri = format!("/v1/channels/own/{second_device}/{second}");
    let (status, _) = signed(
        &state,
        &second_key,
        "PUT",
        &second_uri,
        Some(body(&handle, second)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    for bad in ["Ab", "with space", "UPPER_case", "кириллица"] {
        let (status, _) = signed(
            &state,
            &second_key,
            "PUT",
            &second_uri,
            Some(body(bad, second)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }

    // Имя без ссылки: по имени было бы нечего отдать.
    let (status, _) = signed(
        &state,
        &second_key,
        "PUT",
        &second_uri,
        Some(serde_json::json!({ "set_public": true, "handle": unique_name("nolink") })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Подписчики, просмотры и реакции считаются по аккаунтам.
#[tokio::test]
async fn subscribers_views_and_reactions_are_counted() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 3).await;
    let feed = format!("/v1/channels/feed/{channel_id}");

    let first = subscriber(&state, channel_id).await;
    let second = subscriber(&state, channel_id).await;

    // 🔐 Один аккаунт — один подписчик, сколько бы раз он ни подписался.
    for _ in 0..3 {
        reader(&state, &first, channel_id, "subscribe", None).await;
    }

    let (_, info) = get(&state, &feed).await;
    assert_eq!(info["subscribers"], 2);

    // Первый дочитал до второй записи, второй — до третьей.
    for (who, seq) in [(&first, 2), (&second, 3)] {
        assert_eq!(
            reader(
                &state,
                who,
                channel_id,
                "seen",
                Some(serde_json::json!({ "seq": seq }))
            )
            .await,
            StatusCode::NO_CONTENT
        );
    }
    // Отметка назад не двигается, а «дочитал до сотой» обрезается.
    reader(
        &state,
        &first,
        channel_id,
        "seen",
        Some(serde_json::json!({ "seq": 1 })),
    )
    .await;
    reader(
        &state,
        &second,
        channel_id,
        "seen",
        Some(serde_json::json!({ "seq": 100 })),
    )
    .await;

    for who in [&first, &second] {
        assert_eq!(
            reader(
                &state,
                who,
                channel_id,
                "react",
                Some(serde_json::json!({ "seq": 2, "emoji": "🔥" })),
            )
            .await,
            StatusCode::NO_CONTENT
        );
    }
    // Смена реакции — не вторая реакция.
    reader(
        &state,
        &second,
        channel_id,
        "react",
        Some(serde_json::json!({ "seq": 2, "emoji": "👍" })),
    )
    .await;

    let (_, posts) = get(&state, &format!("{feed}/posts")).await;
    let posts = posts.as_array().unwrap();
    // Лента от новых к старым: третья, вторая, первая.
    assert_eq!(posts[0]["views"], 1);
    assert_eq!(posts[1]["views"], 2);
    assert_eq!(posts[2]["views"], 2);
    assert_eq!(posts[1]["reactions"], "👍:1,🔥:1");
    assert_eq!(posts[0]["reactions"], "");

    // Снятие реакции и отписка.
    reader(
        &state,
        &first,
        channel_id,
        "react",
        Some(serde_json::json!({ "seq": 2 })),
    )
    .await;
    assert_eq!(
        reader(&state, &second, channel_id, "unsubscribe", None).await,
        StatusCode::NO_CONTENT
    );

    let (_, info) = get(&state, &feed).await;
    assert_eq!(info["subscribers"], 1);
    let (_, posts) = get(&state, &format!("{feed}/posts")).await;
    // Реакция отписавшегося ушла вместе с ним.
    assert_eq!(posts[1]["reactions"], "");
    // А просмотр остаётся: запись, которую видели, видели.
    assert_eq!(posts[0]["views"], 1);

    // Счётчики сходятся с таблицами, из которых выросли.
    let reactions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM channel_reactions WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
    let counted: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(n), 0)::bigint FROM channel_reaction_counts WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(reactions, 0);
    assert_eq!(counted, 0);
}

/// 🔐 Повтор одной и той же отметки и той же реакции счётчики не
/// накручивает: считается аккаунт, а не запрос.
#[tokio::test]
async fn repeating_a_request_does_not_inflate_counters() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 2).await;
    let feed = format!("/v1/channels/feed/{channel_id}");
    let who = subscriber(&state, channel_id).await;

    for _ in 0..5 {
        reader(
            &state,
            &who,
            channel_id,
            "seen",
            Some(serde_json::json!({ "seq": 2 })),
        )
        .await;
        reader(
            &state,
            &who,
            channel_id,
            "react",
            Some(serde_json::json!({ "seq": 1, "emoji": "🎉" })),
        )
        .await;
    }

    let (_, posts) = get(&state, &format!("{feed}/posts")).await;
    assert_eq!(posts[0]["views"], 1);
    assert_eq!(posts[1]["views"], 1);
    assert_eq!(posts[1]["reactions"], "🎉:1");

    let (_, info) = get(&state, &feed).await;
    assert_eq!(info["subscribers"], 1);
}

/// 🔐 Негодный ключ восстановления отвергается до записи аккаунта:
/// имя и адрес остаются свободными, и человек может повторить.
#[tokio::test]
async fn a_malformed_recovery_key_leaves_no_half_made_account() {
    let (state, _mailer) = require_state!();
    let username = unique_name("halfmade");
    let email = common::confirmed_email(&state).await;
    let private = device_key();

    let mut broken = registration(&username, &private, &email, common::TEST_EMAIL_CODE);
    broken["recovery_key"] = serde_json::json!(hex::encode([7u8; 5]));
    broken["recovery_pq_key"] = serde_json::json!(hex::encode([8u8; 1952]));

    let (status, _) = post(&state, "/v1/accounts/register", broken).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE username = $1")
        .bind(&username)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(taken, 0, "аккаунт создан наполовину");

    // Тот же код, то же имя — теперь с исправным запросом.
    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&username, &private, &email, common::TEST_EMAIL_CODE),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// 🔐 Реакция — только из закрытого набора и только от подписчика:
/// иначе читатели писали бы в чужой канал что угодно.
#[tokio::test]
async fn reactions_are_a_closed_set_from_subscribers_only() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 1).await;
    let who = subscriber(&state, channel_id).await;
    let react = |seq: i64, emoji: &str| Some(serde_json::json!({ "seq": seq, "emoji": emoji }));

    assert_eq!(
        reader(&state, &who, channel_id, "react", react(1, "купи слона")).await,
        StatusCode::BAD_REQUEST
    );

    // Аккаунт без подписки.
    let outsider_key = device_key();
    let outsider = register(&state, &unique_name("outsider"), &outsider_key).await;
    assert_eq!(
        reader(
            &state,
            &(outsider_key, outsider),
            channel_id,
            "react",
            react(1, "👍")
        )
        .await,
        StatusCode::NOT_FOUND,
        "аккаунт без подписки"
    );

    assert_eq!(
        reader(&state, &who, channel_id, "react", react(9, "👍")).await,
        StatusCode::NOT_FOUND,
        "записи нет"
    );
}

/// 🔐 Подписчик — аккаунт: без подписи устройства и от чужого имени
/// подписаться нельзя, и накрутить счётчик нечем.
#[tokio::test]
async fn subscribing_needs_an_account() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 0).await;
    let who = subscriber(&state, channel_id).await;

    // Без подписи устройства.
    let (status, _) = post(
        &state,
        &format!("/v1/channels/reader/{}/{channel_id}/subscribe", who.1),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Своей подписью — за чужое устройство.
    let other_key = device_key();
    let other = register(&state, &unique_name("other"), &other_key).await;
    let (status, _) = signed(
        &state,
        &other_key,
        "POST",
        &format!("/v1/channels/reader/{}/{channel_id}/subscribe", who.1),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Канала нет.
    assert_eq!(
        reader(
            &state,
            &(other_key, other),
            Uuid::new_v4(),
            "subscribe",
            None
        )
        .await,
        StatusCode::NOT_FOUND
    );

    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["subscribers"], 1);
}

/// Удаление аккаунта уносит его подписки и реакции.
#[tokio::test]
async fn deleting_an_account_removes_its_subscriptions() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 1).await;
    let who = subscriber(&state, channel_id).await;
    reader(
        &state,
        &who,
        channel_id,
        "react",
        Some(serde_json::json!({ "seq": 1, "emoji": "👍" })),
    )
    .await;

    let (status, _) = signed(
        &state,
        &who.0,
        "DELETE",
        &format!("/v1/accounts/{}", who.1),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM channel_subscribers WHERE channel_id = $1)
              + (SELECT count(*) FROM channel_reactions WHERE channel_id = $1)",
    )
    .bind(channel_id)
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(rows, 0);
}

// ---------------------------------------------------------------------------
//  Администраторы канала (миграция 0020)
// ---------------------------------------------------------------------------

/// Администратор, назначенный владельцем, пишет, правит и загружает
/// файлы; всё остальное в канале остаётся за владельцем.
#[tokio::test]
async fn an_admin_writes_but_does_not_own() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = channel_with_posts(&state, 1).await;
    let admin_key = device_key();
    let admin_device = register(&state, &unique_name("admin"), &admin_key).await;
    let admin_posts = format!("/v1/channels/own/{admin_device}/{channel_id}/posts");
    let verify_key = hex::encode(key());

    // До назначения — чужой.
    let (status, _) = signed(
        &state,
        &admin_key,
        "POST",
        &admin_posts,
        Some(serde_json::json!({ "body": hex::encode(b"early") })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let admins = format!("/v1/channels/own/{owner_device}/{channel_id}/admins");
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &admins,
        Some(serde_json::json!({ "device_id": admin_device, "verify_key": verify_key })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, published) = signed(
        &state,
        &admin_key,
        "POST",
        &admin_posts,
        Some(serde_json::json!({ "body": hex::encode(b"from admin"), "seq": 2 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(published["seq"], 2);

    // Правка чужой записи — тоже работа администратора.
    let (status, _) = signed(
        &state,
        &admin_key,
        "PUT",
        &admin_posts,
        Some(serde_json::json!({ "seq": 1, "body": hex::encode(b"fixed") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let media = signed_request(
        &admin_key,
        "POST",
        &format!("/v1/channels/own/{admin_device}/{channel_id}/media"),
        "application/octet-stream",
        vec![5u8; 64],
    );
    let (status, _) = send(&state, media).await;
    assert_eq!(status, StatusCode::OK);

    // 🔐 Описание, публичность, состав администраторов и удаление
    // канала — только владелец.
    let own = format!("/v1/channels/own/{admin_device}/{channel_id}");
    for (method, uri, body) in [
        (
            "PUT",
            own.clone(),
            Some(serde_json::json!({ "meta": hex::encode(b"mine") })),
        ),
        (
            "PUT",
            own.clone(),
            Some(serde_json::json!({
                "set_public": true,
                "handle": unique_name("grab"),
                "public_link": link_to(channel_id),
            })),
        ),
        (
            "POST",
            format!("{own}/admins"),
            Some(serde_json::json!({ "device_id": admin_device, "verify_key": verify_key })),
        ),
        ("DELETE", own.clone(), None),
    ] {
        let (status, _) = signed(&state, &admin_key, method, &uri, body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }

    // Снятый администратор снова чужой.
    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &admins,
        Some(serde_json::json!({ "verify_key": verify_key })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = signed(
        &state,
        &admin_key,
        "POST",
        &admin_posts,
        Some(serde_json::json!({ "body": hex::encode(b"late") })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Чужой не назначает администраторов, владелец — не назначает себя
/// и несуществующее устройство.
#[tokio::test]
async fn only_the_owner_appoints_admins() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = channel_with_posts(&state, 0).await;
    let stranger_key = device_key();
    let stranger_device = register(&state, &unique_name("stranger"), &stranger_key).await;
    let body =
        |device: Uuid| serde_json::json!({ "device_id": device, "verify_key": hex::encode(key()) });

    let (status, _) = signed(
        &state,
        &stranger_key,
        "POST",
        &format!("/v1/channels/own/{stranger_device}/{channel_id}/admins"),
        Some(body(stranger_device)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let admins = format!("/v1/channels/own/{owner_device}/{channel_id}/admins");
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &admins,
        Some(body(owner_device)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "владелец — не администратор себе"
    );

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &admins,
        Some(body(Uuid::new_v4())),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "устройства нет");

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &admins,
        Some(serde_json::json!({ "device_id": stranger_device, "verify_key": "abcd" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "ключ не той длины");
}

/// 🔐 Двое назвали один следующий номер: второму запись не сохраняется,
/// и в ленте не остаётся записи, которую читатели отвергли бы.
#[tokio::test]
async fn a_post_with_a_stale_number_is_not_stored() {
    let (state, _mailer) = require_state!();
    let (private, device_id, channel_id) = channel_with_posts(&state, 2).await;
    let posts = format!("/v1/channels/own/{device_id}/{channel_id}/posts");

    let (status, _) = signed(
        &state,
        &private,
        "POST",
        &posts,
        Some(serde_json::json!({ "body": hex::encode(b"late"), "seq": 2 })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["last_seq"], 2);
    assert_eq!(info["last_rev"], 2);

    let (status, published) = signed(
        &state,
        &private,
        "POST",
        &posts,
        Some(serde_json::json!({ "body": hex::encode(b"in time"), "seq": 3 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(published["seq"], 3);
}

// ---------------------------------------------------------------------------
//  Закрытые каналы (миграция 0021)
// ---------------------------------------------------------------------------

/// Метка ссылки-приглашения, как её несёт ссылка.
const INVITE: [u8; 16] = [0x5a; 16];

fn invite_hash(invite: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    hex::encode(Sha256::digest(invite))
}

/// Закрытый канал с одной записью и одной действующей ссылкой.
async fn closed_channel(state: &Arc<AppState>) -> (DeviceKey, Uuid, Uuid) {
    let (owner_key, owner_device, channel_id) = channel_with_posts(state, 1).await;
    let own = format!("/v1/channels/own/{owner_device}/{channel_id}");

    let (status, _) = signed(
        state,
        &owner_key,
        "PUT",
        &own,
        Some(serde_json::json!({ "closed": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = signed(
        state,
        &owner_key,
        "POST",
        &format!("{own}/invites"),
        Some(serde_json::json!({ "invite_hash": invite_hash(&INVITE) })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    (owner_key, owner_device, channel_id)
}

/// Заводит аккаунт и подаёт от него заявку.
async fn applicant(state: &Arc<AppState>, channel_id: Uuid) -> (Subscriber, String) {
    let private = device_key();
    let username = unique_name("applicant");
    let device_id = register(state, &username, &private).await;
    let who = (private, device_id);

    assert_eq!(
        reader(
            state,
            &who,
            channel_id,
            "join",
            Some(serde_json::json!({
                "invite": hex::encode(INVITE),
                "request": hex::encode(b"ephemeral-key-and-signature"),
            })),
        )
        .await,
        StatusCode::NO_CONTENT
    );

    (who, username)
}

/// Чтение от имени участника.
async fn member_get(
    state: &Arc<AppState>,
    who: &Subscriber,
    channel_id: Uuid,
    what: &str,
) -> (StatusCode, serde_json::Value) {
    signed(
        state,
        &who.0,
        "GET",
        &format!("/v1/channels/reader/{}/{channel_id}/{what}", who.1),
        None,
    )
    .await
}

/// 🔐 Закрытый канал без подписи не существует, подписаться на него
/// нельзя, а одобренная заявка делает человека участником.
#[tokio::test]
async fn a_closed_channel_admits_by_approved_request() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let own = format!("/v1/channels/own/{owner_device}/{channel_id}");

    // Без подписи: канала нет, записей нет.
    let (status, _) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, posts) = get(&state, &format!("/v1/channels/feed/{channel_id}/posts")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(posts.as_array().unwrap().len(), 0);

    let ((applicant_key, applicant_device), username) = applicant(&state, channel_id).await;
    let who = (applicant_key, applicant_device);

    // Заявка ждёт: подписаться в обход нельзя, читать — тоже.
    assert_eq!(
        reader(&state, &who, channel_id, "subscribe", None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        member_get(&state, &who, channel_id, "posts").await.0,
        StatusCode::NOT_FOUND
    );

    let (status, waiting) = member_get(&state, &who, channel_id, "join").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(waiting["status"], "pending");

    // Владелец видит заявку с именем заявителя.
    let (status, requests) =
        signed(&state, &owner_key, "GET", &format!("{own}/requests"), None).await;
    assert_eq!(status, StatusCode::OK);
    let requests = requests.as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["username"], username);
    assert_eq!(
        requests[0]["request"],
        hex::encode(b"ephemeral-key-and-signature")
    );

    let account_id = requests[0]["account_id"].clone();
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("{own}/requests"),
        Some(serde_json::json!({
            "account_id": account_id,
            "grant": hex::encode(b"wrapped-read-key"),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Одобренный получает ответ с ключом и читает за подписью.
    let (_, approved) = member_get(&state, &who, channel_id, "join").await;
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["grant"], hex::encode(b"wrapped-read-key"));

    let (status, info) = member_get(&state, &who, channel_id, "info").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["closed"], true);
    assert_eq!(info["subscribers"], 1);

    let (status, posts) = member_get(&state, &who, channel_id, "posts").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(posts.as_array().unwrap().len(), 1);

    // Заявок больше нет, подписчик в списке есть.
    let (_, requests) = signed(&state, &owner_key, "GET", &format!("{own}/requests"), None).await;
    assert_eq!(requests.as_array().unwrap().len(), 0);

    let (status, members) = signed(
        &state,
        &owner_key,
        "GET",
        &format!("{own}/subscribers"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(members.as_array().unwrap().len(), 1);
    assert_eq!(members[0]["username"], username);
}

/// Отклонённая заявка исчезает, и её можно подать снова.
#[tokio::test]
async fn a_declined_request_is_gone() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let requests_uri = format!("/v1/channels/own/{owner_device}/{channel_id}/requests");
    let (who, _) = applicant(&state, channel_id).await;

    let (_, requests) = signed(&state, &owner_key, "GET", &requests_uri, None).await;
    let account_id = requests[0]["account_id"].clone();

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &requests_uri,
        Some(serde_json::json!({ "account_id": account_id })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, answer) = member_get(&state, &who, channel_id, "join").await;
    assert_eq!(answer["status"], "none");
    assert_eq!(
        member_get(&state, &who, channel_id, "posts").await.0,
        StatusCode::NOT_FOUND
    );

    // Ответить на заявку, которой нет, нельзя.
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &requests_uri,
        Some(serde_json::json!({ "account_id": account_id, "grant": hex::encode(b"late") })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Заявка принимается только по действующей ссылке и только в закрытый
/// канал.
#[tokio::test]
async fn a_request_needs_a_live_invite() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let private = device_key();
    let device_id = register(&state, &unique_name("guest"), &private).await;
    let who = (private, device_id);
    let request = |invite: &[u8]| {
        Some(serde_json::json!({
            "invite": hex::encode(invite),
            "request": hex::encode(b"key"),
        }))
    };

    assert_eq!(
        reader(&state, &who, channel_id, "join", request(&[1u8; 16])).await,
        StatusCode::NOT_FOUND,
        "чужая метка"
    );

    // Слишком большая заявка не принимается.
    assert_eq!(
        reader(
            &state,
            &who,
            channel_id,
            "join",
            Some(serde_json::json!({
                "invite": hex::encode(INVITE),
                "request": hex::encode(vec![1u8; 4097]),
            })),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &format!("/v1/channels/own/{owner_device}/{channel_id}/invites"),
        Some(serde_json::json!({ "invite_hash": invite_hash(&INVITE) })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        reader(&state, &who, channel_id, "join", request(&INVITE)).await,
        StatusCode::NOT_FOUND,
        "ссылка отозвана"
    );

    // В открытый канал заявок не подают.
    let (_, _, open_channel) = channel_with_posts(&state, 0).await;
    assert_eq!(
        reader(&state, &who, open_channel, "join", request(&INVITE)).await,
        StatusCode::NOT_FOUND
    );
}

/// 🔐 Удалённый подписчик перестаёт получать записи и не может
/// вернуться, пока запрет не снят.
#[tokio::test]
async fn a_removed_subscriber_is_locked_out() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let own = format!("/v1/channels/own/{owner_device}/{channel_id}");
    let (who, _) = applicant(&state, channel_id).await;

    let (_, requests) = signed(&state, &owner_key, "GET", &format!("{own}/requests"), None).await;
    let account_id = requests[0]["account_id"].clone();
    let member = serde_json::json!({ "account_id": account_id });

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("{own}/requests"),
        Some(serde_json::json!({ "account_id": account_id, "grant": hex::encode(b"grant") })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        member_get(&state, &who, channel_id, "posts").await.0,
        StatusCode::OK
    );

    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &format!("{own}/subscribers"),
        Some(member.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        member_get(&state, &who, channel_id, "posts").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        member_get(&state, &who, channel_id, "join").await.1["status"],
        "none",
        "ответ с ключом удалён вместе с подпиской"
    );

    let (_, info) = member_get(&state, &(owner_key, owner_device), channel_id, "info").await;
    assert_eq!(info["subscribers"], 0);

    let again = Some(serde_json::json!({
        "invite": hex::encode(INVITE),
        "request": hex::encode(b"key"),
    }));
    assert_eq!(
        reader(&state, &who, channel_id, "join", again.clone()).await,
        StatusCode::FORBIDDEN
    );

    // Удалённый виден в списке — оттуда запрет и снимают.
    let (status, banned) = signed(&state, &owner_key, "GET", &format!("{own}/bans"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(banned.as_array().unwrap().len(), 1);
    assert_eq!(banned[0]["account_id"], account_id);

    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &format!("{own}/bans"),
        Some(member),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, banned) = signed(&state, &owner_key, "GET", &format!("{own}/bans"), None).await;
    assert_eq!(banned.as_array().unwrap().len(), 0);
    assert_eq!(
        reader(&state, &who, channel_id, "join", again).await,
        StatusCode::NO_CONTENT
    );
}

/// Заявки и подписчиков видит и ведёт администратор; посторонний и
/// рядовой подписчик — нет.
#[tokio::test]
async fn admins_moderate_and_strangers_do_not() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let admin_key = device_key();
    let admin_device = register(&state, &unique_name("admin"), &admin_key).await;
    let (member, _) = applicant(&state, channel_id).await;

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("/v1/channels/own/{owner_device}/{channel_id}/admins"),
        Some(serde_json::json!({ "device_id": admin_device, "verify_key": hex::encode(key()) })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Администратор читает закрытый канал и одобряет заявку.
    let admin = (admin_key, admin_device);
    assert_eq!(
        member_get(&state, &admin, channel_id, "posts").await.0,
        StatusCode::OK
    );

    let admin_own = format!("/v1/channels/own/{admin_device}/{channel_id}");
    let (status, requests) = signed(
        &state,
        &admin.0,
        "GET",
        &format!("{admin_own}/requests"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let account_id = requests[0]["account_id"].clone();

    let (status, _) = signed(
        &state,
        &admin.0,
        "POST",
        &format!("{admin_own}/requests"),
        Some(serde_json::json!({ "account_id": account_id, "grant": hex::encode(b"grant") })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Подписчик — не модератор: ни заявок, ни списка, ни удаления.
    let member_own = format!("/v1/channels/own/{}/{channel_id}", member.1);
    for (method, what, body) in [
        ("GET", "requests", None),
        ("GET", "subscribers", None),
        (
            "DELETE",
            "subscribers",
            Some(serde_json::json!({ "account_id": account_id })),
        ),
        (
            "POST",
            "invites",
            Some(serde_json::json!({ "invite_hash": invite_hash(&[9u8; 16]) })),
        ),
    ] {
        let (status, _) = signed(
            &state,
            &member.0,
            method,
            &format!("{member_own}/{what}"),
            body,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {what}");
    }

    // Закрыть либо открыть канал — только владелец.
    let (status, _) = signed(
        &state,
        &admin.0,
        "PUT",
        &admin_own,
        Some(serde_json::json!({ "closed": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Администратор удаляет подписчика.
    let (status, _) = signed(
        &state,
        &admin.0,
        "DELETE",
        &format!("{admin_own}/subscribers"),
        Some(serde_json::json!({ "account_id": account_id })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        member_get(&state, &member, channel_id, "posts").await.0,
        StatusCode::NOT_FOUND
    );
}

/// Закрытый канал не бывает публичным, и наоборот; медиа закрытого
/// канала отдаётся только участнику.
#[tokio::test]
async fn closed_and_public_do_not_mix() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let own = format!("/v1/channels/own/{owner_device}/{channel_id}");
    let public = serde_json::json!({
        "set_public": true,
        "handle": unique_name("shut"),
        "public_link": link_to(channel_id),
    });

    let (status, _) = signed(&state, &owner_key, "PUT", &own, Some(public.clone())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let upload = signed_request(
        &owner_key,
        "POST",
        &format!("{own}/media"),
        "application/octet-stream",
        vec![7u8; 64],
    );
    let (status, stored) = send(&state, upload).await;
    assert_eq!(status, StatusCode::OK);
    let media_id = stored["media_id"].as_str().unwrap().to_owned();

    let (status, _) = get(
        &state,
        &format!("/v1/channels/feed/{channel_id}/media/{media_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = signed(
        &state,
        &owner_key,
        "GET",
        &format!("/v1/channels/reader/{owner_device}/{channel_id}/media/{media_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Открытый снова — и имя дать можно, а закрыть с именем нельзя.
    let (status, _) = signed(
        &state,
        &owner_key,
        "PUT",
        &own,
        Some(serde_json::json!({ "closed": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = signed(&state, &owner_key, "PUT", &own, Some(public)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = signed(
        &state,
        &owner_key,
        "PUT",
        &own,
        Some(serde_json::json!({ "closed": true })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  Боты (миграция 0022)
// ---------------------------------------------------------------------------

fn bot_name() -> String {
    format!("{}bot", unique_name("helper"))
}

/// Тело регистрации бота его программой.
fn bot_registration(username: &str, token: &str, private: &DeviceKey) -> serde_json::Value {
    let identity = key();
    let device = public_key(private);
    let challenge = pow::registration_challenge(username, &identity, &device);

    serde_json::json!({
        "token": token,
        "username": username,
        "identity_key": hex::encode(identity),
        "device_identity_key": hex::encode(device),
        "pq_identity_key": hex::encode([0x51u8; 1952]),
        "identity_binding": hex::encode([0x52u8; 3373]),
        "pow_challenge": hex::encode(challenge),
        "pow_nonce": solve(&challenge),
    })
}

/// Берёт токен под имя и регистрирует по нему бота; возвращает его
/// ключ и устройство.
async fn bot_of(
    state: &Arc<AppState>,
    owner_key: &DeviceKey,
    owner_device: Uuid,
    username: &str,
) -> Subscriber {
    let (status, issued) = signed(
        state,
        owner_key,
        "POST",
        &format!("/v1/bots/own/{owner_device}"),
        Some(serde_json::json!({ "username": username })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let private = device_key();
    let (status, body) = post(
        state,
        "/v1/bots/register",
        bot_registration(username, issued["token"].as_str().unwrap(), &private),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "бот не зарегистрирован: {body:?}");

    (
        private,
        body["device_id"].as_str().unwrap().parse().unwrap(),
    )
}

/// Премиум-владелец заводит бота: токен одноразовый, имя — на `bot`,
/// бот регистрируется без почты и виден владельцу в списке.
#[tokio::test]
async fn a_premium_owner_creates_a_bot() {
    let (state, _mailer) = require_state!();
    let owner_key = device_key();
    let owner_device = premium_account(&state, &owner_key).await;
    let bots = format!("/v1/bots/own/{owner_device}");
    let username = bot_name();

    let (status, issued) = signed(
        &state,
        &owner_key,
        "POST",
        &bots,
        Some(serde_json::json!({ "username": username })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = issued["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 64);

    // Под то же имя второй токен не выдаётся.
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &bots,
        Some(serde_json::json!({ "username": username })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Чужой токен и токен под другое имя не годятся — и настоящий не жгут.
    let private = device_key();
    let (status, _) = post(
        &state,
        "/v1/bots/register",
        bot_registration(&username, &hex::encode([9u8; 32]), &private),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = post(
        &state,
        "/v1/bots/register",
        bot_registration(&bot_name(), &token, &private),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, registered) = post(
        &state,
        "/v1/bots/register",
        bot_registration(&username, &token, &private),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bot_device: Uuid = registered["device_id"].as_str().unwrap().parse().unwrap();

    // Токен одноразовый.
    let (status, _) = post(
        &state,
        "/v1/bots/register",
        bot_registration(&username, &token, &device_key()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, list) = signed(&state, &owner_key, "GET", &bots, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["username"], username);

    // Бот — обычный аккаунт: его запросы за подписью проходят.
    let (status, own) = signed(
        &state,
        &private,
        "GET",
        &format!("/v1/accounts/{bot_device}/status"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(own["premium"], false);

    // 🔐 Адреса почты у бота нет — и в базе его нет.
    let email: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT email_hash FROM accounts WHERE username = $1")
            .bind(&username)
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(email, None);
}

/// Без премиума бота не завести; имя обязано кончаться на `bot`, а
/// обычному аккаунту такое имя не дают.
#[tokio::test]
async fn bot_names_and_premium_are_enforced() {
    let (state, _mailer) = require_state!();
    let plain_key = device_key();
    let plain_device = register(&state, &unique_name("plain"), &plain_key).await;

    let (status, _) = signed(
        &state,
        &plain_key,
        "POST",
        &format!("/v1/bots/own/{plain_device}"),
        Some(serde_json::json!({ "username": bot_name() })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let owner_key = device_key();
    let owner_device = premium_account(&state, &owner_key).await;

    for name in [
        unique_name("helper"),
        "bot".to_owned(),
        "Хелперbot".to_owned(),
    ] {
        let (status, _) = signed(
            &state,
            &owner_key,
            "POST",
            &format!("/v1/bots/own/{owner_device}"),
            Some(serde_json::json!({ "username": name })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
    }

    // Человек ботом не называется.
    let email = common::confirmed_email(&state).await;
    let (status, _) = post(
        &state,
        "/v1/accounts/register",
        registration(&bot_name(), &device_key(), &email, common::TEST_EMAIL_CODE),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Чужой список ботов не открыть: подпись не того устройства.
    let (status, _) = signed(
        &state,
        &plain_key,
        "GET",
        &format!("/v1/bots/own/{owner_device}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Владелец удаляет бота; удалён владелец — удалены и его боты.
#[tokio::test]
async fn bots_are_deleted_by_and_with_their_owner() {
    let (state, _mailer) = require_state!();
    let owner_key = device_key();
    let owner_device = premium_account(&state, &owner_key).await;
    let bots = format!("/v1/bots/own/{owner_device}");
    let first = bot_name();
    let second = bot_name();

    let (first_key, first_device) = bot_of(&state, &owner_key, owner_device, &first).await;
    bot_of(&state, &owner_key, owner_device, &second).await;

    // Чужой бота не удалит.
    let stranger_key = device_key();
    let stranger_device = premium_account(&state, &stranger_key).await;
    let (status, _) = signed(
        &state,
        &stranger_key,
        "DELETE",
        &format!("/v1/bots/own/{stranger_device}"),
        Some(serde_json::json!({ "username": first })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &bots,
        Some(serde_json::json!({ "username": first })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Удалённый бот больше не аккаунт.
    let (status, _) = signed(
        &state,
        &first_key,
        "GET",
        &format!("/v1/accounts/{first_device}/status"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, list) = signed(&state, &owner_key, "GET", &bots, None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["username"], second);

    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &format!("/v1/accounts/{owner_device}"),
        None,
    )
    .await;
    assert!(status.is_success(), "владелец удалён: {status}");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts WHERE username = $1")
        .bind(&second)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(left, 0, "бот пережил владельца");
}

/// 🔐 Бот, назначенный администратором, ведёт закрытый канал: видит
/// заявки, одобряет их и удаляет подписчиков.
#[tokio::test]
async fn a_bot_admin_moderates_a_closed_channel() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let bot = bot_of(&state, &owner_key, owner_device, &bot_name()).await;
    let bot_own = format!("/v1/channels/own/{}/{channel_id}", bot.1);

    // До назначения бот в канале никто.
    let (status, _) = signed(&state, &bot.0, "GET", &format!("{bot_own}/requests"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("/v1/channels/own/{owner_device}/{channel_id}/admins"),
        Some(serde_json::json!({ "device_id": bot.1, "verify_key": hex::encode(key()) })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (member, _) = applicant(&state, channel_id).await;

    let (status, requests) =
        signed(&state, &bot.0, "GET", &format!("{bot_own}/requests"), None).await;
    assert_eq!(status, StatusCode::OK);
    let account_id = requests[0]["account_id"].clone();

    let (status, _) = signed(
        &state,
        &bot.0,
        "POST",
        &format!("{bot_own}/requests"),
        Some(serde_json::json!({ "account_id": account_id, "grant": hex::encode(b"grant") })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        member_get(&state, &member, channel_id, "posts").await.0,
        StatusCode::OK
    );

    let (status, _) = signed(
        &state,
        &bot.0,
        "DELETE",
        &format!("{bot_own}/subscribers"),
        Some(serde_json::json!({ "account_id": account_id })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        member_get(&state, &member, channel_id, "posts").await.0,
        StatusCode::NOT_FOUND
    );
}

// ---------------------------------------------------------------------------
//  Смена ключа закрытого канала (миграция 0023)
// ---------------------------------------------------------------------------

/// Запись под ключом эпохи `epoch`: первый байт и номер — всё, что в ней
/// видит сервер.
fn epoch_body(epoch: u32, text: &[u8]) -> String {
    let mut wire = vec![3u8];
    wire.extend_from_slice(&epoch.to_be_bytes());
    wire.extend_from_slice(text);

    hex::encode(wire)
}

/// 🔐 Смена ключа: оставшиеся участники получают ключ новой эпохи,
/// удалённый — нет, а запись под прежним ключом сервер не принимает.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn rekeying_hands_the_new_key_to_those_who_stay() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let own = format!("/v1/channels/own/{owner_device}/{channel_id}");
    let owner = (owner_key, owner_device);

    // Двое входят по заявке; их ключи из заявок становятся ключами доставки.
    let (stays, _) = applicant(&state, channel_id).await;
    let (leaves, _) = applicant(&state, channel_id).await;
    let (_, requests) = signed(&state, &owner_key, "GET", &format!("{own}/requests"), None).await;
    let mut accounts = Vec::new();
    for request in requests.as_array().unwrap() {
        let (status, _) = signed(
            &state,
            &owner_key,
            "POST",
            &format!("{own}/requests"),
            Some(serde_json::json!({
                "account_id": request["account_id"],
                "grant": hex::encode(b"epoch-0"),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        accounts.push(request["account_id"].clone());
    }

    // Владелец называет свой ключ доставки — как любой участник.
    assert_eq!(
        reader(
            &state,
            &owner,
            channel_id,
            "key",
            Some(serde_json::json!({ "member_key": hex::encode(b"owner-key") })),
        )
        .await,
        StatusCode::NO_CONTENT
    );

    let (status, keys) = signed(&state, &owner_key, "GET", &format!("{own}/keys"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys.as_array().unwrap().len(), 3);

    // Кто из двоих уходит — узнаём по ответу сервера на его чтение позже;
    // удаляем второго по списку заявок.
    let removed = accounts[1].clone();
    let (status, _) = signed(
        &state,
        &owner_key,
        "DELETE",
        &format!("{own}/subscribers"),
        Some(serde_json::json!({ "account_id": removed })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, keys) = signed(&state, &owner_key, "GET", &format!("{own}/keys"), None).await;
    let keys = keys.as_array().unwrap().clone();
    assert_eq!(keys.len(), 2, "ключ удалённого в выдачу не попадает");

    // Смена ключа: звено и ответы — всем, включая удалённого (его ответ
    // сервер обязан отбросить).
    let mut grants: Vec<serde_json::Value> = keys
        .iter()
        .map(|key| serde_json::json!({ "account_id": key["account_id"], "grant": hex::encode(b"epoch-1") }))
        .collect();
    grants.push(serde_json::json!({ "account_id": removed, "grant": hex::encode(b"leak") }));

    // Не та эпоха — отказ.
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("{own}/keys"),
        Some(serde_json::json!({ "epoch": 2, "record": hex::encode(b"link"), "grants": grants })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("{own}/keys"),
        Some(serde_json::json!({ "epoch": 1, "record": hex::encode(b"link"), "grants": grants })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM channel_grants WHERE channel_id = $1 AND grant_blob = $2",
    )
    .bind(channel_id)
    .bind(b"leak".as_slice())
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(leaked, 0, "удалённому ключ новой эпохи не сохранён");

    // Оставшиеся видят новую эпоху, свой ответ и звено цепочки.
    let mut served = 0;
    for who in [&stays, &leaves] {
        let (status, info) = member_get(&state, who, channel_id, "info").await;
        if status != StatusCode::OK {
            assert_eq!(
                member_get(&state, who, channel_id, "epochs").await.0,
                StatusCode::NOT_FOUND,
                "удалённому звенья не отдаются"
            );
            continue;
        }

        served += 1;
        assert_eq!(info["key_epoch"], 1);
        assert_eq!(
            member_get(&state, who, channel_id, "join").await.1["grant"],
            hex::encode(b"epoch-1")
        );

        let (_, chain) = member_get(&state, who, channel_id, "epochs").await;
        assert_eq!(chain.as_array().unwrap().len(), 1);
        assert_eq!(chain[0]["epoch"], 1);
        assert_eq!(chain[0]["record"], hex::encode(b"link"));
    }
    assert_eq!(served, 1);

    // Запись под прежним ключом не принимается; под новым — да.
    let posts = format!("{own}/posts");
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &posts,
        Some(serde_json::json!({ "body": hex::encode(b"old key") })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &posts,
        Some(serde_json::json!({ "body": epoch_body(1, b"new key") })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Канал, у которого меняли ключ, открытым не сделать.
    let (status, _) = signed(
        &state,
        &owner_key,
        "PUT",
        &own,
        Some(serde_json::json!({ "closed": false })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Ключи доставки и смена ключа — только для закрытого канала и только
/// для тех, кто его ведёт; сменивший ключ участник получает новый ответ.
#[tokio::test]
async fn key_delivery_is_for_members_and_writers_only() {
    let (state, _mailer) = require_state!();
    let (owner_key, owner_device, channel_id) = closed_channel(&state).await;
    let own = format!("/v1/channels/own/{owner_device}/{channel_id}");
    let (member, _) = applicant(&state, channel_id).await;
    let key = |text: &[u8]| Some(serde_json::json!({ "member_key": hex::encode(text) }));

    // Заявитель — ещё не участник.
    assert_eq!(
        reader(&state, &member, channel_id, "key", key(b"early")).await,
        StatusCode::NOT_FOUND
    );

    let (_, requests) = signed(&state, &owner_key, "GET", &format!("{own}/requests"), None).await;
    let account_id = requests[0]["account_id"].clone();
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("{own}/requests"),
        Some(serde_json::json!({ "account_id": account_id, "grant": hex::encode(b"grant") })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Подписчик канал не ведёт: ни ключей, ни смены.
    let member_own = format!("/v1/channels/own/{}/{channel_id}/keys", member.1);
    let (status, _) = signed(&state, &member.0, "GET", &member_own, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = signed(
        &state,
        &member.0,
        "POST",
        &member_own,
        Some(serde_json::json!({ "epoch": 1, "record": hex::encode(b"x"), "grants": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Все уже с ответом: «без ключа эпохи» — никого.
    let missing = format!("{own}/keys?missing=true");
    let (_, list) = signed(&state, &owner_key, "GET", &missing, None).await;
    assert_eq!(list.as_array().unwrap().len(), 0);

    // Участник сменил ключ доставки (новое устройство): прежний ответ
    // ему бесполезен, и он снова в списке ждущих.
    assert_eq!(
        reader(&state, &member, channel_id, "key", key(b"fresh")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        member_get(&state, &member, channel_id, "join").await.1["status"],
        "none"
    );
    let (_, list) = signed(&state, &owner_key, "GET", &missing, None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["member_key"], hex::encode(b"fresh"));

    // Досылка ответа для действующей эпохи — без звена.
    let (status, _) = signed(
        &state,
        &owner_key,
        "POST",
        &format!("{own}/keys"),
        Some(serde_json::json!({
            "epoch": 0,
            "grants": [{ "account_id": account_id, "grant": hex::encode(b"again") }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        member_get(&state, &member, channel_id, "join").await.1["grant"],
        hex::encode(b"again")
    );

    // В открытом канале ключей доставки нет.
    let (open_key, open_device, open_channel) = channel_with_posts(&state, 0).await;
    assert_eq!(
        reader(
            &state,
            &(open_key, open_device),
            open_channel,
            "key",
            key(b"k")
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

// ---------------------------------------------------------------------------
//  Жалобы на каналы (миграция 0024)
// ---------------------------------------------------------------------------

/// На канал жалуется любой аккаунт; повторная жалоба заменяет прежнюю,
/// а ссылку канала жалобщик прикладывает по своему выбору.
#[tokio::test]
async fn a_channel_can_be_reported() {
    let (state, _mailer) = require_state!();
    let (_owner_key, _owner_device, channel_id) = channel_with_posts(&state, 1).await;
    let private = device_key();
    let device_id = register(&state, &unique_name("reporter"), &private).await;
    let who = (private, device_id);
    let report = |body: serde_json::Value| reader(&state, &who, channel_id, "report", Some(body));

    assert_eq!(
        report(serde_json::json!({ "reason": 2, "seq": 1 })).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        report(serde_json::json!({ "reason": 3, "link": link_to(channel_id) })).await,
        StatusCode::NO_CONTENT
    );

    let rows: Vec<(i16, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT reason, post_seq, channel_link FROM channel_reports WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_all(&state.pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(3, None, Some(link_to(channel_id)))]);

    // Негодная жалоба и жалоба на несуществующий канал.
    for bad in [
        serde_json::json!({ "reason": 0 }),
        serde_json::json!({ "reason": 9 }),
        serde_json::json!({ "reason": 1, "seq": 0 }),
        serde_json::json!({ "reason": 1, "link": "https://example.org" }),
        // Ссылка другого канала к жалобе на этот не прикладывается.
        serde_json::json!({ "reason": 1, "link": link_to(Uuid::new_v4()) }),
    ] {
        assert_eq!(report(bad).await, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        reader(
            &state,
            &who,
            Uuid::new_v4(),
            "report",
            Some(serde_json::json!({ "reason": 1 })),
        )
        .await,
        StatusCode::NOT_FOUND
    );
}
