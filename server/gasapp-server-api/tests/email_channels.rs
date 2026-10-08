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

/// Клиентская половина пропуска — то же, что делает приложение
/// (`gasapp-protocol::pass`): замаскировать, снять маску, посчитать
/// код траты. Сервер видит только то, что эти функции отдают наружу.
#[allow(clippy::arithmetic_side_effects)]
mod pass_client {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;
    use hmac::{Hmac, Mac as _};
    use sha2::{Digest as _, Sha256, Sha512};

    /// Заготовка: зерно и маска.
    pub struct Pending {
        pub seed: [u8; 32],
        blind: Scalar,
    }

    fn point_of(seed: &[u8; 32]) -> RistrettoPoint {
        let mut hasher = Sha512::new();
        hasher.update(b"GASAPP_PASS_v1_POINT");
        hasher.update(seed);

        RistrettoPoint::from_uniform_bytes(&hasher.finalize().into())
    }

    pub fn prepare(seed: [u8; 32], blind: [u8; 32]) -> (Pending, String) {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&blind);
        let blind = Scalar::from_bytes_mod_order_wide(&wide);
        let blinded = (blind * point_of(&seed)).compress();

        (Pending { seed, blind }, hex::encode(blinded.as_bytes()))
    }

    /// Секрет пропуска по ответу сервера.
    pub fn finish(pending: &Pending, signed_hex: &str) -> [u8; 32] {
        let signed: [u8; 32] = hex::decode(signed_hex).unwrap().try_into().unwrap();
        let point = CompressedRistretto(signed).decompress().unwrap();

        (pending.blind.invert() * point).compress().to_bytes()
    }

    pub fn mac(secret: &[u8; 32], binding: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(b"GASAPP_PASS_v1_REDEEM");
        mac.update(&Sha256::digest(binding));

        hex::encode(mac.finalize().into_bytes())
    }
}

/// Пропуск: зерно и секрет.
type Pass = ([u8; 32], [u8; 32]);

/// Берёт `count` пропусков для аккаунта — как приложение.
async fn take_passes(
    state: &Arc<AppState>,
    private: &DeviceKey,
    device_id: Uuid,
    count: usize,
) -> (StatusCode, Vec<Pass>) {
    let pending: Vec<_> = (0..count)
        .map(|_| pass_client::prepare(key(), key()))
        .collect();
    let blinded: Vec<&String> = pending.iter().map(|(_, blinded)| blinded).collect();

    let (status, issued) = signed(
        state,
        private,
        "POST",
        &format!("/v1/passes/issue/{device_id}"),
        Some(serde_json::json!({ "blinded": blinded })),
    )
    .await;

    if status != StatusCode::OK {
        return (status, Vec::new());
    }

    let passes = pending
        .iter()
        .zip(issued["signed"].as_array().unwrap())
        .map(|((pending, _), signed)| {
            (
                pending.seed,
                pass_client::finish(pending, signed["point"].as_str().unwrap()),
            )
        })
        .collect();

    (status, passes)
}

/// Один пропуск от только что заведённого аккаунта.
async fn fresh_pass(state: &Arc<AppState>) -> Pass {
    let private = device_key();
    let device_id = register(state, &unique_name("reader"), &private).await;
    let (status, mut passes) = take_passes(state, &private, device_id, 1).await;
    assert_eq!(status, StatusCode::OK);

    passes.pop().unwrap()
}

/// Тело запроса подписки жетона `token` с пропуском `pass`.
fn subscription(channel_id: Uuid, token: &[u8; 32], pass: &Pass) -> serde_json::Value {
    let binding = gasapp_server_api::pass::subscribe_binding(&channel_id.to_string(), token);

    serde_json::json!({
        "token": hex::encode(token),
        "pass_seed": hex::encode(pass.0),
        "pass_mac": pass_client::mac(&pass.1, &binding),
    })
}

/// Подписывает случайный жетон на канал; возвращает жетон в hex.
async fn subscribe_token(state: &Arc<AppState>, channel_id: Uuid) -> String {
    let token = key();
    let pass = fresh_pass(state).await;

    let (status, _) = post(
        state,
        &format!("/v1/channels/feed/{channel_id}/subscribe"),
        subscription(channel_id, &token, &pass),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    hex::encode(token)
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

/// Подписчики, просмотры и реакции считаются по жетонам.
#[tokio::test]
async fn subscribers_views_and_reactions_are_counted() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 3).await;
    let feed = format!("/v1/channels/feed/{channel_id}");

    let first = subscribe_token(&state, channel_id).await;
    let second = subscribe_token(&state, channel_id).await;

    // Повторная подписка тем же жетоном второго подписчика не даёт.
    let token: [u8; 32] = hex::decode(&first).unwrap().try_into().unwrap();
    let again = fresh_pass(&state).await;
    post(
        &state,
        &format!("{feed}/subscribe"),
        subscription(channel_id, &token, &again),
    )
    .await;

    let (_, info) = get(&state, &feed).await;
    assert_eq!(info["subscribers"], 2);

    // Первый дочитал до второй записи, второй — до третьей.
    for (token, seq) in [(&first, 2), (&second, 3)] {
        let (status, _) = post(
            &state,
            &format!("{feed}/seen"),
            serde_json::json!({ "token": token, "seq": seq }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    // Отметка назад не двигается, а «дочитал до сотой» обрезается.
    post(
        &state,
        &format!("{feed}/seen"),
        serde_json::json!({ "token": first, "seq": 1 }),
    )
    .await;
    post(
        &state,
        &format!("{feed}/seen"),
        serde_json::json!({ "token": second, "seq": 100 }),
    )
    .await;

    for (token, emoji) in [(&first, "🔥"), (&second, "🔥")] {
        let (status, _) = post(
            &state,
            &format!("{feed}/react"),
            serde_json::json!({ "token": token, "seq": 2, "emoji": emoji }),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    // Смена реакции — не вторая реакция.
    post(
        &state,
        &format!("{feed}/react"),
        serde_json::json!({ "token": second, "seq": 2, "emoji": "👍" }),
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
    post(
        &state,
        &format!("{feed}/react"),
        serde_json::json!({ "token": first, "seq": 2 }),
    )
    .await;
    let (status, _) = post(
        &state,
        &format!("{feed}/unsubscribe"),
        serde_json::json!({ "token": second }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

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
/// накручивает: считается жетон, а не запрос.
#[tokio::test]
async fn repeating_a_request_does_not_inflate_counters() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 2).await;
    let feed = format!("/v1/channels/feed/{channel_id}");
    let token = subscribe_token(&state, channel_id).await;

    for _ in 0..5 {
        post(
            &state,
            &format!("{feed}/seen"),
            serde_json::json!({ "token": token, "seq": 2 }),
        )
        .await;
        post(
            &state,
            &format!("{feed}/react"),
            serde_json::json!({ "token": token, "seq": 1, "emoji": "🎉" }),
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
    let feed = format!("/v1/channels/feed/{channel_id}");
    let token = subscribe_token(&state, channel_id).await;

    let (status, _) = post(
        &state,
        &format!("{feed}/react"),
        serde_json::json!({ "token": token, "seq": 1, "emoji": "купи слона" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = post(
        &state,
        &format!("{feed}/react"),
        serde_json::json!({ "token": hex::encode(key()), "seq": 1, "emoji": "👍" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "жетон без подписки");

    let (status, _) = post(
        &state,
        &format!("{feed}/react"),
        serde_json::json!({ "token": token, "seq": 9, "emoji": "👍" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "записи нет");
}

/// 🔐 Подписка стоит пропуска: без него, с поддельным, с чужим
/// (на другой канал или жетон) и с уже потраченным счётчик не растёт.
#[tokio::test]
async fn subscribing_costs_a_pass() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 0).await;
    let (_other_key, _other_device, other_channel) = channel_with_posts(&state, 0).await;
    let uri = format!("/v1/channels/feed/{channel_id}/subscribe");
    let token = key();

    // Выдуманный пропуск: секрета `k·H(seed)` у выдумавшего нет.
    let forged = (key(), key());
    let (status, _) = post(&state, &uri, subscription(channel_id, &token, &forged)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Настоящий пропуск, но код траты посчитан на другой канал и на
    // другой жетон: перехвативший запрос не потратит его на своё.
    let pass = fresh_pass(&state).await;
    let (status, _) = post(&state, &uri, subscription(other_channel, &token, &pass)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut swapped = subscription(channel_id, &token, &pass);
    swapped["token"] = serde_json::json!(hex::encode(key()));
    let (status, _) = post(&state, &uri, swapped).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["subscribers"], 0);

    // Тот же пропуск по назначению проходит — отказы выше его не сожгли.
    let (status, _) = post(&state, &uri, subscription(channel_id, &token, &pass)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // И второй раз — уже нет: ни на тот же жетон, ни на другой.
    let (status, _) = post(&state, &uri, subscription(channel_id, &token, &pass)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let another = key();
    let (status, _) = post(&state, &uri, subscription(channel_id, &another, &pass)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, info) = get(&state, &format!("/v1/channels/feed/{channel_id}")).await;
    assert_eq!(info["subscribers"], 1);
}

/// Пропуск не сгорает на канале, которого нет.
#[tokio::test]
async fn a_pass_survives_a_missing_channel() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 0).await;
    let pass = fresh_pass(&state).await;
    let token = key();
    let missing = Uuid::new_v4();

    let (status, _) = post(
        &state,
        &format!("/v1/channels/feed/{missing}/subscribe"),
        subscription(missing, &token, &pass),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = post(
        &state,
        &format!("/v1/channels/feed/{channel_id}/subscribe"),
        subscription(channel_id, &token, &pass),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// 🔐 Пропуска выдаются аккаунту и в ограниченном числе: это и есть
/// предел накрутки подписчиков. Без подписи устройства их не дают.
#[tokio::test]
async fn passes_are_rationed_per_account() {
    let (state, _mailer) = require_state!();
    let private = device_key();
    let device_id = register(&state, &unique_name("greedy"), &private).await;
    let per_day = usize::try_from(gasapp_server_db::passes::PASSES_PER_DAY).unwrap();
    let per_request = gasapp_server_db::passes::MAX_PASSES_PER_REQUEST;

    let (status, _) = take_passes(&state, &private, device_id, per_request + 1).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "больше, чем за один запрос"
    );

    let mut taken = 0;
    while taken + per_request <= per_day {
        let (status, passes) = take_passes(&state, &private, device_id, per_request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(passes.len(), per_request);
        taken += per_request;
    }

    // Остаток до предела берётся, сверх него — нет; и отказ ничего
    // не списывает: меньший запрос в пределах всё ещё проходит.
    let left = per_day - taken;
    let (status, _) = take_passes(&state, &private, device_id, left + 1).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    if left > 0 {
        let (status, _) = take_passes(&state, &private, device_id, left).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = take_passes(&state, &private, device_id, 1).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Без подписи устройства — никому.
    let (status, _) = post(
        &state,
        &format!("/v1/passes/issue/{device_id}"),
        serde_json::json!({ "blinded": [hex::encode(key())] }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Мусор вместо точки — отказ, а не подпись.
    let other = device_key();
    let other_device = register(&state, &unique_name("junk"), &other).await;
    let (status, _) = signed(
        &state,
        &other,
        "POST",
        &format!("/v1/passes/issue/{other_device}"),
        Some(serde_json::json!({ "blinded": [hex::encode([0xffu8; 32])] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// 🔐 В базе выданное с потраченным не связать: у выдачи — аккаунт
/// и число, у траты — хеш зерна, которого сервер при выдаче не видел.
#[tokio::test]
async fn issuance_and_spending_are_not_linked_in_the_database() {
    let (state, _mailer) = require_state!();
    let (_private, _device, channel_id) = channel_with_posts(&state, 0).await;
    let private = device_key();
    let device_id = register(&state, &unique_name("quiet"), &private).await;
    let (_, passes) = take_passes(&state, &private, device_id, 1).await;
    let pass = passes[0];

    post(
        &state,
        &format!("/v1/channels/feed/{channel_id}/subscribe"),
        subscription(channel_id, &key(), &pass),
    )
    .await;

    let spent: Vec<Vec<u8>> = sqlx::query_scalar("SELECT seed_hash FROM spent_passes")
        .fetch_all(&state.pool)
        .await
        .unwrap();
    assert!(spent.iter().any(|hash| hash.len() == 32));
    // Само зерно и секрет пропуска в базе не лежат.
    assert!(spent
        .iter()
        .all(|hash| hash.as_slice() != pass.0.as_slice()));
    assert!(spent
        .iter()
        .all(|hash| hash.as_slice() != pass.1.as_slice()));

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns
          WHERE table_name = 'spent_passes' ORDER BY column_name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap();
    assert_eq!(columns, vec!["seed_hash", "spent_on"]);
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
