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
//! GASAPP_TEST_DATABASE_URL=postgres://gasapp:gasapp-dev@localhost:5433/gasapp \
//!     cargo test -p gasapp-server-api
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
        match common::state().await {
            Some(state) => state,
            None => {
                eprintln!("GASAPP_TEST_DATABASE_URL не задан — тест пропущен");
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
    let router = gasapp_server_api::router(Arc::clone(state));

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
        .find(|nonce| pow::verify(challenge, *nonce, common::TEST_DIFFICULTY).is_ok())
        .expect("решение находится")
}

/// Регистрирует аккаунт, возвращая идентификаторы.
async fn register(state: &Arc<AppState>, username: &str) -> (Uuid, Uuid) {
    let (identity, device) = (key(), key());
    let challenge = pow::registration_challenge(username, &identity, &device);
    let nonce = solve(&challenge);

    let (status, body) = call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode(identity),
            "device_identity_key": hex::encode(device),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "email": common::confirmed_email(state).await,
            "email_code": common::TEST_EMAIL_CODE,
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

/// Случайный ключ: сервер не принимает ключ identity, уже занятый
/// другим аккаунтом (аудит 2026-10-02, S-1), а база у тестов общая.
fn key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    key
}

fn unique_name(prefix: &str) -> String {
    // Каноничное имя: строчные буквы, цифры и `_`, не длиннее 32.
    format!("{prefix}_{}", &Uuid::new_v4().simple().to_string()[..16])
}

/// 🧪 Задача M3: регистрация → публикация ключей → получение bundle.
#[tokio::test]
async fn full_registration_and_key_exchange_flow() {
    let state = require_state!();
    let username = unique_name("alice");

    // 1. Регистрация.
    //
    // Устройство с настоящей парой ключей: публикация предключей
    // требует подписи, и фиктивный ключ из `register` для неё не годится.
    let (device_id, private) = register_signing_device(&state, &username, 0x21).await;

    // 2. Discovery находит аккаунт.
    let (status, body) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body["device_ids"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id == &serde_json::json!(device_id))),
        "discovery не назвал устройство: {body:?}"
    );

    // 3. Публикация предключей — 🔐 только за подписью устройства.
    let (status, _) = call_signed_json(
        &state,
        &private,
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

    let username = unique_name("mallory");

    // Челлендж верный: проверяется именно работа, а не его подлинность.
    let challenge = pow::registration_challenge(&username, &[1u8; 32], &[2u8; 32]);

    // Неверное решение — проверенно неверное для этого челленджа.
    // Прежде здесь стоял `u64::MAX` как «заведомо неверное»: имя
    // случайное, а при тестовой сложности в 4 бита случайный nonce
    // проходит с вероятностью 1/16 — тест падал в каждом шестнадцатом
    // прогоне.
    let wrong = (0..u64::MAX)
        .find(|nonce| pow::verify(&challenge, *nonce, common::TEST_DIFFICULTY).is_err())
        .expect("неверное решение находится");

    let (status, _) = call(
        &state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode([1u8; 32]),
            "device_identity_key": hex::encode([2u8; 32]),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "email": common::confirmed_email(&state).await,
            "email_code": common::TEST_EMAIL_CODE,
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": wrong,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// 🔐 Одно решение proof-of-work регистрирует один аккаунт.
///
/// Прежде сервер проверял работу над любым челленджем, который прислал
/// клиент, и одно решение регистрировало сколько угодно аккаунтов:
/// аудитор завёл пять из пяти. Теперь челлендж выводится из имени
/// и ключей, и чужое решение к новому имени не подходит.
#[tokio::test]
async fn one_pow_solution_registers_only_one_account() {
    let state = require_state!();

    let first = unique_name("spam");
    let (identity, device) = (key(), key());
    let challenge = pow::registration_challenge(&first, &identity, &device);
    let nonce = solve(&challenge);

    let mut accepted = 0;
    for index in 0..5 {
        let username = if index == 0 {
            first.clone()
        } else {
            unique_name("spam")
        };

        let (status, _) = call(
            &state,
            "POST",
            "/v1/accounts/register",
            Some(serde_json::json!({
                "username": username,
                "identity_key": hex::encode(identity),
                "device_identity_key": hex::encode(device),
                "pq_identity_key": hex::encode([0x51u8; 1952]),
                "identity_binding": hex::encode([0x52u8; 3373]),
                "email": common::confirmed_email(&state).await,
                "email_code": common::TEST_EMAIL_CODE,
                "pow_challenge": hex::encode(challenge),
                "pow_nonce": nonce,
            })),
        )
        .await;

        if status == StatusCode::OK {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, 1,
        "одно решение зарегистрировало {accepted} аккаунтов из 5"
    );
}

/// 🔐 Занятое имя даёт конфликт, а не подмену аккаунта.
#[tokio::test]
async fn duplicate_username_conflicts() {
    let state = require_state!();
    let username = unique_name("bob");

    register(&state, &username).await;

    let other = key();
    let challenge = pow::registration_challenge(&username, &other, &other);
    let nonce = solve(&challenge);
    let (status, _) = call(
        &state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode(other),
            "device_identity_key": hex::encode(other),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "email": common::confirmed_email(&state).await,
            "email_code": common::TEST_EMAIL_CODE,
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

/// 🔐 Сверх бюджета имени discovery отдаёт недавний снимок, а не отказ.
///
/// Два обязательства сразу. Доступность: отправка идёт через discovery
/// на каждое сообщение, и прежде посторонний, выбрав двадцать запросов
/// в минуту по имени, не давал никому писать этому человеку (429).
/// Слежка: сверх бюджета ответ не меняется — частые запросы не выдают,
/// когда человек сменил ключ или устройство.
#[tokio::test]
async fn discovery_over_budget_serves_a_snapshot_not_a_refusal() {
    let state = require_state!();
    let username = unique_name("carol");
    register(&state, &username).await;

    let first = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);

    // Бюджет — 20/мин; выбирается с запасом.
    for _ in 0..25 {
        call(
            &state,
            "GET",
            &format!("/v1/discovery/username/{username}"),
            None,
        )
        .await;
    }

    // Человек сменил ключ — сверх бюджета этого не видно.
    sqlx::query("UPDATE accounts SET identity_key = $1 WHERE username = $2")
        .bind(vec![0x5Du8; 32])
        .bind(&username)
        .execute(&state.pool)
        .await
        .expect("смена ключа");

    let (status, body) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "сверх бюджета отказ — отправка этому человеку встала бы"
    );
    assert_eq!(
        body["identity_key"], first.1["identity_key"],
        "сверх бюджета виден свежий ключ"
    );
}

/// Кладёт конверт в очередь устройства единственным путём отправки —
/// запечатанным, с решением первого контакта.
async fn enqueue_sealed(
    state: &Arc<AppState>,
    destination: Uuid,
    sealed: &[u8],
) -> (StatusCode, serde_json::Value) {
    let nonce = solve_first_contact(destination, sealed);

    call(
        state,
        "POST",
        "/v1/sealed/messages",
        Some(serde_json::json!({
            "destination_device_id": destination,
            "sealed": hex::encode(sealed),
            "access_key": null,
            "pow_nonce": nonce,
        })),
    )
    .await
}

/// Отправка и приём конверта по HTTP.
#[tokio::test]
async fn envelope_delivery_round_trip() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("dave"), 0x23).await;

    let (status, envelope_id) = enqueue_sealed(&state, device_id, b"opaque").await;

    assert_eq!(status, StatusCode::OK);

    // 🔐 Чтение очереди — за подписью: выдача удаляет конверты,
    // то есть без проверки любой лишал бы адресата переписки.
    let (status, waiting) = call_signed_json(
        &state,
        &private,
        "GET",
        &format!("/v1/messages/{device_id}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(waiting.as_array().map(Vec::len), Some(1));

    // Метка времени округлена до часа — раздел 15.
    let bucketed = waiting[0]["queued_at_bucketed"].as_i64().unwrap();
    assert_eq!(bucketed % 3600, 0, "метка не округлена");

    // Подтверждение удаляет конверт немедленно.
    let envelope = envelope_id.as_str().unwrap();
    let (status, _) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/messages/{device_id}/{envelope}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, empty) = call_signed_json(
        &state,
        &private,
        "GET",
        &format!("/v1/messages/{device_id}"),
        None,
    )
    .await;

    assert_eq!(empty.as_array().map(Vec::len), Some(0), "конверт не удалён");
}

/// 🔐 Незапечатанной отправки нет — ни без подписи, ни с ней.
///
/// Сначала `POST /v1/messages` был без подписи: любой клал конверты
/// в любую очередь, в обход ключа доступа sealed sender. Потом —
/// за подписью отправителя, для первого сообщения; сервер, державший
/// такой маршрут, узнал бы, кто кому пишет, от любого изменённого
/// клиента. Теперь единственный путь — запечатанный.
#[tokio::test]
async fn there_is_no_plain_send_route() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("quiet"), 0x61).await;

    let (status, _) = call_signed_json(
        &state,
        &private,
        "POST",
        &format!("/v1/messages/{device_id}"),
        Some(serde_json::json!({
            "destination_device_id": device_id,
            "ciphertext": hex::encode(b"signed"),
        })),
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "подписанный незапечатанный конверт принят"
    );

    for uri in [
        "/v1/messages".to_owned(),
        format!("/v1/messages/{device_id}"),
    ] {
        let (status, _) = call(
            &state,
            "POST",
            &uri,
            Some(serde_json::json!({
                "destination_device_id": device_id,
                "ciphertext": hex::encode(b"spam"),
            })),
        )
        .await;

        assert_ne!(status, StatusCode::OK, "анонимный конверт принят по {uri}");
    }
}

/// 🔐 Запечатанный мусор без ключа не тратит бюджет собеседников.
///
/// Прежде бюджет получателя расходовался до проверки ключа доступа:
/// попытки без ключа исчерпывали его, и законный собеседник получал 429.
#[tokio::test]
async fn sealed_junk_without_a_key_does_not_starve_friends() {
    let state = require_state!();
    let (victim, victim_key) =
        register_signing_device(&state, &unique_name("friendly"), 0x63).await;
    let access_key = [0x7Du8; 32];

    call_signed_json(
        &state,
        &victim_key,
        "PUT",
        &format!("/v1/sealed/access/{victim}"),
        Some(serde_json::json!({
            "access_key_hash": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(access_key)),
            "allow_from_anyone": false,
        })),
    )
    .await;

    for _ in 0..(gasapp_server_api::rate_limit::MESSAGES_PER_MINUTE * 2) {
        call(
            &state,
            "POST",
            "/v1/sealed/messages",
            Some(serde_json::json!({
                "destination_device_id": victim,
                "sealed": hex::encode(b"spam"),
                "access_key": hex::encode([0u8; 32]),
            })),
        )
        .await;
    }

    let (status, _) = call(
        &state,
        "POST",
        "/v1/sealed/messages",
        Some(serde_json::json!({
            "destination_device_id": victim,
            "sealed": hex::encode(b"hello"),
            "access_key": hex::encode(access_key),
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "мусор без ключа выжег бюджет собеседников: {status}"
    );
}

/// 🔐 Первые контакты по proof-of-work (работа — доли секунды) не
/// выбирают бюджет собеседников с ключом доступа.
#[tokio::test]
async fn first_contacts_do_not_starve_friends() {
    let state = require_state!();
    let (victim, victim_key) = register_signing_device(&state, &unique_name("popular"), 0x64).await;
    let access_key = [0x7Eu8; 32];

    call_signed_json(
        &state,
        &victim_key,
        "PUT",
        &format!("/v1/sealed/access/{victim}"),
        Some(serde_json::json!({
            "access_key_hash": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(access_key)),
            "allow_from_anyone": false,
        })),
    )
    .await;

    // Весь общий бюджет получателя: до разделения бюджетов этого
    // хватало, чтобы собеседник с ключом получил 429. Решения — заранее:
    // иначе бюджет пополнялся бы, пока подбирается следующее.
    let envelopes: Vec<(Vec<u8>, u64)> = (0..gasapp_server_api::rate_limit::MESSAGES_PER_MINUTE)
        .map(|i| {
            let sealed = format!("stranger-{i}").into_bytes();
            let nonce = solve_first_contact(victim, &sealed);
            (sealed, nonce)
        })
        .collect();

    for (sealed, nonce) in &envelopes {
        call(
            &state,
            "POST",
            "/v1/sealed/messages",
            Some(serde_json::json!({
                "destination_device_id": victim,
                "sealed": hex::encode(sealed),
                "access_key": null,
                "pow_nonce": nonce,
            })),
        )
        .await;
    }

    let (status, _) = call(
        &state,
        "POST",
        "/v1/sealed/messages",
        Some(serde_json::json!({
            "destination_device_id": victim,
            "sealed": hex::encode(b"hello friend"),
            "access_key": hex::encode(access_key),
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "незнакомцы выжгли бюджет собеседников: {status}"
    );
}

/// 🔐 Бесплатный перебор bundle не закрывает дверь новым собеседникам:
/// сверх бюджета выдаётся bundle без одноразовых ключей, а не 429,
/// и пул одноразовых ключей сверх бюджета не расходуется.
#[tokio::test]
async fn draining_the_bundle_budget_does_not_lock_out_new_contacts() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("sought"), 0x65).await;

    let one_time: Vec<_> = (0..40)
        .map(|i| serde_json::json!([100 + i, hex::encode([0x33u8; 32])]))
        .collect();
    let (status, _) = call_signed_json(
        &state,
        &private,
        "PUT",
        &format!("/v1/keys/{device_id}"),
        Some(serde_json::json!({
            "signed_key_id": 1,
            "signed_public": hex::encode([0x11u8; 32]),
            "signed_signature": hex::encode([0xAAu8; 64]),
            "kem_key_id": 2,
            "kem_public": hex::encode([0x22u8; 1568]),
            "kem_signature": hex::encode([0xBBu8; 64]),
            "one_time": one_time,
            "one_time_kem": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let mut issued = 0;
    for _ in 0..(gasapp_server_api::rate_limit::BUNDLE_PER_MINUTE * 3) {
        let (status, bundle) =
            call(&state, "GET", &format!("/v1/keys/{device_id}/bundle"), None).await;
        assert_eq!(status, StatusCode::OK, "новому собеседнику отказано");
        if !bundle["one_time"].is_null() {
            issued += 1;
        }
    }

    assert!(
        issued <= gasapp_server_api::rate_limit::BUNDLE_PER_MINUTE,
        "сверх бюджета выдано одноразовых ключей: {issued}"
    );
}

/// Подбирает решение первого контакта для конверта этому получателю.
fn solve_first_contact(destination: Uuid, sealed: &[u8]) -> u64 {
    let challenge = pow::first_contact_challenge(&destination.to_string(), sealed);

    (0u64..1 << 26)
        .find(|nonce| pow::verify(&challenge, *nonce, pow::FIRST_CONTACT_DIFFICULTY).is_ok())
        .expect("решение находится")
}

/// 🔐 Первое сообщение приходит запечатанным: без ключа доступа,
/// с proof-of-work.
///
/// Прежде первое сообщение шло за подписью отправителя: ключа доступа
/// получателя у него ещё нет. Сервер видел, кто начал переписку с кем.
#[tokio::test]
async fn first_contact_is_sealed_with_proof_of_work() {
    let state = require_state!();
    let (stranger, _) = register_signing_device(&state, &unique_name("stranger"), 0x71).await;
    let sealed = b"first sealed envelope";

    let send = |destination: Uuid, body: &'static [u8], nonce: u64| {
        let state = Arc::clone(&state);
        async move {
            call(
                &state,
                "POST",
                "/v1/sealed/messages",
                Some(serde_json::json!({
                    "destination_device_id": destination,
                    "sealed": hex::encode(body),
                    "access_key": null,
                    "pow_nonce": nonce,
                })),
            )
            .await
            .0
        }
    };

    let nonce = solve_first_contact(stranger, sealed);

    assert_eq!(
        send(stranger, sealed, nonce).await,
        StatusCode::OK,
        "запечатанный первый контакт с верной работой не принят"
    );

    // Решение для одного конверта не годится для другого.
    assert_eq!(
        send(stranger, b"another envelope here", nonce).await,
        StatusCode::UNAUTHORIZED,
        "решение перенеслось на другой конверт"
    );

    // Несуществующее устройство — тот же отказ, что у неверной работы:
    // иначе это оракул «кто зарегистрирован».
    let nobody = Uuid::new_v4();
    let nobody_nonce = solve_first_contact(nobody, sealed);
    assert_eq!(
        send(nobody, sealed, nobody_nonce).await,
        StatusCode::UNAUTHORIZED,
        "несуществующее устройство отвечает иначе, чем неверная работа"
    );
}

/// 🔐 Некорректный hex отвергается как плохой запрос, а не роняет сервер.
#[tokio::test]
async fn malformed_hex_is_rejected() {
    let state = require_state!();
    let (device_id, _) = register_signing_device(&state, &unique_name("erin"), 0x24).await;

    let (status, _) = call(
        &state,
        "POST",
        "/v1/sealed/messages",
        Some(serde_json::json!({
            "destination_device_id": device_id,
            "sealed": "не hex",
            "access_key": null,
            "pow_nonce": 0,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Счётчик оставшихся предключей доступен по HTTP.
#[tokio::test]
async fn prekey_count_is_exposed() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("frank"), 0x22).await;

    let (status, _) = call_signed_json(
        &state,
        &private,
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

    assert_eq!(status, StatusCode::NO_CONTENT, "предключи не опубликованы");

    // 🔐 Счётчик тоже за подписью: он говорит, сколько сеансов ещё
    // можно начать с этим устройством, то есть насколько оно активно.
    let (status, count) = call_signed_json(
        &state,
        &private,
        "GET",
        &format!("/v1/keys/{device_id}/count"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(count.as_i64(), Some(2));
}

/// 🔐 Загрузка предключей ограничена: число и длина.
///
/// Прежде устройство добавляло сколько угодно ключей любой длины —
/// любой зарегистрированный аккаунт забивал диск сервера.
#[tokio::test]
async fn prekey_uploads_are_bounded() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("hoarder"), 0x27).await;

    let publish = |one_time: Vec<(i32, String)>, kem_public: String| {
        let state = Arc::clone(&state);
        async move {
            call_signed_json(
                &state,
                &private,
                "PUT",
                &format!("/v1/keys/{device_id}"),
                Some(serde_json::json!({
                    "signed_key_id": 1,
                    "signed_public": hex::encode([0x11u8; 32]),
                    "signed_signature": hex::encode([0xAAu8; 64]),
                    "kem_key_id": 2,
                    "kem_public": kem_public,
                    "kem_signature": hex::encode([0xBBu8; 64]),
                    "one_time": one_time,
                    "one_time_kem": [],
                })),
            )
            .await
            .0
        }
    };
    let keys = |from: i32, count: i32| -> Vec<(i32, String)> {
        (from..from + count)
            .map(|id| (id, hex::encode([0x33u8; 32])))
            .collect()
    };
    let kem = hex::encode([0x22u8; 1568]);

    // Ключ в 64 КБ — в пределе тела, но не ключ: отказ.
    assert_eq!(
        publish(keys(1, 1), hex::encode(vec![0x22u8; 64 * 1024])).await,
        StatusCode::BAD_REQUEST,
        "принят предключ в 64 КБ"
    );

    // Полный пул клиента и пополнение до предела проходят…
    assert_eq!(
        publish(keys(1, 100), kem.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        publish(keys(101, 100), kem.clone()).await,
        StatusCode::NO_CONTENT
    );

    // …а сверх предела — нет.
    assert_eq!(
        publish(keys(201, 1), kem).await,
        StatusCode::INSUFFICIENT_STORAGE,
        "пул предключей растёт без предела"
    );
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
    let Some(state) = common::state().await else {
        eprintln!("пропущено: нет DATABASE_URL");

        return;
    };

    let device = uuid::Uuid::new_v4();

    // Узел B: слушает канал и держит соединение устройства.
    let node_b = std::sync::Arc::new(gasapp_server_api::hub::Hub::new());
    let mut receiver = node_b.connect_for_test(device).await;

    let pool = state.pool.clone();
    let listener = tokio::spawn(gasapp_server_api::hub::listen(
        pool.clone(),
        std::sync::Arc::clone(&node_b),
        std::sync::Arc::new(gasapp_server_api::health::HealthState::new()),
    ));

    // Слушателю нужно время на подписку: NOTIFY до LISTEN теряется.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Узел A: рассылает уведомление, ничего не зная о узле B.
    gasapp_server_api::hub::broadcast(&pool, device)
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
    let Some(state) = common::state().await else {
        eprintln!("пропущено: нет DATABASE_URL");

        return;
    };

    let app = gasapp_server_api::routes::router(state);

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
        "devices",     // сколько людей сейчас в сети
        "connections", // то же самое другими словами
        "accounts",    // размер сообщества и его рост
        "envelopes",   // сколько сейчас переписываются
        "queue",       // то же самое
        "messages",    // объём трафика
        "requests",    // суточный ритм активности
    ] {
        assert!(
            !text.contains(forbidden),
            "ручка здоровья отдаёт «{forbidden}» — это метаданные о пользователях, \
             а не о работоспособности узла"
        );
    }
}

/// Регистрирует устройство и возвращает его идентификатор
/// вместе с приватным ключом.
///
/// Обычный [`register`] кладёт в базу фиксированный публичный ключ,
/// к которому нет приватного, — подписать им ничего нельзя. Здесь
/// пара настоящая, поэтому запросы к защищённым ручкам проходят.
///
/// `seed` различает устройства. С общим ключом «чужое устройство»
/// в тесте подписывало бы не хуже своего, и проверка принадлежности
/// выглядела бы работающей, не проверяя ничего.
async fn register_signing_device(
    state: &Arc<AppState>,
    username: &str,
    seed: u8,
) -> (Uuid, DeviceKey) {
    let private: DeviceKey = [seed; 32];

    let identity = key();
    let challenge = pow::registration_challenge(username, &identity, &public_key(&private));
    let nonce = solve(&challenge);

    let (status, body) = call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode(identity),
            "device_identity_key": hex::encode(public_key(&private)),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "email": common::confirmed_email(state).await,
            "email_code": common::TEST_EMAIL_CODE,
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "регистрация не прошла: {body:?}");

    (
        body["device_id"].as_str().unwrap().parse().unwrap(),
        private,
    )
}

/// 🔐 Двойник имени не регистрируется, а поиск по нему не находит
/// никого.
///
/// Прежде `UNIQUE` сравнивал побайтно: «alice», «Alice» и «аlice»
/// с кириллической «а» были тремя аккаунтами с одинаковым видом.
#[tokio::test]
async fn lookalike_usernames_are_refused() {
    let state = require_state!();
    let genuine = unique_name("alice");
    register_signing_device(&state, &genuine, 0x44).await;

    for lookalike in [genuine.to_uppercase(), genuine.replacen('a', "\u{430}", 1)] {
        let private: DeviceKey = [0x45; 32];
        let challenge = pow::registration_challenge(&lookalike, &[1u8; 32], &public_key(&private));
        let nonce = solve(&challenge);

        let (status, _) = call(
            &state,
            "POST",
            "/v1/accounts/register",
            Some(serde_json::json!({
                "username": lookalike,
                "identity_key": hex::encode([1u8; 32]),
                "device_identity_key": hex::encode(public_key(&private)),
                "pq_identity_key": hex::encode([0x51u8; 1952]),
                "identity_binding": hex::encode([0x52u8; 3373]),
                "email": common::confirmed_email(&state).await,
                "email_code": common::TEST_EMAIL_CODE,
                "pow_challenge": hex::encode(challenge),
                "pow_nonce": nonce,
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "двойник {lookalike:?} зарегистрирован"
        );
    }

    let (status, _) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{}", genuine.to_uppercase()),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "поиск по неканоничному имени что-то нашёл"
    );
}

/// Выполняет подписанный запрос с телом JSON.
///
/// Тип тела здесь важен: обработчики с `Json<…>` отвергают
/// `application/octet-stream` кодом 415 ещё до проверки подписи,
/// и отказ выглядел бы отказом авторизации.
async fn call_signed_json(
    state: &Arc<AppState>,
    private: &DeviceKey,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let raw = body
        .map(|value| value.to_string().into_bytes())
        .unwrap_or_default();

    let router = gasapp_server_api::router(Arc::clone(state));
    let request = signed_request(private, method, uri, "application/json", raw);

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();

    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

    (status, value)
}

/// Отправляет подписанный запрос, подменив тело после подписи.
async fn call_with_body(
    state: &Arc<AppState>,
    request: axum::http::Request<axum::body::Body>,
    body: Vec<u8>,
) -> StatusCode {
    let (parts, _) = request.into_parts();
    let request = axum::http::Request::from_parts(parts, axum::body::Body::from(body));

    gasapp_server_api::router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

/// 🔐 Подпись одного тела не подходит к другому.
///
/// В v1 тела в подписи не было: кто видел запрос открытым — прокси,
/// завершающий TLS, его журнал, — пять минут предъявлял подпись
/// с другим телом. Для `PUT` предключей это подмена личности; здесь
/// проверяется на загрузке вложения, где тело — сырые байты.
#[tokio::test]
async fn a_signature_does_not_cover_a_different_body() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("swapper"), 0x21).await;
    // Загрузка вложений больше не подписана — тело проверяется
    // на другом подписанном маршруте с телом: токене push.
    let uri = format!("/v1/push/{device_id}");
    let genuine = br#"{"provider":"fcm","token":"first"}"#.to_vec();
    let swapped = br#"{"provider":"fcm","token":"other"}"#.to_vec();

    let signed =
        || common::signed_request(&private, "PUT", &uri, "application/json", genuine.clone());

    assert!(
        call_with_body(&state, signed(), genuine.clone())
            .await
            .is_success(),
        "заготовка теста: подписанное тело не принято"
    );
    assert_eq!(
        call_with_body(&state, signed(), swapped).await,
        StatusCode::UNAUTHORIZED,
        "подпись одного тела принята с другим"
    );
}

/// 🔐 Токен push — только известного провайдера и разумной длины.
///
/// `UnifiedPush` (токен — адрес, куда сервер пойдёт сам) не принимается:
/// без списка разрешённых адресов это запрос во внутреннюю сеть
/// оператора по указке клиента.
#[tokio::test]
async fn push_tokens_are_validated() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("pusher"), 0x23).await;
    let uri = format!("/v1/push/{device_id}");

    let put = |provider: &str, token: String| {
        let state = Arc::clone(&state);
        let uri = uri.clone();
        let body = serde_json::json!({ "provider": provider, "token": token });
        async move {
            call_signed_json(&state, &private, "PUT", &uri, Some(body))
                .await
                .0
        }
    };

    assert_eq!(
        put("fcm", "abc:DEF-123".to_owned()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put("unifiedpush", "http://10.0.0.1/internal".to_owned()).await,
        StatusCode::BAD_REQUEST,
        "принят провайдер с токеном-адресом"
    );
    assert_eq!(
        put("fcm", "x".repeat(100_000)).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put("fcm", "with space\n".to_owned()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(put("fcm", String::new()).await, StatusCode::BAD_REQUEST);

    // APNs: только hex — токен встаёт в путь запроса к Apple.
    assert_eq!(put("apns", "ab".repeat(32)).await, StatusCode::NO_CONTENT);
    assert_eq!(
        put("apns-sandbox", "0f".repeat(32)).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        put("apns", format!("{}/../x", "ab".repeat(32))).await,
        StatusCode::BAD_REQUEST,
        "принят токен APNs с путём"
    );
    assert_eq!(put("apns", "ab".repeat(8)).await, StatusCode::BAD_REQUEST);

    // Отзыв — за подписью, и токен действительно уходит.
    assert_eq!(
        call_signed_json(&state, &private, "DELETE", &uri, None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert!(
        gasapp_server_db::repo::find_push_token(&state.pool, device_id)
            .await
            .expect("чтение")
            .is_none(),
        "токен остался после отзыва"
    );
}

/// 🔐 Запрос без хеша тела — формат v1 — отвергается.
#[tokio::test]
async fn a_request_without_the_body_hash_is_refused() {
    let state = require_state!();
    let (device_id, private) =
        register_signing_device(&state, &unique_name("oldclient"), 0x22).await;

    let mut request = common::signed_request(
        &private,
        "GET",
        &format!("/v1/keys/{device_id}/count"),
        "application/json",
        Vec::new(),
    );
    request.headers_mut().remove("x-gasapp-body-sha256");

    let status = gasapp_server_api::router(Arc::clone(&state))
        .oneshot(request)
        .await
        .unwrap()
        .status();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Анонимная загрузка вложения с решением proof-of-work.
async fn upload_anonymously(state: &Arc<AppState>, payload: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let challenge = pow::upload_challenge(&payload);
    let difficulty = pow::upload_difficulty(payload.len());
    let nonce = (0u64..1 << 30)
        .find(|nonce| pow::verify(&challenge, *nonce, difficulty).is_ok())
        .expect("решение находится");

    upload_with_nonce(state, payload, Some(nonce)).await
}

async fn upload_with_nonce(
    state: &Arc<AppState>,
    payload: Vec<u8>,
    nonce: Option<u64>,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/attachments/blob");

    if let Some(nonce) = nonce {
        request = request.header("x-gasapp-upload-pow", nonce.to_string());
    }

    let response = gasapp_server_api::router(Arc::clone(state))
        .oneshot(request.body(Body::from(payload)).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    (status, bytes)
}

/// Вложение загружается и скачивается без изменений.
#[tokio::test]
async fn attachment_round_trips() {
    let state = require_state!();
    let payload = vec![0xABu8; 4096];

    let (status, body) = upload_anonymously(&state, payload.clone()).await;

    assert_eq!(status, StatusCode::OK, "загрузка не прошла");

    let attachment_id: Uuid = serde_json::from_slice::<Uuid>(&body).expect("адрес вложения");

    let (status, downloaded) = call_unsigned(
        &state,
        "GET",
        &format!("/v1/attachments/blob/{attachment_id}"),
        Vec::new(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "скачивание не прошло");
    assert_eq!(downloaded, payload, "вложение изменилось при хранении");
}

/// Запрос без заголовков подписи: так ходит получатель вложения.
async fn call_unsigned(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let response = gasapp_server_api::router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();

    (status, bytes)
}

/// 🔐 Загрузка и скачивание анонимны: сервер не знает ни загрузчика,
/// ни получателя.
///
/// Прежде загрузка была подписана устройством, а скачивание — другим:
/// сервер помнил, кто прислал файл, и видел, кто его забрал. Теперь
/// право на место — работа над самим блобом.
#[tokio::test]
async fn attachments_are_anonymous_both_ways() {
    let state = require_state!();
    let payload = vec![0x11u8; 128];

    // Без решения — отказ.
    let (status, _) = upload_with_nonce(&state, payload.clone(), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "загрузка без работы прошла"
    );

    // Решение для другого блоба не подходит.
    let other = vec![0x22u8; 128];
    let challenge = pow::upload_challenge(&other);
    let foreign = (0u64..1 << 30)
        .find(|nonce| pow::verify(&challenge, *nonce, pow::upload_difficulty(other.len())).is_ok())
        .expect("решение");
    let (status, _) = upload_with_nonce(&state, payload.clone(), Some(foreign)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "решение перенеслось на другой блоб"
    );

    let (status, body) = upload_anonymously(&state, payload.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let attachment_id: Uuid = serde_json::from_slice::<Uuid>(&body).expect("адрес вложения");

    let (status, downloaded) = call_unsigned(
        &state,
        "GET",
        &format!("/v1/attachments/blob/{attachment_id}"),
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "анонимное скачивание не прошло");
    assert_eq!(downloaded, payload);

    // Загрузчик в базе не записан.
    let uploader: Option<Uuid> =
        sqlx::query_scalar("SELECT uploader_device_id FROM attachments WHERE attachment_id = $1")
            .bind(attachment_id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(uploader, None, "сервер записал загрузчика");
}

/// Пустое вложение отвергается.
///
/// Описание, ссылающееся на пустой блоб, у получателя всё равно
/// не откроется.
#[tokio::test]
async fn empty_attachment_is_rejected() {
    let state = require_state!();

    let (status, _) = upload_anonymously(&state, Vec::new()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Несуществующее вложение — 404, а не пустое тело.
#[tokio::test]
async fn missing_attachment_returns_not_found() {
    let state = require_state!();
    let (status, _) = call_unsigned(
        &state,
        "GET",
        &format!("/v1/attachments/blob/{}", Uuid::new_v4()),
        Vec::new(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
//  🔐 Удаление аккаунта (MASVS PRIVACY-3.2)
//
//  До появления этих ручек политика приватности была вынуждена писать,
//  что права на удаление у пользователя нет. Проверяется здесь не «ручка
//  отвечает 200», а то, что после ответа данных действительно нет:
//  «удалено» без проверки — это и есть документ, разошедшийся со сборкой.
// ---------------------------------------------------------------------------

/// 🔐 Удаление уносит аккаунт, устройства, ключи и очередь.
#[tokio::test]
async fn account_deletion_removes_everything() {
    let state = require_state!();
    let username = unique_name("leaving");
    let (device_id, private) = register_signing_device(&state, &username, 0x41).await;

    // Предключи: то, по чему с этим устройством можно начать сеанс.
    let (status, _) = call_signed_json(
        &state,
        &private,
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
            "one_time_kem": [],
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    // Недоставленный конверт в очереди.
    let (status, _) = enqueue_sealed(&state, device_id, b"opaque").await;

    assert_eq!(status, StatusCode::OK);

    // Вложение, отправленное этим устройством, — анонимное: с аккаунтом
    // оно не связано, и удаление аккаунта его не находит. Оно истечёт
    // само (шифроблоб без ключа).
    let (status, _) = upload_anonymously(&state, vec![0x55u8; 128]).await;

    assert_eq!(status, StatusCode::OK);

    // Собственно удаление.
    let (status, report) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{device_id}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "удаление не прошло: {report:?}");
    assert_eq!(report["devices"].as_u64(), Some(1));
    assert_eq!(report["envelopes"].as_u64(), Some(1), "конверт не удалён");
    assert_eq!(
        report["attachments"].as_u64(),
        Some(0),
        "анонимное вложение оказалось связано с аккаунтом"
    );

    // Аккаунта больше нет: discovery его не находит.
    let (status, _) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "аккаунт всё ещё находится");

    // Предключей нет: начать сеанс с удалённым устройством нельзя.
    let (status, _) = call(&state, "GET", &format!("/v1/keys/{device_id}/bundle"), None).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "предключи пережили удаление");
}

/// 🔐 Повторное удаление не находит, что удалять.
///
/// Устройства уже нет, поэтому подпись проверять не с чем, и ответ —
/// `401`, тот же, что на неизвестное устройство. Различать их значило бы
/// отвечать на вопрос «существовал ли такой аккаунт».
#[tokio::test]
async fn deleting_twice_reveals_nothing() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("twice"), 0x42).await;

    let (status, _) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{device_id}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let (status, _) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{device_id}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Тот же ответ, что на устройство, которого никогда не было.
    let (unknown, _) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{}", Uuid::new_v4()),
        None,
    )
    .await;

    assert_eq!(
        unknown,
        StatusCode::UNAUTHORIZED,
        "удалённый аккаунт отличим от несуществующего"
    );
}

/// 🔐 Чужой подписью чужой аккаунт не удалить.
///
/// Самая дорогая ошибка, какая здесь возможна: ручка удаления без
/// проверки владельца — это кнопка «стереть переписку любому».
#[tokio::test]
async fn account_deletion_needs_the_owners_signature() {
    let state = require_state!();
    let (victim, _) = register_signing_device(&state, &unique_name("victim"), 0x43).await;
    let (_, attacker_key) = register_signing_device(&state, &unique_name("attacker"), 0x44).await;

    let (status, _) = call_signed_json(
        &state,
        &attacker_key,
        "DELETE",
        &format!("/v1/accounts/{victim}"),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "чужим ключом удалили чужой аккаунт"
    );

    // И без подписи — тоже нет.
    let router = gasapp_server_api::router(Arc::clone(&state));
    let response = router
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/accounts/{victim}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Жертва на месте: её устройство по-прежнему отвечает на подписанные
    // запросы. Без этой проверки два `401` выше прошли бы и в случае,
    // когда аккаунт всё-таки удалён.
    let (_, victim_key) = (victim, [0x43u8; 32]);
    let (status, _) = call_signed_json(
        &state,
        &victim_key,
        "GET",
        &format!("/v1/keys/{victim}/count"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "аккаунт жертвы пострадал");
}

/// Имя освобождается: его можно занять заново.
///
/// 🔐 Выдать себя за прежнего владельца это не позволяет — identity-ключ
/// будет другим, и у тех, кто сверял отпечаток, сработает предупреждение
/// о смене ключа. Удерживать имя вечно значило бы хранить запись
/// об удалённом аккаунте, то есть не удалять его.
#[tokio::test]
async fn account_deletion_frees_the_username() {
    let state = require_state!();
    let username = unique_name("reused");

    let (device_id, private) = register_signing_device(&state, &username, 0x45).await;

    let (status, _) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{device_id}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Другой человек, другой ключ, то же имя.
    let (new_device, _) = register_signing_device(&state, &username, 0x46).await;

    assert_ne!(new_device, device_id, "выдан прежний идентификатор");
}

/// 🔐 Удаление закрывает открытый сокет уведомлений.
///
/// Подпись проверяется один раз, при апгрейде. Без явного выселения
/// соединение, открытое до удаления, продолжало бы жить, и удалённый
/// аккаунт так и получал бы сигналы о конвертах — то есть удаление
/// не прекращало бы поток метаданных о нём.
#[tokio::test]
async fn account_deletion_closes_the_notification_socket() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("socket"), 0x47).await;

    let mut receiver = state.hub.connect_for_test(device_id).await;

    assert_eq!(
        state.hub.connected().await,
        1,
        "соединение не зарегистрировано"
    );

    let (status, _) = call_signed_json(
        &state,
        &private,
        "DELETE",
        &format!("/v1/accounts/{device_id}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(state.hub.connected().await, 0, "сокет пережил удаление");

    // Канал закрыт, а не просто пуст: цикл сокета на той стороне
    // завершится сам.
    assert!(
        receiver.recv().await.is_none(),
        "канал остался открытым — сокет продолжит слать уведомления"
    );
}

/// 🔐 Ключ ML-KEM sealed sender публикуется с предключами и отдаётся
/// в discovery — отправителю для гибридного внешнего слоя.
#[tokio::test]
async fn sealed_kem_key_is_published_and_discovered() {
    let state = require_state!();
    let username = unique_name("pqkem");
    let (device_id, private) = register_signing_device(&state, &username, 0x81).await;

    let publish = |sealed_public: Option<String>, sealed_signature: Option<String>| {
        let state = Arc::clone(&state);
        async move {
            call_signed_json(
                &state,
                &private,
                "PUT",
                &format!("/v1/keys/{device_id}"),
                Some(serde_json::json!({
                    "signed_key_id": 1,
                    "signed_public": hex::encode([0x11u8; 32]),
                    "signed_signature": hex::encode([0xAAu8; 64]),
                    "kem_key_id": 2,
                    "kem_public": hex::encode([0x22u8; 1568]),
                    "kem_signature": hex::encode([0xBBu8; 64]),
                    "sealed_kem_public": sealed_public,
                    "sealed_kem_signature": sealed_signature,
                })),
            )
            .await
            .0
        }
    };

    // Неверная длина и половинчатый запрос — плохой запрос, а не сбой базы.
    assert_eq!(
        publish(
            Some(hex::encode([0x55u8; 100])),
            Some(hex::encode([0x66u8; 3373]))
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        publish(Some(hex::encode([0x55u8; 1568])), None).await,
        StatusCode::BAD_REQUEST
    );

    assert_eq!(
        publish(
            Some(hex::encode([0x55u8; 1568])),
            Some(hex::encode([0x66u8; 3373]))
        )
        .await,
        StatusCode::NO_CONTENT
    );

    let (status, body) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["sealed_kem_public"],
        serde_json::json!(hex::encode([0x55u8; 1568]))
    );
    assert_eq!(
        body["sealed_kem_signature"],
        serde_json::json!(hex::encode([0x66u8; 3373]))
    );

    // Публикация без ключа прежний не стирает.
    assert_eq!(publish(None, None).await, StatusCode::NO_CONTENT);
    let (_, again) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;
    assert_eq!(again["sealed_kem_public"], body["sealed_kem_public"]);
}

// --- Возвращение аккаунта на новое устройство (миграция 0013) ---

/// Ключ восстановления аккаунта: XEdDSA-половина и ML-DSA-65.
struct RecoveryKeys {
    classical: DeviceKey,
    pq: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

fn recovery_keys(seed: u8) -> RecoveryKeys {
    RecoveryKeys {
        classical: [seed; 32],
        pq: ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[seed; 32].into()),
    }
}

impl RecoveryKeys {
    fn pq_public(&self) -> Vec<u8> {
        self.pq.expanded_key().verifying_key().encode().to_vec()
    }

    /// Гибридная подпись, как у клиента: XEdDSA ‖ ML-DSA-65 с доменом.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut out = common::client_sign(&self.classical, message).to_vec();
        out.extend_from_slice(
            &self
                .pq
                .expanded_key()
                .sign_deterministic(message, gasapp_server_api::recovery::RECOVER_DOMAIN)
                .expect("подпись")
                .encode(),
        );
        out
    }
}

/// Регистрирует аккаунт с ключом восстановления; возвращает счёт и устройство.
async fn register_with_recovery(
    state: &Arc<AppState>,
    username: &str,
    keys: &RecoveryKeys,
) -> (String, String) {
    let private: DeviceKey = key();
    let challenge =
        pow::registration_challenge(username, &public_key(&private), &public_key(&private));
    let nonce = solve(&challenge);

    let (status, body) = call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode(public_key(&private)),
            "device_identity_key": hex::encode(public_key(&private)),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "recovery_key": hex::encode(public_key(&keys.classical)),
            "recovery_pq_key": hex::encode(keys.pq_public()),
            "email": common::confirmed_email(state).await,
            "email_code": common::TEST_EMAIL_CODE,
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "регистрация: {body:?}");

    (
        body["account_id"].as_str().unwrap().to_owned(),
        body["device_id"].as_str().unwrap().to_owned(),
    )
}

/// Закрытый ключ из `seed` — свой на каждый прогон: база у тестов общая,
/// а ключ identity, занятый прошлым прогоном, сервер не примет (S-1).
fn seeded(seed: u8) -> DeviceKey {
    static BASE: std::sync::OnceLock<DeviceKey> = std::sync::OnceLock::new();
    let mut private = *BASE.get_or_init(key);
    // Не нулевой байт: у X25519 младшие три бита первого байта
    // обнуляются, и `seed` 0x40…0x47 давали бы один и тот же ключ.
    private[1] = seed;
    private
}

/// Запрос перепривязки на новый identity-ключ `seed`, подписанный `keys`.
fn recover_body(
    username: &str,
    seed: u8,
    keys: &RecoveryKeys,
    issued_at: i64,
) -> serde_json::Value {
    let identity = public_key(&seeded(seed));
    let pq = [0x61u8; 1952];
    let binding = [0x62u8; 3373];
    let message = gasapp_server_api::recovery::message(
        username, &identity, &identity, &pq, &binding, issued_at,
    );

    serde_json::json!({
        "username": username,
        "identity_key": hex::encode(identity),
        "device_identity_key": hex::encode(identity),
        "pq_identity_key": hex::encode(pq),
        "identity_binding": hex::encode(binding),
        "issued_at": issued_at,
        "signature": hex::encode(keys.sign(&message)),
    })
}

/// 🔐 Верная подпись ключа восстановления перепривязывает аккаунт:
/// тот же счёт и то же имя, новая identity, прежнее устройство удалено,
/// а имя по-прежнему не занять.
#[tokio::test]
async fn recovery_rebinds_the_account_and_keeps_the_name() {
    let state = require_state!();
    let username = unique_name("phoenix");
    let keys = recovery_keys(0x41);
    let (account_id, old_device) = register_with_recovery(&state, &username, &keys).await;

    let (status, body) = call(
        &state,
        "POST",
        "/v1/accounts/recover",
        Some(recover_body(&username, 0x42, &keys, common::now_millis())),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "перепривязка: {body:?}");
    assert_eq!(
        body["account_id"].as_str(),
        Some(account_id.as_str()),
        "счёт другой"
    );
    assert_ne!(body["device_id"].as_str(), Some(old_device.as_str()));

    let (_, found) = call(
        &state,
        "GET",
        &format!("/v1/discovery/username/{username}"),
        None,
    )
    .await;
    assert_eq!(
        found["identity_key"],
        hex::encode(public_key(&seeded(0x42)))
    );
    assert_eq!(found["device_ids"].as_array().map(Vec::len), Some(1));
    assert_ne!(
        found["device_ids"][0].as_str(),
        Some(old_device.as_str()),
        "прежнее устройство живо"
    );

    // Имя за аккаунтом: чужая регистрация его не получит.
    let private: DeviceKey = key();
    let challenge =
        pow::registration_challenge(&username, &public_key(&private), &public_key(&private));
    let nonce = solve(&challenge);
    let (status, _) = call(
        &state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode(public_key(&private)),
            "device_identity_key": hex::encode(public_key(&private)),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "email": common::confirmed_email(&state).await,
            "email_code": common::TEST_EMAIL_CODE,
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "имя освободилось после перепривязки"
    );
}

/// 🔐 Чужой ключ, повтор и просроченный запрос — отказ.
/// 🔐 Посторонний, зная имя, не мешает владельцу вернуть аккаунт.
///
/// Прежде перепривязка делила ограничитель с discovery: двадцать
/// бесплатных запросов в минуту по имени — и владелец получал 429
/// на каждую попытку. Теперь в бюджет идут только отказы, а верная
/// подпись ключа восстановления проходит всегда.
#[tokio::test]
async fn a_stranger_cannot_lock_the_owner_out_of_recovery() {
    let state = require_state!();
    let username = unique_name("besieged");
    let keys = recovery_keys(0x53);
    register_with_recovery(&state, &username, &keys).await;

    let stranger = recovery_keys(0x54);
    let mut refused_for_rate = false;

    for _ in 0..30 {
        let _ = call(
            &state,
            "GET",
            &format!("/v1/discovery/username/{username}"),
            None,
        )
        .await;
        let status = call(
            &state,
            "POST",
            "/v1/accounts/recover",
            Some(recover_body(
                &username,
                0x55,
                &stranger,
                common::now_millis(),
            )),
        )
        .await
        .0;
        assert_ne!(status, StatusCode::OK, "чужой ключ перепривязал аккаунт");
        refused_for_rate |= status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(refused_for_rate, "неудачные попытки не ограничены вовсе");

    let status = call(
        &state,
        "POST",
        "/v1/accounts/recover",
        Some(recover_body(&username, 0x56, &keys, common::now_millis())),
    )
    .await
    .0;
    assert_eq!(
        status,
        StatusCode::OK,
        "посторонний заблокировал владельцу восстановление"
    );
}

#[tokio::test]
async fn recovery_refuses_foreign_keys_replays_and_stale_requests() {
    let state = require_state!();
    let username = unique_name("guarded");
    let keys = recovery_keys(0x43);
    register_with_recovery(&state, &username, &keys).await;

    let recover = |body: serde_json::Value| {
        let state = Arc::clone(&state);
        async move {
            call(&state, "POST", "/v1/accounts/recover", Some(body))
                .await
                .0
        }
    };

    // Чужой ключ восстановления.
    let stranger = recovery_keys(0x44);
    assert_eq!(
        recover(recover_body(
            &username,
            0x45,
            &stranger,
            common::now_millis()
        ))
        .await,
        StatusCode::UNAUTHORIZED
    );

    // Просроченный: час назад.
    assert_eq!(
        recover(recover_body(
            &username,
            0x45,
            &keys,
            common::now_millis() - 3_600_000
        ))
        .await,
        StatusCode::UNAUTHORIZED
    );

    // Верный — проходит один раз; тот же запрос второй раз — нет.
    let body = recover_body(&username, 0x46, &keys, common::now_millis());
    assert_eq!(recover(body.clone()).await, StatusCode::OK);
    assert_eq!(
        recover(body).await,
        StatusCode::UNAUTHORIZED,
        "повтор перепривязки принят"
    );

    // Неизвестное имя — тот же отказ.
    assert_eq!(
        recover(recover_body(
            &unique_name("nobody"),
            0x47,
            &keys,
            common::now_millis()
        ))
        .await,
        StatusCode::UNAUTHORIZED
    );
}

// --- Аудит 2026-10-02 ---------------------------------------------------------

/// Регистрирует с заданными ключами и возвращает код ответа.
async fn register_with_keys(
    state: &Arc<AppState>,
    username: &str,
    identity: &[u8],
    device: &[u8],
) -> StatusCode {
    let challenge = pow::registration_challenge(username, identity, device);
    let nonce = solve(&challenge);

    call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode(identity),
            "device_identity_key": hex::encode(device),
            "pq_identity_key": hex::encode([0x51u8; 1952]),
            "identity_binding": hex::encode([0x52u8; 3373]),
            "email": common::confirmed_email(state).await,
            "email_code": common::TEST_EMAIL_CODE,
            "pow_challenge": hex::encode(challenge),
            "pow_nonce": nonce,
        })),
    )
    .await
    .0
}

/// 🔐 Чужой ключ identity не регистрируется под другим именем (S-1).
///
/// Владение ключом при регистрации не доказывается, а открытый ключ
/// любого человека отдаёт discovery. Прежде его можно было занять
/// под своим именем — «двойник» с тем же ключом.
#[tokio::test]
async fn someone_elses_identity_key_cannot_be_registered_again() {
    let state = require_state!();
    let identity = key();

    assert_eq!(
        register_with_keys(&state, &unique_name("owner"), &identity, &key()).await,
        StatusCode::OK,
        "заготовка теста: владелец не зарегистрирован"
    );
    assert_eq!(
        register_with_keys(&state, &unique_name("twin"), &identity, &key()).await,
        StatusCode::BAD_REQUEST,
        "чужой ключ identity занят под вторым именем"
    );
}

/// 🔐 Ключи — ровно 32 байта (S-1): прежде длина не проверялась.
#[tokio::test]
async fn identity_keys_of_the_wrong_length_are_refused() {
    let state = require_state!();

    for (identity, device) in [
        (vec![1u8; 31], key().to_vec()),
        (key().to_vec(), vec![2u8; 33]),
    ] {
        assert_eq!(
            register_with_keys(&state, &unique_name("short"), &identity, &device).await,
            StatusCode::BAD_REQUEST,
        );
    }
}

/// 🔐 Подписанное тело — не больше 4 МиБ (S-3).
///
/// Прежде предел был от вложений — 101 МБ на любой подписанный
/// маршрут, и узел буферизовал такие тела целиком.
#[tokio::test]
async fn a_signed_body_is_bounded() {
    let state = require_state!();
    let (device_id, private) = register_signing_device(&state, &unique_name("bulky"), 0x23).await;

    let request = signed_request(
        &private,
        "PUT",
        &format!("/v1/push/{device_id}"),
        "application/json",
        vec![b' '; 5 * 1024 * 1024],
    );
    let status = gasapp_server_api::router(Arc::clone(&state))
        .oneshot(request)
        .await
        .unwrap()
        .status();

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// 🔐 Мест для загрузки нет — отказ до чтения тела (S-3).
#[tokio::test]
async fn uploads_wait_for_a_free_slot() {
    let state = require_state!();
    let mut state = Arc::try_unwrap(state)
        .ok()
        .expect("одна ссылка на состояние");
    state.upload_slots = Arc::new(tokio::sync::Semaphore::new(0));
    let state = Arc::new(state);

    let (status, _) = upload_anonymously(&state, b"blob".to_vec()).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// Жалоба с причиной и уликами (миграция 0030).
///
/// 🔐 Улики — шифр для админ-центра: сервер проверяет только форму и
/// то, что ключ админ-центра заведён; без ключа улики не хранятся, а
/// жалоба всё равно учитывается.
#[tokio::test]
async fn a_report_carries_a_reason_and_sealed_evidence() {
    let state = require_state!();
    let (spammer, spammer_key) = register_signing_device(&state, &unique_name("rep_a"), 41).await;
    let (victim, victim_key) = register_signing_device(&state, &unique_name("rep_b"), 42).await;

    let (status, issued) = call_signed_json(
        &state,
        &spammer_key,
        "GET",
        &format!("/v1/sealed/certificate/{spammer}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let certificate = issued["certificate"].as_str().unwrap().to_owned();
    let report = format!("/v1/sealed/report/{victim}");
    let mut sealed = b"GRE1".to_vec();
    sealed.extend_from_slice(&[7u8; 80]);
    let evidence = hex::encode(&sealed);

    // Причина вне 1–6 и улики не того формата — отказ.
    for body in [
        serde_json::json!({ "certificate": certificate, "reason": 9 }),
        serde_json::json!({ "certificate": certificate, "evidence": hex::encode([1u8; 80]) }),
    ] {
        let (status, _) = call_signed_json(&state, &victim_key, "POST", &report, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    sqlx::query("UPDATE admin_state SET evidence_key = NULL WHERE id = 1")
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, body) = call_signed_json(
        &state,
        &victim_key,
        "POST",
        &report,
        Some(serde_json::json!({ "certificate": certificate, "reason": 1, "evidence": evidence })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recorded"], true);
    assert_eq!(body["evidence_stored"], false, "без ключа админ-центра улики не хранятся");

    // Админ-центр завёл ключ — узел отдаёт его и принимает улики.
    sqlx::query("UPDATE admin_state SET evidence_key = $1 WHERE id = 1")
        .bind(vec![9u8; 32])
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, key) = call(&state, "GET", "/v1/sealed/report-key", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(key["key"], hex::encode([9u8; 32]));

    let (status, body) = call_signed_json(
        &state,
        &victim_key,
        "POST",
        &report,
        Some(serde_json::json!({ "certificate": certificate, "reason": 4, "evidence": evidence })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recorded"], false, "повторная жалоба не считается второй");
    assert_eq!(body["evidence_stored"], true);

    let account: Uuid = sqlx::query_scalar("SELECT account_id FROM devices WHERE device_id = $1")
        .bind(spammer)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let stored: Vec<u8> = sqlx::query_scalar("SELECT sealed FROM report_evidence WHERE reported_account = $1")
        .bind(account)
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(stored, sealed);
    let reason: Option<i16> =
        sqlx::query_scalar("SELECT reason FROM sealed_sender_reports WHERE reported_account = $1")
            .bind(account)
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(reason, Some(1), "причина первой жалобы не переписывается");

    sqlx::query("UPDATE admin_state SET evidence_key = NULL WHERE id = 1")
        .execute(&state.pool)
        .await
        .unwrap();
}
