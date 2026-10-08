// SPDX-License-Identifier: AGPL-3.0-only

//! Сверка клиентского контракта с настоящим сервером.
//!
//! # Что здесь проверяется
//!
//! Клиентские типы (`gasapp-net::api`) продублированы вручную, потому
//! что связать крейты зависимостью нельзя: клиент под Apache-2.0,
//! сервер под AGPL-3.0 (ADR-006). Дублирование безопасно ровно до
//! первого расхождения — и обнаружить его должен тест, а не пользователь.
//!
//! Здесь **клиентский JSON скармливается серверу**: если поле
//! переименовано или изменён тип, сервер ответит `400`, и тест упадёт.
//!
//! Зависимость на `gasapp-net` тут не нужна: воспроизводится точная
//! проволочная форма, зафиксированная в `crates/gasapp-net/tests/
//! wire_contract.rs`. Так серверный workspace остаётся независимым
//! от клиентского в обе стороны.
//!
//! # Как запускать
//!
//! ```text
//! docker compose -f server/deploy/docker-compose.yml up -d
//!
//! GASAPP_TEST_DATABASE_URL=postgres://gasapp:gasapp-dev@localhost:5433/gasapp \
//!     cargo test -p gasapp-server-api --test client_contract
//! ```

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
        match common::state().await {
            Some(state) => state,
            None => {
                eprintln!("GASAPP_TEST_DATABASE_URL не задан — тест пропущен");
                return;
            }
        }
    };
}

/// Отправляет сырую строку тела **с подписью устройства**.
///
/// 🔐 Часть маршрутов требует подписи, и без неё сервер отвечает `401`
/// ещё до разбора тела — то есть форма запроса остаётся непроверенной,
/// а тест выглядит упавшим по другой причине. Ровно так два теста
/// в этом файле были красными всё время, пока набор не запускался.
async fn call_raw_signed(
    state: &Arc<AppState>,
    private: &DeviceKey,
    method: &str,
    uri: &str,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let router = gasapp_server_api::router(Arc::clone(state));
    let raw = body.map(String::into_bytes).unwrap_or_default();
    let request = signed_request(private, method, uri, "application/json", raw);

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

/// Отправляет **сырую строку** тела, как её сформировал бы клиент.
async fn call_raw(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let router = gasapp_server_api::router(Arc::clone(state));

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
        .find(|nonce| pow::verify(challenge, *nonce, common::TEST_DIFFICULTY).is_ok())
        .expect("решение находится")
}

/// Поля пост-квантовой половины identity для тела регистрации.
///
/// Сервер проверяет только длины (ключ ML-DSA-65 — 1952 байта,
/// гибридная привязка — 3373): подлинность проверяют клиенты.
fn pq_fields() -> String {
    format!(
        r#""pq_identity_key":"{}","identity_binding":"{}","#,
        hex::encode([0x51u8; 1952]),
        hex::encode([0x52u8; 3373]),
    )
}

/// Поля пост-квантовой identity и подтверждённой почты — всё, что
/// регистрация требует сверх имени и классических ключей.
async fn pq_and_email_fields(state: &AppState) -> String {
    let mut fields = pq_fields();
    fields.push_str(&common::email_fields(state).await);

    fields
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

/// 🔐 Клиентская форма регистрации принимается сервером.
///
/// Тело собрано ровно так, как его сериализует `gasapp_net::api::
/// RegisterRequest`. Переименованное поле дало бы `400`.
#[tokio::test]
async fn client_register_shape_is_accepted() {
    let state = require_state!();
    let username = unique_name("wire");
    let (identity, device) = (key(), key());
    let challenge = pow::registration_challenge(&username, &identity, &device);
    let nonce = solve(&challenge);

    // Точная форма клиентского запроса: порядок полей неважен,
    // важны имена и типы.
    let body = format!(
        r#"{{"username":"{}","identity_key":"{}","device_identity_key":"{}",{pq}"pow_challenge":"{}","pow_nonce":{}}}"#,
        username,
        hex::encode(identity),
        hex::encode(device),
        hex::encode(challenge),
        nonce,
        pq = pq_and_email_fields(&state).await,
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

    // Ключ настоящий: публикация предключей требует подписи, и
    // фиктивные 32 байта для неё не годятся.
    let private: DeviceKey = [0x31u8; 32];
    let username = unique_name("keys");
    let identity = key();
    let challenge = pow::registration_challenge(&username, &identity, &public_key(&private));
    let nonce = solve(&challenge);
    let register = format!(
        r#"{{"username":"{}","identity_key":"{}","device_identity_key":"{}",{pq}"pow_challenge":"{}","pow_nonce":{}}}"#,
        username,
        hex::encode(identity),
        hex::encode(public_key(&private)),
        hex::encode(challenge),
        nonce,
        pq = pq_and_email_fields(&state).await,
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

    let (status, _) = call_raw_signed(
        &state,
        &private,
        "PUT",
        &format!("/v1/keys/{device_id}"),
        Some(body),
    )
    .await;

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

    let private: DeviceKey = [0x32u8; 32];
    let username = unique_name("send");
    let identity = key();
    let challenge = pow::registration_challenge(&username, &identity, &public_key(&private));
    let nonce = solve(&challenge);
    let register = format!(
        r#"{{"username":"{}","identity_key":"{}","device_identity_key":"{}",{pq}"pow_challenge":"{}","pow_nonce":{}}}"#,
        username,
        hex::encode(identity),
        hex::encode(public_key(&private)),
        hex::encode(challenge),
        nonce,
        pq = pq_and_email_fields(&state).await,
    );
    let (_, account) = call_raw(&state, "POST", "/v1/accounts/register", Some(register)).await;
    let device_id = account["device_id"].as_str().unwrap();

    // Форма `gasapp_net::api::SealedSendRequest` первого контакта:
    // ключа доступа нет, есть решение proof-of-work. Незапечатанной
    // отправки у сервера нет вовсе.
    let sealed = b"opaque envelope";
    let challenge = pow::first_contact_challenge(device_id, sealed);
    let pow_nonce = (0u64..1 << 26)
        .find(|nonce| pow::verify(&challenge, *nonce, pow::FIRST_CONTACT_DIFFICULTY).is_ok())
        .expect("решение находится");
    let body = format!(
        r#"{{"destination_device_id":"{device_id}","sealed":"{}","access_key":null,"pow_nonce":{pow_nonce}}}"#,
        hex::encode(sealed),
    );

    let (status, _) = call_raw(&state, "POST", "/v1/sealed/messages", Some(body)).await;

    assert_eq!(status, StatusCode::OK, "сервер отверг форму отправки");

    // Ответ со списком конвертов обязан разбираться клиентом.
    //
    // 🔐 Чтение очереди — за подписью: выдача удаляет конверты.
    let (status, envelopes) = call_raw_signed(
        &state,
        &private,
        "GET",
        &format!("/v1/messages/{device_id}"),
        None,
    )
    .await;

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

    let (identity, device) = (key(), key());
    let challenge = pow::registration_challenge(&username, &identity, &device);
    let nonce = solve(&challenge);
    let register = format!(
        r#"{{"username":"{username}","identity_key":"{}","device_identity_key":"{}",{pq}"pow_challenge":"{}","pow_nonce":{}}}"#,
        hex::encode(identity),
        hex::encode(device),
        hex::encode(challenge),
        nonce,
        pq = pq_and_email_fields(&state).await,
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

/// 🔐 Клиентский и серверный proof-of-work считают один хеш.
///
/// Клиент под Apache-2.0, сервер под AGPL-3.0, поэтому общий крейт
/// невозможен и код продублирован. Тест — единственное, что не даёт
/// копиям разойтись: расхождение проявилось бы как отклонение **всех**
/// регистраций без внятной причины.
///
/// Вектор зафиксирован байтами, а не вызовом клиентского крейта:
/// линковка клиента в тесты сервера — ровно то смешение лицензий,
/// которого требуется избежать.
#[test]
fn client_and_server_pow_agree() {
    // Эталон посчитан независимой реализацией (Python, hashlib) — ему же
    // обязана следовать клиентская (gasapp-net::pow).
    let challenge = [0x42u8; 32];
    let nonce = 12345u64;
    let expected = [0x0d, 0x40, 0x13, 0x38, 0x4d, 0x1d, 0x77, 0xbd];

    let actual = gasapp_server_api::pow::hash(&challenge, nonce).expect("хеш");

    assert_eq!(
        actual.get(..8).expect("восемь байт"),
        expected,
        "клиентский и серверный proof-of-work разошлись: \
         регистрация перестанет проходить"
    );
}

/// 🔐 Клиент и сервер выводят один челлендж регистрации.
///
/// Эталон посчитан независимой реализацией (Python, hashlib); тот же
/// вектор проверяет клиент (`gasapp-net::pow`). Расхождение отвергло бы
/// все регистрации.
#[test]
fn client_and_server_registration_challenge_agree() {
    let challenge = pow::registration_challenge("alice", &[1u8; 32], &[2u8; 32]);

    assert_eq!(
        challenge.get(..8).expect("восемь байт"),
        [0x93, 0xaa, 0x00, 0xf3, 0xc9, 0xaf, 0xc6, 0xcf]
    );
}

/// SHA-256 пустого тела — у GET и DELETE, в том числе у сокета.
const EMPTY_BODY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// 🔐 Клиент и сервер собирают одно сообщение для подписи.
///
/// Клиент под Apache-2.0, сервер под AGPL-3.0, поэтому общего крейта
/// быть не может и код продублирован. Тест — единственное, что не даёт
/// копиям разойтись: расхождение проявилось бы как отказ **всех**
/// запросов с кодом 401 без объяснений (сервер намеренно не
/// подсказывает атакующему, что именно не так).
///
/// Вектор зафиксирован байтами, а не вызовом клиентского крейта:
/// линковка клиента в тесты сервера — ровно то смешение лицензий,
/// которого требуется избежать. Те же байты проверяются в
/// `gasapp-net/src/auth.rs`.
#[test]
fn client_and_server_sign_the_same_message() {
    let message = gasapp_server_api::authz::signed_message(
        "GET",
        "/v1/messages/abc",
        1_700_000_000_000,
        &EMPTY_BODY_SHA256,
    );

    assert_eq!(
        message,
        b"GASAPP_AUTH_v2\nGET\n/v1/messages/abc\n1700000000000\n\
          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_vec(),
        "клиент и сервер разошлись в формате подписи: все запросы будут отвергнуты"
    );
}

/// Путь сокета уведомлений подписывается так же, как остальные.
///
/// 🔐 Маршрут `/v1/ws/{device}` потребовал подписи после внутреннего
/// пентеста (раздел 23.6). Подпись там строит не сетевой слой ядра,
/// а платформа: рукопожатие WebSocket на Android собрано руками,
/// и путь в строку запроса она подставляет сама
/// (`NotificationSocket.handshake`).
///
/// Отсюда риск, которого нет у прочих маршрутов: путь в подписи и путь
/// в запросе строятся **в разных местах**. Разойдись они хоть одним
/// символом — сервер отвергнет рукопожатие, клиент уйдёт в бесконечный
/// цикл переподключений, и выглядеть это будет сетевой неполадкой,
/// а не ошибкой формата.
///
/// Вектор ниже фиксирует ровно ту строку, которую обязаны построить
/// обе стороны.
#[test]
fn websocket_path_signs_like_every_other_route() {
    let device = "0f8fad5b-d9cb-469f-a165-70867728950e";

    let message = gasapp_server_api::authz::signed_message(
        "GET",
        &format!("/v1/ws/{device}"),
        1_700_000_000_000,
        &EMPTY_BODY_SHA256,
    );

    let expected =
        b"GASAPP_AUTH_v2\nGET\n/v1/ws/0f8fad5b-d9cb-469f-a165-70867728950e\n1700000000000\n\
          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    assert_eq!(
        message,
        expected.to_vec(),
        "путь сокета в подписи разошёлся с тем, что ставит клиент"
    );
}
