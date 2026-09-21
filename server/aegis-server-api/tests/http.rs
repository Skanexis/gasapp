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
use tower::ServiceExt as _;
use uuid::Uuid;

mod common;

use common::{public_key, signed_request, DeviceKey};

macro_rules! require_state {
    () => {
        match common::state().await {
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
        .find(|nonce| pow::verify(challenge, *nonce, common::TEST_DIFFICULTY).is_ok())
        .expect("решение находится")
}

/// Регистрирует аккаунт, возвращая идентификаторы.
async fn register(state: &Arc<AppState>, username: &str) -> (Uuid, Uuid) {
    let challenge = pow::registration_challenge(username, &[1u8; 32], &[2u8; 32]);
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

    let (status, _) = call(
        &state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode([1u8; 32]),
            "device_identity_key": hex::encode([2u8; 32]),
            "pow_challenge": hex::encode(challenge),
            // Заведомо неверное решение.
            "pow_nonce": u64::MAX,
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
    let challenge = pow::registration_challenge(&first, &[1u8; 32], &[2u8; 32]);
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
                "identity_key": hex::encode([1u8; 32]),
                "device_identity_key": hex::encode([2u8; 32]),
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

    let challenge = pow::registration_challenge(&username, &[9u8; 32], &[9u8; 32]);
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
    let (device_id, private) = register_signing_device(&state, &unique_name("dave"), 0x23).await;

    // Отправка анонимна по замыслу: подпись отправителя и была бы той
    // меткой, которую убирает sealed sender.
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
    let Some(state) = common::state().await else {
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

    let challenge = pow::registration_challenge(username, &[1u8; 32], &public_key(&private));
    let nonce = solve(&challenge);

    let (status, body) = call(
        state,
        "POST",
        "/v1/accounts/register",
        Some(serde_json::json!({
            "username": username,
            "identity_key": hex::encode([1u8; 32]),
            "device_identity_key": hex::encode(public_key(&private)),
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

/// Выполняет подписанный запрос с сырым телом.
async fn call_signed(
    state: &Arc<AppState>,
    private: &DeviceKey,
    method: &str,
    uri: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let router = aegis_server_api::router(Arc::clone(state));
    let request = signed_request(private, method, uri, "application/octet-stream", body);

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

    let router = aegis_server_api::router(Arc::clone(state));
    let request = signed_request(private, method, uri, "application/json", raw);

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();

    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

    (status, value)
}

/// Вложение загружается и скачивается без изменений.
#[tokio::test]
async fn attachment_round_trips() {
    let state = require_state!();
    let (device_id, private) =
        register_signing_device(&state, &unique_name("uploader"), 0x11).await;

    let payload = vec![0xABu8; 4096];

    let (status, body) = call_signed(
        &state,
        &private,
        "POST",
        &format!("/v1/attachments/{device_id}"),
        payload.clone(),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "загрузка не прошла");

    let attachment_id: Uuid = serde_json::from_slice::<Uuid>(&body).expect("адрес вложения");

    let (status, downloaded) = call_signed(
        &state,
        &private,
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
    let (device_id, private) = register_signing_device(&state, &unique_name("anon"), 0x12).await;

    let (status, body) = call_signed(
        &state,
        &private,
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
    let (_, private) = register_signing_device(&state, &unique_name("mallory"), 0x13).await;
    let victim = Uuid::new_v4();

    let (status, _) = call_signed(
        &state,
        &private,
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
    let (device_id, private) = register_signing_device(&state, &unique_name("empty"), 0x14).await;

    let (status, _) = call_signed(
        &state,
        &private,
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
    let (device_id, private) = register_signing_device(&state, &unique_name("seeker"), 0x15).await;

    let (status, _) = call_signed(
        &state,
        &private,
        "GET",
        &format!("/v1/attachments/{device_id}/{}", Uuid::new_v4()),
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
    let (status, _) = call(
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

    // Вложение, загруженное этим устройством.
    let (status, _) = call_signed(
        &state,
        &private,
        "POST",
        &format!("/v1/attachments/{device_id}"),
        vec![0x55u8; 128],
    )
    .await;

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
        Some(1),
        "вложение не удалено"
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
    let router = aegis_server_api::router(Arc::clone(&state));
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
