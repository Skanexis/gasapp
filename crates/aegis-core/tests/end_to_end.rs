// SPDX-License-Identifier: Apache-2.0

//! Сквозной тест: два клиента обмениваются сообщениями.
//!
//! # Что здесь проверяется
//!
//! Полный путь, который проходит сообщение в бою: регистрация обоих
//! участников, публикация предключей, установление сессии, отправка,
//! доставка и расшифровка. Модульные тесты проверяют каждое звено
//! отдельно; здесь проверяется, что они соединены правильно.
//!
//! # Почему сервер поддельный
//!
//! Настоящий сервер требует Postgres и живёт в отдельном workspace под
//! AGPL — связать его с клиентскими тестами нельзя по лицензии.
//! Заглушка воспроизводит то, что важно для клиента: раздачу bundle,
//! очередь конвертов и адресацию по устройствам. Всё остальное
//! проверяется тестами самого сервера.

// Линты, ослабленные для этого файла.
//
// `expect` в тестах — это и есть проверка: падение с внятным текстом
// лучше, чем молчаливое поглощение ошибки. Ограничение на длину
// функции снято для обработчика поддельного сервера: он читается
// как таблица маршрутов, и дробление на части сделало бы её менее
// понятной, а не более.
#![allow(
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::collections::HashMap;

use aegis_core::client::Client;
use aegis_net::api::{
    BundleResponse, DiscoveryResponse, EnvelopeResponse, PublishKeysRequest, RegisterRequest,
    RegisterResponse, SendRequest,
};
use aegis_net::client::{HttpRequest, HttpResponse, Method, Transport};
use aegis_storage::Storage;
use aegis_types::{Result, Timestamp};
use rand_core::OsRng;

/// Состояние поддельного сервера.
#[derive(Default)]
struct ServerState {
    /// Аккаунты по имени: идентификатор аккаунта и identity-ключ.
    accounts: HashMap<String, (String, String)>,
    /// Устройство аккаунта.
    devices: HashMap<String, String>,
    /// Опубликованные предключи по устройству.
    bundles: HashMap<String, PublishKeysRequest>,
    /// Identity-ключ устройства.
    device_identity: HashMap<String, String>,
    /// Очереди конвертов по устройству.
    queues: HashMap<String, Vec<EnvelopeResponse>>,
    /// Счётчик для генерации идентификаторов.
    counter: u128,
}

/// Поддельный сервер, разделяемый между клиентами.
#[derive(Clone)]
struct FakeServer {
    state: std::rc::Rc<RefCell<ServerState>>,
}

impl FakeServer {
    fn new() -> Self {
        Self {
            state: std::rc::Rc::new(RefCell::new(ServerState::default())),
        }
    }

    fn next_uuid(state: &mut ServerState) -> String {
        state.counter += 1;

        uuid::Uuid::from_u128(state.counter).to_string()
    }
}

impl Transport for FakeServer {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut state = self.state.borrow_mut();
        let path = request.path.as_str();

        let (status, body) = match (&request.method, path) {
            (Method::Post, "/v1/accounts/register") => {
                let parsed: RegisterRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;

                let account_id = Self::next_uuid(&mut state);
                let device_id = Self::next_uuid(&mut state);

                state.accounts.insert(
                    parsed.username.clone(),
                    (account_id.clone(), parsed.identity_key.clone()),
                );
                state.devices.insert(account_id.clone(), device_id.clone());
                state
                    .device_identity
                    .insert(device_id.clone(), parsed.device_identity_key);

                (
                    200,
                    serde_json::to_string(&RegisterResponse {
                        account_id,
                        device_id,
                    })
                    .unwrap_or_default(),
                )
            }
            (Method::Get, path) if path.starts_with("/v1/discovery/username/") => {
                let username = path.trim_start_matches("/v1/discovery/username/");

                match state.accounts.get(username) {
                    Some((account_id, identity_key)) => {
                        let device_id =
                            state.devices.get(account_id).cloned().unwrap_or_default();

                        (
                            200,
                            serde_json::to_string(&DiscoveryResponse {
                                account_id: account_id.clone(),
                                identity_key: identity_key.clone(),
                                device_ids: vec![device_id],
                            })
                            .unwrap_or_default(),
                        )
                    }
                    None => (404, String::new()),
                }
            }
            (Method::Put, path) if path.starts_with("/v1/keys/") => {
                let device_id = path.trim_start_matches("/v1/keys/").to_owned();
                let parsed: PublishKeysRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;

                state.bundles.insert(device_id, parsed);

                (200, String::new())
            }
            (Method::Get, path) if path.ends_with("/bundle") => {
                // Адресация по устройству, как на настоящем сервере.
                let device_id = path
                    .trim_start_matches("/v1/keys/")
                    .trim_end_matches("/bundle")
                    .to_owned();

                let identity = state
                    .device_identity
                    .get(&device_id)
                    .cloned()
                    .unwrap_or_default();

                match state.bundles.get(&device_id) {
                    Some(keys) => (
                        200,
                        serde_json::to_string(&BundleResponse {
                            device_id,
                            identity_key: identity,
                            signed_key_id: keys.signed_key_id,
                            signed_public: keys.signed_public.clone(),
                            signed_signature: keys.signed_signature.clone(),
                            kem_key_id: keys.kem_key_id,
                            kem_public: keys.kem_public.clone(),
                            kem_signature: keys.kem_signature.clone(),
                            one_time: keys.one_time.first().cloned(),
                            one_time_kem: keys.one_time_kem.first().cloned(),
                            degraded: false,
                        })
                        .unwrap_or_default(),
                    ),
                    None => (404, String::new()),
                }
            }
            (Method::Post, "/v1/messages") => {
                let parsed: SendRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;

                let envelope_id = Self::next_uuid(&mut state);
                state
                    .queues
                    .entry(parsed.destination_device_id)
                    .or_default()
                    .push(EnvelopeResponse {
                        envelope_id: envelope_id.clone(),
                        ciphertext: parsed.ciphertext,
                        queued_at_bucketed: 0,
                    });

                // Клиент ждёт JSON-строку: send_envelope разбирает ответ
                // как идентификатор конверта.
                (200, serde_json::to_string(&envelope_id).unwrap_or_default())
            }
            (Method::Get, path) if path.starts_with("/v1/messages/") => {
                let device_id = path.trim_start_matches("/v1/messages/");
                let queue = state.queues.get(device_id).cloned().unwrap_or_default();

                (200, serde_json::to_string(&queue).unwrap_or_default())
            }
            (Method::Delete, path) if path.starts_with("/v1/messages/") => {
                // Подтверждение доставки: сервер удаляет конверт.
                let remainder = path.trim_start_matches("/v1/messages/");
                if let Some((device_id, envelope_id)) = remainder.split_once('/') {
                    if let Some(queue) = state.queues.get_mut(device_id) {
                        queue.retain(|envelope| envelope.envelope_id != envelope_id);
                    }
                }

                (200, String::new())
            }
            _ => (404, String::new()),
        };

        Ok(HttpResponse { status, body })
    }
}

/// Открывает временное хранилище.
fn open_storage(dir: &tempfile::TempDir, name: &str) -> Storage {
    let path = dir.path().join(name).to_string_lossy().into_owned();

    Storage::new(&path, &[0x5A; 32]).expect("хранилище открывается")
}

fn now() -> Timestamp {
    Timestamp::from_millis(1_760_000_000_000)
}

/// 🔐 Полный цикл: Алиса регистрируется, пишет Бобу, Боб читает.
#[test]
fn two_clients_exchange_a_message() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    let bob_account = bob
        .register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    assert_ne!(alice_account.account_id, bob_account.account_id);

    alice
        .send_message("bob", "attack at dawn", now(), &mut OsRng)
        .expect("сообщение отправлено");

    let received = bob
        .receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём удался");

    assert_eq!(received, 1, "Боб не получил сообщение");
}

/// 🔐 Сервер видит только шифротекст.
///
/// Главное свойство мессенджера: оператор сервера не может прочитать
/// переписку. Проверяется поиском открытого текста во всём, что
/// прошло через сервер.
#[test]
fn server_never_sees_plaintext() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    let secret = "ATTACK-AT-DAWN-CANARY";
    alice
        .send_message("bob", secret, now(), &mut OsRng)
        .expect("отправка");

    let state = server.state.borrow();
    for queue in state.queues.values() {
        for envelope in queue {
            assert!(
                !envelope.ciphertext.contains(secret),
                "открытый текст найден в очереди сервера"
            );

            // Hex тоже проверяется: текст мог уехать закодированным.
            let hex: String = secret.bytes().map(|byte| format!("{byte:02x}")).collect();
            assert!(
                !envelope.ciphertext.contains(&hex),
                "открытый текст найден в очереди сервера в hex"
            );
        }
    }
}

/// Переписка продолжается в обе стороны.
#[test]
fn conversation_flows_both_ways() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("отправка");
    assert_eq!(
        bob.receive_messages(&bob_account.device_id.to_string(), now())
            .expect("приём"),
        1
    );

    // Боб отвечает: это задействует приёмную цепочку храповика,
    // которую односторонняя проверка не затрагивает.
    bob.send_message("alice", "ответ", now(), &mut OsRng)
        .expect("ответ отправлен");
    assert_eq!(
        alice
            .receive_messages(&alice_account.device_id.to_string(), now())
            .expect("приём"),
        1,
        "Алиса не получила ответ"
    );
}

/// Сообщения сохраняются и читаются из хранилища.
#[test]
fn messages_are_persisted() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");

    alice
        .send_message("bob", "сохранённое", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём");

    let chats = bob.chats().expect("список чатов");
    assert_eq!(chats.len(), 1, "чат не появился у получателя");

    let messages = bob.messages(&chats[0], 10).expect("сообщения");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text, "сохранённое");
    assert!(!messages[0].outgoing, "входящее помечено как исходящее");
}
