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

use aegis_core::client::{Client, Contact};
use aegis_net::api::{
    BundleResponse, CertificateResponse, DiscoveryResponse, EnvelopeResponse, PublishKeysRequest,
    RegisterRequest, RegisterResponse, SealedAccessRequest, SealedSendRequest, SendRequest,
};
use aegis_net::client::{HttpRequest, HttpResponse, Method, Transport};
use aegis_protocol::sealed_sender::{self, SenderCertificate};
use aegis_protocol::xeddsa;
use aegis_storage::Storage;
use aegis_types::{AccountId, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
use sha2::{Digest, Sha256};

/// Приватный ключ подписи сертификатов у поддельного сервера.
const FAKE_SERVER_KEY: [u8; 32] = [0x77; 32];

/// Срок сертификата у поддельного сервера: 2100 год.
///
/// Тесты работают с фиксированным временем, и сертификату не нужно
/// истекать посреди прогона — истечение проверяется модульными тестами.
const FAR_FUTURE_MILLIS: i64 = 4_102_444_800_000;
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
    /// Загруженные вложения по адресу.
    ///
    /// Как и настоящий сервер, заглушка не знает ни получателя,
    /// ни имени файла — только байты.
    attachments: HashMap<String, Vec<u8>>,
    /// Хеши ключей доступа sealed sender по устройству.
    ///
    /// Как и настоящий сервер, заглушка хранит хеш, а не сам ключ.
    access_hashes: HashMap<String, Vec<u8>>,
    /// Сколько принято запечатанных конвертов.
    ///
    /// Тесты сверяют по нему, что переписка действительно пошла
    /// запечатанной, а не только что клиент утверждает это.
    sealed_accepted: usize,
    /// Сколько принято обычных конвертов.
    plain_accepted: usize,
    /// Сколько раз устройство публиковало предключи.
    publishes: HashMap<String, usize>,
    /// Путь и заголовки каждого пришедшего запроса.
    ///
    /// Нужны, чтобы проверять не только ответ, но и то, что клиент
    /// **отправил**: подпись под запросом видна только здесь —
    /// в ответе её нет, и её отсутствие выглядело бы как успех.
    requests: Vec<(String, Vec<(String, String)>)>,
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

    /// Возвращает копии всех загруженных блобов.
    ///
    /// Нужна проверке того, что сервер не видит содержимого: тест
    /// обязан смотреть ровно на то, что лежит у оператора.
    fn stored_attachments(&self) -> Vec<Vec<u8>> {
        self.state.borrow().attachments.values().cloned().collect()
    }

    /// Портит каждый хранимый блоб на один бит.
    ///
    /// Так ведёт себя недобросовестный оператор: файл у него, и
    /// изменить его он может.
    fn tamper_with_attachments(&self) {
        let mut state = self.state.borrow_mut();

        for blob in state.attachments.values_mut() {
            if let Some(byte) = blob.first_mut() {
                *byte ^= 0x01;
            }
        }
    }

    /// Сколько принято запечатанных конвертов.
    fn sealed_accepted(&self) -> usize {
        self.state.borrow().sealed_accepted
    }

    /// Сколько принято обычных конвертов.
    fn plain_accepted(&self) -> usize {
        self.state.borrow().plain_accepted
    }

    /// Конверты в очереди устройства — ровно то, что лежит у оператора.
    fn queued(&self, device_id: &str) -> Vec<Vec<u8>> {
        self.state
            .borrow()
            .queues
            .get(device_id)
            .map(|queue| {
                queue
                    .iter()
                    .filter_map(|envelope| hex::decode(&envelope.ciphertext).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Identity-ключ аккаунта в том виде, в каком его знает сервер.
    fn identity_of(&self, username: &str) -> Vec<u8> {
        self.state
            .borrow()
            .accounts
            .get(username)
            .and_then(|(_, key)| hex::decode(key).ok())
            .unwrap_or_default()
    }

    /// Портит хеш ключа доступа устройства.
    ///
    /// Так выглядит ключ, устаревший после переустановки приложения
    /// у получателя, — и так же выглядит сервер, отвергающий
    /// запечатанные конверты намеренно.
    fn revoke_access(&self, device_id: &str) {
        self.state
            .borrow_mut()
            .access_hashes
            .insert(device_id.to_owned(), vec![0u8; 32]);
    }

    /// Сколько одноразовых предключей лежит у устройства.
    ///
    /// Считается по опубликованному bundle — то есть по тому, что
    /// сервер реально отдаст спрашивающему.
    fn one_time_left(&self, device_id: &str) -> usize {
        self.state
            .borrow()
            .bundles
            .get(device_id)
            .map_or(0, |bundle| bundle.one_time.len())
    }

    /// Забирает одноразовый предключ, как это делает `take_bundle`.
    ///
    /// Заглушка хранит опубликованное целиком, поэтому расход
    /// изображается вычёркиванием.
    fn consume_one_time(&self, device_id: &str) {
        if let Some(bundle) = self.state.borrow_mut().bundles.get_mut(device_id) {
            if !bundle.one_time.is_empty() {
                bundle.one_time.remove(0);
            }

            if !bundle.one_time_kem.is_empty() {
                bundle.one_time_kem.remove(0);
            }
        }
    }

    /// Сколько конвертов лежит в очереди устройства.
    fn queue_len(&self, device_id: &str) -> usize {
        self.state
            .borrow()
            .queues
            .get(device_id)
            .map_or(0, Vec::len)
    }

    /// Сколько раз устройство публиковало предключи.
    ///
    /// Считается по записям публикации, а не по всем обращениям
    /// к `/v1/keys/`: обслуживание обязано спрашивать остаток
    /// и без надобности в публикации.
    fn publish_count(&self, device_id: &str) -> usize {
        self.state
            .borrow()
            .publishes
            .get(device_id)
            .copied()
            .unwrap_or(0)
    }

    /// Заголовки последнего запроса по префиксу пути.
    fn last_request(&self, prefix: &str) -> Option<Vec<(String, String)>> {
        self.state
            .borrow()
            .requests
            .iter()
            .rev()
            .find(|(path, _)| path.starts_with(prefix))
            .map(|(_, headers)| headers.clone())
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

        state
            .requests
            .push((request.path.clone(), request.headers.clone()));

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
                        let device_id = state.devices.get(account_id).cloned().unwrap_or_default();

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
            (Method::Get, path) if path.starts_with("/v1/keys/") && path.ends_with("/count") => {
                // Остаток одноразовых ключей — то, что сервер реально
                // отдаст спрашивающему. Именно по нему клиент решает,
                // надо ли пополнять: свой список у него не меняется,
                // когда ключ забирает чужой.
                let device_id = path
                    .trim_start_matches("/v1/keys/")
                    .trim_end_matches("/count");

                let left = state
                    .bundles
                    .get(device_id)
                    .map_or(0, |bundle| bundle.one_time.len());

                (200, left.to_string())
            }
            (Method::Put, path) if path.starts_with("/v1/keys/") => {
                let device_id = path.trim_start_matches("/v1/keys/").to_owned();
                let parsed: PublishKeysRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;

                *state.publishes.entry(device_id.clone()).or_insert(0) += 1;

                // Настоящий сервер дополняет пул (`ON CONFLICT DO
                // NOTHING`), а не заменяет его. Заглушка, заменявшая
                // целиком, показала бы пополнение работающим даже
                // тогда, когда оно затирает остаток.
                match state.bundles.get_mut(&device_id) {
                    Some(existing) => {
                        existing.signed_key_id = parsed.signed_key_id;
                        existing.signed_public = parsed.signed_public;
                        existing.signed_signature = parsed.signed_signature;
                        existing.kem_key_id = parsed.kem_key_id;
                        existing.kem_public = parsed.kem_public;
                        existing.kem_signature = parsed.kem_signature;
                        existing.one_time.extend(parsed.one_time);
                        existing.one_time_kem.extend(parsed.one_time_kem);
                    }
                    None => {
                        state.bundles.insert(device_id, parsed);
                    }
                }

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

                state.plain_accepted += 1;

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
            (Method::Put, path) if path.starts_with("/v1/sealed/access/") => {
                let device_id = path.trim_start_matches("/v1/sealed/access/").to_owned();
                let parsed: SealedAccessRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;

                let hash = hex::decode(&parsed.access_key_hash)
                    .map_err(|_| aegis_types::AegisError::Malformed)?;
                state.access_hashes.insert(device_id, hash);

                (200, String::new())
            }
            (Method::Get, path) if path.starts_with("/v1/sealed/certificate/") => {
                let device_id = path
                    .trim_start_matches("/v1/sealed/certificate/")
                    .to_owned();

                let account_id = state
                    .devices
                    .iter()
                    .find(|(_, device)| **device == device_id)
                    .map(|(account, _)| account.clone());
                let identity = state.device_identity.get(&device_id).cloned();

                match (account_id, identity) {
                    (Some(account_id), Some(identity)) => {
                        let account = uuid::Uuid::parse_str(&account_id).expect("uuid аккаунта");
                        let device = uuid::Uuid::parse_str(&device_id).expect("uuid устройства");
                        let identity: [u8; 32] = hex::decode(&identity)
                            .expect("hex ключа")
                            .try_into()
                            .expect("32 байта");
                        let identity_key = PublicKeyBytes::new(identity);

                        let payload = SenderCertificate::signed_payload(
                            account.as_bytes(),
                            device.as_bytes(),
                            &identity_key,
                            FAR_FUTURE_MILLIS,
                        );
                        let private = PrivateKeyBytes::new(FAKE_SERVER_KEY);
                        let signature =
                            xeddsa::montgomery::sign(&private, &payload).expect("подпись");
                        let server_key =
                            xeddsa::montgomery::public_key(&private).expect("ключ сервера");

                        let certificate = SenderCertificate {
                            account_id: *account.as_bytes(),
                            device_id: *device.as_bytes(),
                            identity_key,
                            expires_at_millis: FAR_FUTURE_MILLIS,
                            signature,
                        };

                        (
                            200,
                            serde_json::to_string(&CertificateResponse {
                                certificate: hex::encode(certificate.to_bytes()),
                                expires_at_millis: FAR_FUTURE_MILLIS,
                                server_key: hex::encode(server_key.as_bytes()),
                            })
                            .unwrap_or_default(),
                        )
                    }
                    _ => (404, String::new()),
                }
            }
            (Method::Post, "/v1/sealed/messages") => {
                let parsed: SealedSendRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;

                let presented = match &parsed.access_key {
                    None => None,
                    Some(encoded) => {
                        Some(hex::decode(encoded).map_err(|_| aegis_types::AegisError::Malformed)?)
                    }
                };

                // Как настоящий сервер: хеш предъявленного ключа сверяется
                // с опубликованным, отправитель при этом не называется.
                let allowed = match (
                    state.access_hashes.get(&parsed.destination_device_id),
                    presented,
                ) {
                    (Some(stored), Some(key)) => {
                        Sha256::digest(&key).as_slice() == stored.as_slice()
                    }
                    _ => false,
                };

                if allowed {
                    state.sealed_accepted += 1;

                    let envelope_id = Self::next_uuid(&mut state);
                    state
                        .queues
                        .entry(parsed.destination_device_id)
                        .or_default()
                        .push(EnvelopeResponse {
                            envelope_id: envelope_id.clone(),
                            ciphertext: parsed.sealed,
                            queued_at_bucketed: 0,
                        });

                    (200, serde_json::to_string(&envelope_id).unwrap_or_default())
                } else {
                    (401, String::new())
                }
            }
            (Method::Get, path) if path.starts_with("/v1/messages/") => {
                let device_id = path.trim_start_matches("/v1/messages/");
                let queue = state.queues.get(device_id).cloned().unwrap_or_default();

                (200, serde_json::to_string(&queue).unwrap_or_default())
            }
            (Method::Delete, path) if path.starts_with("/v1/accounts/") => {
                // 🔐 Удаление аккаунта. Заглушка ведёт себя как сервер:
                // без подписи — 401, и после удаления не остаётся ни
                // аккаунта, ни устройства, ни ключей, ни очереди.
                let device_id = path.trim_start_matches("/v1/accounts/").to_owned();

                let signed = request
                    .headers
                    .iter()
                    .any(|(name, _)| name == "x-aegis-signature");

                if !signed || !state.device_identity.contains_key(&device_id) {
                    (401, String::new())
                } else {
                    let envelopes = state
                        .queues
                        .remove(&device_id)
                        .map_or(0, |queue| queue.len());

                    state.device_identity.remove(&device_id);
                    state.bundles.remove(&device_id);
                    state.access_hashes.remove(&device_id);

                    let account = state
                        .devices
                        .iter()
                        .find(|(_, device)| *device == &device_id)
                        .map(|(account, _)| account.clone());

                    if let Some(account) = account {
                        state.devices.remove(&account);
                        state.accounts.retain(|_, (id, _)| id != &account);
                    }

                    (
                        200,
                        format!(r#"{{"devices":1,"envelopes":{envelopes},"attachments":0}}"#),
                    )
                }
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
            (Method::Post, path) if path.starts_with("/v1/attachments/") => {
                let payload = request.binary_body.clone().unwrap_or_default();

                if payload.is_empty() {
                    (400, String::new())
                } else {
                    let attachment_id = Self::next_uuid(&mut state);
                    state.attachments.insert(attachment_id.clone(), payload);

                    (
                        200,
                        serde_json::to_string(&attachment_id).unwrap_or_default(),
                    )
                }
            }
            (Method::Get, path) if path.starts_with("/v1/attachments/") => {
                // Последний сегмент — адрес вложения; перед ним стоит
                // устройство, которое подписало запрос.
                let attachment_id = path.rsplit('/').next().unwrap_or_default();

                match state.attachments.get(attachment_id) {
                    Some(payload) => {
                        return Ok(HttpResponse {
                            status: 200,
                            body: String::new(),
                            binary_body: payload.clone(),
                        })
                    }
                    None => (404, String::new()),
                }
            }
            _ => (404, String::new()),
        };

        Ok(HttpResponse {
            status,
            body,
            // Байты отдаёт только скачивание вложения, и оно
            // возвращается выше отдельной веткой.
            binary_body: Vec::new(),
        })
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

/// Алиса добавляет Боба по ссылке из его профиля.
#[test]
fn contact_is_added_from_profile_link() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    let link = bob.own_contact_link().expect("ссылка Боба");

    let contact = alice
        .add_contact_from_link(&link, now())
        .expect("контакт добавлен");

    assert_eq!(contact.username.as_deref(), Some("bob"));
    assert!(
        !contact.verified,
        "контакт не может быть верифицирован сразу"
    );

    let contacts = alice.contacts().expect("список контактов");

    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].identity, contact.identity);
}

/// 🔐 Ссылка с чужим именем не приклеивает имя к ключу.
///
/// Сделать ссылку с именем «bob» и собственным ключом может кто
/// угодно. Проверка через сервер не делает сервер доверенным: ключ
/// пришёл со ссылки, то есть из канала, которого сервер не видел, —
/// но чужое имя к нему приклеиться не должно.
#[test]
fn link_with_mismatched_name_is_rejected() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));
    let mallory = Client::new(server.clone(), open_storage(&dir, "mallory.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");
    mallory
        .register("mallory", now(), &mut OsRng)
        .expect("Мэллори зарегистрирована");

    // Мэллори берёт свою ссылку и подменяет в ней имя на «bob».
    let forged = mallory
        .own_contact_link()
        .expect("ссылка Мэллори")
        .replace("?name=mallory", "?name=bob");

    assert!(
        alice.add_contact_from_link(&forged, now()).is_err(),
        "ключ Мэллори добавлен под именем Боба"
    );

    assert!(
        alice.contacts().expect("список").is_empty(),
        "отклонённый контакт всё же попал в базу"
    );
}

/// Повторное добавление той же ссылки не задваивает контакт.
///
/// ⚠️ Тест назывался `key_change_via_link_is_rejected` и обещал
/// в комментарии, что смена ключа «не проходит молча». Проверял он
/// при этом другое: ту же самую ссылку, добавленную дважды. Смены
/// ключа в нём не было вовсе, и зелёным он был всегда.
///
/// Настоящая проверка — `a_new_key_for_a_known_name_is_flagged` ниже.
#[test]
fn re_adding_the_same_link_is_idempotent() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    let link = bob.own_contact_link().expect("ссылка Боба");

    alice
        .add_contact_from_link(&link, now())
        .expect("контакт добавлен");

    // Та же ссылка второй раз — это повтор, он безобиден.
    alice
        .add_contact_from_link(&link, now())
        .expect("повторное добавление");

    assert_eq!(
        alice.contacts().expect("список").len(),
        1,
        "повтор задвоил контакт"
    );
}

/// 🔐 Новый ключ под знакомым именем помечается как смена ключа.
///
/// # Почему по имени, а не по счёту
///
/// Счёт контакта выводится из первых шестнадцати байт его
/// identity-ключа. Поэтому сменившийся ключ тихо переписать прежнюю
/// запись **не может** — но и на неё не попадает: он заводит новую.
/// По счёту смена не видна никогда, и искать её там бесполезно.
///
/// Видна она по имени: «то же имя при другом ключе» — это и есть
/// смена ключа, как её наблюдает получатель.
///
/// # Что именно проверяется
///
/// Не отказ. Смена бывает законной — переустановка, восстановление
/// из копии, — и отказ означал бы, что после переустановки
/// с человеком нельзя связаться вовсе. Проверяется, что признак
/// выставлен: решать, тот ли это собеседник, человек будет сверкой
/// safety number, но узнать о смене он обязан.
#[test]
fn a_new_key_for_a_known_name_is_flagged() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    let first = alice
        .add_contact_from_link(&bob.own_contact_link().expect("ссылка Боба"), now())
        .expect("контакт добавлен");

    assert!(
        !first.key_changed,
        "первое добавление не может быть сменой ключа"
    );

    // Боб переустановил приложение: чистая база, то же имя,
    // другой identity-ключ. Сервер отдаёт по имени «bob» уже его.
    let bob_again = Client::new(server.clone(), open_storage(&dir, "bob-again.db"));

    bob_again
        .register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован заново");

    let second = alice
        .add_contact_from_link(
            &bob_again.own_contact_link().expect("новая ссылка Боба"),
            now(),
        )
        .expect("контакт добавлен");

    assert_ne!(
        second.identity, first.identity,
        "заготовка теста: ключ не сменился, проверять нечего"
    );

    assert!(
        second.key_changed,
        "новый ключ под знакомым именем не помечен как смена ключа"
    );

    // 🔐 Прежний контакт остаётся на месте: верификация старой записи
    // не может перенестись на новый ключ.
    let contacts = alice.contacts().expect("список контактов");

    assert_eq!(
        contacts.len(),
        2,
        "новый ключ должен заводить новую запись, а не переписывать прежнюю"
    );

    assert!(
        contacts.iter().all(|contact| contact.key_changed),
        "имя, известное под двумя ключами, не помечено в списке"
    );
}

/// Алиса и Боб, добавившие друг друга по ссылкам.
///
/// Возвращает клиентов и контакты, которыми каждый видит другого.
fn two_mutual_contacts(
    server: &FakeServer,
    dir: &tempfile::TempDir,
) -> (Client<FakeServer>, Client<FakeServer>, Contact, Contact) {
    let alice = Client::new(server.clone(), open_storage(dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(dir, "bob.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    let bob_seen_by_alice = alice
        .add_contact_from_link(&bob.own_contact_link().expect("ссылка Боба"), now())
        .expect("Алиса добавила Боба");
    let alice_seen_by_bob = bob
        .add_contact_from_link(&alice.own_contact_link().expect("ссылка Алисы"), now())
        .expect("Боб добавил Алису");

    (alice, bob, bob_seen_by_alice, alice_seen_by_bob)
}

/// 🔐 У собеседников safety number совпадает.
///
/// Это единственное свойство, ради которого safety number существует:
/// два человека сравнивают цифры, и совпадение означает, что ключи
/// между ними не подменены.
///
/// ⚠️ Экран сверки считал цифры по **двум случайным ключам** —
/// `generateIdentityPublicKey()` дважды на каждое открытие. Совпасть
/// у собеседников они не могли никогда.
#[test]
fn safety_numbers_match_on_both_sides() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let (alice, bob, bob_contact, alice_contact) = two_mutual_contacts(&server, &dir);

    let seen_by_alice = alice
        .safety_number(&bob_contact.account_id)
        .expect("safety number у Алисы");
    let seen_by_bob = bob
        .safety_number(&alice_contact.account_id)
        .expect("safety number у Боба");

    assert_eq!(
        seen_by_alice.chars().filter(char::is_ascii_digit).count(),
        60,
        "safety number не из 60 цифр (ADR-022)"
    );

    assert_eq!(
        seen_by_alice, seen_by_bob,
        "у собеседников разные safety number — сверка невозможна"
    );
}

/// 🔐 Safety number не меняется от показа к показу.
///
/// Прежний экран выдавал новые цифры при каждом открытии: сверить
/// их с собеседником было нельзя даже в принципе.
#[test]
fn a_safety_number_is_the_same_every_time() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let (alice, _bob, bob_contact, _) = two_mutual_contacts(&server, &dir);

    let first = alice
        .safety_number(&bob_contact.account_id)
        .expect("первый показ");
    let second = alice
        .safety_number(&bob_contact.account_id)
        .expect("второй показ");

    assert_eq!(first, second, "safety number меняется от показа к показу");
}

/// 🔐 Подменённый ключ даёт другие цифры.
///
/// Ровно то, что сверка должна обнаружить: сервер подсунул Алисе
/// вместо ключа Боба ключ Мэллори. Цифры Алисы и Боба обязаны
/// разойтись — иначе сверка ничего не проверяет.
#[test]
fn a_substituted_key_shows_a_different_safety_number() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let (alice, bob, _, alice_contact) = two_mutual_contacts(&server, &dir);

    // Мэллори регистрируется под именем Боба — так выглядит подмена
    // с точки зрения Алисы, которой сервер отдаёт по «bob» чужой ключ.
    let mallory = Client::new(server.clone(), open_storage(&dir, "mallory.db"));
    mallory
        .register("bob", now(), &mut OsRng)
        .expect("Мэллори заняла имя");

    let impostor = alice
        .add_contact_from_link(&mallory.own_contact_link().expect("ссылка Мэллори"), now())
        .expect("Алиса добавила подставной контакт");

    let alice_with_impostor = alice
        .safety_number(&impostor.account_id)
        .expect("цифры с подставным");
    let bob_with_alice = bob
        .safety_number(&alice_contact.account_id)
        .expect("цифры у настоящего Боба");

    assert_ne!(
        alice_with_impostor, bob_with_alice,
        "подменённый ключ дал те же цифры — сверка его не обнаружит"
    );
}

/// 🔐 Отметка о сверке ставится, снимается и доживает до списка.
///
/// Прежде кнопка «Отметить сверенным» закрывала экран, и только:
/// отметку в продукте не ставил никто.
#[test]
fn verification_is_recorded_and_can_be_revoked() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let (alice, _bob, bob_contact, _) = two_mutual_contacts(&server, &dir);

    let verified_in_list = |client: &Client<FakeServer>| {
        client
            .contacts()
            .expect("список")
            .into_iter()
            .find(|contact| contact.account_id == bob_contact.account_id)
            .expect("Боб в списке")
            .verified
    };

    assert!(!verified_in_list(&alice), "контакт сверен сам собой");

    alice
        .set_contact_verified(&bob_contact.account_id, true, now())
        .expect("отметка поставлена");

    assert!(verified_in_list(&alice), "отметка о сверке не сохранилась");

    alice
        .set_contact_verified(&bob_contact.account_id, false, now())
        .expect("отметка снята");

    assert!(!verified_in_list(&alice), "снятая отметка осталась");
}

/// Неизвестный контакт отметить нельзя.
///
/// Иначе в таблице сверенных завелась бы запись без ключа,
/// и сверка относилась бы неизвестно к чему.
#[test]
fn an_unknown_contact_cannot_be_verified() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");

    let stranger = AccountId::from_uuid(uuid::Uuid::from_bytes([9; 16]));

    assert!(
        alice.set_contact_verified(&stranger, true, now()).is_err(),
        "отмечен контакт, которого нет в книге"
    );
    assert!(
        alice.safety_number(&stranger).is_err(),
        "safety number посчитан для контакта, которого нет"
    );
}

/// 🔐 Первое сообщение, отправленное до ротации, расшифровывается после неё.
///
/// Алиса пишет, пока Боб не в сети. Боб открывает приложение через
/// восемь дней: сначала обслуживание предключей — оно ротирует
/// подписанный ключ, — затем приём. Это порядок Android.
///
/// Прежде ротация затирала ключ на месте, и такое сообщение терялось
/// навсегда вместе со всей перепиской, которая за ним шла. Тест
/// перенесён из аудита.
#[test]
fn first_message_sent_before_rotation_still_decrypts() {
    const DAY: i64 = 24 * 60 * 60 * 1000;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");
    let bob_device = bob_account.device_id.to_string();

    alice
        .send_message("bob", "пока тебя не было", now(), &mut OsRng)
        .expect("отправка");

    let later = Timestamp::from_millis(now().as_millis() + 8 * DAY);
    let maintenance = bob
        .maintain_prekeys(later, &mut OsRng)
        .expect("обслуживание");
    assert!(
        maintenance.rotated_signed,
        "заготовка теста: ротация не случилась"
    );

    assert_eq!(
        bob.receive_messages(&bob_device, later).expect("приём"),
        1,
        "первое сообщение, зашифрованное на прежний ключ, потеряно"
    );
}

/// Поиск находит отправленное сообщение.
#[test]
fn search_finds_sent_message() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    let bob_account = bob
        .register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    alice
        .send_message("bob", "встречаемся в среду", now(), &mut OsRng)
        .expect("сообщение отправлено");
    alice
        .send_message("bob", "и захвати документы", now(), &mut OsRng)
        .expect("сообщение отправлено");

    bob.receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём удался");

    let hits = alice.search("среду", 10).expect("поиск у отправителя");

    assert_eq!(hits.len(), 1, "поиск не нашёл своё сообщение");
    assert_eq!(hits[0].message.text, "встречаемся в среду");
    assert!(hits[0].message.outgoing, "своё сообщение помечено входящим");

    let received = bob.search("среду", 10).expect("поиск у получателя");

    assert_eq!(received.len(), 1, "поиск не нашёл принятое сообщение");
    assert!(
        !received[0].message.outgoing,
        "принятое сообщение помечено исходящим"
    );
}

/// Поиск возвращает чат, чтобы результат можно было открыть.
#[test]
fn search_hit_points_at_its_chat() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    alice
        .send_message("bob", "уникальное слово", now(), &mut OsRng)
        .expect("сообщение отправлено");

    let hits = alice.search("уникальное", 10).expect("поиск");
    let chats = alice.chats().expect("чаты");

    assert_eq!(hits.len(), 1);
    assert!(
        chats.contains(&hits[0].chat_id),
        "найденное сообщение указывает на несуществующий чат"
    );
}

/// Файл, отправленный вложением, доходит и совпадает побайтово.
#[test]
fn attachment_round_trips_through_the_server() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::{AttachmentDescriptor, AttachmentKind};

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

    // Файл заведомо крупнее одного чанка: склейка и обратная нарезка
    // на границе чанков — самое вероятное место ошибки.
    let original: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();

    alice
        .send_attachment(
            "bob",
            &alice_account.device_id.to_string(),
            &AttachmentFile {
                kind: AttachmentKind::Document,
                bytes: original.clone(),
                name: Some("отчёт.pdf".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            "вот документ",
            now(),
            &mut OsRng,
        )
        .expect("вложение отправлено");

    let received = bob
        .receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём удался");

    assert_eq!(received, 1, "Боб не получил сообщение с вложением");

    // Тот же файл загружается ещё раз, чтобы получить описание
    // на руки: разбор содержимого сообщения — задача интерфейса,
    // а проверяется сейчас доставка самого файла.
    let descriptor = alice
        .upload_attachment(
            &alice_account.device_id.to_string(),
            &AttachmentFile {
                kind: AttachmentKind::Document,
                bytes: original.clone(),
                name: Some("отчёт.pdf".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            now(),
            &mut OsRng,
        )
        .expect("описание построено");

    let downloaded = bob
        .fetch_attachment(&bob_account.device_id.to_string(), &descriptor, now())
        .expect("вложение скачано");

    assert_eq!(downloaded, original, "файл изменился при передаче");

    // Проверка, что описание вообще разбирается обратно.
    let encoded = descriptor.to_bytes().expect("сериализация");
    assert!(AttachmentDescriptor::from_bytes(&encoded).is_ok());
}

/// 🔐 Сервер не видит содержимого файла.
///
/// То же свойство, что и у сообщений, но для вложений: оператор
/// хранит блоб и не может его прочитать.
#[test]
fn server_never_sees_attachment_contents() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

    const CANARY: &[u8] = b"SECRET-FILE-CONTENTS-CANARY";

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    let mut payload = CANARY.to_vec();
    payload.extend_from_slice(&[0x00; 1024]);

    alice
        .send_attachment(
            "bob",
            &alice_account.device_id.to_string(),
            &AttachmentFile {
                kind: AttachmentKind::Document,
                bytes: payload,
                name: Some("секрет.txt".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            "",
            now(),
            &mut OsRng,
        )
        .expect("вложение отправлено");

    let stored = server.stored_attachments();

    assert!(!stored.is_empty(), "сервер не получил вложение");

    for blob in &stored {
        assert!(
            !blob.windows(CANARY.len()).any(|window| window == CANARY),
            "содержимое файла нашлось у сервера в открытом виде"
        );
    }

    // Имя файла тоже не должно попасть на сервер: оно уезжает внутри
    // сообщения, а не рядом с блобом.
    let name = "секрет.txt".as_bytes();

    for blob in &stored {
        assert!(
            !blob.windows(name.len()).any(|window| window == name),
            "имя файла нашлось у сервера в открытом виде"
        );
    }
}

/// 🔐 Подменённый блоб не расшифровывается.
///
/// Сервер хранит файл и может его подправить. Аутентифицированное
/// шифрование каждого чанка означает, что подмена будет замечена,
/// а не показана пользователю как содержимое.
#[test]
fn tampered_attachment_is_rejected() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    let alice_account = alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");

    let original = vec![0x5Au8; 4096];

    let descriptor = alice
        .upload_attachment(
            &alice_account.device_id.to_string(),
            &AttachmentFile {
                kind: AttachmentKind::Document,
                bytes: original,
                name: None,
                description: None,
                duration_millis: None,
                waveform: None,
            },
            now(),
            &mut OsRng,
        )
        .expect("описание построено");

    server.tamper_with_attachments();

    assert!(
        alice
            .fetch_attachment(&alice_account.device_id.to_string(), &descriptor, now())
            .is_err(),
        "подменённый блоб расшифровался"
    );
}

/// Получатель скачивает файл по описанию из пришедшего сообщения.
///
/// Главный путь вложения: до этого описания отбрасывались при приёме,
/// и файл, который сервер честно хранил, получателю был недоступен —
/// адрес и ключ существовали только внутри сообщения и никуда
/// не сохранялись.
#[test]
fn recipient_downloads_attachment_from_received_message() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

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

    let original: Vec<u8> = (0..150_000u32).map(|index| (index % 253) as u8).collect();

    alice
        .send_attachment(
            "bob",
            &alice_account.device_id.to_string(),
            &AttachmentFile {
                kind: AttachmentKind::Image,
                bytes: original.clone(),
                name: Some("снимок.png".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            "смотри",
            now(),
            &mut OsRng,
        )
        .expect("вложение отправлено");

    bob.receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём удался");

    // Боб находит сообщение и берёт описание из хранилища — так же,
    // как это сделает интерфейс.
    let chat = bob.chats().expect("чаты").into_iter().next().expect("чат");
    let message = bob
        .messages(&chat, 10)
        .expect("сообщения")
        .into_iter()
        .next()
        .expect("сообщение с вложением");

    assert_eq!(message.text, "смотри", "подпись к вложению потерялась");

    let descriptors = bob
        .attachments_of(&message.message_id)
        .expect("описания вложений");

    assert_eq!(descriptors.len(), 1, "описание вложения не сохранено");
    assert_eq!(descriptors[0].name.as_deref(), Some("снимок.png"));

    let downloaded = bob
        .fetch_attachment(&bob_account.device_id.to_string(), &descriptors[0], now())
        .expect("файл скачан");

    assert_eq!(downloaded, original, "файл изменился при передаче");
}

/// Отправитель видит собственное вложение в переписке.
///
/// Иначе отправленный файл исчезал бы из своего же чата: исходник
/// в приложении не хранится, а сообщение о нём не записывалось.
#[test]
fn sender_keeps_its_own_attachment() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован");

    let original = vec![0x7Eu8; 8192];

    alice
        .send_attachment(
            "bob",
            &alice_account.device_id.to_string(),
            &AttachmentFile {
                kind: AttachmentKind::Document,
                bytes: original.clone(),
                name: Some("договор.pdf".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            "подпиши",
            now(),
            &mut OsRng,
        )
        .expect("вложение отправлено");

    let chat = alice
        .chats()
        .expect("чаты")
        .into_iter()
        .next()
        .expect("чат");
    let message = alice
        .messages(&chat, 10)
        .expect("сообщения")
        .into_iter()
        .next()
        .expect("своё сообщение");

    assert!(message.outgoing, "своё сообщение помечено входящим");

    let descriptors = alice
        .attachments_of(&message.message_id)
        .expect("описания вложений");

    assert_eq!(descriptors.len(), 1, "своё описание не сохранено");

    let reopened = alice
        .fetch_attachment(&alice_account.device_id.to_string(), &descriptors[0], now())
        .expect("файл открыт заново");

    assert_eq!(reopened, original);
}

/// Проводит первый обмен: после него оба знают ключи доступа друг друга.
///
/// Возвращает клиентов и их устройства.
fn handshake(
    server: &FakeServer,
    dir: &tempfile::TempDir,
) -> (Client<FakeServer>, Client<FakeServer>, String, String) {
    let alice = Client::new(server.clone(), open_storage(dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(dir, "bob.db"));

    let alice_device = alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса зарегистрирована")
        .device_id
        .to_string();
    let bob_device = bob
        .register("bob", now(), &mut OsRng)
        .expect("Боб зарегистрирован")
        .device_id
        .to_string();

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("первое сообщение");
    bob.receive_messages(&bob_device, now())
        .expect("приём у Боба");

    bob.send_message("alice", "ответ", now(), &mut OsRng)
        .expect("ответ Боба");
    alice
        .receive_messages(&alice_device, now())
        .expect("приём у Алисы");

    (alice, bob, alice_device, bob_device)
}

/// 🔐 После первого обмена переписка идёт запечатанной.
///
/// Первое сообщение запечатать нечем — ключ доступа ещё не передан.
/// Тест это фиксирует явно, чтобы граница защиты была видна, а не
/// подразумевалась.
#[test]
fn conversation_becomes_sealed_after_first_exchange() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_device = alice
        .register("alice", now(), &mut OsRng)
        .expect("Алиса")
        .device_id
        .to_string();
    let bob_device = bob
        .register("bob", now(), &mut OsRng)
        .expect("Боб")
        .device_id
        .to_string();

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("отправка");

    assert_eq!(
        server.sealed_accepted(),
        0,
        "первое сообщение запечатано без ключа доступа получателя"
    );
    assert_eq!(
        bob.receive_messages(&bob_device, now()).expect("приём"),
        1,
        "служебный ключ доступа посчитан как сообщение"
    );

    // Боб отвечает: ключ доступа Алисы у него уже есть.
    bob.send_message("alice", "ответ", now(), &mut OsRng)
        .expect("ответ");

    assert!(server.sealed_accepted() >= 1, "ответ Боба не запечатан");
    assert_eq!(
        alice.receive_messages(&alice_device, now()).expect("приём"),
        1,
        "Алиса не получила запечатанный ответ"
    );

    // Дальше Алиса пишет только запечатанным.
    let plain_before = server.plain_accepted();
    let sealed_before = server.sealed_accepted();

    alice
        .send_message("bob", "снова", now(), &mut OsRng)
        .expect("отправка");

    assert_eq!(
        server.plain_accepted(),
        plain_before,
        "Алиса отправила незапечатанное, имея ключ доступа Боба"
    );
    assert!(server.sealed_accepted() > sealed_before);
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);

    assert!(alice.sealed_sender_enabled().expect("состояние"));
    assert!(bob.sealed_sender_enabled().expect("состояние"));
}

/// 🔐 Запечатанный конверт не несёт identity-ключа отправителя.
#[test]
fn sealed_envelope_hides_sender_identity_from_server() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _alice_device, bob_device) = handshake(&server, &dir);

    let alice_identity = server.identity_of("alice");
    assert_eq!(alice_identity.len(), 32, "ключ Алисы не найден на сервере");

    alice
        .send_message("bob", "секрет", now(), &mut OsRng)
        .expect("отправка");

    let queued = server.queued(&bob_device);
    assert!(!queued.is_empty(), "очередь Боба пуста");

    for envelope in queued {
        assert!(
            sealed_sender::is_sealed(&envelope),
            "в очереди лежит незапечатанный конверт"
        );
        assert!(
            !envelope
                .windows(alice_identity.len())
                .any(|window| window == alice_identity.as_slice()),
            "identity-ключ Алисы виден серверу"
        );
    }
}

/// 🔐 Отвергнутый ключ доступа не приводит к тихой отправке без запечатывания.
///
/// Иначе сервер узнавал бы отправителя, просто отвечая отказом
/// на каждый запечатанный конверт.
#[test]
fn rejected_access_key_does_not_fall_back_to_plain() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = handshake(&server, &dir);

    server.revoke_access(&bob_device);
    let plain_before = server.plain_accepted();

    let outcome = alice.send_message("bob", "не дойдёт", now(), &mut OsRng);

    assert!(
        outcome.is_err(),
        "отправка прошла с отвергнутым ключом доступа"
    );
    assert_eq!(
        server.plain_accepted(),
        plain_before,
        "клиент молча отправил незапечатанное"
    );

    let events = alice.security_events(20).expect("журнал");
    assert!(
        events
            .iter()
            .any(|(kind, _, _)| kind == "sealed_sender_access_rejected"),
        "отказ не записан в журнал безопасности"
    );

    // Устаревший ключ забыт: следующая попытка — видимая пользователю,
    // обычным путём. Сообщение доходит, пропуск ключа храповик переживает.
    alice
        .send_message("bob", "повтор", now(), &mut OsRng)
        .expect("повтор");

    assert_eq!(server.plain_accepted(), plain_before + 1);
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);
}

// ---------------------------------------------------------------------------
//  🔐 Удаление аккаунта (MASVS PRIVACY-3.2)
// ---------------------------------------------------------------------------

/// 🔐 Удаление уносит аккаунт и очередь, и сообщает, что именно унесло.
///
/// Числа проверяются наравне с самим удалением: «готово» без них
/// неотличимо от «готово» при запросе, который ничего не удалил,
/// а человеку после удаления проверить уже нечем — аккаунта,
/// которым можно было бы спросить, больше нет.
#[test]
fn account_deletion_removes_the_account_and_its_queue() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    // Недоставленный конверт в очереди Алисы.
    bob.send_message("alice", "ещё не прочитано", now(), &mut OsRng)
        .expect("сообщение отправлено");

    // Сколько лежит в очереди — спрашивается у сервера, а не берётся
    // из головы: одно отправленное сообщение не обязано быть одним
    // конвертом (рукопожатие добавляет свои), и зашитое «1» сделало бы
    // тест проверкой этой детали, а не удаления.
    let device = alice_account.device_id.to_string();
    let queued = server.queue_len(&device);

    assert!(
        queued > 0,
        "в очереди нечего удалять — тест ничего не проверит"
    );

    let report = alice.delete_account(now()).expect("аккаунт удалён");

    assert_eq!(report.devices, 1);
    // Сравнение в u64, а не приведение к usize: на 32-битной цели
    // приведение обрезало бы число, и тест начал бы врать именно там,
    // где его некому перепроверить.
    assert_eq!(
        report.envelopes, queued as u64,
        "удалено не то число конвертов, что лежало в очереди"
    );
    assert_eq!(server.queue_len(&device), 0, "очередь пережила удаление");

    // Аккаунта нет: Боб больше не находит Алису по имени.
    let lookup = bob.add_contact_from_link(
        &format!("aegis://contact?u=alice&k={}", "A".repeat(52)),
        now(),
    );

    assert!(lookup.is_err(), "удалённый аккаунт всё ещё находится");
}

/// 🔐 Запрос удаления подписан.
///
/// Заглушка отвечает `401` на неподписанный `DELETE`, как настоящий
/// сервер. Тест на то, что подпись **ставится**, а не на то, что
/// сервер её требует, — требование проверено на стороне сервера.
#[test]
fn account_deletion_is_signed() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    alice.register("alice", now(), &mut OsRng).expect("Алиса");

    alice.delete_account(now()).expect("аккаунт удалён");

    let request = server
        .last_request("/v1/accounts/")
        .expect("запроса на удаление не было");

    assert!(
        request.iter().any(|(name, _)| name == "x-aegis-signature"),
        "запрос ушёл без подписи"
    );
    assert!(
        request.iter().any(|(name, _)| name == "x-aegis-issued-at"),
        "запрос ушёл без времени выпуска"
    );
}

/// Без регистрации удалять нечего.
///
/// 🔐 Важно, что это отказ, а не молчаливый успех: экран, показавший
/// «аккаунт удалён» там, где на сервере ничего не было, научил бы
/// доверять этому сообщению и в тех случаях, когда удаление не прошло.
#[test]
fn deleting_without_an_account_fails() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let client = Client::new(server.clone(), open_storage(&dir, "empty.db"));

    let outcome = client.delete_account(now());

    // Именно «сеанса нет», а не любая ошибка: сетевой сбой здесь
    // выглядел бы так же, и тест прошёл бы, проверив не то.
    assert!(
        matches!(outcome, Err(aegis_types::AegisError::SessionNotFound)),
        "ожидался отказ «сеанса нет», получено {:?}",
        outcome.err()
    );

    // И до сервера запрос не дошёл.
    //
    // ⚠️ Без этой проверки тест прошёл бы и в случае, когда запрос
    // всё-таки уходит: заглушка отвечает `401` на неизвестное
    // устройство, то есть отказ выглядел бы тем же самым.
    //
    // ⚠️ Какая именно из двух проверок в ядре сработала, тест
    // не различает, и различать не берётся: отсутствие устройства
    // и отсутствие ключа дают один и тот же `SessionNotFound`,
    // и мутация любой из них по отдельности оставляет тест зелёным
    // (проверено). Закрепляется поведение — отказ и молчание в сеть.
    assert!(
        server.last_request("/v1/accounts/").is_none(),
        "ядро отправило запрос на удаление, не зная, что удалять"
    );
}

/// 🔐 Повторное удаление не выдаёт себя за успешное.
#[test]
fn deleting_twice_fails_the_second_time() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server, open_storage(&dir, "alice.db"));
    alice.register("alice", now(), &mut OsRng).expect("Алиса");

    alice.delete_account(now()).expect("первое удаление");

    assert!(
        alice.delete_account(now()).is_err(),
        "второе удаление объявлено успешным"
    );
}

// ---------------------------------------------------------------------------
//  🔐 Выгрузка данных (MASVS PRIVACY-3.1)
//
//  Право забрать свои данные проверяется двумя вопросами: попало ли
//  в файл то, что должно, и — важнее — не попало ли то, чего не должно.
//  Второй вопрос здесь главный: выгрузка не зашифрована по замыслу,
//  и приватный ключ в ней отменил бы всю защиту переписки разом.
// ---------------------------------------------------------------------------

/// Выгрузка содержит переписку, контакты и имя аккаунта.
#[test]
fn export_contains_the_conversation() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    alice
        .send_message("bob", "встречаемся в семь", now(), &mut OsRng)
        .expect("сообщение отправлено");

    let export = alice.export_data(now()).expect("выгрузка");

    assert!(export.contains("aegis-export-v1"), "нет версии формата");
    assert!(export.contains("alice"), "нет имени аккаунта");
    assert!(
        export.contains("встречаемся в семь"),
        "в выгрузке нет отправленного сообщения",
    );
}

/// 🔐 В выгрузке нет ни одного приватного ключа.
///
/// Самая дорогая ошибка, какая здесь возможна. Файл не зашифрован
/// и создаётся для того, чтобы его унесли с устройства: ключ в нём
/// означал бы, что всю защиту переписки обходит один этот файл,
/// лежащий в загрузках.
///
/// Проверяется не отсутствие слова «ключ», а отсутствие **самих
/// байтов**: приватный identity-ключ берётся из хранилища и ищется
/// в выгрузке в hex. Слово можно переименовать, байты — нет.
#[test]
fn export_never_contains_private_keys() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let storage = open_storage(&dir, "alice.db");
    let alice = Client::new(server, storage);

    alice.register("alice", now(), &mut OsRng).expect("Алиса");

    let export = alice.export_data(now()).expect("выгрузка");

    // Приватные части берутся прямо из хранилища — то есть то же
    // самое, что утекло бы, окажись оно в файле.
    let keys = open_storage(&dir, "alice.db")
        .load_own_keys()
        .expect("чтение ключей")
        .expect("аккаунт заведён");

    let secrets: Vec<(&str, &[u8])> = vec![
        ("приватный identity-ключ", keys.identity_private.as_slice()),
        ("секреты предключей", keys.prekey_secrets.as_slice()),
    ];

    for (name, bytes) in secrets {
        assert!(!bytes.is_empty(), "{name} пуст — тест ничего не проверит");

        let as_hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert!(
            !export.contains(&as_hex),
            "🔐 {name} попал в выгрузку — файл отменяет защиту переписки",
        );
    }
}

/// Выгрузка — разбираемый JSON, а не строка, похожая на него.
///
/// «Право забрать данные» в файле, который не читается ничем, правом
/// не является. Проверяется разбором, а не глазами.
#[test]
fn export_is_valid_json_with_the_promised_shape() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server, open_storage(&dir, "alice.db"));
    alice.register("alice", now(), &mut OsRng).expect("Алиса");

    let export = alice.export_data(now()).expect("выгрузка");
    let parsed: serde_json::Value = serde_json::from_str(&export).expect("выгрузка не разбирается");

    assert_eq!(parsed["format"], "aegis-export-v1");
    assert!(
        parsed["account"]["username"].is_string(),
        "нет имени аккаунта"
    );
    assert!(parsed["contacts"].is_array(), "контакты не массив");
    assert!(parsed["chats"].is_array(), "чаты не массив");
    assert!(parsed["settings"].is_object(), "настройки не объект");

    // Файл сам говорит, чего в нём нет: он переживёт тот экран,
    // на котором его сделали.
    assert!(
        parsed["not_included"].is_array(),
        "файл не называет, чего в нём нет",
    );
}

/// Имя с кавычкой не ломает файл.
///
/// ⚠️ Самая вероятная поломка выгрузки, собранной конкатенацией строк.
/// Заметил бы её не автор, а тот, кто пытается прочитать собственные
/// данные и получает файл, который не разбирается ничем.
#[test]
fn export_survives_quotes_in_message_text() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    let nasty = r#"он сказал "да", а потом \ушёл"#;

    alice
        .send_message("bob", nasty, now(), &mut OsRng)
        .expect("сообщение отправлено");

    let export = alice.export_data(now()).expect("выгрузка");
    let parsed: serde_json::Value =
        serde_json::from_str(&export).expect("кавычка в тексте сломала выгрузку");

    let text = parsed["chats"][0]["messages"][0]["text"]
        .as_str()
        .expect("текста нет");

    assert_eq!(text, nasty, "текст изменился при выгрузке");
}

/// Без аккаунта выгружать нечего.
#[test]
fn exporting_without_an_account_fails() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let client = Client::new(server, open_storage(&dir, "empty.db"));

    assert!(
        matches!(
            client.export_data(now()),
            Err(aegis_types::AegisError::SessionNotFound)
        ),
        "выгрузка несуществующего аккаунта объявлена успешной",
    );
}

// ---------------------------------------------------------------------------
//  🔐 Обслуживание предключей
//
//  Одноразовый предключ расходуется при каждом первом контакте.
//  Пул публикуется при регистрации и конечен: без пополнения он
//  кончается навсегда, и каждая новая переписка заводится без
//  одноразового ключа — тихо, с успешным ответом сервера.
// ---------------------------------------------------------------------------

/// 🔐 Исчерпанный пул пополняется.
///
/// Главный тест этой пары. До его появления `refill_one_time`
/// существовала, была покрыта тестами в `aegis-protocol` — и
/// не вызывалась из продукта ни разу.
#[test]
fn an_exhausted_one_time_pool_is_refilled() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let account = alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let device = account.device_id.to_string();

    let published = server.one_time_left(&device);

    assert!(
        published > 0,
        "при регистрации не опубликовано ни одного одноразового ключа",
    );

    // Кто угодно вычерпывает пул: `take_bundle` подписи не требует.
    for _ in 0..published {
        server.consume_one_time(&device);
    }

    assert_eq!(server.one_time_left(&device), 0, "пул не опустошён");

    let report = alice
        .maintain_prekeys(now(), &mut OsRng)
        .expect("обслуживание");

    assert!(report.added_one_time > 0, "пул не пополнен");
    assert!(
        server.one_time_left(&device) > 0,
        "сервер по-прежнему отдаёт пустой пул",
    );
}

/// Полный пул не публикуется заново.
///
/// Обслуживание вызывается после каждого приёма сообщений. Спросить
/// остаток у сервера оно обязано всегда — иначе вычерпанный чужими
/// пул так и выглядел бы полным, — но **публиковать** при полном
/// пуле нечего, и лишний `PUT` был бы собственным источником
/// нагрузки.
#[test]
fn a_full_pool_is_not_republished() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let account = alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let device = account.device_id.to_string();

    // ⚠️ После регистрации пул на сервере НЕ полон: `generate`
    // публикует `one_time.first()` — один ключ из ста. Поэтому
    // сперва обслуживание доводит пул до полного, и только второй
    // вызов проверяет, что лишнего он не делает.
    let first = alice
        .maintain_prekeys(now(), &mut OsRng)
        .expect("первое обслуживание");

    assert!(
        first.added_one_time > 0,
        "после регистрации пул на сервере уже полон — проверять нечего",
    );

    let publishes_before = server.publish_count(&device);

    let report = alice
        .maintain_prekeys(now(), &mut OsRng)
        .expect("обслуживание");

    assert_eq!(report.added_one_time, 0, "полный пул пополнять не нужно");
    assert!(!report.rotated_signed, "свежий ключ ротировать не нужно");
    assert_eq!(
        server.publish_count(&device),
        publishes_before,
        "полный пул опубликован заново без надобности",
    );
}

/// 🔐 Подписанный предключ ротируется по сроку.
///
/// Срок ограничивает, сколько будущих рукопожатий раскроет
/// компрометация ключа. Ключ, не меняющийся никогда, делает это
/// окно бесконечным.
#[test]
fn the_signed_prekey_rotates_when_it_is_old() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    alice.register("alice", now(), &mut OsRng).expect("Алиса");

    let later = aegis_types::Timestamp::from_millis(
        now().as_millis()
            + i64::from(aegis_protocol::SIGNED_PRE_KEY_ROTATION_DAYS) * 24 * 60 * 60 * 1000
            + 1,
    );

    let report = alice
        .maintain_prekeys(later, &mut OsRng)
        .expect("обслуживание");

    assert!(report.rotated_signed, "подписанный предключ не ротирован");
}

/// Без аккаунта обслуживать нечего.
#[test]
fn maintenance_without_an_account_fails() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let client = Client::new(server, open_storage(&dir, "empty.db"));

    assert!(
        matches!(
            client.maintain_prekeys(now(), &mut OsRng),
            Err(aegis_types::AegisError::SessionNotFound)
        ),
        "обслуживание без аккаунта объявлено успешным",
    );
}

/// 🔐 Длина сообщения не видна по размеру конверта.
///
/// Раздел 15.3: наблюдатель, видящий трафик, не должен отличать
/// «ок» от абзаца. Содержимое дополняется до размера из списка
/// корзин, и два сообщения, попадающие в одну корзину, обязаны дать
/// конверт одного размера.
///
/// # Почему это проверяется здесь, а не в `aegis-protocol`
///
/// Там проверено, что `pad` выдаёт размер из корзины. Условие
/// необходимое, но не достаточное: паддинг может быть посчитан
/// и не применён на пути отправки. Ровно так в этом проекте
/// обстояло дело с пополнением предключей — функция была, вызова
/// не было. Здесь проверяется путь целиком: от `send_message`
/// до байтов, которые лежат у оператора сервера.
///
/// # ⚠️ Две ловушки, в которые первая редакция этого теста попала
///
/// **Первая: не тот конверт.** Первое сообщение собеседнику создаёт
/// два конверта — установление сессии и собственно сообщение.
/// Первый (2220 байт) заполнен шифротекстом ML-KEM и от длины
/// текста не зависит вовсе. Сравнивая его, тест проходил и тогда,
/// когда паддинг снят совсем.
///
/// **Вторая: разные корзины.** Тексты в 4 и 600 байт дают 574 и 1086
/// байт — и это **правильная** работа паддинга: 600 в корзину 512
/// не помещается. Сравнивать надо тексты из одной корзины, иначе
/// тест требует невозможного.
#[test]
fn message_length_is_hidden_by_padding() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));
    let carol = Client::new(server.clone(), open_storage(&dir, "carol.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");
    let carol_account = carol.register("carol", now(), &mut OsRng).expect("Кэрол");

    // Оба текста помещаются в наименьшую корзину (512 байт),
    // различаясь при этом в сто раз.
    alice
        .send_message("bob", "ок", now(), &mut OsRng)
        .expect("короткое отправлено");

    let long = "a".repeat(400);
    alice
        .send_message("carol", &long, now(), &mut OsRng)
        .expect("длинное отправлено");

    // Последний конверт — само сообщение; первый устанавливает сессию.
    let short_len = *server
        .queued(&bob_account.device_id.to_string())
        .last()
        .map(Vec::len)
        .as_ref()
        .expect("конверт Боба");

    let long_len = *server
        .queued(&carol_account.device_id.to_string())
        .last()
        .map(Vec::len)
        .as_ref()
        .expect("конверт Кэрол");

    assert_eq!(
        short_len, long_len,
        "по размеру конверта видно длину сообщения: {short_len} против {long_len}",
    );
}
