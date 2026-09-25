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

use aegis_core::client::{ChatRequest, Client, Contact};
use aegis_net::api::{
    BundleResponse, CertificateResponse, DiscoveryResponse, EnvelopeResponse, PublishKeysRequest,
    RegisterRequest, RegisterResponse, SealedAccessRequest, SealedSendRequest,
};
use aegis_net::client::{HttpRequest, HttpResponse, Method, Transport};
use aegis_protocol::key_transparency as kt;
use aegis_protocol::sealed_sender::{self, SenderCertificate};
use aegis_protocol::xeddsa;
use aegis_storage::{MessageStatus, Storage};
use aegis_types::{AccountId, AegisError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
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
    /// Пост-квантовая половина identity и привязка — по классическому
    /// ключу (hex).
    pq: HashMap<String, (String, String)>,
    /// Ключ восстановления аккаунта (hex, классический и ML-DSA) —
    /// по идентификатору аккаунта.
    recovery: HashMap<String, (String, String)>,
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

    /// После скольких успешных подтверждений доставки сервер начинает
    /// отвечать 500 — сбой посреди пачки.
    acks_before_failure: Option<usize>,

    /// Журнал ключей (§9.7): эпохи — номер, корень, вершина, дерево
    /// и листы (identity, хеш PQ-половины, версия) по индексу.
    kt_epochs: Vec<KtEpochState>,
}

/// Эпоха журнала ключей поддельного сервера.
struct KtEpochState {
    epoch: u64,
    root: [u8; 32],
    head: [u8; 32],
    tree: kt::Tree,
    leaves: HashMap<[u8; 32], ([u8; 32], [u8; 32], u64)>,
}

/// Старшие нулевые биты — проверка решения proof-of-work.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0;

    for byte in bytes {
        total += byte.leading_zeros();

        if *byte != 0 {
            break;
        }
    }

    total
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

    /// Запись discovery для имени: идентификатор аккаунта и ключ.
    fn account_entry(&self, name: &str) -> (String, String) {
        self.state.borrow().accounts[name].clone()
    }

    /// 🔐 Сервер начинает называть для имени другую запись.
    ///
    /// Так выглядит подмена ключа злонамеренным или взломанным
    /// сервером: ответ discovery — всё, что клиент о нём знает.
    fn point_name(&self, name: &str, entry: (String, String)) {
        self.state
            .borrow_mut()
            .accounts
            .insert(name.to_owned(), entry);
    }

    /// Сколько раз устройства публиковали ключи — всего.
    fn total_publishes(&self) -> usize {
        self.state.borrow().publishes.values().sum()
    }

    /// 🔐 Сервер подменяет пост-квантовую половину identity владельца
    /// классического ключа (hex).
    fn replace_pq(&self, identity: &str, replacement: (String, String)) {
        self.state
            .borrow_mut()
            .pq
            .insert(identity.to_owned(), replacement);
    }

    /// 🔐 Сервер подменяет ключ ML-KEM sealed sender устройства.
    ///
    /// `None` — не отдаёт вовсе; иначе подставляет свой (с чужой подписью).
    fn replace_sealed_kem(&self, device_id: &str, replacement: Option<(String, String)>) {
        let mut state = self.state.borrow_mut();
        let bundle = state
            .bundles
            .get_mut(device_id)
            .expect("устройство публиковало ключи");

        match replacement {
            None => {
                bundle.sealed_kem_public = None;
                bundle.sealed_kem_signature = None;
            }
            Some((public, signature)) => {
                bundle.sealed_kem_public = Some(public);
                bundle.sealed_kem_signature = Some(signature);
            }
        }
    }

    /// Сколько конвертов ждёт устройство.
    fn queued_for(&self, device_id: &str) -> usize {
        self.state
            .borrow()
            .queues
            .get(device_id)
            .map_or(0, Vec::len)
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

    /// Забирает **все** одноразовые предключи устройства — как сервер,
    /// который их не выдаёт, или как вычерпавший пул злоумышленник.
    fn drain_one_time(&self, device_id: &str) {
        if let Some(bundle) = self.state.borrow_mut().bundles.get_mut(device_id) {
            bundle.one_time.clear();
            bundle.one_time_kem.clear();
        }
    }

    /// Подтверждения доставки начнут отказывать после `count` успешных.
    fn fail_acknowledgements_after(&self, count: usize) {
        self.state.borrow_mut().acks_before_failure = Some(count);
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
                state.pq.insert(
                    parsed.identity_key.clone(),
                    (
                        parsed.pq_identity_key.clone(),
                        parsed.identity_binding.clone(),
                    ),
                );
                if let (Some(public), Some(pq_public)) =
                    (parsed.recovery_key.clone(), parsed.recovery_pq_key.clone())
                {
                    state
                        .recovery
                        .insert(account_id.clone(), (public, pq_public));
                }
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
            // Перепривязка аккаунта к новой identity — как на настоящем
            // сервере: подпись ключа восстановления, затем прежние
            // устройства удаляются и заводится новое.
            (Method::Post, "/v1/accounts/recover") => {
                let parsed: aegis_net::api::RecoverAccountRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| aegis_types::AegisError::Malformed)?;
                let decode =
                    |text: &str| hex::decode(text).map_err(|_| aegis_types::AegisError::Malformed);

                let Some((account_id, _)) = state.accounts.get(&parsed.username).cloned() else {
                    return Ok(HttpResponse {
                        status: 401,
                        body: String::new(),
                        binary_body: Vec::new(),
                    });
                };
                let Some((public, pq_public)) = state.recovery.get(&account_id).cloned() else {
                    return Ok(HttpResponse {
                        status: 401,
                        body: String::new(),
                        binary_body: Vec::new(),
                    });
                };

                let identity = decode(&parsed.identity_key)?;
                let device_identity = decode(&parsed.device_identity_key)?;
                let pq = decode(&parsed.pq_identity_key)?;
                let binding = decode(&parsed.identity_binding)?;
                let signed = aegis_protocol::account_recovery::RecoverRequest {
                    username: &parsed.username,
                    identity_key: &identity,
                    device_identity_key: &device_identity,
                    pq_identity_key: &pq,
                    identity_binding: &binding,
                    issued_at_millis: parsed.issued_at,
                };
                let public = aegis_types::PublicKeyBytes::new(
                    decode(&public)?
                        .try_into()
                        .map_err(|_| aegis_types::AegisError::Malformed)?,
                );

                if aegis_protocol::account_recovery::verify(
                    &public,
                    &decode(&pq_public)?,
                    &signed,
                    &decode(&parsed.signature)?,
                )
                .is_err()
                {
                    return Ok(HttpResponse {
                        status: 401,
                        body: String::new(),
                        binary_body: Vec::new(),
                    });
                }

                if let Some(old) = state.devices.get(&account_id).cloned() {
                    state.bundles.remove(&old);
                    state.device_identity.remove(&old);
                    state.queues.remove(&old);
                }

                let device_id = Self::next_uuid(&mut state);
                state.accounts.insert(
                    parsed.username.clone(),
                    (account_id.clone(), parsed.identity_key.clone()),
                );
                state.devices.insert(account_id.clone(), device_id.clone());
                state
                    .device_identity
                    .insert(device_id.clone(), parsed.device_identity_key.clone());
                state.pq.insert(
                    parsed.identity_key.clone(),
                    (
                        parsed.pq_identity_key.clone(),
                        parsed.identity_binding.clone(),
                    ),
                );

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
                        let pq = state.pq.get(identity_key).cloned();

                        (
                            200,
                            serde_json::to_string(&DiscoveryResponse {
                                account_id: account_id.clone(),
                                identity_key: identity_key.clone(),
                                sealed_kem_public: state
                                    .bundles
                                    .get(&device_id)
                                    .and_then(|bundle| bundle.sealed_kem_public.clone()),
                                sealed_kem_signature: state
                                    .bundles
                                    .get(&device_id)
                                    .and_then(|bundle| bundle.sealed_kem_signature.clone()),
                                device_ids: vec![device_id],
                                pq_identity_key: pq.as_ref().map(|(public, _)| public.clone()),
                                identity_binding: pq.map(|(_, binding)| binding),
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

                // Пост-квантовая половина — у аккаунтов, заведённых без неё.
                if let (Some(public), Some(binding)) = (
                    parsed.pq_identity_key.clone(),
                    parsed.identity_binding.clone(),
                ) {
                    if let Some(identity) = state.device_identity.get(&device_id).cloned() {
                        state.pq.insert(identity, (public, binding));
                    }
                }

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

                        // Ключ sealed sender — как на настоящем сервере:
                        // публикация без него прежний не стирает.
                        if parsed.sealed_kem_public.is_some() {
                            existing.sealed_kem_public = parsed.sealed_kem_public;
                            existing.sealed_kem_signature = parsed.sealed_kem_signature;
                        }
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

                let pq = state.pq.get(&identity).cloned();

                match state.bundles.get_mut(&device_id) {
                    Some(keys) => {
                        // Одноразовый ключ выдаётся один раз и уходит
                        // из пула — как на настоящем сервере (`DELETE …
                        // FOR UPDATE SKIP LOCKED`). Прежде подделка
                        // отдавала `first()`, не вычёркивая: два новых
                        // собеседника получали один ключ, и первое
                        // сообщение второго не расшифровывалось.
                        let one_time = (!keys.one_time.is_empty()).then(|| keys.one_time.remove(0));
                        let one_time_kem =
                            (!keys.one_time_kem.is_empty()).then(|| keys.one_time_kem.remove(0));

                        (
                            200,
                            serde_json::to_string(&BundleResponse {
                                device_id,
                                pq_identity_key: pq.as_ref().map(|(public, _)| public.clone()),
                                identity_binding: pq.map(|(_, binding)| binding),
                                identity_key: identity,
                                signed_key_id: keys.signed_key_id,
                                signed_public: keys.signed_public.clone(),
                                signed_signature: keys.signed_signature.clone(),
                                kem_key_id: keys.kem_key_id,
                                kem_public: keys.kem_public.clone(),
                                kem_signature: keys.kem_signature.clone(),
                                one_time,
                                one_time_kem,
                                degraded: false,
                            })
                            .unwrap_or_default(),
                        )
                    }
                    None => (404, String::new()),
                }
            }
            // 🔐 Незапечатанной отправки у сервера нет: заглушка, как
            // и сервер, её не принимает, но считает попытки — тесты
            // проверяют, что клиент их не делает вовсе.
            (Method::Post, path) if path.starts_with("/v1/messages") => {
                state.plain_accepted += 1;

                (405, String::new())
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
                let by_key = match (
                    state.access_hashes.get(&parsed.destination_device_id),
                    presented,
                ) {
                    (Some(stored), Some(key)) => {
                        Sha256::digest(&key).as_slice() == stored.as_slice()
                    }
                    _ => false,
                };

                // Первый контакт: вместо ключа доступа — работа над этим
                // конвертом этому получателю, как на настоящем сервере.
                let by_work = parsed.pow_nonce.is_some_and(|nonce| {
                    let sealed = hex::decode(&parsed.sealed).unwrap_or_default();
                    let challenge = aegis_net::pow::first_contact_challenge(
                        &parsed.destination_device_id,
                        &sealed,
                    );

                    leading_zero_bits(&aegis_net::pow::hash(&challenge, nonce))
                        >= aegis_net::pow::FIRST_CONTACT_DIFFICULTY
                        && state
                            .device_identity
                            .contains_key(&parsed.destination_device_id)
                });

                let allowed = by_key || by_work;

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
            (Method::Delete, path)
                if path.starts_with("/v1/messages/") && state.acks_before_failure == Some(0) =>
            {
                (500, String::new())
            }
            (Method::Delete, path) if path.starts_with("/v1/messages/") => {
                if let Some(left) = state.acks_before_failure.as_mut() {
                    *left -= 1;
                }

                // Подтверждение доставки: сервер удаляет конверт.
                let remainder = path.trim_start_matches("/v1/messages/");
                if let Some((device_id, envelope_id)) = remainder.split_once('/') {
                    if let Some(queue) = state.queues.get_mut(device_id) {
                        queue.retain(|envelope| envelope.envelope_id != envelope_id);
                    }
                }

                (200, String::new())
            }
            (Method::Post, "/v1/attachments/blob") => {
                let payload = request.binary_body.clone().unwrap_or_default();

                // Как настоящий сервер: без подписи, но с работой над
                // этим блобом — и без записи, кто его прислал.
                let nonce = request
                    .headers
                    .iter()
                    .find(|(name, _)| name == aegis_net::client::UPLOAD_POW_HEADER)
                    .and_then(|(_, value)| value.parse::<u64>().ok());
                let signed = request
                    .headers
                    .iter()
                    .any(|(name, _)| name.starts_with("x-aegis-signature"));
                let worked = nonce.is_some_and(|nonce| {
                    leading_zero_bits(&aegis_net::pow::hash(
                        &aegis_net::pow::upload_challenge(&payload),
                        nonce,
                    )) >= aegis_net::pow::upload_difficulty(payload.len())
                });

                if payload.is_empty() {
                    (400, String::new())
                } else if !worked || signed {
                    (401, String::new())
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
            // Журнал ключей — как у настоящего сервера (`aegis-server-api::kt`).
            (Method::Get, path) if path.starts_with("/v1/kt/heads") => {
                let from = path
                    .strip_prefix("/v1/kt/heads/")
                    .and_then(|text| text.parse::<u64>().ok())
                    .unwrap_or(0);
                let epochs: Vec<aegis_net::api::KtEpochView> = state
                    .kt_epochs
                    .iter()
                    .filter(|epoch| epoch.epoch >= from)
                    .map(|epoch| aegis_net::api::KtEpochView {
                        epoch: epoch.epoch,
                        root: hex::encode(epoch.root),
                        head: hex::encode(epoch.head),
                    })
                    .collect();

                (
                    200,
                    serde_json::to_string(&aegis_net::api::KtHeadsResponse { epochs })
                        .unwrap_or_default(),
                )
            }
            (Method::Post, "/v1/kt/proofs") => {
                let parsed: aegis_net::api::KtProofsRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| AegisError::Malformed)?;
                let index: [u8; 32] = hex::decode(&parsed.index)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(AegisError::Malformed)?;

                let proofs = parsed
                    .epochs
                    .iter()
                    .filter_map(|wanted| {
                        state.kt_epochs.iter().find(|epoch| epoch.epoch == *wanted)
                    })
                    .map(|epoch| {
                        let proof = epoch.tree.prove(&index);
                        let (leaf, other) = match proof.terminal {
                            kt::Terminal::Empty => (None, None),
                            kt::Terminal::Leaf { index: found, .. } if found == index => {
                                let (identity, pq_hash, version) = epoch.leaves[&index];
                                (
                                    Some(aegis_net::api::KtLeafView {
                                        identity_key: hex::encode(identity),
                                        pq_hash: hex::encode(pq_hash),
                                        version,
                                    }),
                                    None,
                                )
                            }
                            kt::Terminal::Leaf {
                                index: found,
                                value,
                            } => (
                                None,
                                Some(aegis_net::api::KtOtherLeafView {
                                    index: hex::encode(found),
                                    value: hex::encode(value),
                                }),
                            ),
                        };

                        aegis_net::api::KtProofView {
                            epoch: epoch.epoch,
                            leaf,
                            other,
                            siblings: proof.siblings.iter().map(hex::encode).collect(),
                        }
                    })
                    .collect();

                (
                    200,
                    serde_json::to_string(&aegis_net::api::KtProofsResponse { proofs })
                        .unwrap_or_default(),
                )
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
/// Стороны подтверждают ключи друг друга — как после сверки safety
/// number при встрече. Без этого отправка запрещена (`PeerUnconfirmed`).
impl FakeServer {
    /// Строит эпоху журнала ключей из текущих аккаунтов.
    ///
    /// `forged` — 🔐 поддельные листы: имя и ключ, которые «сервер»
    /// показывает вместо настоящих.
    fn publish_kt_epoch(&self, epoch: u64, forged: &[(&str, [u8; 32])]) {
        let mut state = self.state.borrow_mut();
        let mut leaves = HashMap::new();

        for (name, (_, identity_hex)) in &state.accounts {
            let Some((pq_hex, _)) = state.pq.get(identity_hex) else {
                continue;
            };
            let mut identity: [u8; 32] = hex::decode(identity_hex)
                .expect("hex")
                .try_into()
                .expect("32 байта");
            let mut pq_hash =
                aegis_protocol::pq_identity::pq_identity_hash(&hex::decode(pq_hex).expect("hex"));

            if let Some((_, key)) = forged.iter().find(|(forged, _)| forged == name) {
                identity = *key;
                pq_hash = [0xEE; 32];
            }

            leaves.insert(kt::index(name), (identity, pq_hash, 1u64));
        }

        let tree = kt::Tree::new(
            leaves
                .iter()
                .map(|(index, (identity, pq_hash, version))| {
                    (*index, kt::leaf_value(index, identity, pq_hash, *version))
                })
                .collect(),
        );
        let root = tree.root();
        let previous = state.kt_epochs.last().map_or(kt::ZERO, |last| last.head);

        state.kt_epochs.push(KtEpochState {
            epoch,
            root,
            head: kt::head(epoch, &root, &previous),
            tree,
            leaves,
        });
    }

    /// Эпохи с `from` по `to` включительно.
    fn publish_kt_epochs(&self, from: u64, to: u64) {
        for epoch in from..=to {
            self.publish_kt_epoch(epoch, &[]);
        }
    }

    /// 🔐 «Сервер переписывает историю»: забывает показанную цепочку.
    fn forget_kt_history(&self) {
        self.state.borrow_mut().kt_epochs.clear();
    }
}

/// Эпоха журнала в момент [`now`].
fn now_epoch() -> u64 {
    kt::epoch_at(now().as_millis())
}

/// Регистрирует двоих **без** личной сверки ключей.
fn unconfirmed_pair(
    server: &FakeServer,
    dir: &tempfile::TempDir,
) -> (Client<FakeServer>, Client<FakeServer>) {
    let alice = Client::new(server.clone(), open_storage(dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    (alice, bob)
}

fn confirm_pair(a: &Client<FakeServer>, a_name: &str, b: &Client<FakeServer>, b_name: &str) {
    for (client, peer) in [(a, b_name), (b, a_name)] {
        let contact = client
            .discover_contact(peer, now())
            .expect("собеседник найден");
        client
            .set_contact_verified(&contact.account_id, true, now())
            .expect("ключ сверен");
    }
}

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");
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

/// 🔐 Неверный PIN не открывает vault с файлами.
///
/// Прежде проверки не было: любой PIN «открывал» vault, список имён
/// отдавался, удаление работало. Тест перенесён из аудита; проверочного
/// значения здесь нет — это путь базы, заведённой до него.
#[test]
fn a_wrong_pin_does_not_open_the_vault() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let owner = Client::new(server, open_storage(&dir, "owner.db"));
    let salt = [0x33u8; 16];

    owner
        .unlock_vault("482915", &salt, now())
        .expect("владелец открывает vault");
    let sealed = owner
        .add_vault_file("паспорт.png", b"scan", "/files/1", now(), &mut OsRng)
        .expect("файл добавлен");
    owner.seal_vault().expect("vault закрыт");

    let opened = owner.unlock_vault("000000", &salt, now());
    let names: Vec<String> = owner
        .vault_files(10, now())
        .map(|files| files.into_iter().map(|file| file.name).collect())
        .unwrap_or_default();
    let deleted = owner.delete_vault_file(&sealed.file_id, now());

    assert!(
        opened.is_err() && names.is_empty() && deleted.is_err(),
        "неверный PIN открыл vault: имена {names:?}, удаление {:?}",
        deleted.map(|path| path.is_some())
    );

    owner
        .unlock_vault("482915", &salt, now())
        .expect("верный PIN открывает");
}

/// 🔐 Заведённое проверочное значение отвергает неверный PIN и в пустом vault.
///
/// Иначе опечатка при первом открытии пустого vault привязала бы
/// к ней первый же добавленный файл.
#[test]
fn a_typo_at_first_vault_open_is_rejected() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let owner = Client::new(server, open_storage(&dir, "owner.db"));
    let salt = [0x44u8; 16];

    // Так делает платформа сразу после того, как база открылась PIN-ом.
    owner
        .establish_vault_verifier("482915", &salt, &mut OsRng)
        .expect("проверочное значение заведено");

    assert!(
        owner.unlock_vault("482916", &salt, now()).is_err(),
        "опечатка открыла пустой vault"
    );
    owner
        .unlock_vault("482915", &salt, now())
        .expect("верный PIN открывает");
}

/// 🔐 Повторное заведение не перепривязывает vault, в котором есть файлы.
///
/// Файлы завёрнуты в прежний ключ; перевести проверку на другой PIN
/// значило бы открыть vault ключом, который их не разворачивает.
#[test]
fn establishing_again_does_not_rebind_a_vault_with_files() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let owner = Client::new(server, open_storage(&dir, "owner.db"));
    let salt = [0x55u8; 16];

    owner
        .establish_vault_verifier("111111", &salt, &mut OsRng)
        .expect("заведено");
    owner.unlock_vault("111111", &salt, now()).expect("открыт");
    owner
        .add_vault_file("договор.pdf", b"text", "/files/2", now(), &mut OsRng)
        .expect("файл добавлен");
    owner.seal_vault().expect("закрыт");

    owner
        .establish_vault_verifier("222222", &salt, &mut OsRng)
        .expect("вызов проходит");

    assert!(
        owner.unlock_vault("222222", &salt, now()).is_err(),
        "vault с файлами перепривязан к чужому PIN"
    );
    owner
        .unlock_vault("111111", &salt, now())
        .expect("прежний PIN открывает");
}

/// 🔐 На первое сообщение от нового собеседника можно ответить.
///
/// Начальный конверт несёт только identity-ключ отправителя — ни имени,
/// ни устройства. Прежде ответить было нечем: чат появлялся, а отправка
/// в него падала. Нашлось живым обменом с эмулятором: сообщение пришло,
/// ответ не ушёл. Теперь имя едет под шифрованием вместе с ключом доступа.
#[test]
fn a_first_contact_can_be_answered() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

    // Боб Алису не знает: она пишет первой.
    alice
        .send_message("bob", "привет, мы не знакомы", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём");

    let chat = bob
        .chats()
        .expect("чаты")
        .into_iter()
        .next()
        .expect("чат появился");
    let known = bob
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| contact.chat_id == Some(chat))
        .expect("собеседник этого чата не известен");

    assert_eq!(
        known.username.as_deref(),
        Some("alice"),
        "имя собеседника неизвестно — ответить нечем"
    );

    bob.send_message("alice", "привет, теперь знакомы", now(), &mut OsRng)
        .expect("ответ");

    assert!(
        alice
            .receive_messages(&alice_account.device_id.to_string(), now())
            .expect("приём")
            >= 1,
        "ответ не дошёл"
    );
}

/// 🔐 Чужое заявленное имя не принимается.
///
/// Мэллори называется «alice». Прими Боб это на слово — его ответ ушёл
/// бы настоящей Алисе, в другой чат. Имя принимается, только если
/// discovery по нему возвращает identity-ключ самого отправителя.
#[test]
fn a_claimed_username_that_is_not_the_senders_is_ignored() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));
    let mallory = Client::new(server.clone(), open_storage(&dir, "mallory.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");
    mallory
        .register("mallory", now(), &mut OsRng)
        .expect("Мэллори");

    // Мэллори переписывает своё имя в собственной базе на «alice».
    let forged = open_storage(&dir, "mallory.db");
    let keys = forged.load_own_keys().expect("чтение").expect("ключи есть");
    forged
        .save_own_keys(
            &keys.identity_private,
            &keys.identity_public,
            &keys.prekey_secrets,
            keys.device_id.as_deref(),
            Some("alice"),
            now(),
        )
        .expect("имя подменено");
    drop(forged);

    // Мэллори подтверждает ключ Боба — писать иначе нельзя.
    let bob_seen = mallory.discover_contact("bob", now()).expect("Боб найден");
    mallory
        .set_contact_verified(&bob_seen.account_id, true, now())
        .expect("сверено");

    mallory
        .send_message("bob", "это я, Алиса", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём");

    assert!(
        bob.contacts()
            .expect("контакты")
            .iter()
            .all(|contact| contact.username.as_deref() != Some("alice")),
        "Боб принял чужое имя «alice» от Мэллори"
    );
}

/// 🔐 Сессия без одноразового ключа собеседника записывается в журнал.
///
/// Флаг `degraded` вычислялся и выбрасывался. Систематическое начало
/// без одноразовых ключей — признак того, что пул собеседника вычерпан
/// или сервер их не выдаёт, и заметить это было нечем. Тест перенесён
/// из аудита.
#[test]
fn a_session_started_without_one_time_keys_is_recorded() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_account = bob.register("bob", now(), &mut OsRng).expect("Боб");

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

    server.drain_one_time(&bob_account.device_id.to_string());

    alice
        .send_message("bob", "без одноразовых ключей", now(), &mut OsRng)
        .expect("отправка");

    let events = alice.security_events(50).expect("журнал");

    assert!(
        events
            .iter()
            .any(|event| event.0 == "session_started_without_one_time_key"),
        "сессия без одноразовых ключей не записана: {events:?}"
    );
}

/// С одноразовым ключом ничего тревожного не пишется.
#[test]
fn a_normal_session_start_is_not_recorded_as_degraded() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

    alice
        .send_message("bob", "обычное начало", now(), &mut OsRng)
        .expect("отправка");

    assert!(
        alice
            .security_events(50)
            .expect("журнал")
            .iter()
            .all(|event| event.0 != "session_started_without_one_time_key"),
        "обычное начало записано как ослабленное"
    );
}

/// Алиса и Боб, зарегистрированные на одном сервере, и их устройства.
fn alice_and_bob(
    server: &FakeServer,
    dir: &tempfile::TempDir,
) -> (Client<FakeServer>, Client<FakeServer>, String, String) {
    let alice = Client::new(server.clone(), open_storage(dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(dir, "bob.db"));

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

    (alice, bob, alice_device, bob_device)
}

/// Тексты сообщений единственного чата клиента.
fn texts_of(client: &Client<FakeServer>) -> Vec<String> {
    let chat = client.chats().expect("чаты")[0];

    client
        .messages(&chat, 50)
        .expect("сообщения")
        .into_iter()
        .map(|message| message.text)
        .collect()
}

/// Момент через `seconds` секунд после [`now`].
fn later(seconds: i64) -> Timestamp {
    Timestamp::from_millis(now().as_millis() + seconds * 1_000)
}

/// 🔐 «Удалить у всех» удаляет у получателя.
///
/// Идентификатор сообщения каждая сторона выдумывала сама, а
/// `Content::Text` его не нёс: `Delete { target }` называл сообщение
/// идентификатором отправителя, которого у получателя не было, и
/// удаление тихо ничего не находило. Интерфейс при этом говорил
/// «удаление запрошено». Тест перенесён из аудита (АУДИТ-6).
#[test]
fn delete_for_everyone_deletes_at_the_recipient() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _, bob_device) = alice_and_bob(&server, &dir);

    let sent = alice
        .send_message("bob", "адрес: улица Ленина, 5", now(), &mut OsRng)
        .expect("отправка");
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);

    alice
        .delete_for_everyone("bob", &sent, now(), &mut OsRng)
        .expect("просьба удалить отправлена");
    bob.receive_messages(&bob_device, now())
        .expect("приём просьбы");
    assert_eq!(
        server.queue_len(&bob_device),
        0,
        "просьба расшифрована, разобрана и подтверждена — дошла"
    );

    let remaining = texts_of(&bob);
    assert!(
        remaining.is_empty(),
        "сообщение осталось у получателя после «удалить у всех»: {remaining:?}"
    );
}

/// Правка доходит до получателя.
///
/// Та же причина, что у удаления: правка называла сообщение
/// идентификатором, которого у получателя не было.
#[test]
fn an_edit_reaches_the_recipient() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _, bob_device) = alice_and_bob(&server, &dir);

    let sent = alice
        .send_message("bob", "встречаемся в пять", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, now()).expect("приём");

    alice
        .edit_message("bob", &sent, "встречаемся в шесть", now(), &mut OsRng)
        .expect("правка");
    bob.receive_messages(&bob_device, now())
        .expect("приём правки");

    assert_eq!(texts_of(&bob), vec!["встречаемся в шесть".to_owned()]);
    assert_eq!(texts_of(&alice), vec!["встречаемся в шесть".to_owned()]);
}

/// 🔐 Собеседник не правит и не удаляет **наши** сообщения у нас.
///
/// С общими идентификаторами собеседник знает идентификаторы наших
/// сообщений — он их получал. Прежде правка и удаление применялись
/// к любому найденному сообщению: Боб переписал бы слова Алисы
/// в её же переписке или стёр бы их.
#[test]
fn a_peer_cannot_edit_or_delete_our_messages() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let first = alice
        .send_message("bob", "я согласна на 100", now(), &mut OsRng)
        .expect("отправка");
    let second = alice
        .send_message("bob", "и это тоже моё", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, now()).expect("приём");

    // Боб пользуется обычным клиентом: правка и удаление уходят
    // с идентификаторами сообщений Алисы — теми, под которыми они
    // лежат у него.
    bob.edit_message("alice", &first, "я согласна на 1000", now(), &mut OsRng)
        .expect("правка ушла");
    bob.delete_for_everyone("alice", &second, now(), &mut OsRng)
        .expect("удаление ушло");

    alice
        .receive_messages(&alice_device, now())
        .expect("приём у Алисы");
    assert_eq!(server.queue_len(&alice_device), 0, "всё дошло и разобрано");

    assert_eq!(
        texts_of(&alice),
        vec!["я согласна на 100".to_owned(), "и это тоже моё".to_owned()],
        "собеседник переписал или стёр сообщения Алисы у неё"
    );
}

/// 🔐 Удаление, названное идентификатором сообщения из **другого**
/// чата, ничего не трогает.
///
/// Карол пишет Алисе; идентификатор этого сообщения оказался у Боба
/// (Карол переслала, утечка — не важно как). Удаление от Боба
/// не должно стирать переписку Алисы с Карол.
#[test]
fn a_peer_cannot_delete_a_message_of_another_chat() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);
    let carol = Client::new(server.clone(), open_storage(&dir, "carol.db"));
    carol.register("carol", now(), &mut OsRng).expect("Карол");
    confirm_pair(&alice, "alice", &carol, "carol");

    // У Алисы два чата: с Бобом и с Карол.
    bob.send_message("alice", "привет от Боба", now(), &mut OsRng)
        .expect("Боб пишет");
    let carols = carol
        .send_message("alice", "секрет Карол", now(), &mut OsRng)
        .expect("Карол пишет");
    alice
        .receive_messages(&alice_device, now())
        .expect("приём у Алисы");

    bob.delete_for_everyone("alice", &carols, now(), &mut OsRng)
        .expect("удаление ушло");
    alice
        .receive_messages(&alice_device, now())
        .expect("приём удаления");
    assert_eq!(
        server.queue_len(&alice_device),
        0,
        "удаление дошло и разобрано"
    );
    let _ = bob_device;

    let everything: Vec<String> = alice
        .chats()
        .expect("чаты")
        .iter()
        .flat_map(|chat| alice.messages(chat, 50).expect("сообщения"))
        .map(|message| message.text)
        .collect();

    assert!(
        everything.contains(&"секрет Карол".to_owned()),
        "удаление из чата с Бобом стёрло сообщение из чата с Карол: {everything:?}"
    );
}

/// Квитанция о прочтении отмечает прочитанными наши сообщения —
/// до названного включительно, и не дальше.
///
/// Прежде квитанция доходила и выбрасывалась, а называла она
/// идентификатор, которого у отправителя не было: отметка «прочитано»
/// не появлялась никогда, хотя собеседник включал передачу присутствия
/// ради неё.
#[test]
fn a_read_receipt_marks_our_messages_read_up_to_it() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let first = alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("отправка");
    let second = alice
        .send_message("bob", "второе", later(1), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, later(2)).expect("приём");

    // Третье уходит позже, чем Боб прочитал второе.
    let third = alice
        .send_message("bob", "третье", later(3), &mut OsRng)
        .expect("отправка");

    // Как приложение: квитанция называет последнее входящее из переписки
    // Боба — идентификатор, под которым сообщение лежит **у него**.
    // Идентификатор отправителя тест не подставляет: иначе он прошёл бы
    // и тогда, когда у сторон идентификаторы разные.
    let bob_chat = bob.chats().expect("чаты")[0];
    let last_seen = bob
        .messages(&bob_chat, 50)
        .expect("сообщения")
        .into_iter()
        .rfind(|message| !message.outgoing)
        .expect("входящее")
        .message_id;

    // Переписку начала Алиса: у Боба это запрос, и квитанции уходят
    // только после его согласия.
    bob.accept_chat(&bob_chat, later(4), &mut OsRng)
        .expect("принятие");
    bob.set_presence_sharing(true).expect("присутствие");
    bob.send_read_receipt("alice", &last_seen, later(4), &mut OsRng)
        .expect("квитанция");
    alice
        .receive_messages(&alice_device, later(5))
        .expect("приём квитанции");

    let chat = alice.chats().expect("чаты")[0];
    let status_of = |id: &aegis_types::MessageId| {
        alice
            .messages(&chat, 50)
            .expect("сообщения")
            .into_iter()
            .find(|message| message.message_id == *id)
            .expect("сообщение на месте")
            .status
    };

    assert_eq!(status_of(&first), MessageStatus::Read, "первое не отмечено");
    assert_eq!(
        status_of(&second),
        MessageStatus::Read,
        "названное не отмечено"
    );
    assert_eq!(
        status_of(&third),
        MessageStatus::Sent,
        "отмечено то, что ушло после прочитанного"
    );
}

/// 🔐 Квитанция не отмечает сообщения самого собеседника.
///
/// Прочитанность — сведение о чужом чтении наших сообщений. Квитанция,
/// названная сообщением собеседника, не должна менять ни его, ни наши.
#[test]
fn a_read_receipt_naming_the_peers_own_message_marks_nothing() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "от Алисы", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, now()).expect("приём");
    let bobs = bob
        .send_message("alice", "от Боба", later(1), &mut OsRng)
        .expect("ответ");
    alice
        .receive_messages(&alice_device, later(2))
        .expect("приём ответа");

    bob.set_presence_sharing(true).expect("присутствие");
    bob.send_read_receipt("alice", &bobs, later(3), &mut OsRng)
        .expect("квитанция");
    alice
        .receive_messages(&alice_device, later(4))
        .expect("приём квитанции");

    let chat = alice.chats().expect("чаты")[0];
    let read: Vec<String> = alice
        .messages(&chat, 50)
        .expect("сообщения")
        .into_iter()
        .filter(|message| message.status == MessageStatus::Read)
        .map(|message| message.text)
        .collect();

    assert!(read.is_empty(), "отмечено прочитанным: {read:?}");
}

/// У вложения тот же идентификатор у обеих сторон — удаление
/// сообщения с файлом доходит так же, как удаление текста.
#[test]
fn an_attachment_is_deleted_for_everyone_too() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_attachment(
            "bob",
            &alice_device,
            &AttachmentFile {
                kind: AttachmentKind::Document,
                bytes: vec![7; 1_000],
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
    bob.receive_messages(&bob_device, now()).expect("приём");

    let chat = alice.chats().expect("чаты")[0];
    let sent = alice.messages(&chat, 10).expect("сообщения")[0].message_id;

    alice
        .delete_for_everyone("bob", &sent, now(), &mut OsRng)
        .expect("удаление");
    bob.receive_messages(&bob_device, now())
        .expect("приём удаления");

    assert!(texts_of(&bob).is_empty(), "вложение осталось у получателя");
}

/// Кладёт в очередь устройства конверт, снятый с неё раньше, —
/// ровно то, что может сделать оператор сервера.
fn replay_into_queue(server: &FakeServer, device_id: &str, captured: &EnvelopeResponse) {
    let mut state = server.state.borrow_mut();
    let envelope_id = FakeServer::next_uuid(&mut state);

    state
        .queues
        .entry(device_id.to_owned())
        .or_default()
        .push(EnvelopeResponse {
            envelope_id,
            ciphertext: captured.ciphertext.clone(),
            queued_at_bucketed: 0,
        });
}

/// Алиса начинает переписку с Бобом без одноразовых ключей и получает
/// ответ; возвращает снятую оператором копию конверта инициации.
fn conversation_without_one_time_keys(
    server: &FakeServer,
    alice: &Client<FakeServer>,
    bob: &Client<FakeServer>,
    alice_device: &str,
    bob_device: &str,
) -> EnvelopeResponse {
    // Сервер отдаёт Алисе bundle Боба без одноразовых ключей —
    // исчерпанный пул или намеренно вырезанный: одноразовый ключ
    // не подписан, и отличить одно от другого клиенту нечем.
    server.drain_one_time(bob_device);

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("отправка");

    // Оператор снимает копию конверта инициации (первый в очереди).
    let initial = server.state.borrow().queues[bob_device][0].clone();

    assert_eq!(bob.receive_messages(bob_device, now()).expect("приём"), 1);

    bob.send_message("alice", "ответ", now(), &mut OsRng)
        .expect("ответ");
    assert_eq!(
        alice.receive_messages(alice_device, now()).expect("приём"),
        1
    );

    initial
}

/// 🔐 Повтор конверта инициации не сбрасывает сессию получателя.
///
/// Защита от повтора держалась только на одноразовых предключах.
/// Сервер, не выдавший их, мог спустя сколько угодно времени положить
/// в очередь копию давно принятого конверта инициации: клиент принимал
/// её как новую сессию и затирал действующую — переписка молча вставала.
/// Тест перенесён из аудита (АУДИТ-1).
#[test]
fn a_replayed_initial_envelope_does_not_reset_the_session() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let initial =
        conversation_without_one_time_keys(&server, &alice, &bob, &alice_device, &bob_device);

    replay_into_queue(&server, &bob_device, &initial);
    bob.receive_messages(&bob_device, now())
        .expect("приём повтора");
    assert_eq!(server.queue_len(&bob_device), 0, "повтор не подтверждён");

    alice
        .send_message("bob", "второе", now(), &mut OsRng)
        .expect("второе");
    assert_eq!(
        bob.receive_messages(&bob_device, now()).expect("приём"),
        1,
        "повтор старого конверта инициации сбросил сессию Боба: \
         сообщение Алисы больше не расшифровывается"
    );

    assert!(
        bob.security_events(50)
            .expect("журнал")
            .iter()
            .any(|event| event.0 == "initial_envelope_replayed"),
        "повтор не записан в журнал"
    );
    assert_eq!(
        texts_of(&bob)
            .iter()
            .filter(|text| text.as_str() == "первое")
            .count(),
        1,
        "повтор показал сообщение второй раз"
    );
}

/// 🔐 Повтор отвергается и после ротации подписанного предключа.
///
/// Выведенный предключ ещё месяц принимает конверты инициации, а значит,
/// и их повторы. Запись о принятом конверте обязана жить столько же:
/// забытая при ротации, она вернула бы ровно ту дыру, которую закрывает.
#[test]
fn a_replay_after_signed_prekey_rotation_is_still_rejected() {
    const DAY: i64 = 24 * 60 * 60 * 1000;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let initial =
        conversation_without_one_time_keys(&server, &alice, &bob, &alice_device, &bob_device);

    let after_rotation = Timestamp::from_millis(now().as_millis() + 8 * DAY);
    assert!(
        bob.maintain_prekeys(after_rotation, &mut OsRng)
            .expect("обслуживание")
            .rotated_signed,
        "заготовка теста: ротация не случилась"
    );

    replay_into_queue(&server, &bob_device, &initial);
    bob.receive_messages(&bob_device, after_rotation)
        .expect("приём повтора");

    alice
        .send_message("bob", "после ротации", after_rotation, &mut OsRng)
        .expect("отправка");
    assert_eq!(
        bob.receive_messages(&bob_device, after_rotation)
            .expect("приём"),
        1,
        "повтор после ротации сбросил сессию"
    );
}

/// Число одноразовых предключей, приватные части которых лежат на диске.
fn one_time_secrets_on_disk(dir: &tempfile::TempDir, name: &str) -> usize {
    let keys = open_storage(dir, name)
        .load_own_keys()
        .expect("чтение")
        .expect("ключи");

    aegis_protocol::prekeys::PreKeySecrets::from_bytes(&keys.prekey_secrets)
        .expect("секреты")
        .one_time
        .len()
}

/// 🔐 Израсходованный одноразовый предключ стирается с диска, даже если
/// приём прервался посреди пачки.
///
/// Секреты сохранялись одним разом в конце пачки, а подтверждение шло
/// по конверту. Сбой подтверждения на втором конверте прерывал приём:
/// первый, уже подтверждённый и удалённый с сервера, повторно не придёт,
/// а приватная часть его одноразового предключа оставалась на диске —
/// та, стирание которой и даёт первому сообщению прямую секретность.
#[test]
fn a_consumed_one_time_key_leaves_the_disk_even_if_the_batch_fails() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("отправка");
    let before = one_time_secrets_on_disk(&dir, "bob.db");

    // Первый конверт — начальный, с одноразовым ключом; его подтверждение
    // проходит, следующее — нет.
    server.fail_acknowledgements_after(1);
    assert!(
        bob.receive_messages(&bob_device, now()).is_err(),
        "заготовка теста: приём не прервался"
    );

    assert_eq!(
        one_time_secrets_on_disk(&dir, "bob.db"),
        before - 1,
        "одноразовый предключ подтверждённого конверта остался на диске"
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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("отправка");

    // 🔐 Первое сообщение тоже запечатано: ключа доступа Боба у Алисы
    // нет, и право на анонимную отправку она доказала работой. Прежде
    // оно уходило за подписью, и сервер видел, кто начал переписку.
    assert!(
        server.sealed_accepted() >= 1,
        "первое сообщение не запечатано"
    );
    assert_eq!(
        server.plain_accepted(),
        0,
        "первое сообщение ушло за подписью отправителя"
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

    // Устаревший ключ забыт: следующая попытка — видимая пользователю
    // и снова запечатанная, теперь с proof-of-work, как первый контакт.
    // Сообщение доходит, пропуск ключа храповик переживает.
    alice
        .send_message("bob", "повтор", now(), &mut OsRng)
        .expect("повтор");

    assert_eq!(
        server.plain_accepted(),
        plain_before,
        "после отказа ключа сообщение ушло за подписью"
    );
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);
}

/// 🔐 За всю переписку сервер не получает ни одного конверта с отправителем.
///
/// Первое сообщение, ответ, служебные ключи доступа, реакция и вложение —
/// всё запечатано. Скачивание вложения уходит без подписи: прежде
/// пара «кто загрузил → кто скачал» выдавала, кто кому прислал файл.
#[test]
fn the_server_never_learns_who_sent_what() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let first = alice
        .send_message("bob", "привет", now(), &mut OsRng)
        .expect("первое сообщение");
    bob.receive_messages(&bob_device, now()).expect("приём");
    bob.send_message("alice", "и тебе", now(), &mut OsRng)
        .expect("ответ");
    alice.receive_messages(&alice_device, now()).expect("приём");
    bob.send_reaction("alice", &first, "👍", now(), &mut OsRng)
        .expect("реакция");

    alice
        .send_attachment(
            "bob",
            &alice_device,
            &aegis_core::client::AttachmentFile {
                kind: aegis_media::descriptor::AttachmentKind::Document,
                bytes: vec![0x42; 5_000],
                name: Some("отчёт.pdf".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            "",
            now(),
            &mut OsRng,
        )
        .expect("вложение отправлено");

    assert_eq!(
        server.plain_accepted(),
        0,
        "конверт ушёл за подписью отправителя"
    );

    for device in [&alice_device, &bob_device] {
        for envelope in server.queued(device) {
            assert!(
                sealed_sender::is_sealed(&envelope),
                "в очереди незапечатанный конверт"
            );
        }
    }

    // Скачивание вложения — без подписи и без устройства в пути.
    let descriptor = alice
        .upload_attachment(
            &alice_device,
            &aegis_core::client::AttachmentFile {
                kind: aegis_media::descriptor::AttachmentKind::Document,
                bytes: vec![0x42; 5_000],
                name: None,
                description: None,
                duration_millis: None,
                waveform: None,
            },
            now(),
            &mut OsRng,
        )
        .expect("описание построено");

    bob.fetch_attachment(&bob_device, &descriptor, now())
        .expect("вложение скачано");

    let headers = server
        .last_request("/v1/attachments/blob/")
        .expect("скачивание не по анонимному адресу");

    assert!(
        headers
            .iter()
            .all(|(name, _)| !name.to_ascii_lowercase().starts_with("x-aegis")),
        "скачивание вложения подписано: {headers:?}"
    );
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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

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

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");
    let carol_account = carol.register("carol", now(), &mut OsRng).expect("Кэрол");
    confirm_pair(&alice, "alice", &carol, "carol");

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

// --- 🔐 Подмена ключа сервером -------------------------------------------
//
// Отправка адресуется по имени, и ключ собеседника называет сервер.
// Прежде этот ответ не сверялся ни с чем: сервер, назвавший свой ключ
// для «bob», получал следующее же сообщение — даже в сверенный чат.
// Тесты ниже — `identity_change_blocks_send` раздела 24.4.

/// Алиса и Боб знакомы; Мэллори готов выдать себя за Боба.
///
/// Мэллори регистрируется под своим именем, а сервер затем начинает
/// отдавать его запись по имени «bob».
fn substitution_setup(
    server: &FakeServer,
    dir: &tempfile::TempDir,
) -> (
    Client<FakeServer>,
    Client<FakeServer>,
    Contact,
    Client<FakeServer>,
    String,
    (String, String),
) {
    let (alice, bob, bob_seen_by_alice, _) = two_mutual_contacts(server, dir);

    alice
        .send_message("bob", "до подмены", now(), &mut OsRng)
        .expect("до подмены сообщение уходит");

    let mallory = Client::new(server.clone(), open_storage(dir, "mallory.db"));
    let mallory_device = mallory
        .register("mallory", now(), &mut OsRng)
        .expect("Мэллори зарегистрирован")
        .device_id
        .to_string();

    let genuine = server.account_entry("bob");
    server.point_name("bob", server.account_entry("mallory"));

    (
        alice,
        bob,
        bob_seen_by_alice,
        mallory,
        mallory_device,
        genuine,
    )
}

/// 🔐 Подставленный ключ не получает следующее сообщение.
#[test]
fn a_substituted_key_does_not_receive_the_next_message() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _, _mallory, mallory_device, _) = substitution_setup(&server, &dir);

    let result = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    assert!(
        matches!(result, Err(AegisError::IdentityChanged)),
        "сообщение ушло на ключ, подставленный сервером: {result:?}"
    );
    assert_eq!(
        server.queued_for(&mallory_device),
        0,
        "подставленный ключ получил конверт"
    );
}

/// 🔐 То же для сверенного контакта — строка раздела 24.4 дословно.
#[test]
fn identity_change_blocks_send_to_a_verified_contact() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, bob_seen_by_alice, _mallory, mallory_device, _) =
        substitution_setup(&server, &dir);

    alice
        .set_contact_verified(&bob_seen_by_alice.account_id, true, now())
        .expect("Боб сверен");

    let result = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    assert!(
        matches!(result, Err(AegisError::IdentityChanged)),
        "{result:?}"
    );
    assert_eq!(server.queued_for(&mallory_device), 0);
}

/// 🔐 Реакции, правки и вложения идут той же проверкой, что и текст.
#[test]
fn a_substituted_key_does_not_receive_other_content_either() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _, _mallory, mallory_device, _) = substitution_setup(&server, &dir);

    let target = aegis_types::MessageId::generate();
    let result = alice.send_reaction("bob", &target, "👍", later(1), &mut OsRng);

    assert!(
        matches!(result, Err(AegisError::IdentityChanged)),
        "{result:?}"
    );
    assert_eq!(server.queued_for(&mallory_device), 0);
}

/// 🔐 Смена видна, а не только отказ: новый ключ — второй контакт с тем же именем.
#[test]
fn a_refused_substitution_is_recorded_and_flagged() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _, _mallory, _, _) = substitution_setup(&server, &dir);

    let _ = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    let named_bob: Vec<Contact> = alice
        .contacts()
        .expect("контакты")
        .into_iter()
        .filter(|contact| contact.username.as_deref() == Some("bob"))
        .collect();

    assert_eq!(named_bob.len(), 2, "новый ключ не записан контактом");
    assert!(
        named_bob.iter().all(|contact| contact.key_changed),
        "имя под двумя ключами не помечено"
    );
}

/// 🔐 Пока под именем два ключа, отказ — для обоих чатов.
///
/// Иначе сообщение, набранное в одном чате, молча уходило бы в другой —
/// туда, куда указывает сервер.
#[test]
fn two_keys_under_one_name_block_both() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _, _mallory, _, genuine) = substitution_setup(&server, &dir);

    let _ = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    // Сервер вернул настоящий ключ — но имя уже неоднозначно.
    server.point_name("bob", genuine);

    let result = alice.send_message("bob", "секрет", later(2), &mut OsRng);

    assert!(
        matches!(result, Err(AegisError::IdentityChanged)),
        "{result:?}"
    );
}

/// Явное принятие нового ключа возобновляет отправку — ему.
#[test]
fn accepting_the_new_key_resumes_sending_to_it() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, bob_seen_by_alice, mallory, mallory_device, _) =
        substitution_setup(&server, &dir);

    let _ = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    let new_key = alice
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| {
            contact.username.as_deref() == Some("bob")
                && contact.identity != bob_seen_by_alice.identity
        })
        .expect("новый ключ записан");

    alice
        .accept_contact_identity(&new_key.account_id, later(2))
        .expect("новый ключ принят");

    // 🔐 Принятие снимает неоднозначность имени, но ключ по-прежнему
    // назвал только сервер: писать можно после подтверждения.
    assert!(matches!(
        alice.send_message("bob", "после принятия", later(3), &mut OsRng),
        Err(AegisError::PeerUnconfirmed)
    ));

    alice
        .set_contact_verified(&new_key.account_id, true, later(3))
        .expect("новый ключ сверен");

    alice
        .send_message("bob", "после принятия", later(3), &mut OsRng)
        .expect("после сверки отправка разрешена");

    // Принятый ключ получает и читает сообщение.
    mallory
        .receive_messages(&mallory_device, later(4))
        .expect("приём");
    assert!(
        texts_of(&mallory)
            .iter()
            .any(|text| text == "после принятия"),
        "принятый ключ не получил сообщение"
    );

    let contacts = alice.contacts().expect("контакты");
    let old = contacts
        .iter()
        .find(|contact| contact.account_id == bob_seen_by_alice.account_id)
        .expect("прежний контакт остался");

    assert!(old.replaced, "прежний ключ не помечен заменённым");
    assert!(
        contacts.iter().all(|contact| !contact.key_changed),
        "после выбора имя всё ещё помечено неоднозначным"
    );
}

/// Сверка нового ключа вживую — тот же выбор, что и принятие.
#[test]
fn verifying_the_new_key_in_person_resolves_the_name() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, bob_seen_by_alice, _mallory, _, _) = substitution_setup(&server, &dir);

    let _ = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    let new_key = alice
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| {
            contact.username.as_deref() == Some("bob")
                && contact.identity != bob_seen_by_alice.identity
        })
        .expect("новый ключ записан");

    alice
        .set_contact_verified(&new_key.account_id, true, later(2))
        .expect("сверен");

    alice
        .send_message("bob", "после сверки", later(3), &mut OsRng)
        .expect("после сверки отправка разрешена");
}

/// 🔐 Сервер, вернувшийся к прежнему — заменённому — ключу, снова получает отказ.
#[test]
fn switching_back_to_a_replaced_key_is_refused_again() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, bob_seen_by_alice, _mallory, _, genuine) = substitution_setup(&server, &dir);

    let _ = alice.send_message("bob", "секрет", later(1), &mut OsRng);

    let new_key = alice
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| {
            contact.username.as_deref() == Some("bob")
                && contact.identity != bob_seen_by_alice.identity
        })
        .expect("новый ключ записан");

    alice
        .accept_contact_identity(&new_key.account_id, later(2))
        .expect("принят");

    server.point_name("bob", genuine);

    let result = alice.send_message("bob", "обратно", later(3), &mut OsRng);

    assert!(
        matches!(result, Err(AegisError::IdentityChanged)),
        "{result:?}"
    );
}

/// 🔐 Ключ, который назвал только сервер, не годится для отправки.
///
/// Прежде первый контакт по имени доверял серверу («доверие при первом
/// использовании»): сервер, назвавший свой ключ, получал первое же
/// сообщение. Теперь писать можно только после подтверждения вне
/// сервера — сверки safety number или ссылки/QR самого собеседника.
#[test]
fn a_key_named_only_by_the_server_cannot_be_written_to() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));
    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    let bob_device = bob
        .register("bob", now(), &mut OsRng)
        .expect("Боб")
        .device_id
        .to_string();

    let result = alice.send_message("bob", "привет", now(), &mut OsRng);
    assert!(
        matches!(result, Err(AegisError::PeerUnconfirmed)),
        "ушло на ключ от сервера: {result:?}"
    );
    assert_eq!(server.queued_for(&bob_device), 0);

    // Контакт записан — неподтверждённым: интерфейс показывает
    // safety number для сверки ещё до первого сообщения.
    let bob_seen = alice.discover_contact("bob", now()).expect("найден");
    assert!(!bob_seen.key_confirmed);

    alice
        .set_contact_verified(&bob_seen.account_id, true, now())
        .expect("сверено при встрече");

    alice
        .send_message("bob", "привет", now(), &mut OsRng)
        .expect("после сверки отправка разрешена");
}

/// Ключ из ссылки или QR самого собеседника подтверждён сразу.
#[test]
fn a_key_from_the_peers_own_link_is_confirmed() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));
    alice.register("alice", now(), &mut OsRng).expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    let contact = alice
        .add_contact_from_link(&bob.own_contact_link().expect("ссылка"), now())
        .expect("добавлен");

    assert!(contact.key_confirmed);
    assert!(!contact.verified, "ссылка — не сверка при встрече");

    alice
        .send_message("bob", "привет", now(), &mut OsRng)
        .expect("по ссылке писать можно");
}

// --- 🔐 Метаданные вложений ------------------------------------------------

/// Минимальный JPEG с EXIF: GPS-координаты и модель камеры.
fn photo_with_location() -> Vec<u8> {
    let segment = |marker: u8, payload: &[u8]| {
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(payload);
        out
    };

    let mut exif = b"Exif\0\0MM\0\x2A\0\0\0\x08\0\0\0\0\0\0".to_vec();
    exif.extend_from_slice(b"GPSLatitude 55.7558 GPSLongitude 37.6173 Model Pixel 8 Pro");

    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend(segment(0xE1, &exif));
    jpeg.extend(segment(0xDB, &[0u8; 65]));
    jpeg.extend(segment(0xC0, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0]));
    jpeg.extend(segment(0xDA, &[1, 1, 0, 0, 63, 0]));
    jpeg.extend_from_slice(&[0x12, 0x34, 0x56, 0xFF, 0xD9]);
    jpeg
}

/// 🔐 Фото приходит без координат, модели камеры и имени файла.
#[test]
fn a_photo_arrives_without_its_metadata() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let descriptor = alice
        .upload_attachment(
            &alice_device,
            &AttachmentFile {
                kind: AttachmentKind::Image,
                bytes: photo_with_location(),
                name: Some("IMG_20260924_183005.jpg".to_owned()),
                description: None,
                duration_millis: None,
                waveform: None,
            },
            now(),
            &mut OsRng,
        )
        .expect("фото загружено");

    assert_eq!(
        descriptor.name, None,
        "имя фото с датой съёмки ушло собеседнику"
    );

    let received = bob
        .fetch_attachment(&bob_device, &descriptor, now())
        .expect("фото скачано");

    for leak in [&b"GPSLatitude"[..], b"55.7558", b"Pixel 8 Pro"] {
        assert!(
            !received.windows(leak.len()).any(|window| window == leak),
            "в фото осталось {}",
            String::from_utf8_lossy(leak)
        );
    }
    assert!(
        received.ends_with(&[0x12, 0x34, 0x56, 0xFF, 0xD9]),
        "кадр испорчен"
    );
}

/// 🔐 Сервер видит не точный размер файла, а его порядок (Padmé).
#[test]
fn the_server_sees_only_a_padded_size() {
    use aegis_core::client::AttachmentFile;
    use aegis_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    let upload = |len: usize| {
        alice
            .upload_attachment(
                &alice_device,
                &AttachmentFile {
                    kind: AttachmentKind::Document,
                    bytes: vec![0x5A; len],
                    name: Some("файл.bin".to_owned()),
                    description: None,
                    duration_millis: None,
                    waveform: None,
                },
                now(),
                &mut OsRng,
            )
            .expect("загружено")
    };

    let first = upload(1_000_001);
    let second = upload(1_010_000);

    let mut sizes: Vec<usize> = server.stored_attachments().iter().map(Vec::len).collect();
    sizes.dedup();

    assert_eq!(sizes.len(), 1, "размеры блобов различимы: {sizes:?}");

    // А получатель получает ровно свой файл.
    assert_eq!(
        bob.fetch_attachment(&bob_device, &first, now())
            .expect("первый")
            .len(),
        1_000_001
    );
    assert_eq!(
        bob.fetch_attachment(&bob_device, &second, now())
            .expect("второй")
            .len(),
        1_010_000
    );
}

// --- 🔐 Пост-квантовый sealed sender ------------------------------------------

/// 🔐 Подменённый сервером ключ ML-KEM получателя не принимается.
///
/// Сервер раздаёт ключ sealed sender; подставив свой, он получил бы
/// пост-квантовую половину внешнего слоя. Подпись identity-ключа
/// получателя это исключает.
#[test]
fn a_substituted_sealed_kem_key_is_refused() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    // Ключ ML-KEM, подписанный не Бобом.
    let forger = aegis_protocol::prekeys::generate_identity(&mut OsRng).expect("identity");
    let forger_pq = aegis_protocol::pq_identity::PqIdentityKeyPair::generate(&mut OsRng);
    let forged_kem = aegis_protocol::mlkem::MlKem1024PrivateKey::generate(&mut OsRng)
        .public_key()
        .as_bytes();
    let forged_signature =
        aegis_protocol::sealed_sender::sign_sealed_kem_key(&forger, &forger_pq, &forged_kem)
            .expect("подпись");

    server.replace_sealed_kem(
        &bob_device,
        Some((hex::encode(&forged_kem), hex::encode(forged_signature))),
    );

    let result = alice.send_message("bob", "секрет", now(), &mut OsRng);

    assert!(result.is_err(), "запечатано на подставленный ключ");
    assert_eq!(server.queued_for(&bob_device), 0);
}

/// 🔐 Нет ключа ML-KEM — нет отправки, а не откат на одну кривую.
///
/// Откат вернул бы «записать сейчас, раскрыть отправителя потом»,
/// и навязать его мог бы сервер, просто не отдав ключ.
#[test]
fn a_missing_sealed_kem_key_does_not_fall_back_to_classical() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    server.replace_sealed_kem(&bob_device, None);

    let result = alice.send_message("bob", "секрет", now(), &mut OsRng);

    assert!(
        matches!(result, Err(AegisError::Uninitialized)),
        "отправка без ключа ML-KEM: {result:?}"
    );
    assert_eq!(server.queued_for(&bob_device), 0);
}

/// Ключ ML-KEM публикуется при регистрации и подписан владельцем.
#[test]
fn the_sealed_kem_key_is_published_at_registration() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, _bob, _alice_device, _bob_device) = alice_and_bob(&server, &dir);

    let bob = aegis_net::client::ApiClient::new(server.clone());
    let found = bob.discover("bob").expect("discovery");

    let public = hex::decode(found.sealed_kem_public.expect("ключ опубликован")).expect("hex");
    let signature =
        hex::decode(found.sealed_kem_signature.expect("подпись опубликована")).expect("hex");
    let identity = aegis_types::PublicKeyBytes::new(
        hex::decode(&found.identity_key)
            .expect("hex")
            .try_into()
            .expect("32 байта"),
    );

    let pq = hex::decode(found.pq_identity_key.expect("половина опубликована")).expect("hex");
    let binding = hex::decode(found.identity_binding.expect("привязка")).expect("hex");

    aegis_protocol::pq_identity::verify_binding(&identity, &pq, &binding)
        .expect("привязка половин");
    aegis_protocol::sealed_sender::verify_sealed_kem_key(&identity, &pq, &public, &signature)
        .expect("подпись владельца");
}

/// 🔐 Сервер подменяет пост-квантовую половину собеседника — своей,
/// со своей же привязкой к **своему** классическому ключу. Привязка
/// к настоящему классическому ключу не сходится: отправки нет.
#[test]
fn a_substituted_pq_identity_is_refused() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    let (_, bob_identity) = server.account_entry("bob");
    let forger = aegis_protocol::prekeys::generate_identity(&mut OsRng).expect("identity");
    let forger_pq = aegis_protocol::pq_identity::PqIdentityKeyPair::generate(&mut OsRng);
    let binding = aegis_protocol::pq_identity::bind(&forger, &forger_pq).expect("привязка");
    server.replace_pq(
        &bob_identity,
        (hex::encode(forger_pq.public()), hex::encode(binding)),
    );

    let result = alice.send_message("bob", "секрет", now(), &mut OsRng);

    assert!(
        result.is_err(),
        "отправлено при чужой пост-квантовой половине"
    );
    assert_eq!(server.queued_for(&bob_device), 0);
}

/// 🔐 Подмена пост-квантовой половины **после** первой встречи —
/// `IdentityChanged`, даже если сервер сумел подделать привязку
/// (квантовый противник подделает классическую подпись). Хеш
/// запомнен и входит в safety number.
#[test]
fn a_changed_pq_identity_after_first_contact_is_refused() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, _bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("первое сообщение");
    let before = server.queued_for(&bob_device);

    // Подменённая половина с «верной» привязкой: в тесте её можно
    // сделать только своим ключом, поэтому проверяется порядок —
    // сверка хеша срабатывает и без неё.
    let (_, bob_identity) = server.account_entry("bob");
    let other_pq = aegis_protocol::pq_identity::PqIdentityKeyPair::generate(&mut OsRng);
    let stranger = aegis_protocol::prekeys::generate_identity(&mut OsRng).expect("identity");
    server.replace_pq(
        &bob_identity,
        (
            hex::encode(other_pq.public()),
            hex::encode(aegis_protocol::pq_identity::bind(&stranger, &other_pq).expect("привязка")),
        ),
    );

    assert!(alice
        .send_message("bob", "второе", now(), &mut OsRng)
        .is_err());
    assert_eq!(
        server.queued_for(&bob_device),
        before,
        "ушло под чужой половиной"
    );
}

/// Safety number одинаков у обеих сторон и зависит от пост-квантовых
/// половин.
#[test]
fn the_safety_number_is_hybrid_and_symmetric() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, _bob_device) = alice_and_bob(&server, &dir);

    let bob_account = alice
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| contact.username.as_deref() == Some("bob"))
        .expect("Боб")
        .account_id;
    let alice_account = bob
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| contact.username.as_deref() == Some("alice"))
        .expect("Алиса")
        .account_id;

    assert_eq!(
        alice.safety_number(&bob_account).expect("у Алисы"),
        bob.safety_number(&alice_account).expect("у Боба")
    );
}

/// Ключ ML-KEM sealed sender, опубликованный на сервере, в hex.
fn published_sealed_kem(server: &FakeServer, username: &str) -> String {
    aegis_net::client::ApiClient::new(server.clone())
        .discover(username)
        .expect("discovery")
        .sealed_kem_public
        .expect("ключ опубликован")
}

/// 🔐 Ключ ML-KEM sealed sender сменяется, и конверт, запечатанный
/// на прежний, всё равно открывается.
///
/// Прежде ключ не менялся никогда: изъятие устройства раскрывало
/// отправителя каждого записанного конверта за всё время.
#[test]
fn the_sealed_kem_key_rotates_and_the_previous_one_still_opens() {
    const DAY: i64 = 24 * 60 * 60 * 1000;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    let before = published_sealed_kem(&server, "bob");

    alice
        .send_message("bob", "до смены ключа", now(), &mut OsRng)
        .expect("отправка");

    let later = Timestamp::from_millis(now().as_millis() + 8 * DAY);
    bob.maintain_prekeys(later, &mut OsRng)
        .expect("обслуживание");

    let after = published_sealed_kem(&server, "bob");
    assert_ne!(before, after, "ключ ML-KEM не сменился за восемь дней");

    assert_eq!(
        bob.receive_messages(&bob_device, later).expect("приём"),
        1,
        "конверт, запечатанный на прежний ключ, потерян"
    );

    // Следующее сообщение запечатано уже на новый ключ.
    alice
        .send_message("bob", "после смены", later, &mut OsRng)
        .expect("отправка");
    assert_eq!(
        bob.receive_messages(&bob_device, later).expect("приём"),
        1,
        "конверт на новый ключ не открылся"
    );
}

/// 🔐 Выведенный ключ ML-KEM стирается через месяц: запечатанное
/// на него больше не открывается даже на самом устройстве.
///
/// Месяц — срок жизни конверта в очереди. Дольше ключ хранить незачем,
/// а каждый лишний день — прошлое, которое откроет изъятое устройство.
#[test]
fn a_retired_sealed_kem_key_is_erased_after_a_month() {
    const DAY: i64 = 24 * 60 * 60 * 1000;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    // Сессия установлена: дальше проверяется только внешний слой.
    alice
        .send_message("bob", "привет", now(), &mut OsRng)
        .expect("отправка");
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);

    alice
        .send_message("bob", "на старый ключ", now(), &mut OsRng)
        .expect("отправка");

    let rotated = Timestamp::from_millis(now().as_millis() + 8 * DAY);
    bob.maintain_prekeys(rotated, &mut OsRng).expect("смена");

    let month_later = Timestamp::from_millis(rotated.as_millis() + 31 * DAY);
    bob.maintain_prekeys(month_later, &mut OsRng)
        .expect("чистка");

    assert_eq!(
        bob.receive_messages(&bob_device, month_later).unwrap_or(0),
        0,
        "конверт открылся ключом, который должен быть стёрт"
    );
}

/// 🔐 Имя приводится к каноничной форме, двойник отвергается до сети.
///
/// «@Bob» находит «bob»; «bоb» с кириллической «о» не находит никого
/// и на сервер не уходит: запрос выдал бы, кого искали.
#[test]
fn usernames_are_canonical_and_lookalikes_are_refused() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    alice
        .register("  Alice ", now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");
    assert_eq!(alice.own_username().expect("имя").as_deref(), Some("alice"));

    let found = alice.discover_contact("@Bob", now()).expect("поиск");
    assert_eq!(found.username.as_deref(), Some("bob"));

    for lookalike in ["b\u{43e}b", "bob\u{200b}", "bo b"] {
        assert!(
            matches!(
                alice.discover_contact(lookalike, now()),
                Err(AegisError::InvalidUsername)
            ),
            "двойник {lookalike:?} не отвергнут"
        );
    }

    assert!(matches!(
        Client::new(server.clone(), open_storage(&dir, "mallory.db")).register(
            "\u{430}lice",
            now(),
            &mut OsRng
        ),
        Err(AegisError::InvalidUsername)
    ));
}

/// 🔐 Ключ доступа sealed sender публикуется обслуживанием ключей,
/// а не первым отправленным сообщением: у нового пользователя центр
/// безопасности не показывает «sealed sender: нет».
#[test]
fn a_new_account_publishes_its_access_key_without_writing_to_anyone() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    alice
        .register("alice", now(), &mut OsRng)
        .expect("регистрация");
    assert!(!alice.sealed_sender_enabled().expect("чтение"));

    alice
        .maintain_prekeys(now(), &mut OsRng)
        .expect("обслуживание");

    assert!(
        alice
            .security_report(now())
            .expect("отчёт")
            .sealed_sender_enabled,
        "ключ доступа не опубликован без отправки"
    );
}

/// 🔐 Первое сообщение от собеседника — запрос: до принятия ему
/// не уходят ни квитанции, ни «печатает…».
#[test]
fn a_first_message_is_a_request_until_accepted() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice.set_presence_sharing(true).expect("настройка");
    bob.set_presence_sharing(true).expect("настройка");

    let sent = alice
        .send_message("bob", "привет, это Алиса", now(), &mut OsRng)
        .expect("отправка");
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);

    let alice_chat = alice.chats().expect("чаты")[0];
    let bob_chat = bob.chats().expect("чаты")[0];
    assert_eq!(
        alice.chat_request(&alice_chat).expect("состояние"),
        Some(ChatRequest::Outgoing)
    );
    assert_eq!(
        bob.chat_request(&bob_chat).expect("состояние"),
        Some(ChatRequest::Incoming)
    );

    // Непринятый запрос: квитанция и «печатает…» не уходят.
    bob.send_read_receipt("alice", &sent, now(), &mut OsRng)
        .expect("квитанция молча пропущена");
    bob.send_typing("alice", true, now(), &mut OsRng)
        .expect("индикатор молча пропущен");
    assert_eq!(
        alice.receive_messages(&alice_device, now()).expect("приём"),
        0,
        "незнакомец узнал, что сообщение прочли"
    );
    assert_eq!(
        alice.chat_request(&alice_chat).expect("состояние"),
        Some(ChatRequest::Outgoing),
        "запрос у Алисы закрылся без ответа Боба"
    );

    // Принятие: у Боба — сразу, у Алисы — когда дойдёт ключ доступа.
    bob.accept_chat(&bob_chat, now(), &mut OsRng)
        .expect("принятие");
    assert_eq!(
        bob.chat_request(&bob_chat).expect("состояние"),
        Some(ChatRequest::Settled)
    );

    alice.receive_messages(&alice_device, now()).expect("приём");
    assert_eq!(
        alice.chat_request(&alice_chat).expect("состояние"),
        Some(ChatRequest::Settled),
        "Алиса не узнала о принятии"
    );
}

/// Собственный ответ в запрос — согласие.
#[test]
fn replying_to_a_request_accepts_it() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "привет", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, now()).expect("приём");
    let bob_chat = bob.chats().expect("чаты")[0];

    bob.send_message("alice", "привет-привет", now(), &mut OsRng)
        .expect("ответ");

    assert_eq!(
        bob.chat_request(&bob_chat).expect("состояние"),
        Some(ChatRequest::Settled)
    );
}

/// 🔐 Отклонённый запрос исчезает целиком, и в ответ не уходит ничего.
#[test]
fn declining_a_request_deletes_it_silently() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "купи курс", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, now()).expect("приём");
    let bob_chat = bob.chats().expect("чаты")[0];

    bob.decline_chat(&bob_chat, now()).expect("отказ");

    assert!(
        bob.chats().expect("чаты").is_empty(),
        "отклонённый чат остался"
    );
    assert!(bob.messages(&bob_chat, 10).expect("сообщения").is_empty());
    assert_eq!(bob.chat_request(&bob_chat).expect("состояние"), None);
    assert_eq!(
        alice.receive_messages(&alice_device, now()).expect("приём"),
        0,
        "отказ что-то отправил незнакомцу"
    );
}

/// 🔐 Ключ ML-KEM sealed sender сменяется не один раз, а каждую неделю.
///
/// Прежде после смены обслуживание не отмечало новый ключ
/// опубликованным: срок следующей смены не наступал никогда,
/// а ключ переотправлялся при каждом запуске.
#[test]
fn the_sealed_kem_key_keeps_rotating() {
    const DAY: i64 = 24 * 60 * 60 * 1000;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, bob, _alice_device, _bob_device) = alice_and_bob(&server, &dir);

    let first = published_sealed_kem(&server, "bob");

    let week = Timestamp::from_millis(now().as_millis() + 8 * DAY);
    bob.maintain_prekeys(week, &mut OsRng)
        .expect("обслуживание");
    let second = published_sealed_kem(&server, "bob");

    // На следующий день делать нечего: ключ свежий и опубликован.
    let publishes = server.total_publishes();
    let next_day = Timestamp::from_millis(week.as_millis() + DAY);
    bob.maintain_prekeys(next_day, &mut OsRng)
        .expect("обслуживание");
    assert_eq!(
        server.total_publishes(),
        publishes,
        "свежий ключ переотправлен"
    );

    let two_weeks = Timestamp::from_millis(week.as_millis() + 8 * DAY);
    bob.maintain_prekeys(two_weeks, &mut OsRng)
        .expect("обслуживание");
    let third = published_sealed_kem(&server, "bob");

    assert_ne!(first, second, "первая смена не случилась");
    assert_ne!(second, third, "вторая смена не случилась");
}

/// 🔐 Переустановка: копия возвращает аккаунт **с прежним именем**
/// на новую identity. Приватный identity-ключ не копировался —
/// собеседник видит смену ключа, а имя занять нельзя.
#[test]
fn a_reinstalled_device_gets_its_account_and_name_back() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);
    let (alice_account, old_identity) = server.account_entry("alice");

    alice
        .send_message("bob", "до переустановки", now(), &mut OsRng)
        .expect("отправка");
    bob.receive_messages(&bob_device, now()).expect("приём");

    let backup_key = aegis_backup::RecoveryKey::generate(&mut OsRng);
    let backup = alice
        .create_backup(&backup_key, None, now(), &mut OsRng)
        .expect("копия");

    // «Переустановка»: новая база, ни ключей, ни устройства.
    let reinstalled = Client::new(server.clone(), open_storage(&dir, "alice-reinstalled.db"));
    let (account, outcome) = reinstalled
        .recover_account(&backup_key, &[backup.archive], later(10), &mut OsRng)
        .expect("аккаунт возвращён");

    assert_eq!(account.username, "alice");
    assert_eq!(
        account.account_id.to_string(),
        alice_account,
        "аккаунт другой"
    );
    assert!(outcome.identity_changed);

    let (_, new_identity) = server.account_entry("alice");
    assert_ne!(
        new_identity, old_identity,
        "приватный identity-ключ скопирован"
    );

    // Переписка вернулась.
    let chat = reinstalled.chats().expect("чаты")[0];
    assert!(reinstalled
        .messages(&chat, 10)
        .expect("сообщения")
        .iter()
        .any(|message| message.text == "до переустановки"));

    // 🔐 Собеседник видит смену ключа и без новой сверки не пишет.
    assert!(matches!(
        bob.send_message("alice", "это ты?", later(11), &mut OsRng),
        Err(AegisError::IdentityChanged)
    ));
}

/// 🔐 Копия без ключа восстановления аккаунта имени не возвращает —
/// в том числе копия **чужого** аккаунта: ключ из неё подпишет только
/// своё имя.
#[test]
fn another_accounts_backup_cannot_take_a_name() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, bob, _alice_device, _bob_device) = alice_and_bob(&server, &dir);
    let (_, alice_identity) = server.account_entry("alice");

    // Копия Боба возвращает Боба, а не Алису.
    let backup_key = aegis_backup::RecoveryKey::generate(&mut OsRng);
    let backup = bob
        .create_backup(&backup_key, None, now(), &mut OsRng)
        .expect("копия");

    let stranger = Client::new(server.clone(), open_storage(&dir, "stranger.db"));
    let (account, _) = stranger
        .recover_account(&backup_key, &[backup.archive], later(10), &mut OsRng)
        .expect("возвращение Боба");

    assert_eq!(account.username, "bob");
    assert_eq!(
        server.account_entry("alice").1,
        alice_identity,
        "имя Алисы тронуто"
    );
}

/// 🔐 Журнал ключей (§9.7): ключ, простоявший в журнале сутки, годится
/// для отправки без личной сверки — и контакт помечен именно так.
/// Запросы к журналу уходят без подписи устройства.
#[test]
fn a_key_a_day_old_in_the_log_needs_no_manual_check() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, bob) = unconfirmed_pair(&server, &dir);

    server.publish_kt_epochs(now_epoch() - kt::TRUST_DELAY_EPOCHS - 2, now_epoch());

    let contact = bob.discover_contact("alice", now()).expect("Алиса найдена");
    assert!(contact.key_confirmed, "журнал не подтвердил ключ");
    assert!(
        contact.kt_confirmed,
        "подтверждение журналом не отмечено отдельно"
    );

    bob.send_message("alice", "привет по журналу", now(), &mut OsRng)
        .expect("отправка без личной сверки");

    let state = server.state.borrow();
    let kt_requests: Vec<_> = state
        .requests
        .iter()
        .filter(|(path, _)| path.starts_with("/v1/kt/"))
        .collect();
    assert!(!kt_requests.is_empty(), "журнал не спрашивали");
    assert!(
        kt_requests.iter().all(|(_, headers)| headers.is_empty()),
        "запрос к журналу подписан — сервер знает, кто проверяет"
    );
}

/// 🔐 Ключ младше суток в журнале — только личная сверка: свежую
/// подмену владелец имени должен успеть увидеть раньше.
#[test]
fn a_fresh_key_in_the_log_still_needs_a_manual_check() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, bob) = unconfirmed_pair(&server, &dir);

    server.publish_kt_epochs(now_epoch() - 3, now_epoch());

    let contact = bob.discover_contact("alice", now()).expect("Алиса найдена");
    assert!(!contact.key_confirmed);

    assert!(matches!(
        bob.send_message("alice", "рано", now(), &mut OsRng),
        Err(AegisError::PeerUnconfirmed)
    ));
}

/// 🔐 Подменённый в журнале ключ не подтверждается, а владелец имени
/// находит подмену у себя и получает событие безопасности.
#[test]
fn a_forged_key_under_my_name_is_found_by_me() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    // Алиса зарегистрирована заранее: её проверка начинается раньше
    // поддельных эпох.
    alice
        .register("alice", later(-6 * 3600), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", now(), &mut OsRng).expect("Боб");

    let start = now_epoch() - kt::TRUST_DELAY_EPOCHS - 2;
    for epoch in start..=now_epoch() {
        let forged: &[(&str, [u8; 32])] = if epoch >= now_epoch() - 3 {
            &[("alice", [0x66; 32])]
        } else {
            &[]
        };
        server.publish_kt_epoch(epoch, forged);
    }

    // Бобу подделку не подтвердить: сутки назад в журнале был другой лист.
    let contact = bob.discover_contact("alice", now()).expect("Алиса найдена");
    assert!(!contact.key_confirmed, "подделка подтвердилась");

    let check = alice.kt_check_self(now()).expect("проверка своего имени");
    assert_eq!(check.foreign_epochs.len(), 4, "подмена не найдена");
    assert!(alice
        .security_events(10)
        .expect("журнал")
        .iter()
        .any(|(kind, _, _)| kind == "kt_foreign_key_for_own_name"));

    // Проверенное не проверяется заново.
    let again = alice.kt_check_self(now()).expect("повтор");
    assert!(again.foreign_epochs.is_empty());
}

/// 🔐 Сервер переписал цепочку, которую уже показывал: клиент замечает
/// это и не принимает новую как продолжение.
#[test]
fn a_rewritten_log_is_detected() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, bob) = unconfirmed_pair(&server, &dir);

    server.publish_kt_epochs(now_epoch() - 2, now_epoch());
    bob.kt_sync(now()).expect("первая синхронизация");

    server.forget_kt_history();
    for epoch in now_epoch() - 2..=now_epoch() + 1 {
        server.publish_kt_epoch(epoch, &[("alice", [0x77; 32])]);
    }

    assert!(
        bob.kt_sync(later(3600)).is_err(),
        "переписанная цепочка принята"
    );
    assert!(bob
        .security_events(10)
        .expect("журнал")
        .iter()
        .any(|(kind, _, _)| kind == "kt_log_forked"));
}
