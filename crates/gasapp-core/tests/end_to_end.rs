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

use gasapp_core::client::{ChatRequest, Client, Contact};
use gasapp_net::api::{
    BundleResponse, CertificateResponse, DiscoveryResponse, EnvelopeResponse, PublishKeysRequest,
    RegisterRequest, RegisterResponse, SealedAccessRequest, SealedReportRequest,
    SealedReportResponse, SealedSendRequest,
};
use gasapp_net::client::{HttpRequest, HttpResponse, Method, Transport};
use gasapp_protocol::key_transparency as kt;
use gasapp_protocol::sealed_sender::{self, SenderCertificate};
use gasapp_protocol::xeddsa;
use gasapp_storage::{MessageStatus, Storage};
use gasapp_types::{AccountId, GasAppError, PrivateKeyBytes, PublicKeyBytes, Result, Timestamp};
use sha2::{Digest, Sha256};

/// Адрес почты и код из письма для регистрации у поддельного сервера.
///
/// Заглушка письма не отправляет и код не сверяет — это проверяют
/// интеграционные тесты настоящего сервера (`email_channels.rs`).
/// Здесь важно, что клиент их **передаёт**.
const TEST_EMAIL: &str = "tester@test.example";
const TEST_EMAIL_CODE: &str = "424242";

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
    /// Невыкупленные токены ботов: токен → устройство владельца и имя.
    bot_tokens: HashMap<String, (String, String)>,
    /// Боты: имя → устройство владельца.
    bots: HashMap<String, String>,
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

    /// 🔐 Discovery отвечает 429 — как при чужом переборе по имени.
    discovery_refused: bool,

    /// Сервер не принимает конверты — как при обрыве сети посреди отправки.
    sends_refused: bool,

    /// 🔐 «Сервер» не выдаёт доказательств журнала для этого индекса.
    kt_refused_index: Option<[u8; 32]>,

    /// Журнал ключей (§9.7): эпохи — номер, корень, вершина, дерево
    /// и листы (identity, хеш PQ-половины, версия) по индексу.
    kt_epochs: Vec<KtEpochState>,

    /// Жалобы: (устройство жалобщика, устройство отправителя из
    /// проверенного сертификата) — одна пара учитывается один раз.
    reports: Vec<(String, [u8; 16])>,

    /// Адреса почты, на которые клиенты просили код.
    email_code_requests: Vec<String>,
    /// Сколько бит работы стоит письмо сейчас.
    email_difficulty: u32,
    /// На сколько бит занизить ближайший ответ о цене: узел
    /// «нагрузили» между вопросом и решением.
    email_price_jumps: u32,
    /// Адрес и код, с которыми пришла последняя регистрация.
    last_registration_email: Option<(String, String)>,
    /// Устройства с премиумом — как после решения оператора.
    premium_devices: std::collections::HashSet<String>,
    /// Каналы по идентификатору.
    channels: HashMap<String, FakeChannel>,
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

/// Окно времени, которое называет поддельный сервер.
const EMAIL_WINDOW: u64 = 2_933_334;

impl FakeServer {
    fn new() -> Self {
        Self {
            state: std::rc::Rc::new(RefCell::new(ServerState {
                email_difficulty: 20,
                ..ServerState::default()
            })),
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

    /// Оператор выдаёт (или снимает) премиум устройству.
    fn set_premium(&self, device_id: &str, premium: bool) {
        let mut state = self.state.borrow_mut();

        if premium {
            state.premium_devices.insert(device_id.to_owned());
        } else {
            state.premium_devices.remove(device_id);
        }
    }

    /// Канал в том виде, в каком его хранит «сервер».
    fn channel(&self, channel_id: &str) -> FakeChannel {
        self.state.borrow().channels[channel_id].clone()
    }

    /// 🔐 «Сервер» переписывает канал по своему усмотрению.
    fn tamper_channel(&self, channel_id: &str, change: impl FnOnce(&mut FakeChannel)) {
        let mut state = self.state.borrow_mut();
        change(state.channels.get_mut(channel_id).expect("канал есть"));
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

/// Запись канала у поддельного сервера.
#[derive(Clone, Default)]
struct FakePost {
    /// Шифротекст либо отметка об удалении, hex.
    body: String,
    rev: u64,
    deleted: bool,
    /// Реакции: устройство подписчика → эмодзи.
    reactions: HashMap<String, String>,
}

/// Канал у поддельного сервера: ровно то, что знает настоящий.
#[derive(Clone, Default)]
struct FakeChannel {
    owner_device: String,
    verify_key: String,
    meta: String,
    /// Записи; номер записи — место в списке плюс один.
    posts: Vec<FakePost>,
    last_rev: u64,
    handle: Option<String>,
    public_link: Option<String>,
    /// Медиаблобы по адресу.
    media: HashMap<String, Vec<u8>>,
    /// Подписчики: устройство → до какой записи дочитал.
    subscribers: HashMap<String, u64>,
    /// Администраторы: устройство → ключ подписи, hex.
    admins: HashMap<String, String>,
    /// Сколько ближайших публикаций отвергнуть как «номер занят».
    conflicts: u32,
    /// Закрытый ли канал.
    closed: bool,
    /// Хеши меток действующих ссылок-приглашений, hex.
    invites: std::collections::HashSet<String>,
    /// Заявки: аккаунт → заявка, hex.
    requests: HashMap<String, String>,
    /// Ответы на одобренные заявки: аккаунт → ответ, hex.
    grants: HashMap<String, String>,
    /// Удалённые из канала аккаунты.
    bans: std::collections::HashSet<String>,
    /// Номер действующей эпохи ключа.
    key_epoch: u32,
    /// Звенья цепочки ключей: звено эпохи `n` — на месте `n - 1`.
    epochs: Vec<String>,
    /// Ключи доставки участников: аккаунт → ключ, hex.
    member_keys: HashMap<String, String>,
    /// Удостоверения участников: аккаунт → подпись ведущего канал, hex.
    approvals: HashMap<String, String>,
    /// Под какую эпоху выдан ответ аккаунту.
    grant_epochs: HashMap<String, u32>,
    /// Сколько ближайших смен ключа отвергнуть как сбой сети.
    rekey_failures: u32,
    /// Жалобы: причина и ссылка канала, если её приложили.
    reports: Vec<(u8, Option<String>)>,
}

impl FakeChannel {
    /// Дописывает запись — как публикация; возвращает номер и ревизию.
    fn push(&mut self, body: String) -> (u64, u64) {
        self.last_rev += 1;
        self.posts.push(FakePost {
            body,
            rev: self.last_rev,
            ..FakePost::default()
        });

        (self.posts.len() as u64, self.last_rev)
    }

    fn info(&self, channel_id: &str) -> gasapp_net::api::ChannelResponse {
        gasapp_net::api::ChannelResponse {
            channel_id: channel_id.to_owned(),
            verify_key: self.verify_key.clone(),
            meta: self.meta.clone(),
            last_seq: self.posts.len() as u64,
            last_rev: self.last_rev,
            handle: self.handle.clone(),
            public_link: self.public_link.clone(),
            subscribers: self.subscribers.len() as u64,
            closed: self.closed,
            key_epoch: self.key_epoch,
        }
    }

    /// Сделана ли запись под действующей эпохой ключа.
    fn current_epoch(&self, body_hex: &str) -> bool {
        let body = hex::decode(body_hex).unwrap_or_default();
        let epoch = match body.as_slice() {
            [3, a, b, c, d, ..] => u32::from_be_bytes([*a, *b, *c, *d]),
            _ => 0,
        };

        epoch == self.key_epoch
    }

    /// Участник ли устройство: владелец, администратор либо подписчик.
    fn member(&self, device_id: &str) -> bool {
        self.owner_device == device_id
            || self.admins.contains_key(device_id)
            || self.subscribers.contains_key(device_id)
    }

    fn post(&self, index: usize) -> gasapp_net::api::ChannelPostResponse {
        let post = &self.posts[index];
        let seq = index as u64 + 1;

        let mut counts: Vec<(String, u64)> = Vec::new();
        for emoji in post.reactions.values() {
            match counts.iter_mut().find(|(known, _)| known == emoji) {
                Some((_, count)) => *count += 1,
                None => counts.push((emoji.clone(), 1)),
            }
        }
        counts.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));

        gasapp_net::api::ChannelPostResponse {
            seq,
            rev: post.rev,
            body: post.body.clone(),
            deleted: post.deleted,
            posted_at: 0,
            views: self
                .subscribers
                .values()
                .filter(|seen| **seen >= seq)
                .count() as u64,
            reactions: counts
                .iter()
                .map(|(emoji, count)| format!("{emoji}:{count}"))
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

fn plain(status: u16, body: String) -> HttpResponse {
    HttpResponse {
        status,
        body,
        binary_body: Vec::new(),
    }
}

fn json(value: &impl ChannelJson) -> HttpResponse {
    plain(200, value.to_json())
}

/// Ответы каналов, которые уходят в JSON: у тестов нет своей
/// зависимости от `serde`, только от `serde_json`.
trait ChannelJson {
    fn to_json(&self) -> String;
}

impl ChannelJson for gasapp_net::api::ChannelResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl ChannelJson for Vec<gasapp_net::api::ChannelResponse> {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl ChannelJson for Vec<gasapp_net::api::ChannelPostResponse> {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl ChannelJson for Vec<gasapp_net::api::ChannelMemberResponse> {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl ChannelJson for Vec<gasapp_net::api::ChannelJoinRequestResponse> {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl ChannelJson for gasapp_net::api::ChannelJoinStatusResponse {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Место записи в списке по её номеру; несуществующий номер даёт
/// место за концом списка.
fn post_index(seq: u64) -> usize {
    usize::try_from(seq).unwrap_or(0).wrapping_sub(1)
}

fn query_number(query: &str, name: &str) -> Option<u64> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
        .and_then(|value| value.parse().ok())
}

/// Боты поддельного сервера — те же маршруты, что у настоящего
/// (`gasapp-server-api::bots`).
fn bot_route(state: &mut ServerState, request: &HttpRequest, signed: bool) -> HttpResponse {
    let path = request.path.as_str();
    let body = request.body.as_deref().unwrap_or_default();

    if path == "/v1/bots/register" {
        // Программа бота аккаунта ещё не имеет: запрос не подписан.
        assert!(!signed, "регистрация бота не может быть подписана");

        let Ok(parsed) = serde_json::from_str::<gasapp_net::api::RegisterBotRequest>(body) else {
            return plain(400, String::new());
        };

        // Токен годится один раз и только под своё имя.
        let Some((owner_device, _)) = state
            .bot_tokens
            .get(&parsed.token)
            .filter(|(_, username)| *username == parsed.username)
            .cloned()
        else {
            return plain(403, String::new());
        };
        state.bot_tokens.remove(&parsed.token);

        let account_id = FakeServer::next_uuid(state);
        let device_id = FakeServer::next_uuid(state);

        state.accounts.insert(
            parsed.username.clone(),
            (account_id.clone(), parsed.identity_key.clone()),
        );
        state.pq.insert(
            parsed.identity_key,
            (parsed.pq_identity_key, parsed.identity_binding),
        );
        state.devices.insert(account_id.clone(), device_id.clone());
        state
            .device_identity
            .insert(device_id.clone(), parsed.device_identity_key);
        state.bots.insert(parsed.username, owner_device);

        return plain(
            200,
            serde_json::to_string(&RegisterResponse {
                account_id,
                device_id,
            })
            .unwrap_or_default(),
        );
    }

    let Some(device_id) = path.strip_prefix("/v1/bots/own/") else {
        return plain(404, String::new());
    };

    if !signed || !state.device_identity.contains_key(device_id) {
        return plain(401, String::new());
    }

    let named =
        serde_json::from_str::<gasapp_net::api::BotNameRequest>(body).map(|parsed| parsed.username);

    match request.method {
        Method::Post => {
            let Ok(username) = named else {
                return plain(400, String::new());
            };

            if !state.premium_devices.contains(device_id) {
                return plain(403, String::new());
            }
            if !username.ends_with("bot") {
                return plain(400, String::new());
            }
            // Свой невыкупленный токен под это имя заменяется — как на
            // настоящем сервере.
            state
                .bot_tokens
                .retain(|_, (owner, held)| !(owner.as_str() == device_id && *held == username));
            if state.accounts.contains_key(&username)
                || state.bot_tokens.values().any(|(_, held)| *held == username)
            {
                return plain(409, String::new());
            }

            state.counter += 1;
            let token = format!("{:064x}", state.counter);
            state
                .bot_tokens
                .insert(token.clone(), (device_id.to_owned(), username));

            plain(200, format!(r#"{{"token":"{token}","expires_in":3600}}"#))
        }
        Method::Get => {
            let mut list: Vec<_> = state
                .bots
                .iter()
                .filter(|(_, owner)| owner.as_str() == device_id)
                .map(|(username, _)| {
                    serde_json::json!({
                        "account_id": state.accounts[username].0,
                        "username": username,
                    })
                })
                .collect();
            list.extend(
                state
                    .bot_tokens
                    .values()
                    .filter(|(owner, _)| owner.as_str() == device_id)
                    .map(|(_, username)| {
                        serde_json::json!({
                            "account_id": "00000000-0000-0000-0000-000000000000",
                            "username": username,
                            "pending": true,
                            "expires_in": 3600,
                        })
                    }),
            );
            list.sort_by_key(|bot| bot["username"].as_str().map(str::to_owned));

            plain(200, serde_json::Value::Array(list).to_string())
        }
        Method::Delete => {
            let Ok(username) = named else {
                return plain(400, String::new());
            };

            let before = state.bot_tokens.len();
            state
                .bot_tokens
                .retain(|_, (owner, held)| !(owner.as_str() == device_id && *held == username));
            let token_removed = state.bot_tokens.len() != before;
            if state.bots.get(&username).map(String::as_str) != Some(device_id) {
                return plain(if token_removed { 204 } else { 404 }, String::new());
            }

            state.bots.remove(&username);
            if let Some((account_id, _)) = state.accounts.remove(&username) {
                if let Some(bot_device) = state.devices.remove(&account_id) {
                    state.device_identity.remove(&bot_device);
                }
            }

            plain(204, String::new())
        }
        Method::Put => plain(404, String::new()),
    }
}

/// Каналы поддельного сервера — те же маршруты, что у настоящего
/// (`gasapp-server-api::channels`).
fn channel_route(state: &mut ServerState, request: &HttpRequest, signed: bool) -> HttpResponse {
    let path = request.path.as_str();
    let body = request.body.as_deref().unwrap_or_default();

    if let Some(rest) = path.strip_prefix("/v1/channels/feed/") {
        // 🔐 Чтение ленты анонимно: эти запросы не подписаны.
        assert!(!signed, "чтение канала не должно быть подписано");

        return channel_feed(state, request, rest);
    }

    if let Some(rest) = path.strip_prefix("/v1/channels/reader/") {
        // 🔐 Подписчик — аккаунт: его действия подписаны устройством.
        let mut parts = rest.split('/');
        let device_id = parts.next().unwrap_or_default();
        let channel_id = parts.next().unwrap_or_default();
        let action = parts.next().unwrap_or_default();

        if !signed || !state.device_identity.contains_key(device_id) {
            return plain(401, String::new());
        }

        let tail = rest.splitn(3, '/').nth(2).unwrap_or_default();

        if let Some(response) = channel_member_route(state, request, device_id, channel_id, tail) {
            return response;
        }

        let Some(channel) = state.channels.get_mut(channel_id) else {
            return plain(404, String::new());
        };

        // 🔐 В закрытый канал подписчиком делает только одобренная заявка.
        if action == "subscribe" && channel.closed && !channel.subscribers.contains_key(device_id) {
            return plain(403, String::new());
        }

        return channel_reader_action(channel, device_id, action, body);
    }

    if let Some(handle) = path.strip_prefix("/v1/channels/handle/") {
        assert!(!signed, "поиск канала не должен быть подписан");

        return state
            .channels
            .iter()
            .find(|(_, channel)| channel.handle.as_deref() == Some(handle))
            .map_or_else(
                || plain(404, String::new()),
                |(id, channel)| json(&channel.info(id)),
            );
    }

    if let Some(prefix) = path.strip_prefix("/v1/channels/search?q=") {
        assert!(!signed, "поиск канала не должен быть подписан");

        let mut found: Vec<_> = state
            .channels
            .iter()
            .filter(|(_, channel)| {
                channel
                    .handle
                    .as_deref()
                    .is_some_and(|handle| handle.starts_with(prefix))
            })
            .map(|(id, channel)| channel.info(id))
            .collect();
        found.sort_by(|left, right| left.handle.cmp(&right.handle));

        return json(&found);
    }

    let Some(rest) = path.strip_prefix("/v1/channels/own/") else {
        return plain(404, String::new());
    };

    let (rest, _) = rest.split_once('?').unwrap_or((rest, ""));
    let mut parts = rest.split('/');
    let device_id = parts.next().unwrap_or_default().to_owned();
    let channel_id = parts.next().map(str::to_owned);
    let tail = parts.next();

    // Свои каналы — только за подписью устройства.
    if !signed || !state.device_identity.contains_key(&device_id) {
        return plain(401, String::new());
    }

    let Some(channel_id) = channel_id else {
        let Ok(parsed) = serde_json::from_str::<gasapp_net::api::CreateChannelRequest>(body) else {
            return plain(400, String::new());
        };

        if !state.premium_devices.contains(&device_id) {
            return plain(403, String::new());
        }

        state.channels.insert(
            parsed.channel_id,
            FakeChannel {
                owner_device: device_id,
                verify_key: parsed.verify_key,
                meta: parsed.meta,
                ..FakeChannel::default()
            },
        );

        return plain(201, String::new());
    };

    let Some(channel) = state.channels.get(&channel_id) else {
        return plain(404, String::new());
    };
    let owned = channel.owner_device == device_id;
    let writes = owned || channel.admins.contains_key(&device_id);

    // Записи и файлы — владелец и администраторы; остальное — владелец.
    let allowed = match tail {
        Some("posts" | "media" | "invites" | "requests" | "subscribers" | "bans" | "keys") => {
            writes
        }
        _ => owned,
    };
    if !allowed {
        return plain(404, String::new());
    }

    if matches!(
        tail,
        Some("invites" | "requests" | "subscribers" | "bans" | "keys")
    ) {
        return channel_moderation(state, request, &channel_id, tail.unwrap_or_default());
    }

    match (&request.method, tail) {
        (Method::Post, Some("admins")) => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::AddChannelAdminRequest>(body)
            else {
                return plain(400, String::new());
            };

            if !state.device_identity.contains_key(&parsed.device_id) {
                return plain(404, String::new());
            }
            if parsed.device_id == device_id {
                return plain(400, String::new());
            }

            state
                .channels
                .get_mut(&channel_id)
                .expect("канал есть")
                .admins
                .insert(parsed.device_id, parsed.verify_key);

            plain(204, String::new())
        }
        (Method::Delete, Some("admins")) => {
            let Ok(parsed) =
                serde_json::from_str::<gasapp_net::api::RemoveChannelAdminRequest>(body)
            else {
                return plain(400, String::new());
            };

            state
                .channels
                .get_mut(&channel_id)
                .expect("канал есть")
                .admins
                .retain(|_, key| *key != parsed.verify_key);

            plain(204, String::new())
        }
        (Method::Put, None) => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::UpdateChannelRequest>(body)
            else {
                return plain(400, String::new());
            };

            if parsed.set_public
                && parsed.handle.is_some()
                && state
                    .channels
                    .iter()
                    .any(|(id, channel)| *id != channel_id && channel.handle == parsed.handle)
            {
                return plain(409, String::new());
            }

            let channel = state.channels.get_mut(&channel_id).expect("канал есть");

            // Закрытый канал публичным не бывает — и наоборот; канал,
            // у которого меняли ключ, остаётся закрытым.
            if parsed.closed == Some(false) && channel.key_epoch > 0 {
                return plain(400, String::new());
            }
            if parsed.closed == Some(true) && channel.handle.is_some()
                || parsed.set_public && parsed.handle.is_some() && channel.closed
            {
                return plain(400, String::new());
            }
            if let Some(closed) = parsed.closed {
                channel.closed = closed;
            }

            if let Some(meta) = parsed.meta {
                channel.meta = meta;
            }
            if parsed.set_public {
                channel.public_link = parsed.handle.as_ref().and(parsed.public_link);
                channel.handle = parsed.handle;
            }

            plain(204, String::new())
        }
        (Method::Delete, None) => {
            state.channels.remove(&channel_id);

            plain(204, String::new())
        }
        (Method::Post, Some("posts")) => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::PublishPostRequest>(body)
            else {
                return plain(400, String::new());
            };
            let channel = state.channels.get_mut(&channel_id).expect("канал есть");

            // Запись под ключом, который сменили, не принимается.
            if !channel.current_epoch(&parsed.body) {
                return plain(409, String::new());
            }

            // Кто-то написал в канал между «узнал номер» и «опубликовал».
            if channel.conflicts > 0 {
                channel.conflicts -= 1;
                channel.push(hex::encode([0x42u8; 600]));
            }

            // Как настоящий сервер: запись под чужим номером не сохраняется.
            if parsed
                .seq
                .is_some_and(|expected| expected != channel.posts.len() as u64 + 1)
            {
                return plain(409, String::new());
            }

            let (seq, rev) = channel.push(parsed.body);

            plain(200, format!(r#"{{"seq":{seq},"rev":{rev}}}"#))
        }
        (Method::Put, Some("posts")) => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::ReplacePostRequest>(body)
            else {
                return plain(400, String::new());
            };
            let channel = state.channels.get_mut(&channel_id).expect("канал есть");
            let index = post_index(parsed.seq);

            if !channel.current_epoch(&parsed.body) {
                return plain(409, String::new());
            }

            // Удалённую запись настоящий сервер тоже не заменяет.
            if channel.posts.get(index).is_none_or(|post| post.deleted) {
                return plain(404, String::new());
            }

            channel.last_rev += 1;
            let rev = channel.last_rev;
            let post = &mut channel.posts[index];
            post.body = parsed.body;
            post.rev = rev;
            post.deleted = parsed.deleted;
            if parsed.deleted {
                post.reactions.clear();
            }

            plain(200, format!(r#"{{"seq":{},"rev":{rev}}}"#, parsed.seq))
        }
        (Method::Post, Some("media")) => {
            let blob = request.binary_body.clone().unwrap_or_default();

            if blob.is_empty() {
                return plain(400, String::new());
            }

            let media_id = FakeServer::next_uuid(state);
            state
                .channels
                .get_mut(&channel_id)
                .expect("канал есть")
                .media
                .insert(media_id.clone(), blob);

            plain(200, format!(r#"{{"media_id":"{media_id}"}}"#))
        }
        (Method::Delete, Some("media")) => {
            let Ok(parsed) =
                serde_json::from_str::<gasapp_net::api::DeleteChannelMediaRequest>(body)
            else {
                return plain(400, String::new());
            };
            let channel = state.channels.get_mut(&channel_id).expect("канал есть");

            match channel.media.remove(&parsed.media_id) {
                Some(_) => plain(204, String::new()),
                None => plain(404, String::new()),
            }
        }
        _ => plain(404, String::new()),
    }
}

/// Выборка записей по строке запроса — общая для открытого и закрытого
/// чтения.
fn select_posts(channel: &FakeChannel, query: &str) -> Vec<gasapp_net::api::ChannelPostResponse> {
    let limit = query_number(query, "limit").unwrap_or(100).min(100) as usize;
    let all = (0..channel.posts.len()).map(|index| channel.post(index));

    if let Some(after) = query_number(query, "after_rev") {
        let mut changed: Vec<_> = all.filter(|post| post.rev > after).collect();
        changed.sort_by_key(|post| post.rev);
        changed.truncate(limit);
        changed
    } else {
        let before = query_number(query, "before_seq").unwrap_or(u64::MAX);
        let mut page: Vec<_> = all
            .filter(|post| !post.deleted && post.seq < before)
            .collect();
        page.reverse();
        page.truncate(limit);
        page
    }
}

/// Аккаунт устройства.
fn account_of(state: &ServerState, device_id: &str) -> Option<String> {
    state
        .devices
        .iter()
        .find(|(_, device)| device.as_str() == device_id)
        .map(|(account, _)| account.clone())
}

/// Имя аккаунта.
fn username_of(state: &ServerState, account_id: &str) -> String {
    state
        .accounts
        .iter()
        .find(|(_, (account, _))| account == account_id)
        .map(|(username, _)| username.clone())
        .unwrap_or_default()
}

fn member_list(state: &ServerState, accounts: Vec<String>) -> HttpResponse {
    let mut list: Vec<_> = accounts
        .into_iter()
        .map(|account_id| gasapp_net::api::ChannelMemberResponse {
            username: username_of(state, &account_id),
            account_id,
        })
        .collect();
    list.sort_by(|left, right| left.account_id.cmp(&right.account_id));

    json(&list)
}

/// Заявка и чтение закрытого канала — от имени участника, за подписью.
/// `None` — это не такой запрос.
fn channel_member_route(
    state: &mut ServerState,
    request: &HttpRequest,
    device_id: &str,
    channel_id: &str,
    tail: &str,
) -> Option<HttpResponse> {
    let (action, query) = tail.split_once('?').unwrap_or((tail, ""));
    let body = request.body.as_deref().unwrap_or_default();

    if !matches!(action, "join" | "info" | "posts" | "key" | "epochs")
        && !action.starts_with("media/")
    {
        return None;
    }

    let account = account_of(state, device_id)?;
    let Some(channel) = state.channels.get_mut(channel_id) else {
        // Статус заявки в несуществующий канал — «нет», а не ошибка.
        return Some(if action == "join" && request.method == Method::Get {
            json(&gasapp_net::api::ChannelJoinStatusResponse {
                status: "none".to_owned(),
                grant: None,
            })
        } else {
            plain(404, String::new())
        });
    };

    Some(match (&request.method, action) {
        (Method::Post, "join") => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::JoinChannelRequest>(body)
            else {
                return Some(plain(400, String::new()));
            };
            let hash = hex::encode(Sha256::digest(
                hex::decode(&parsed.invite).unwrap_or_default(),
            ));

            if !channel.closed || !channel.invites.contains(&hash) {
                plain(404, String::new())
            } else if channel.bans.contains(&account) {
                plain(403, String::new())
            } else {
                channel.requests.insert(account, parsed.request);
                plain(204, String::new())
            }
        }
        (Method::Get, "join") => {
            // Ждущая заявка важнее прежнего ответа — как у сервера.
            let (status, grant) = if channel.requests.contains_key(&account) {
                ("pending", None)
            } else if let Some(grant) = channel.grants.get(&account) {
                ("approved", Some(grant.clone()))
            } else {
                ("none", None)
            };

            json(&gasapp_net::api::ChannelJoinStatusResponse {
                status: status.to_owned(),
                grant,
            })
        }
        (_, _) if !channel.member(device_id) => plain(404, String::new()),
        (Method::Post, "key") => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::ChannelMemberKeyRequest>(body)
            else {
                return Some(plain(400, String::new()));
            };

            if !channel.closed {
                return Some(plain(404, String::new()));
            }

            // Сменившийся ключ делает прежний ответ бесполезным.
            if channel.member_keys.get(&account) != Some(&parsed.member_key) {
                channel.grants.remove(&account);
                channel.grant_epochs.remove(&account);
                channel.approvals.remove(&account);
                channel
                    .member_keys
                    .insert(account.clone(), parsed.member_key);
            }
            if let Some(approval) = parsed.approval {
                channel.approvals.insert(account, approval);
            }

            plain(204, String::new())
        }
        (Method::Get, "epochs") => {
            let after = usize::try_from(query_number(query, "after").unwrap_or(0)).unwrap_or(0);
            let list: Vec<_> = channel
                .epochs
                .iter()
                .enumerate()
                .skip(after)
                .map(|(index, record)| serde_json::json!({ "epoch": index + 1, "record": record }))
                .collect();

            plain(200, serde_json::Value::Array(list).to_string())
        }
        (Method::Get, "info") => json(&channel.info(channel_id)),
        (Method::Get, "posts") => json(&select_posts(channel, query)),
        (Method::Get, media) => media
            .strip_prefix("media/")
            .and_then(|media_id| channel.media.get(media_id))
            .map_or_else(
                || plain(404, String::new()),
                |blob| HttpResponse {
                    status: 200,
                    body: String::new(),
                    binary_body: blob.clone(),
                },
            ),
        _ => plain(404, String::new()),
    })
}

/// Приглашения, заявки, подписчики и удалённые — для тех, кто ведёт
/// канал. Право уже проверено.
fn channel_moderation(
    state: &mut ServerState,
    request: &HttpRequest,
    channel_id: &str,
    what: &str,
) -> HttpResponse {
    let body = request.body.as_deref().unwrap_or_default();
    let member = serde_json::from_str::<gasapp_net::api::ChannelMemberRequest>(body)
        .map(|parsed| parsed.account_id);

    match (&request.method, what) {
        (Method::Post | Method::Delete, "invites") => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::ChannelInviteRequest>(body)
            else {
                return plain(400, String::new());
            };
            let channel = state.channels.get_mut(channel_id).expect("канал есть");

            if request.method == Method::Post {
                channel.invites.insert(parsed.invite_hash);
            } else {
                channel.invites.remove(&parsed.invite_hash);
            }

            plain(204, String::new())
        }
        (Method::Get, "requests") => {
            let channel = &state.channels[channel_id];
            let mut list: Vec<_> = channel
                .requests
                .iter()
                .map(
                    |(account_id, request)| gasapp_net::api::ChannelJoinRequestResponse {
                        account_id: account_id.clone(),
                        username: username_of(state, account_id),
                        request: request.clone(),
                    },
                )
                .collect();
            list.sort_by(|left, right| left.account_id.cmp(&right.account_id));

            json(&list)
        }
        (Method::Post, "requests") => {
            let Ok(parsed) =
                serde_json::from_str::<gasapp_net::api::AnswerChannelJoinRequest>(body)
            else {
                return plain(400, String::new());
            };
            let device = state.devices.get(&parsed.account_id).cloned();
            let channel = state.channels.get_mut(channel_id).expect("канал есть");

            let request = channel.requests.get(&parsed.account_id).cloned();

            if channel.requests.remove(&parsed.account_id).is_none() {
                return plain(404, String::new());
            }

            if let (Some(grant), Some(device)) = (parsed.grant, device) {
                channel
                    .grant_epochs
                    .insert(parsed.account_id.clone(), channel.key_epoch);
                // Ключ из заявки становится ключом доставки.
                channel
                    .member_keys
                    .insert(parsed.account_id.clone(), request.unwrap_or_default());
                match parsed.approval {
                    Some(approval) => {
                        channel
                            .approvals
                            .insert(parsed.account_id.clone(), approval);
                    }
                    None => {
                        channel.approvals.remove(&parsed.account_id);
                    }
                }
                channel.grants.insert(parsed.account_id, grant);
                channel.subscribers.entry(device).or_insert(0);
            }

            plain(204, String::new())
        }
        (Method::Get, "subscribers") => {
            let accounts = state.channels[channel_id]
                .subscribers
                .keys()
                .filter_map(|device| account_of(state, device))
                .collect();

            member_list(state, accounts)
        }
        (Method::Delete, "subscribers") => {
            let Ok(account_id) = member else {
                return plain(400, String::new());
            };
            let device = state.devices.get(&account_id).cloned().unwrap_or_default();
            let channel = state.channels.get_mut(channel_id).expect("канал есть");

            // Того, кто ведёт канал, так не удалить.
            if channel.owner_device == device || channel.admins.contains_key(&device) {
                return plain(400, String::new());
            }

            channel.subscribers.remove(&device);
            for post in &mut channel.posts {
                post.reactions.remove(&device);
            }
            channel.grants.remove(&account_id);
            channel.grant_epochs.remove(&account_id);
            channel.member_keys.remove(&account_id);
            channel.approvals.remove(&account_id);
            channel.requests.remove(&account_id);
            channel.bans.insert(account_id);

            plain(204, String::new())
        }
        (Method::Get, "keys") => {
            let missing = request.path.contains("missing=true");
            let after = request
                .path
                .split("after=")
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let channel = &state.channels[channel_id];

            // Только действующие участники, по аккаунту, страницами по два:
            // так тест проходит и досылку остальных страниц.
            let mut list: Vec<_> = channel
                .member_keys
                .iter()
                .filter(|(account, _)| {
                    state
                        .devices
                        .get(*account)
                        .is_some_and(|device| channel.member(device))
                })
                .filter(|(account, _)| account.as_str() > after.as_str())
                .filter(|(account, _)| {
                    !missing
                        || (channel.approvals.contains_key(*account)
                            && channel
                                .grant_epochs
                                .get(*account)
                                .is_none_or(|epoch| *epoch < channel.key_epoch))
                })
                .map(|(account, key)| {
                    serde_json::json!({
                        "account_id": account,
                        "member_key": key,
                        "approval": channel.approvals.get(account),
                    })
                })
                .collect();
            list.sort_by_key(|key| key["account_id"].as_str().map(str::to_owned));
            list.truncate(2);

            plain(200, serde_json::Value::Array(list).to_string())
        }
        (Method::Post, "keys") => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::RekeyChannelRequest>(body)
            else {
                return plain(400, String::new());
            };
            let channel = state.channels.get_mut(channel_id).expect("канал есть");

            if !channel.closed {
                return plain(404, String::new());
            }

            match parsed.record {
                Some(record) => {
                    if channel.rekey_failures > 0 {
                        channel.rekey_failures -= 1;
                        return plain(503, String::new());
                    }
                    if parsed.epoch != channel.key_epoch + 1 {
                        return plain(409, String::new());
                    }

                    channel.epochs.push(record);
                    channel.key_epoch = parsed.epoch;
                }
                None if parsed.epoch != channel.key_epoch => return plain(409, String::new()),
                None => {}
            }

            for grant in parsed.grants {
                // Ответ — только участнику с известным ключом доставки.
                if channel.member_keys.contains_key(&grant.account_id) {
                    channel
                        .grant_epochs
                        .insert(grant.account_id.clone(), parsed.epoch);
                    if let Some(approval) = grant.approval {
                        channel.approvals.insert(grant.account_id.clone(), approval);
                    }
                    channel.grants.insert(grant.account_id, grant.grant);
                }
            }

            plain(204, String::new())
        }
        (Method::Get, "bans") => {
            let accounts = state.channels[channel_id].bans.iter().cloned().collect();

            member_list(state, accounts)
        }
        (Method::Delete, "bans") => {
            let Ok(account_id) = member else {
                return plain(400, String::new());
            };

            state
                .channels
                .get_mut(channel_id)
                .expect("канал есть")
                .bans
                .remove(&account_id);

            plain(204, String::new())
        }
        _ => plain(404, String::new()),
    }
}

/// Чтение канала — анонимно: канал, записи, медиа.
fn channel_feed(state: &mut ServerState, request: &HttpRequest, rest: &str) -> HttpResponse {
    let (target, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (channel_id, action) = target.split_once('/').unwrap_or((target, ""));

    if request.method == Method::Get && action == "posts" {
        // Несуществующий канал даёт пустой список, как на настоящем;
        // закрытый для запроса без подписи не существует.
        let Some(channel) = state
            .channels
            .get(channel_id)
            .filter(|channel| !channel.closed)
        else {
            return json(&Vec::<gasapp_net::api::ChannelPostResponse>::new());
        };

        return json(&select_posts(channel, query));
    }

    let Some(channel) = state
        .channels
        .get_mut(channel_id)
        .filter(|channel| !channel.closed)
    else {
        return plain(404, String::new());
    };

    if request.method != Method::Get {
        return plain(404, String::new());
    }

    match action.strip_prefix("media/") {
        Some(media_id) => channel.media.get(media_id).map_or_else(
            || plain(404, String::new()),
            |blob| HttpResponse {
                status: 200,
                body: String::new(),
                binary_body: blob.clone(),
            },
        ),
        None if action.is_empty() => json(&channel.info(channel_id)),
        None => plain(404, String::new()),
    }
}

/// Действия подписчика — подписка, отписка, отметка о прочтении,
/// реакция. Подписчик — устройство, подписавшее запрос.
fn channel_reader_action(
    channel: &mut FakeChannel,
    device_id: &str,
    action: &str,
    body: &str,
) -> HttpResponse {
    match action {
        "subscribe" => {
            channel.subscribers.entry(device_id.to_owned()).or_insert(0);

            plain(204, String::new())
        }
        // Жалоба: сервер запоминает причину и ссылку, если её приложили.
        "report" => match serde_json::from_str::<gasapp_net::api::ReportChannelRequest>(body) {
            Ok(parsed) if (1..=5).contains(&parsed.reason) => {
                channel.reports.push((parsed.reason, parsed.link));
                plain(204, String::new())
            }
            _ => plain(400, String::new()),
        },
        "unsubscribe" => {
            channel.subscribers.remove(device_id);
            for post in &mut channel.posts {
                post.reactions.remove(device_id);
            }

            plain(204, String::new())
        }
        "seen" => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::ChannelSeenRequest>(body)
            else {
                return plain(400, String::new());
            };

            match channel.subscribers.get_mut(device_id) {
                Some(seen) => {
                    *seen = (*seen).max(parsed.seq);
                    plain(204, String::new())
                }
                None => plain(404, String::new()),
            }
        }
        "react" => {
            let Ok(parsed) = serde_json::from_str::<gasapp_net::api::ChannelReactRequest>(body)
            else {
                return plain(400, String::new());
            };

            if parsed
                .emoji
                .as_deref()
                .is_some_and(|emoji| !gasapp_core::client::CHANNEL_REACTIONS.contains(&emoji))
            {
                return plain(400, String::new());
            }

            let subscribed = channel.subscribers.contains_key(device_id);
            let post = channel
                .posts
                .get_mut(post_index(parsed.seq))
                .filter(|post| !post.deleted);

            match (subscribed, post) {
                (true, Some(post)) => {
                    match parsed.emoji {
                        Some(emoji) => post.reactions.insert(device_id.to_owned(), emoji),
                        None => post.reactions.remove(device_id),
                    };
                    plain(204, String::new())
                }
                _ => plain(404, String::new()),
            }
        }
        _ => plain(404, String::new()),
    }
}

impl Transport for FakeServer {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut state = self.state.borrow_mut();
        let path = request.path.as_str();

        state
            .requests
            .push((request.path.clone(), request.headers.clone()));

        if state.sends_refused
            && request.method == Method::Post
            && (path.starts_with("/v1/sealed/messages") || path.starts_with("/v1/messages"))
        {
            return Err(GasAppError::Network);
        }

        let signed = request
            .headers
            .iter()
            .any(|(name, _)| name == "x-gasapp-signature");

        let (status, body) = match (&request.method, path) {
            (Method::Get, "/v1/accounts/email/challenge") => {
                // Цена, названная клиенту, может оказаться ниже той, что
                // спросят с него через мгновение: узел успели нагрузить.
                let quoted = state
                    .email_difficulty
                    .saturating_sub(state.email_price_jumps);
                state.email_price_jumps = 0;

                (
                    200,
                    format!(r#"{{"difficulty":{quoted},"window":{EMAIL_WINDOW}}}"#),
                )
            }
            (Method::Post, "/v1/accounts/email/code") => {
                let parsed: gasapp_net::api::EmailCodeRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?;

                // Как настоящий сервер: письмо стоит работы — по цене,
                // которая действует сейчас, и в названном окне времени.
                let challenge = gasapp_net::pow::email_code_challenge(&parsed.email, parsed.window);
                let hash = gasapp_net::pow::hash(&challenge, parsed.pow_nonce);

                if parsed.window != EMAIL_WINDOW
                    || leading_zero_bits(&hash) < state.email_difficulty
                {
                    (401, String::new())
                } else {
                    state.email_code_requests.push(parsed.email);
                    (204, String::new())
                }
            }
            (Method::Get, path)
                if path.starts_with("/v1/accounts/") && path.ends_with("/status") =>
            {
                let device_id = path
                    .trim_start_matches("/v1/accounts/")
                    .trim_end_matches("/status");

                if signed && state.device_identity.contains_key(device_id) {
                    let premium = state.premium_devices.contains(device_id);
                    (200, format!(r#"{{"premium":{premium}}}"#))
                } else {
                    (401, String::new())
                }
            }
            // Боты — отдельной функцией (`bot_route`).
            (_, path) if path.starts_with("/v1/bots/") => {
                return Ok(bot_route(&mut state, request, signed));
            }
            // Каналы — отдельной функцией (`channel_route`).
            (_, path) if path.starts_with("/v1/channels/") => {
                return Ok(channel_route(&mut state, request, signed));
            }
            (Method::Post, "/v1/accounts/register") => {
                let parsed: RegisterRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?;

                state.last_registration_email =
                    Some((parsed.email.clone(), parsed.email_code.clone()));

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
                let parsed: gasapp_net::api::RecoverAccountRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?;
                let decode = |text: &str| {
                    hex::decode(text).map_err(|_| gasapp_types::GasAppError::Malformed)
                };

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
                let signed = gasapp_protocol::account_recovery::RecoverRequest {
                    username: &parsed.username,
                    identity_key: &identity,
                    device_identity_key: &device_identity,
                    pq_identity_key: &pq,
                    identity_binding: &binding,
                    issued_at_millis: parsed.issued_at,
                };
                let public = gasapp_types::PublicKeyBytes::new(
                    decode(&public)?
                        .try_into()
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?,
                );

                if gasapp_protocol::account_recovery::verify(
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
            (Method::Get, path)
                if path.starts_with("/v1/discovery/username/") && state.discovery_refused =>
            {
                (429, String::new())
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
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?;

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
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?;

                let hash = hex::decode(&parsed.access_key_hash)
                    .map_err(|_| gasapp_types::GasAppError::Malformed)?;
                state.access_hashes.insert(device_id, hash);

                (200, String::new())
            }
            // Жалоба: как на настоящем сервере — сертификат обязан быть
            // подписан ключом сервера, иначе это слово жалобщика.
            (Method::Post, path) if path.starts_with("/v1/sealed/report/") => {
                let complainant = path.trim_start_matches("/v1/sealed/report/").to_owned();
                let request: SealedReportRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .expect("тело жалобы");
                let raw = hex::decode(&request.certificate).expect("hex сертификата");
                let certificate = SenderCertificate::from_bytes(&raw).expect("сертификат");
                let private = PrivateKeyBytes::new(FAKE_SERVER_KEY);
                let server_key = xeddsa::montgomery::public_key(&private).expect("ключ сервера");

                if certificate.verify(&server_key, 0).is_err() {
                    (400, String::new())
                } else {
                    let pair = (complainant, certificate.device_id);
                    let recorded = !state.reports.contains(&pair);
                    if recorded {
                        state.reports.push(pair);
                    }
                    let total_reporters = i64::try_from(state.reports.len()).unwrap_or(i64::MAX);

                    (
                        200,
                        serde_json::to_string(&SealedReportResponse {
                            recorded,
                            evidence_stored: false,
                            total_reporters,
                        })
                        .unwrap_or_default(),
                    )
                }
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
                        .map_err(|_| gasapp_types::GasAppError::Malformed)?;

                let presented = match &parsed.access_key {
                    None => None,
                    Some(encoded) => Some(
                        hex::decode(encoded).map_err(|_| gasapp_types::GasAppError::Malformed)?,
                    ),
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
                    let challenge = gasapp_net::pow::first_contact_challenge(
                        &parsed.destination_device_id,
                        &sealed,
                    );

                    leading_zero_bits(&gasapp_net::pow::hash(&challenge, nonce))
                        >= gasapp_net::pow::FIRST_CONTACT_DIFFICULTY
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
                // Как настоящий сервер: самые старые, не больше сотни.
                let queue: Vec<EnvelopeResponse> = state
                    .queues
                    .get(device_id)
                    .map(|queue| queue.iter().take(100).cloned().collect())
                    .unwrap_or_default();

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
                    .any(|(name, _)| name == "x-gasapp-signature");

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
                    .find(|(name, _)| name == gasapp_net::client::UPLOAD_POW_HEADER)
                    .and_then(|(_, value)| value.parse::<u64>().ok());
                let signed = request
                    .headers
                    .iter()
                    .any(|(name, _)| name.starts_with("x-gasapp-signature"));
                let worked = nonce.is_some_and(|nonce| {
                    leading_zero_bits(&gasapp_net::pow::hash(
                        &gasapp_net::pow::upload_challenge(&payload),
                        nonce,
                    )) >= gasapp_net::pow::upload_difficulty(payload.len())
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
            // Журнал ключей — как у настоящего сервера (`gasapp-server-api::kt`).
            (Method::Get, path) if path.starts_with("/v1/kt/heads") => {
                let from = path
                    .strip_prefix("/v1/kt/heads/")
                    .and_then(|text| text.parse::<u64>().ok())
                    .unwrap_or(0);
                let epochs: Vec<gasapp_net::api::KtEpochView> = state
                    .kt_epochs
                    .iter()
                    .filter(|epoch| epoch.epoch >= from)
                    // Страница — как у настоящего сервера.
                    .take(7 * 24 + 8)
                    .map(|epoch| gasapp_net::api::KtEpochView {
                        epoch: epoch.epoch,
                        root: hex::encode(epoch.root),
                        head: hex::encode(epoch.head),
                    })
                    .collect();

                (
                    200,
                    serde_json::to_string(&gasapp_net::api::KtHeadsResponse { epochs })
                        .unwrap_or_default(),
                )
            }
            (Method::Post, "/v1/kt/proofs") => {
                let parsed: gasapp_net::api::KtProofsRequest =
                    serde_json::from_str(request.body.as_deref().unwrap_or_default())
                        .map_err(|_| GasAppError::Malformed)?;
                let index: [u8; 32] = hex::decode(&parsed.index)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(GasAppError::Malformed)?;

                let refused = state.kt_refused_index == Some(index);
                let proofs = parsed
                    .epochs
                    .iter()
                    .filter(|_| !refused)
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
                                    Some(gasapp_net::api::KtLeafView {
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
                                Some(gasapp_net::api::KtOtherLeafView {
                                    index: hex::encode(found),
                                    value: hex::encode(value),
                                }),
                            ),
                        };

                        gasapp_net::api::KtProofView {
                            epoch: epoch.epoch,
                            leaf,
                            other,
                            siblings: proof.siblings.iter().map(hex::encode).collect(),
                        }
                    })
                    .collect();

                (
                    200,
                    serde_json::to_string(&gasapp_net::api::KtProofsResponse { proofs })
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
                gasapp_protocol::pq_identity::pq_identity_hash(&hex::decode(pq_hex).expect("hex"));

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

impl FakeServer {
    /// Очередь устройства в её нынешнем виде.
    fn queue_of(&self, device: &str) -> Vec<EnvelopeResponse> {
        self.state
            .borrow()
            .queues
            .get(device)
            .cloned()
            .unwrap_or_default()
    }

    /// 🔐 Кладёт в очередь устройства конверты от имени «сервера» —
    /// повторы старых или мусор.
    fn inject(&self, device: &str, ciphertexts: &[String]) {
        let mut state = self.state.borrow_mut();
        for ciphertext in ciphertexts {
            let envelope_id = Self::next_uuid(&mut state);
            state
                .queues
                .entry(device.to_owned())
                .or_default()
                .push(EnvelopeResponse {
                    envelope_id,
                    ciphertext: ciphertext.clone(),
                    queued_at_bucketed: 0,
                });
        }
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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

/// Своё имя и своя ссылка — не собеседник.
///
/// Прежде поиск по собственному имени заводил контакт с собственным
/// ключом: чат с самим собой, закрытый для записи, и safety number
/// с собой. Найдено на эмуляторе.
#[test]
fn own_name_and_own_link_are_not_a_contact() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");

    assert!(matches!(
        alice.discover_contact("@Alice", now()),
        Err(GasAppError::InvalidUsername)
    ));

    let link = alice.own_contact_link().expect("своя ссылка");
    assert!(matches!(
        alice.add_contact_from_link(&link, now()),
        Err(GasAppError::Malformed)
    ));

    assert!(
        alice.contacts().expect("контакты").is_empty(),
        "завёлся контакт с собой"
    );
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб зарегистрирован");
    mallory
        .register("mallory", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");
    mallory
        .register("mallory", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса")
        .device_id
        .to_string();
    let bob_device = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
    carol
        .register("carol", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Карол");
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
    let status_of = |id: &gasapp_types::MessageId| {
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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

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

    gasapp_protocol::prekeys::PreKeySecrets::from_bytes(&keys.prekey_secrets)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::{AttachmentDescriptor, AttachmentKind};

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

    const CANARY: &[u8] = b"SECRET-FILE-CONTENTS-CANARY";

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let bob = Client::new(server.clone(), open_storage(&dir, "bob.db"));

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса зарегистрирована")
        .device_id
        .to_string();
    let bob_device = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса")
        .device_id
        .to_string();
    let bob_device = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
            &gasapp_core::client::AttachmentFile {
                kind: gasapp_media::descriptor::AttachmentKind::Document,
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
            &gasapp_core::client::AttachmentFile {
                kind: gasapp_media::descriptor::AttachmentKind::Document,
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
            .all(|(name, _)| !name.to_ascii_lowercase().starts_with("x-gasapp")),
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

    let alice_account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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
        &format!("gasapp://contact?u=alice&k={}", "A".repeat(52)),
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
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");

    alice.delete_account(now()).expect("аккаунт удалён");

    let request = server
        .last_request("/v1/accounts/")
        .expect("запроса на удаление не было");

    assert!(
        request.iter().any(|(name, _)| name == "x-gasapp-signature"),
        "запрос ушёл без подписи"
    );
    assert!(
        request.iter().any(|(name, _)| name == "x-gasapp-issued-at"),
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
        matches!(outcome, Err(gasapp_types::GasAppError::SessionNotFound)),
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
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");

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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");

    alice
        .send_message("bob", "встречаемся в семь", now(), &mut OsRng)
        .expect("сообщение отправлено");

    let export = alice.export_data(now()).expect("выгрузка");

    assert!(export.contains("gasapp-export-v1"), "нет версии формата");
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");

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
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");

    let export = alice.export_data(now()).expect("выгрузка");
    let parsed: serde_json::Value = serde_json::from_str(&export).expect("выгрузка не разбирается");

    assert_eq!(parsed["format"], "gasapp-export-v1");
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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
            Err(gasapp_types::GasAppError::SessionNotFound)
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
/// существовала, была покрыта тестами в `gasapp-protocol` — и
/// не вызывалась из продукта ни разу.
#[test]
fn an_exhausted_one_time_pool_is_refilled() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");

    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
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
    let account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
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
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");

    let later = gasapp_types::Timestamp::from_millis(
        now().as_millis()
            + i64::from(gasapp_protocol::SIGNED_PRE_KEY_ROTATION_DAYS) * 24 * 60 * 60 * 1000
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
            Err(gasapp_types::GasAppError::SessionNotFound)
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
/// # Почему это проверяется здесь, а не в `gasapp-protocol`
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

    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_account = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

    // Ключи сверены — без этого писать нельзя (PeerUnconfirmed).
    confirm_pair(&alice, "alice", &bob, "bob");
    let carol_account = carol
        .register("carol", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Кэрол");
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
        .register("mallory", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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
        matches!(result, Err(GasAppError::IdentityChanged)),
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
        matches!(result, Err(GasAppError::IdentityChanged)),
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

    let target = gasapp_types::MessageId::generate();
    let result = alice.send_reaction("bob", &target, "👍", later(1), &mut OsRng);

    assert!(
        matches!(result, Err(GasAppError::IdentityChanged)),
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
        matches!(result, Err(GasAppError::IdentityChanged)),
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
        Err(GasAppError::PeerUnconfirmed)
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
        matches!(result, Err(GasAppError::IdentityChanged)),
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
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    let bob_device = bob
        .register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб")
        .device_id
        .to_string();

    let result = alice.send_message("bob", "привет", now(), &mut OsRng);
    assert!(
        matches!(result, Err(GasAppError::PeerUnconfirmed)),
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
    alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

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
    use gasapp_core::client::AttachmentFile;
    use gasapp_media::descriptor::AttachmentKind;

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
    let forger = gasapp_protocol::prekeys::generate_identity(&mut OsRng).expect("identity");
    let forger_pq = gasapp_protocol::pq_identity::PqIdentityKeyPair::generate(&mut OsRng);
    let forged_kem = gasapp_protocol::mlkem::MlKem1024PrivateKey::generate(&mut OsRng)
        .public_key()
        .as_bytes();
    let forged_signature =
        gasapp_protocol::sealed_sender::sign_sealed_kem_key(&forger, &forger_pq, &forged_kem)
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
        matches!(result, Err(GasAppError::Uninitialized)),
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

    let bob = gasapp_net::client::ApiClient::new(server.clone());
    let found = bob.discover("bob").expect("discovery");

    let public = hex::decode(found.sealed_kem_public.expect("ключ опубликован")).expect("hex");
    let signature =
        hex::decode(found.sealed_kem_signature.expect("подпись опубликована")).expect("hex");
    let identity = gasapp_types::PublicKeyBytes::new(
        hex::decode(&found.identity_key)
            .expect("hex")
            .try_into()
            .expect("32 байта"),
    );

    let pq = hex::decode(found.pq_identity_key.expect("половина опубликована")).expect("hex");
    let binding = hex::decode(found.identity_binding.expect("привязка")).expect("hex");

    gasapp_protocol::pq_identity::verify_binding(&identity, &pq, &binding)
        .expect("привязка половин");
    gasapp_protocol::sealed_sender::verify_sealed_kem_key(&identity, &pq, &public, &signature)
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
    let forger = gasapp_protocol::prekeys::generate_identity(&mut OsRng).expect("identity");
    let forger_pq = gasapp_protocol::pq_identity::PqIdentityKeyPair::generate(&mut OsRng);
    let binding = gasapp_protocol::pq_identity::bind(&forger, &forger_pq).expect("привязка");
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
    let other_pq = gasapp_protocol::pq_identity::PqIdentityKeyPair::generate(&mut OsRng);
    let stranger = gasapp_protocol::prekeys::generate_identity(&mut OsRng).expect("identity");
    server.replace_pq(
        &bob_identity,
        (
            hex::encode(other_pq.public()),
            hex::encode(
                gasapp_protocol::pq_identity::bind(&stranger, &other_pq).expect("привязка"),
            ),
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
    gasapp_net::client::ApiClient::new(server.clone())
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
        .register("  Alice ", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");
    assert_eq!(alice.own_username().expect("имя").as_deref(), Some("alice"));

    let found = alice.discover_contact("@Bob", now()).expect("поиск");
    assert_eq!(found.username.as_deref(), Some("bob"));

    for lookalike in ["b\u{43e}b", "bob\u{200b}", "bo b"] {
        assert!(
            matches!(
                alice.discover_contact(lookalike, now()),
                Err(GasAppError::InvalidUsername)
            ),
            "двойник {lookalike:?} не отвергнут"
        );
    }

    assert!(matches!(
        Client::new(server.clone(), open_storage(&dir, "mallory.db")).register(
            "\u{430}lice",
            TEST_EMAIL,
            TEST_EMAIL_CODE,
            now(),
            &mut OsRng
        ),
        Err(GasAppError::InvalidUsername)
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
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
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

    let backup_key = gasapp_backup::RecoveryKey::generate(&mut OsRng);
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

    // 🔐 И вернулась в тот чат, куда придут новые сообщения собеседника:
    // идентификатор чата выводится из ключей обоих, а свой ключ теперь
    // новый. Прежде история оставалась в чате без контакта, а новое
    // сообщение того же человека открывало другой.
    let bob_contact = reinstalled
        .contacts()
        .expect("контакты")
        .into_iter()
        .find(|contact| contact.username.as_deref() == Some("bob"))
        .expect("контакт вернулся");
    assert_eq!(
        bob_contact.chat_id,
        Some(chat),
        "контакт указывает на прежний чат"
    );
    assert_eq!(reinstalled.chats().expect("чаты").len(), 1);

    // 🔐 Собеседник видит смену ключа и без новой сверки не пишет.
    assert!(matches!(
        bob.send_message("alice", "это ты?", later(11), &mut OsRng),
        Err(GasAppError::IdentityChanged)
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
    let backup_key = gasapp_backup::RecoveryKey::generate(&mut OsRng);
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
        Err(GasAppError::PeerUnconfirmed)
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
        .register(
            "alice",
            TEST_EMAIL,
            TEST_EMAIL_CODE,
            later(-6 * 3600),
            &mut OsRng,
        )
        .expect("Алиса");
    bob.register("bob", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Боб");

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

/// 🔐 Сервер показал Бобу свою ветку журнала, а Алисе — настоящую.
/// Вершина, которую Боб присылает в переписке, расходится с цепочкой
/// Алисы — и Алиса получает событие безопасности.
#[test]
fn a_split_log_view_is_caught_by_the_other_side() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, _bob_device) = alice_and_bob(&server, &dir);

    for epoch in now_epoch() - 2..=now_epoch() {
        server.publish_kt_epoch(epoch, &[("alice", [0x99; 32])]);
    }
    bob.kt_sync(now()).expect("Боб видит поддельную ветку");

    server.forget_kt_history();
    server.publish_kt_epochs(now_epoch() - 2, now_epoch());
    alice.kt_sync(now()).expect("Алиса видит настоящую");

    bob.send_message("alice", "привет", now(), &mut OsRng)
        .expect("отправка");
    alice.receive_messages(&alice_device, now()).expect("приём");

    assert!(alice
        .security_events(10)
        .expect("журнал")
        .iter()
        .any(|(kind, _, _)| kind == "kt_peer_log_differs"));
}

/// Одинаковые цепочки — никаких событий: обмен вершинами не шумит.
#[test]
fn agreeing_log_views_raise_nothing() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, alice_device, _bob_device) = alice_and_bob(&server, &dir);

    server.publish_kt_epochs(now_epoch() - 2, now_epoch());
    bob.kt_sync(now()).expect("Боб");
    alice.kt_sync(now()).expect("Алиса");

    bob.send_message("alice", "привет", now(), &mut OsRng)
        .expect("отправка");
    let received = alice.receive_messages(&alice_device, now()).expect("приём");

    assert!(!alice
        .security_events(10)
        .expect("журнал")
        .iter()
        .any(|(kind, _, _)| kind.starts_with("kt_")));
    // Вершина — служебное сообщение: в счёт новых не идёт.
    assert_eq!(received, 1);
}

/// Журнал длиннее одной страницы (новая установка, неделя истории)
/// синхронизируется до последней эпохи, а не останавливается на первой
/// странице.
#[test]
fn a_long_log_is_synced_in_pages() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (_alice, bob) = unconfirmed_pair(&server, &dir);

    server.publish_kt_epochs(now_epoch() - kt::HISTORY_EPOCHS + 1, now_epoch());

    assert_eq!(bob.kt_sync(now()).expect("синхронизация"), now_epoch());
}

/// 🔐 Сотня нерасшифровываемых конвертов (повторы уже принятого
/// и мусор) не заслоняет настоящие сообщения: сервер отдаёт очередь
/// с самых старых, и неподтверждённый мусор иначе возвращался бы
/// каждым приёмом до истечения срока — тридцать дней без сообщений.
#[test]
fn undecryptable_envelopes_do_not_block_the_queue() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "первое", now(), &mut OsRng)
        .expect("первое");
    let old = server.queue_of(&bob_device);
    bob.receive_messages(&bob_device, now())
        .expect("приём первого");

    // Повторы уже принятого конверта и просто мусор — две сотни.
    let mut junk: Vec<String> = std::iter::repeat_n(old[0].ciphertext.clone(), 100).collect();
    junk.extend((0..100u8).map(|i| hex::encode([i; 64])));
    server.inject(&bob_device, &junk);

    alice
        .send_message("bob", "после мусора", later(1), &mut OsRng)
        .expect("второе");

    for _ in 0..4 {
        bob.receive_messages(&bob_device, later(2)).expect("приём");
    }

    assert!(
        texts_of(&bob).iter().any(|text| text == "после мусора"),
        "мусор заслонил настоящее сообщение"
    );
    assert!(
        server.queue_of(&bob_device).is_empty(),
        "мусор остался в очереди"
    );
}

/// 🔐 Отказ discovery (чужой перебор по имени собеседника выбрал бюджет)
/// не отрезает от собеседника: отправка берёт последний известный ответ,
/// а без него — честная ошибка сети.
#[test]
fn a_refused_discovery_does_not_cut_off_known_contacts() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob, _alice_device, bob_device) = alice_and_bob(&server, &dir);

    alice
        .send_message("bob", "до перебора", now(), &mut OsRng)
        .expect("первое");

    server.state.borrow_mut().discovery_refused = true;

    alice
        .send_message("bob", "во время перебора", later(60), &mut OsRng)
        .expect("отправка по последнему ответу");
    bob.receive_messages(&bob_device, later(61)).expect("приём");
    assert!(texts_of(&bob)
        .iter()
        .any(|text| text == "во время перебора"));

    // Через сутки последний ответ уже не годится.
    assert!(matches!(
        alice.send_message("bob", "слишком поздно", later(25 * 3600), &mut OsRng),
        Err(GasAppError::Network)
    ));
}

/// 🔐 Сервер, отказывающий владельцу имени в доказательствах его записи
/// (и только ему), не прячет этим подмену: долгая невозможность
/// проверить себя — событие безопасности.
#[test]
fn a_blocked_self_check_raises_an_event() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    alice
        .register(
            "alice",
            TEST_EMAIL,
            TEST_EMAIL_CODE,
            later(-12 * 3600),
            &mut OsRng,
        )
        .expect("Алиса");

    server.publish_kt_epochs(now_epoch() - 12, now_epoch());
    server.state.borrow_mut().kt_refused_index = Some(kt::index("alice"));

    alice.kt_check_self(now()).expect("журнал доступен");

    assert!(alice
        .security_events(10)
        .expect("журнал")
        .iter()
        .any(|(kind, _, _)| kind == "kt_self_check_blocked"));
}

/// 🔐 Заблокированный собеседник молчит, пока его не разблокируют,
/// а жалоба на него доказывается сертификатом с его конверта.
#[test]
fn a_blocked_contact_is_silenced_and_can_be_reported() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob) = unconfirmed_pair(&server, &dir);
    confirm_pair(&alice, "alice", &bob, "bob");
    let bob_device = bob.own_device_id().expect("устройство").expect("есть");

    alice
        .send_message("bob", "hello", now(), &mut OsRng)
        .expect("отправлено");
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);

    let chat = *bob.chats().expect("чаты").first().expect("чат с Алисой");
    assert!(
        bob.can_report_chat(&chat).expect("чтение"),
        "запечатанный конверт должен оставить доказательство для жалобы"
    );

    // Заблокирована: конверт принят и отброшен, в переписке его нет.
    bob.block_chat(&chat, Some("alice"), now())
        .expect("блокировка");
    alice
        .send_message("bob", "spam", now(), &mut OsRng)
        .expect("отправлено");
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 0);
    assert_eq!(bob.messages(&chat, 10).expect("переписка").len(), 1);
    assert_eq!(bob.blocked_chats().expect("список").len(), 1);
    // Отброшенное по блокировке — не «нечитаемое»: журнал об этом молчит.
    assert!(
        !bob.security_events(50)
            .expect("журнал")
            .iter()
            .any(|(kind, _, _)| kind == "undecryptable_envelopes_dropped"),
        "сообщение заблокированного записано как нечитаемое"
    );

    // Разблокирована: переписка идёт дальше — сессия не сломана.
    bob.unblock_chat(&chat).expect("разблокировка");
    alice
        .send_message("bob", "sorry", now(), &mut OsRng)
        .expect("отправлено");
    assert_eq!(bob.receive_messages(&bob_device, now()).expect("приём"), 1);

    // Жалоба учитывается один раз.
    assert!(bob.report_chat(&chat, now()).expect("жалоба").recorded);
    assert!(!bob.report_chat(&chat, now()).expect("повтор").recorded);
}

/// Сбой сети посреди отправки не теряет текст: сообщение остаётся
/// в переписке «не отправленным». Прежде оно исчезало бесследно, если
/// сбой пришёлся на обмен ключом доступа (первое сообщение новому
/// собеседнику — proof-of-work и Tor, десятки секунд).
#[test]
fn a_failed_send_keeps_the_message_as_failed() {
    let server = FakeServer::new();
    let dir = tempfile::tempdir().expect("временный каталог");
    let (alice, bob) = unconfirmed_pair(&server, &dir);
    confirm_pair(&alice, "alice", &bob, "bob");

    server.state.borrow_mut().sends_refused = true;
    assert!(alice
        .send_message("bob", "important", now(), &mut OsRng)
        .is_err());

    let chat = *alice.chats().expect("чаты").first().expect("чат с Бобом");
    let messages = alice.messages(&chat, 10).expect("переписка");
    assert_eq!(messages.len(), 1, "текст не должен теряться");
    assert_eq!(messages[0].text, "important");
    assert_eq!(messages[0].status, MessageStatus::Failed);

    // Сеть вернулась — следующее сообщение уходит, как обычно.
    server.state.borrow_mut().sends_refused = false;
    alice
        .send_message("bob", "again", now(), &mut OsRng)
        .expect("отправлено");
    let bob_device = bob.own_device_id().expect("устройство").expect("есть");
    assert!(bob.receive_messages(&bob_device, now()).expect("приём") >= 1);
}

// ---------------------------------------------------------------------------
//  Почта при регистрации
// ---------------------------------------------------------------------------

/// Клиент просит код на каноничный адрес и решает над ним работу.
#[test]
fn email_code_is_requested_for_the_canonical_address() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    alice
        .request_email_code("  Alice@Example.ORG ")
        .expect("код запрошен");

    assert_eq!(
        server.state.borrow().email_code_requests,
        vec!["alice@example.org".to_owned()]
    );
}

/// То, что не похоже на адрес, до сервера не доходит.
#[test]
fn a_malformed_email_never_reaches_the_server() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    assert!(matches!(
        alice.request_email_code("not-an-address"),
        Err(GasAppError::InvalidEmail)
    ));
    assert!(matches!(
        alice.register("alice", "not-an-address", "123456", now(), &mut OsRng),
        Err(GasAppError::InvalidEmail)
    ));
    assert!(server.state.borrow().requests.is_empty());
}

/// Регистрация несёт адрес в каноничном виде и код без пробелов.
#[test]
fn registration_carries_the_email_and_the_code() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    alice
        .register("alice", " Alice@Example.org", " 123456 ", now(), &mut OsRng)
        .expect("регистрация");

    assert_eq!(
        server.state.borrow().last_registration_email,
        Some(("alice@example.org".to_owned(), "123456".to_owned()))
    );
}

// ---------------------------------------------------------------------------
//  Премиум и каналы
// ---------------------------------------------------------------------------

/// Цена письма выросла, пока решалась задача: клиент переспрашивает её
/// и письмо получает. 🔐 Работу на часы клиент не берёт.
#[test]
fn a_dearer_letter_is_asked_for_again() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

    // Первый ответ о цене занижен на шесть бит: решение по нему не проходит.
    server.state.borrow_mut().email_price_jumps = 6;
    alice
        .request_email_code("alice@example.org")
        .expect("письмо со второй попытки");
    assert_eq!(server.state.borrow().email_code_requests.len(), 1);

    server.state.borrow_mut().email_difficulty = 40;
    assert!(matches!(
        alice.request_email_code("bob@example.org"),
        Err(GasAppError::Network)
    ));
    assert_eq!(server.state.borrow().email_code_requests.len(), 1);
}

/// Автор с премиумом и читатель, оба зарегистрированы.
fn author_and_reader(
    server: &FakeServer,
    dir: &tempfile::TempDir,
) -> (Client<FakeServer>, Client<FakeServer>) {
    let author = Client::new(server.clone(), open_storage(dir, "author.db"));
    let reader = Client::new(server.clone(), open_storage(dir, "reader.db"));

    let account = author
        .register("author", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("автор");
    reader
        .register("reader", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("читатель");

    server.set_premium(&account.device_id.to_string(), true);

    (author, reader)
}

use gasapp_core::client::AttachmentFile;
use gasapp_media::descriptor::AttachmentKind;

/// Канал автора и читатель, уже подписанный по ссылке.
fn followed_channel(author: &Client<FakeServer>, reader: &Client<FakeServer>) -> (String, String) {
    let channel = author
        .create_channel("Канал", "", now(), &mut OsRng)
        .expect("канал");
    let link = author.channel_link(&channel.channel_id).expect("ссылка");
    reader.join_channel(&link, now()).expect("подписка");

    (channel.channel_id, link)
}

fn post_text(author: &Client<FakeServer>, channel_id: &str, text: &str) -> u64 {
    author
        .publish_channel_post(channel_id, text, &[], now(), &mut OsRng)
        .expect("запись")
        .seq
}

fn texts(client: &Client<FakeServer>, channel_id: &str) -> Vec<String> {
    client
        .channel_posts(channel_id, 500)
        .expect("записи")
        .into_iter()
        .map(|post| post.text)
        .collect()
}

fn document(name: &str, bytes: Vec<u8>) -> AttachmentFile {
    AttachmentFile {
        kind: AttachmentKind::Document,
        bytes,
        name: Some(name.to_owned()),
        description: None,
        duration_millis: None,
        waveform: None,
    }
}

/// Без премиума канал не создаётся, и заготовка на устройстве не остаётся.
#[test]
fn a_channel_needs_premium() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let account = alice
        .register("alice", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("Алиса");

    assert!(!alice.refresh_premium(now()).expect("состояние"));
    assert!(matches!(
        alice.create_channel("Новости", "", now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(alice.channels().expect("список").is_empty());

    server.set_premium(&account.device_id.to_string(), true);

    assert!(alice.refresh_premium(now()).expect("состояние"));
    assert!(alice.premium_cached().expect("настройка"));

    let channel = alice
        .create_channel("  Новости  ", "Раз в день.", now(), &mut OsRng)
        .expect("канал");

    assert_eq!(channel.title, "Новости");
    assert!(channel.owned());
    assert_eq!(alice.channels().expect("список"), vec![channel]);
}

/// Полный путь: автор пишет, читатель по ссылке читает.
#[test]
fn a_reader_follows_a_channel_by_link() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Gas News", "Объявления.", now(), &mut OsRng)
        .expect("канал");
    post_text(&author, &channel.channel_id, "первая запись");

    let link = author.channel_link(&channel.channel_id).expect("ссылка");
    let joined = reader.join_channel(&link, now()).expect("подписка");

    assert_eq!(joined.title, "Gas News");
    assert_eq!(joined.description, "Объявления.");
    assert!(!joined.owned());
    assert_eq!(joined.unread, 1);
    assert_eq!(joined.last_post.as_deref(), Some("первая запись"));

    post_text(&author, &channel.channel_id, "вторая запись");

    assert_eq!(reader.sync_channels(now()).expect("синхронизация"), 1);
    assert_eq!(
        texts(&reader, &channel.channel_id),
        vec!["первая запись", "вторая запись"]
    );

    reader
        .mark_channel_read(&channel.channel_id)
        .expect("прочитано");
    assert_eq!(reader.channels().expect("список")[0].unread, 0);

    // Повторный переход по ссылке второй канал не заводит.
    reader.join_channel(&link, now()).expect("та же ссылка");
    assert_eq!(reader.channels().expect("список").len(), 1);
}

/// 🔐 Сервер видит шифротекст: ни названия, ни текста записи, ни файла
/// у него нет.
#[test]
fn the_server_sees_only_ciphertext() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, _reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Секретное название", "", now(), &mut OsRng)
        .expect("канал");
    let file = b"SECRET-FILE-CONTENT ".repeat(40);
    author
        .publish_channel_post(
            &channel.channel_id,
            "секретный текст",
            &[document("тайна.txt", file.clone())],
            now(),
            &mut OsRng,
        )
        .expect("запись");

    let stored = server.channel(&channel.channel_id);
    let bodies: String = stored.posts.iter().map(|post| post.body.as_str()).collect();
    let on_server = format!("{}{bodies}", stored.meta);

    for secret in ["Секретное название", "секретный текст", "тайна.txt"]
    {
        assert!(
            !on_server.contains(&hex::encode(secret)),
            "«{secret}» лежит на сервере открытым текстом"
        );
    }

    assert_eq!(stored.media.len(), 1);
    for blob in stored.media.values() {
        assert!(
            !blob.windows(11).any(|window| window == b"SECRET-FILE"),
            "файл лежит на сервере открытым"
        );
    }

    // И ссылка-приглашение на сервер не уходила: секрета чтения там нет.
    let link = author.channel_link(&channel.channel_id).expect("ссылка");
    let secret_part = link.split('.').nth(1).expect("секрет в ссылке");
    assert!(server
        .state
        .borrow()
        .requests
        .iter()
        .all(|(path, _)| !path.contains(secret_part)));
    assert!(stored.public_link.is_none());
}

/// 🔐 Читатель не ведёт чужой канал: ключа подписи у него нет.
#[test]
fn a_reader_cannot_post() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);
    let seq = post_text(&author, &channel_id, "авторская");
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    assert!(matches!(
        reader.publish_channel_post(&channel_id, "чужая", &[], now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.update_channel(&channel_id, "Моё", "", now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.edit_channel_post(&channel_id, seq, "правка", now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.delete_channel_post(&channel_id, seq, now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.pin_channel_post(&channel_id, seq, now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.set_channel_avatar(&channel_id, Some(&[1, 2, 3]), now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.set_channel_handle(&channel_id, Some("mine"), now()),
        Err(GasAppError::Forbidden)
    ));

    let stored = server.channel(&channel_id);
    assert_eq!(stored.posts.len(), 1);
    assert!(stored.media.is_empty());
    assert!(stored.handle.is_none());
}

/// 🔐 Запись, которую вписал сам сервер, читатель не принимает; настоящие
/// записи при этом доходят.
#[test]
fn a_post_forged_by_the_server_is_dropped() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Канал", "", now(), &mut OsRng)
        .expect("канал");
    post_text(&author, &channel.channel_id, "настоящая");
    let link = author.channel_link(&channel.channel_id).expect("ссылка");

    // Сервер дописывает мусор и повтор первой записи под новым номером.
    server.tamper_channel(&channel.channel_id, |stored| {
        let genuine = stored.posts[0].body.clone();
        stored.push(hex::encode([0x41u8; 600]));
        stored.push(genuine);
    });
    post_text(&author, &channel.channel_id, "после подделок");

    reader.join_channel(&link, now()).expect("подписка");

    assert_eq!(
        texts(&reader, &channel.channel_id),
        vec!["настоящая", "после подделок"]
    );
    // Отброшенные записи непрочитанными не считаются.
    assert_eq!(reader.channels().expect("список")[0].unread, 2);
    // И синхронизация на них не зацикливается.
    assert_eq!(reader.sync_channels(now()).expect("синхронизация"), 0);
}

/// 🔐 Сервер не подменит автора: канал с другим ключом подписи — не тот
/// канал, и подписка по ссылке не состоится.
#[test]
fn a_swapped_author_key_is_refused() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Канал", "", now(), &mut OsRng)
        .expect("канал");
    let link = author.channel_link(&channel.channel_id).expect("ссылка");

    server.tamper_channel(&channel.channel_id, |stored| {
        stored.verify_key = hex::encode([0x09u8; 32]);
    });

    assert!(matches!(
        reader.join_channel(&link, now()),
        Err(GasAppError::InvalidSignature)
    ));
    assert!(reader.channels().expect("список").is_empty());
}

/// Автор меняет название; читатель видит новое и не принимает прежнее,
/// если сервер попробует его вернуть.
#[test]
fn a_renamed_channel_does_not_roll_back() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Старое", "", now(), &mut OsRng)
        .expect("канал");
    let link = author.channel_link(&channel.channel_id).expect("ссылка");
    let old_meta = server.channel(&channel.channel_id).meta;

    reader.join_channel(&link, now()).expect("подписка");

    let renamed = author
        .update_channel(&channel.channel_id, "Новое", "Описание.", now(), &mut OsRng)
        .expect("переименование");
    assert_eq!(renamed.title, "Новое");

    reader.sync_channels(now()).expect("синхронизация");
    assert_eq!(reader.channels().expect("список")[0].title, "Новое");

    // «Сервер» возвращает прежнее описание — оно подписано автором,
    // но старше известного.
    server.tamper_channel(&channel.channel_id, |stored| stored.meta = old_meta);
    reader.sync_channels(now()).expect("синхронизация");

    assert_eq!(reader.channels().expect("список")[0].title, "Новое");
}

/// Запись с файлом: читатель скачивает и расшифровывает то, что
/// приложил автор; подменённый сервером блоб не открывается.
#[test]
fn a_post_carries_attachments() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);

    let original: Vec<u8> = (0..150_000u32).map(|index| (index % 251) as u8).collect();
    let published = author
        .publish_channel_post(
            &channel_id,
            "",
            &[document("отчёт.pdf", original.clone())],
            now(),
            &mut OsRng,
        )
        .expect("запись с файлом");
    assert_eq!(published.attachments.len(), 1);

    assert_eq!(
        reader
            .sync_channel(&channel_id, now())
            .expect("синхронизация"),
        1
    );
    let received = reader.channel_posts(&channel_id, 10).expect("записи");
    let attachment = &received[0].attachments[0];

    assert_eq!(attachment.kind, AttachmentKind::Document);
    assert_eq!(attachment.name.as_deref(), Some("отчёт.pdf"));
    assert_eq!(attachment.size, original.len() as u64);
    assert_eq!(
        reader.channels().expect("список")[0].last_post_attachments,
        1
    );
    assert_eq!(
        reader
            .fetch_channel_media(&channel_id, &attachment.descriptor, now())
            .expect("файл"),
        original
    );

    // 🔐 Скачивание медиа — без подписи: сервер не знает, кто смотрит.
    let headers = server
        .last_request(&format!("/v1/channels/feed/{channel_id}/media/"))
        .expect("скачивание");
    assert!(
        headers.is_empty(),
        "скачивание медиа подписано: {headers:?}"
    );

    server.tamper_channel(&channel_id, |stored| {
        for blob in stored.media.values_mut() {
            blob[100] ^= 0x01;
        }
    });
    assert!(reader
        .fetch_channel_media(&channel_id, &attachment.descriptor, now())
        .is_err());

    // Пустая запись и лишние вложения не уходят — и файлов не оставляют.
    assert!(matches!(
        author.publish_channel_post(&channel_id, "  ", &[], now(), &mut OsRng),
        Err(GasAppError::Malformed)
    ));
    let crowd: Vec<_> = (0..11).map(|_| document("a.txt", vec![1; 10])).collect();
    assert!(matches!(
        author.publish_channel_post(&channel_id, "много", &crowd, now(), &mut OsRng),
        Err(GasAppError::Malformed)
    ));
    assert_eq!(server.channel(&channel_id).media.len(), 1);
}

/// Правка доходит до читателя с пометкой; 🔐 прежнюю редакцию сервер
/// вернуть не может.
#[test]
fn an_edit_reaches_readers_and_does_not_roll_back() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);

    let seq = post_text(&author, &channel_id, "с ошыбкой");
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let first_edition = server.channel(&channel_id).posts[0].clone();

    let edited = author
        .edit_channel_post(&channel_id, seq, "без ошибки", now(), &mut OsRng)
        .expect("правка");
    assert_eq!(edited.text, "без ошибки");
    assert!(edited.edited_at.is_some());

    // Правка — не новая запись: счётчик непрочитанного не растёт.
    assert_eq!(
        reader
            .sync_channel(&channel_id, now())
            .expect("синхронизация"),
        0
    );
    let seen = reader.channel_posts(&channel_id, 10).expect("записи");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].text, "без ошибки");
    assert!(seen[0].edited_at.is_some());

    // Сервер выдаёт прежний шифротекст как свежее изменение.
    server.tamper_channel(&channel_id, |stored| {
        stored.last_rev += 1;
        stored.posts[0] = FakePost {
            rev: stored.last_rev,
            ..first_edition
        };
    });
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    assert_eq!(texts(&reader, &channel_id), vec!["без ошибки"]);

    // Пустой правка не бывает.
    assert!(matches!(
        author.edit_channel_post(&channel_id, seq, " ", now(), &mut OsRng),
        Err(GasAppError::Malformed)
    ));
}

/// Удаление: запись и её файл исчезают у читателя и с сервера; 🔐 слову
/// сервера «удалено» без подписи автора читатель не верит, и удалённое
/// из прежнего шифротекста не возвращается.
#[test]
fn a_deletion_needs_the_authors_signature() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);

    let keep = post_text(&author, &channel_id, "остаётся");
    let doomed = author
        .publish_channel_post(
            &channel_id,
            "уйдёт",
            &[document("a.txt", vec![3; 500])],
            now(),
            &mut OsRng,
        )
        .expect("запись")
        .seq;
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    reader.mark_channel_read(&channel_id).expect("прочитано");
    let doomed_body = server.channel(&channel_id).posts[1].clone();

    // Сервер объявляет первую запись удалённой сам — без отметки автора.
    server.tamper_channel(&channel_id, |stored| {
        stored.last_rev += 1;
        stored.posts[0].rev = stored.last_rev;
        stored.posts[0].deleted = true;
    });
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&reader, &channel_id), vec!["остаётся", "уйдёт"]);
    server.tamper_channel(&channel_id, |stored| stored.posts[0].deleted = false);

    author
        .pin_channel_post(&channel_id, doomed, now(), &mut OsRng)
        .expect("закреп");
    author
        .delete_channel_post(&channel_id, doomed, now(), &mut OsRng)
        .expect("удаление");

    assert_eq!(texts(&author, &channel_id), vec!["остаётся"]);
    assert!(server.channel(&channel_id).media.is_empty());
    // Закреп удалённой записи снимается вместе с ней.
    assert_eq!(author.channel(&channel_id).expect("канал").pinned_seq, 0);

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&reader, &channel_id), vec!["остаётся"]);
    assert!(reader
        .channel_post(&channel_id, doomed)
        .expect("запись")
        .is_none());

    // Сервер возвращает прежний шифротекст удалённой записи.
    server.tamper_channel(&channel_id, |stored| {
        stored.last_rev += 1;
        stored.posts[1] = FakePost {
            rev: stored.last_rev,
            ..doomed_body
        };
    });
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&reader, &channel_id), vec!["остаётся"]);

    // Второй раз удалить нечего.
    assert!(matches!(
        author.delete_channel_post(&channel_id, doomed, now(), &mut OsRng),
        Err(GasAppError::SessionNotFound)
    ));
    assert!(author
        .channel_post(&channel_id, keep)
        .expect("запись")
        .is_some());
}

/// Закреп и аватар едут в описании канала, подписанном автором.
#[test]
fn pin_and_avatar_travel_in_the_signed_meta() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);

    let seq = post_text(&author, &channel_id, "важное");
    let picture: Vec<u8> = b"not-a-real-image".repeat(64);

    let pinned = author
        .pin_channel_post(&channel_id, seq, now(), &mut OsRng)
        .expect("закреп");
    assert_eq!(pinned.pinned_seq, seq);
    author
        .set_channel_avatar(&channel_id, Some(&picture), now(), &mut OsRng)
        .expect("аватар");

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let seen = reader.channel(&channel_id).expect("канал");
    assert_eq!(seen.pinned_seq, seq);
    assert_eq!(seen.title, "Канал");
    assert_eq!(
        reader
            .fetch_channel_media(&channel_id, &seen.avatar.expect("аватар"), now())
            .expect("картинка"),
        picture
    );

    // Новый аватар заменяет прежний блоб, а не копит их.
    author
        .set_channel_avatar(&channel_id, Some(&[9u8; 300]), now(), &mut OsRng)
        .expect("новый аватар");
    assert_eq!(server.channel(&channel_id).media.len(), 1);

    author
        .set_channel_avatar(&channel_id, None, now(), &mut OsRng)
        .expect("без аватара");
    author
        .pin_channel_post(&channel_id, 0, now(), &mut OsRng)
        .expect("без закрепа");
    assert!(server.channel(&channel_id).media.is_empty());

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let cleared = reader.channel(&channel_id).expect("канал");
    assert_eq!(cleared.pinned_seq, 0);
    assert!(cleared.avatar.is_none());

    // Закрепить можно только существующую запись.
    assert!(matches!(
        author.pin_channel_post(&channel_id, 99, now(), &mut OsRng),
        Err(GasAppError::SessionNotFound)
    ));
}

/// Публичный канал находится по `@имени` и поиском; занятое имя — отказ.
#[test]
fn a_public_channel_is_found_by_handle() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Gas News", "Объявления.", now(), &mut OsRng)
        .expect("канал");
    let other = author
        .create_channel("Второй", "", now(), &mut OsRng)
        .expect("второй канал");
    post_text(&author, &channel.channel_id, "привет");

    assert!(matches!(
        reader.find_public_channel("gas_news"),
        Err(GasAppError::SessionNotFound)
    ));

    let public = author
        .set_channel_handle(&channel.channel_id, Some("@Gas_News"), now())
        .expect("публичность");
    assert_eq!(public.handle.as_deref(), Some("gas_news"));

    assert!(matches!(
        author.set_channel_handle(&other.channel_id, Some("gas_news"), now()),
        Err(GasAppError::UsernameTaken)
    ));
    assert!(matches!(
        author.set_channel_handle(&other.channel_id, Some("нет"), now()),
        Err(GasAppError::Malformed)
    ));

    let found = reader.find_public_channel("@gas_news").expect("канал");
    assert_eq!(found.title, "Gas News");
    assert_eq!(found.description, "Объявления.");
    assert_eq!(found.handle, "gas_news");
    assert!(!found.joined);
    // Автор — тоже подписчик своего канала.
    assert_eq!(found.subscribers, 1);

    let results = reader.search_public_channels("gas").expect("поиск");
    assert_eq!(results, vec![found.clone()]);
    assert!(reader
        .search_public_channels("zzz")
        .expect("поиск")
        .is_empty());

    let joined = reader.join_channel(&found.link, now()).expect("подписка");
    assert_eq!(joined.handle.as_deref(), Some("gas_news"));
    assert_eq!(texts(&reader, &channel.channel_id), vec!["привет"]);
    assert!(
        reader
            .find_public_channel("gas_news")
            .expect("канал")
            .joined
    );

    // Снова закрытый: по имени больше не находится.
    author
        .set_channel_handle(&channel.channel_id, None, now())
        .expect("закрытие");
    assert!(matches!(
        reader.find_public_channel("gas_news"),
        Err(GasAppError::SessionNotFound)
    ));
    reader
        .sync_channel(&channel.channel_id, now())
        .expect("синхронизация");
    assert!(reader
        .channel(&channel.channel_id)
        .expect("канал")
        .handle
        .is_none());
}

/// 🔐 Сервер не покажет под именем описание другого канала: ссылка
/// обязана вести к тому каналу, который он отдаёт.
#[test]
fn a_swapped_public_link_is_refused() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let honest = author
        .create_channel("Настоящий", "", now(), &mut OsRng)
        .expect("канал");
    let decoy = author
        .create_channel("Подставной", "", now(), &mut OsRng)
        .expect("канал");
    author
        .set_channel_handle(&honest.channel_id, Some("honest"), now())
        .expect("публичность");

    let decoy_link = author.channel_link(&decoy.channel_id).expect("ссылка");
    server.tamper_channel(&honest.channel_id, |stored| {
        stored.public_link = Some(decoy_link);
    });

    assert!(matches!(
        reader.find_public_channel("honest"),
        Err(GasAppError::InvalidSignature)
    ));
    assert!(reader
        .search_public_channels("hon")
        .expect("поиск")
        .is_empty());
}

/// Подписчики, просмотры и реакции считаются по аккаунтам.
#[test]
fn subscribers_views_and_reactions() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);

    let seq = post_text(&author, &channel_id, "запись");
    author
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(author.channel(&channel_id).expect("канал").subscribers, 2);

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    reader.mark_channel_read(&channel_id).expect("прочитано");
    reader
        .report_channel_seen(&channel_id, now())
        .expect("отметка");

    // Вторая отметка о том же до сервера не доходит.
    let before = server.state.borrow().requests.len();
    reader
        .report_channel_seen(&channel_id, now())
        .expect("отметка");
    assert_eq!(server.state.borrow().requests.len(), before);

    let reacted = reader
        .react_to_channel_post(&channel_id, seq, Some("🔥"), now())
        .expect("реакция");
    assert_eq!(reacted.my_reaction.as_deref(), Some("🔥"));
    assert_eq!(reacted.views, 1);
    assert_eq!(reacted.reactions.len(), 1);
    assert_eq!(reacted.reactions[0].emoji, "🔥");
    assert_eq!(reacted.reactions[0].count, 1);

    author
        .react_to_channel_post(&channel_id, seq, Some("👍"), now())
        .expect("реакция автора");
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let seen = reader
        .channel_post(&channel_id, seq)
        .expect("запись")
        .expect("есть");
    assert_eq!(seen.reactions.len(), 2);
    // Своя реакция переживает синхронизацию.
    assert_eq!(seen.my_reaction.as_deref(), Some("🔥"));

    // Смена и снятие.
    reader
        .react_to_channel_post(&channel_id, seq, Some("👍"), now())
        .expect("смена");
    let cleared = reader
        .react_to_channel_post(&channel_id, seq, None, now())
        .expect("снятие");
    assert!(cleared.my_reaction.is_none());
    assert_eq!(cleared.reactions.len(), 1);

    assert!(matches!(
        reader.react_to_channel_post(&channel_id, seq, Some("<b>"), now()),
        Err(GasAppError::Malformed)
    ));

    // 🔐 Подписчик — аккаунт: подписка, отметка и реакция подписаны
    // устройством, и на сервере два подписчика — два устройства.
    let headers = server
        .last_request("/v1/channels/reader/")
        .expect("действие подписчика");
    assert!(!headers.is_empty(), "действие подписчика не подписано");

    let stored = server.channel(&channel_id);
    assert_eq!(stored.subscribers.len(), 2);
}

/// Канал с длинной историей: при подписке приходит свежая страница,
/// старое догружается по запросу.
#[test]
fn older_posts_load_on_demand() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);

    let channel = author
        .create_channel("Летопись", "", now(), &mut OsRng)
        .expect("канал");
    for number in 1..=105 {
        post_text(&author, &channel.channel_id, &format!("запись {number}"));
    }
    let link = author.channel_link(&channel.channel_id).expect("ссылка");

    reader.join_channel(&link, now()).expect("подписка");
    let fresh = texts(&reader, &channel.channel_id);
    assert_eq!(fresh.len(), 100);
    assert_eq!(fresh[0], "запись 6");

    assert_eq!(
        reader
            .load_older_channel_posts(&channel.channel_id, now())
            .expect("история"),
        5
    );
    assert_eq!(texts(&reader, &channel.channel_id).len(), 105);
    assert_eq!(
        reader
            .load_older_channel_posts(&channel.channel_id, now())
            .expect("история"),
        0
    );

    let page = reader
        .channel_posts_before(&channel.channel_id, 6, 3)
        .expect("страница");
    assert_eq!(
        page.iter().map(|post| post.seq).collect::<Vec<_>>(),
        vec![3, 4, 5]
    );

    // Новое после подписки приходит изменениями, а не страницей.
    post_text(&author, &channel.channel_id, "запись 106");
    assert_eq!(reader.sync_channels(now()).expect("синхронизация"), 1);
}

/// «Без звука» убирает канал из общего счётчика; поиск по каналу —
/// локальный.
#[test]
fn mute_unread_total_and_search() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&author, &reader);

    post_text(&author, &channel_id, "скидка на бензин");
    post_text(&author, &channel_id, "новости недели");
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    assert_eq!(reader.unread_channel_posts().expect("счётчик"), 2);
    // Свой канал автором прочитан.
    assert_eq!(author.unread_channel_posts().expect("счётчик"), 0);

    assert!(
        reader
            .set_channel_muted(&channel_id, true)
            .expect("без звука")
            .muted
    );
    assert_eq!(reader.unread_channel_posts().expect("счётчик"), 0);
    assert_eq!(reader.channel(&channel_id).expect("канал").unread, 2);

    let before = server.state.borrow().requests.len();
    let found = reader
        .search_channel_posts(&channel_id, " бензин ", 10)
        .expect("поиск");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].text, "скидка на бензин");
    assert_eq!(
        server.state.borrow().requests.len(),
        before,
        "поиск по каналу не должен ходить на сервер"
    );
}

/// Третий участник: ни автор, ни администратор — просто читатель.
fn bystander(server: &FakeServer, dir: &tempfile::TempDir, link: &str) -> Client<FakeServer> {
    let client = Client::new(server.clone(), open_storage(dir, "bystander.db"));
    client
        .register("bystander", TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("третий");
    client.join_channel(link, now()).expect("подписка третьего");

    client
}

/// Устройство из заявки на администрирование — в виде UUID, как его знает сервер.
fn device_of_request(request: &str) -> String {
    let hex = request.rsplit('.').next().expect("устройство в заявке");

    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Владелец назначает администратора по заявке; администратор пишет и
/// правит, читатели это принимают. Описание, закреп и состав
/// администраторов остаются за владельцем.
#[test]
fn an_admin_posts_and_readers_accept_it() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, admin) = author_and_reader(&server, &dir);
    let (channel_id, link) = followed_channel(&owner, &admin);
    let reader = bystander(&server, &dir, &link);
    let first = post_text(&owner, &channel_id, "от владельца");

    // До назначения — читатель: писать нельзя.
    assert!(!admin.channel(&channel_id).expect("канал").can_post());

    let request = admin
        .channel_admin_request(&channel_id, &mut OsRng)
        .expect("заявка");
    // Заявка, показанная дважды, называет тот же ключ.
    assert_eq!(
        admin
            .channel_admin_request(&channel_id, &mut OsRng)
            .expect("заявка"),
        request
    );
    let pending = admin.channel(&channel_id).expect("канал");
    assert!(pending.admin_pending() && !pending.can_post());
    assert!(matches!(
        admin.publish_channel_post(&channel_id, "рано", &[], now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));

    let admins = owner
        .add_channel_admin(&channel_id, &request, "  Анна  ", now(), &mut OsRng)
        .expect("назначение");
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].label, "Анна");
    assert!(admins[0].active);

    admin
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let appointed = admin.channel(&channel_id).expect("канал");
    assert!(appointed.can_post() && !appointed.owned() && !appointed.admin_pending());

    let second = post_text(&admin, &channel_id, "от администратора");
    admin
        .edit_channel_post(
            &channel_id,
            first,
            "исправил администратор",
            now(),
            &mut OsRng,
        )
        .expect("правка чужой записи");

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(
        texts(&reader, &channel_id),
        vec!["исправил администратор", "от администратора"]
    );
    owner
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&owner, &channel_id).len(), 2);

    // 🔐 Администратор — не владелец.
    assert!(matches!(
        admin.update_channel(&channel_id, "Моё", "", now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        admin.pin_channel_post(&channel_id, second, now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        admin.set_channel_handle(&channel_id, Some("mine"), now()),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        admin.add_channel_admin(&channel_id, &request, "я", now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    // Уходя, администратор канал не удаляет.
    admin.leave_channel(&channel_id, now()).expect("уход");
    assert!(server.state.borrow().channels.contains_key(&channel_id));
}

/// 🔐 Сервер не назначает администраторов: запись, подписанная ключом,
/// которого нет в описании владельца, читателями не принимается.
#[test]
fn the_server_cannot_appoint_an_admin() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, impostor) = author_and_reader(&server, &dir);
    let (channel_id, link) = followed_channel(&owner, &impostor);
    let reader = bystander(&server, &dir, &link);
    post_text(&owner, &channel_id, "настоящая");

    // Владелец назначает, затем снимает: у бывшего администратора
    // остаётся ключ, а у сервера — желание ему помочь.
    let request = impostor
        .channel_admin_request(&channel_id, &mut OsRng)
        .expect("заявка");
    owner
        .add_channel_admin(&channel_id, &request, "временный", now(), &mut OsRng)
        .expect("назначение");
    impostor
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let before = post_text(&impostor, &channel_id, "до снятия");

    let admins = owner
        .remove_channel_admin(
            &channel_id,
            &owner.channel_admins(&channel_id).expect("список")[0].verify_key,
            now(),
            &mut OsRng,
        )
        .expect("снятие");
    assert!(!admins[0].active);

    // Честный сервер бывшему администратору отказывает.
    assert!(matches!(
        impostor.publish_channel_post(&channel_id, "после снятия", &[], now(), &mut OsRng),
        Err(GasAppError::SessionNotFound)
    ));

    // Нечестный — пускает его обратно сам, без владельца.
    let impostor_device = device_of_request(&request);
    server.tamper_channel(&channel_id, |stored| {
        stored.admins.insert(impostor_device, "ignored".to_owned());
    });
    impostor
        .publish_channel_post(&channel_id, "подделка", &[], now(), &mut OsRng)
        .expect("сервер принял");

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&reader, &channel_id), vec!["настоящая", "до снятия"]);
    assert!(reader
        .channel_post(&channel_id, before)
        .expect("запись")
        .is_some());

    // Сам снятый узнаёт о снятии при синхронизации и больше не пишет.
    impostor
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    let removed = impostor.channel(&channel_id).expect("канал");
    assert!(!removed.can_post() && removed.admin_pending());
}

/// В канал пишут двое: номер заняли между «узнал» и «опубликовал» —
/// запись выходит под следующим, а не теряется и не засоряет ленту.
#[test]
fn a_taken_post_number_is_retried() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&owner, &reader);

    server.tamper_channel(&channel_id, |stored| stored.conflicts = 2);
    let seq = post_text(&owner, &channel_id, "дошла");

    // Две чужие записи заняли номера 1 и 2.
    assert_eq!(seq, 3);
    assert_eq!(server.channel(&channel_id).posts.len(), 3);

    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&reader, &channel_id), vec!["дошла"]);
}

/// Заявка в другой канал и собственная заявка владельца не принимаются.
#[test]
fn an_admin_request_is_bound_to_its_channel() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, reader) = author_and_reader(&server, &dir);
    let (channel_id, _) = followed_channel(&owner, &reader);
    let other = owner
        .create_channel("Другой", "", now(), &mut OsRng)
        .expect("второй канал");

    let request = reader
        .channel_admin_request(&channel_id, &mut OsRng)
        .expect("заявка");

    assert!(matches!(
        owner.add_channel_admin(&other.channel_id, &request, "", now(), &mut OsRng),
        Err(GasAppError::Malformed)
    ));
    assert!(matches!(
        owner.add_channel_admin(
            &channel_id,
            "gasapp://channel-admin/zz",
            "",
            now(),
            &mut OsRng
        ),
        Err(GasAppError::Malformed)
    ));
    assert!(matches!(
        owner.channel_admin_request(&channel_id, &mut OsRng),
        Err(GasAppError::Malformed)
    ));
    assert!(server.channel(&channel_id).admins.is_empty());
    assert!(owner
        .channel_admins(&channel_id)
        .expect("список")
        .is_empty());
}

/// 🔐 Подписчик — аккаунт: один аккаунт — один подписчик, сколько бы
/// раз он ни добавлял канал. Чтение ленты при этом остаётся анонимным.
#[test]
fn one_account_is_one_subscriber() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, reader) = author_and_reader(&server, &dir);
    let (channel_id, link) = followed_channel(&owner, &reader);

    assert_eq!(server.channel(&channel_id).subscribers.len(), 2);

    // Ушёл и вернулся — подписчик тот же.
    reader.leave_channel(&channel_id, now()).expect("уход");
    assert_eq!(server.channel(&channel_id).subscribers.len(), 1);
    reader.join_channel(&link, now()).expect("возвращение");
    reader.join_channel(&link, now()).expect("ещё раз");
    assert_eq!(server.channel(&channel_id).subscribers.len(), 2);

    // Подписка подписана устройством, а чтение ленты — нет.
    let subscribe = server
        .last_request("/v1/channels/reader/")
        .expect("подписка");
    assert!(!subscribe.is_empty(), "подписка обязана быть подписана");
    let feed = server
        .last_request(&format!("/v1/channels/feed/{channel_id}"))
        .expect("чтение");
    assert!(feed.is_empty(), "чтение ленты подписано: {feed:?}");
}

/// Читатель уходит — его подписка снимается; автор удаляет — канала нет.
#[test]
fn leaving_and_deleting_a_channel() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, link) = followed_channel(&author, &reader);

    assert_eq!(server.channel(&channel_id).subscribers.len(), 2);

    reader.leave_channel(&channel_id, now()).expect("отписка");

    assert!(reader.channels().expect("список").is_empty());
    assert_eq!(server.channel(&channel_id).subscribers.len(), 1);

    author.leave_channel(&channel_id, now()).expect("удаление");

    assert!(author.channels().expect("список").is_empty());
    assert!(!server.state.borrow().channels.contains_key(&channel_id));
    assert!(matches!(
        reader.join_channel(&link, now()),
        Err(GasAppError::SessionNotFound)
    ));
}

/// Незавершённая регистрация переживает закрытие базы и стирается,
/// когда аккаунт создан: адрес почты на устройстве не остаётся.
#[test]
fn a_pending_registration_survives_until_the_account_exists() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();

    {
        let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));

        assert_eq!(alice.pending_registration().expect("чтение"), None);
        alice
            .set_pending_registration(" Alice ", " Alice@Example.org ")
            .expect("запись");
    }

    // Приложение заблокировалось и открылось заново.
    let alice = Client::new(server.clone(), open_storage(&dir, "alice.db"));
    let pending = alice
        .pending_registration()
        .expect("чтение")
        .expect("регистрация не закончена");

    assert_eq!(pending.username, "alice");
    assert_eq!(pending.email, "alice@example.org");

    alice
        .register(
            &pending.username,
            &pending.email,
            "123456",
            now(),
            &mut OsRng,
        )
        .expect("регистрация");

    assert_eq!(alice.pending_registration().expect("чтение"), None);
}

// ---------------------------------------------------------------------------
//  Закрытые каналы
// ---------------------------------------------------------------------------

/// Закрытый канал автора с одной записью и ссылкой-приглашением.
fn closed_channel(author: &Client<FakeServer>) -> (String, String) {
    let channel = author
        .create_channel("Свои", "", now(), &mut OsRng)
        .expect("канал");
    post_text(author, &channel.channel_id, "только для своих");

    assert!(
        author
            .set_channel_closed(&channel.channel_id, true, now())
            .expect("закрыть")
            .closed
    );

    let invite = author
        .create_channel_invite(&channel.channel_id, now(), &mut OsRng)
        .expect("ссылка");

    (channel.channel_id, invite)
}

/// Автор одобряет единственную заявку.
fn approve_only_request(author: &Client<FakeServer>, channel_id: &str) {
    let requests = author
        .channel_join_requests(channel_id, now())
        .expect("заявки");
    assert_eq!(requests.len(), 1);

    author
        .answer_channel_join(channel_id, &requests[0].account_id, true, now(), &mut OsRng)
        .expect("одобрение");
}

/// 🔐 В закрытый канал входят по заявке: ссылка секрета не несёт,
/// секрет приходит одобренному шифротекстом, а записи забираются за
/// подписью.
#[test]
fn a_closed_channel_is_joined_by_approved_request() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, invite) = closed_channel(&author);

    // Ссылка-приглашение — не ссылка открытого канала, и секрета в ней нет.
    assert!(matches!(
        reader.join_channel(&invite, now()),
        Err(GasAppError::Malformed)
    ));
    assert_eq!(
        author.channel_invites(&channel_id).expect("ссылки"),
        vec![invite.clone()]
    );

    // Полная ссылка с секретом закрытый канал не открывает: сервер
    // его без подписи не отдаёт, а подписаться в обход нельзя.
    let full = author.channel_link(&channel_id).expect("ссылка");
    assert!(reader.join_channel(&full, now()).is_err());
    assert!(reader.channels().expect("каналы").is_empty());

    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");
    let pending = reader.pending_channel_joins().expect("заявки");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].channel_id, channel_id);

    // Пока не одобрили — канала нет, заявка ждёт.
    assert!(reader
        .check_channel_joins(now())
        .expect("проверка")
        .is_empty());
    assert_eq!(reader.pending_channel_joins().expect("заявки").len(), 1);

    let requests = author
        .channel_join_requests(&channel_id, now())
        .expect("заявки");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].username, "reader");
    assert!(!requests[0].known_contact);

    approve_only_request(&author, &channel_id);
    assert!(author
        .channel_join_requests(&channel_id, now())
        .expect("заявки")
        .is_empty());

    let joined = reader.check_channel_joins(now()).expect("проверка");
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0].title, "Свои");
    assert!(joined[0].closed);
    assert!(reader.pending_channel_joins().expect("заявки").is_empty());
    assert_eq!(texts(&reader, &channel_id), ["только для своих"]);

    // Новые записи доходят — запросом за подписью, а не анонимным.
    post_text(&author, &channel_id, "вторая");
    let before = server.state.borrow().requests.len();
    assert_eq!(
        reader
            .sync_channel(&channel_id, now())
            .expect("синхронизация"),
        1
    );
    assert_eq!(texts(&reader, &channel_id), ["только для своих", "вторая"]);
    assert!(
        server.state.borrow().requests[before..]
            .iter()
            .all(|(path, _)| path.starts_with("/v1/channels/reader/")),
        "закрытый канал читается только за подписью"
    );

    let members = author
        .channel_subscribers(&channel_id, None, now())
        .expect("подписчики");
    assert!(members.iter().any(|member| member.username == "reader"));
}

/// Отклонённая заявка исчезает у заявителя; удалённый подписчик
/// перестаёт получать записи и не может подать заявку, пока запрет
/// не снят.
#[test]
fn declined_and_removed_readers_are_locked_out() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, invite) = closed_channel(&author);

    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");
    let requests = author
        .channel_join_requests(&channel_id, now())
        .expect("заявки");
    let account_id = requests[0].account_id.clone();

    author
        .answer_channel_join(&channel_id, &account_id, false, now(), &mut OsRng)
        .expect("отказ");
    assert!(reader
        .check_channel_joins(now())
        .expect("проверка")
        .is_empty());
    assert!(reader.pending_channel_joins().expect("заявки").is_empty());

    // Вторая попытка — одобрена.
    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");
    approve_only_request(&author, &channel_id);
    assert_eq!(
        reader.check_channel_joins(now()).expect("проверка").len(),
        1
    );

    author
        .remove_channel_subscriber(&channel_id, &account_id, false, now(), &mut OsRng)
        .expect("удаление");
    post_text(&author, &channel_id, "после удаления");

    assert!(matches!(
        reader.sync_channel(&channel_id, now()),
        Err(GasAppError::SessionNotFound)
    ));
    assert_eq!(texts(&reader, &channel_id), ["только для своих"]);

    let banned = author
        .channel_banned(&channel_id, now())
        .expect("удалённые");
    assert_eq!(banned.len(), 1);
    assert_eq!(banned[0].username, "reader");

    // Удалённый уходит из канала у себя и просится снова — нельзя.
    reader.leave_channel(&channel_id, now()).expect("уход");
    assert!(matches!(
        reader.request_channel_join(&invite, now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(reader.pending_channel_joins().expect("заявки").is_empty());

    author
        .remove_channel_subscriber(&channel_id, &account_id, true, now(), &mut OsRng)
        .expect("снятие запрета");
    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");
}

/// Отозванная ссылка заявок не принимает; читатель канал не ведёт;
/// закрытому каналу нельзя дать `@имя`.
#[test]
fn closed_channel_rules_hold() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, invite) = closed_channel(&author);

    assert!(matches!(
        author.set_channel_handle(&channel_id, Some("svoi_kanal"), now()),
        Err(GasAppError::Malformed)
    ));

    author
        .revoke_channel_invite(&channel_id, &invite, now())
        .expect("отзыв");
    assert!(author
        .channel_invites(&channel_id)
        .expect("ссылки")
        .is_empty());
    assert!(matches!(
        reader.request_channel_join(&invite, now(), &mut OsRng),
        Err(GasAppError::SessionNotFound)
    ));
    assert!(reader.pending_channel_joins().expect("заявки").is_empty());

    // Открытый канал читателя: вести его он не может.
    let (open_id, _) = followed_channel(&author, &reader);
    assert!(matches!(
        reader.set_channel_closed(&open_id, true, now()),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.create_channel_invite(&open_id, now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.channel_join_requests(&open_id, now()),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        reader.channel_subscribers(&open_id, None, now()),
        Err(GasAppError::Forbidden)
    ));

    // Канал, закрытый после подписки, читатель продолжает читать — уже
    // за подписью.
    post_text(&author, &open_id, "до закрытия");
    reader.sync_channel(&open_id, now()).expect("синхронизация");
    author
        .set_channel_closed(&open_id, true, now())
        .expect("закрыть");
    post_text(&author, &open_id, "после закрытия");
    assert_eq!(
        reader.sync_channel(&open_id, now()).expect("синхронизация"),
        1
    );
    assert!(reader.channel(&open_id).expect("канал").closed);
    assert_eq!(texts(&reader, &open_id), ["до закрытия", "после закрытия"]);
}

/// 🔐 Ответ с чужим секретом не принимается: описание канала им не
/// расшифровывается, и канал не добавляется.
#[test]
fn a_forged_grant_is_refused() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, invite) = closed_channel(&author);

    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");

    // Сервер «одобряет» сам: подсовывает ответ, которого автор не давал.
    {
        let mut state = server.state.borrow_mut();
        let reader_account = state.accounts["reader"].0.clone();
        let reader_device = state.devices[&reader_account].clone();
        let channel = state.channels.get_mut(&channel_id).expect("канал");

        channel.requests.remove(&reader_account);
        channel
            .grants
            .insert(reader_account, hex::encode([7u8; 93]));
        channel.subscribers.insert(reader_device, 0);
    }

    assert!(reader
        .check_channel_joins(now())
        .expect("проверка")
        .is_empty());
    assert!(reader.channels().expect("каналы").is_empty());
    assert!(reader.pending_channel_joins().expect("заявки").is_empty());
}

// ---------------------------------------------------------------------------
//  Боты
// ---------------------------------------------------------------------------

/// Владелец с премиумом заводит бота: токен одноразовый, программа
/// бота регистрируется по нему со своими ключами.
#[test]
fn an_owner_creates_and_deletes_a_bot() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, plain) = author_and_reader(&server, &dir);

    // Без премиума и с именем не на `bot` — нельзя.
    assert!(matches!(
        plain.create_bot("helper_bot", now()),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        owner.create_bot("helper", now()),
        Err(GasAppError::InvalidUsername)
    ));

    let token = owner.create_bot("Helper_Bot", now()).expect("токен");
    assert!(token.starts_with("gasapp-bot:helper_bot:"));
    // Пока программа бота не запущена, бот виден как ждущий; строку
    // можно взять заново — прежняя гаснет.
    let pending = owner.bot_list(now()).expect("боты");
    assert_eq!(pending.len(), 1);
    assert!(pending[0].pending);
    let stale = token;
    let token = owner.create_bot("helper_bot", now()).expect("новый токен");
    assert_ne!(token, stale);

    let bot = Client::new(server.clone(), open_storage(&dir, "bot.db"));
    let account = bot.register_bot(&token, now(), &mut OsRng).expect("бот");
    assert_eq!(account.username, "helper_bot");
    assert_eq!(
        bot.own_username().expect("имя").as_deref(),
        Some("helper_bot")
    );
    assert_eq!(owner.bots(now()).expect("боты"), ["helper_bot"]);

    // Токен одноразовый; чужая строка — не токен.
    let second = Client::new(server.clone(), open_storage(&dir, "bot2.db"));
    assert!(matches!(
        second.register_bot(&token, now(), &mut OsRng),
        Err(GasAppError::Forbidden)
    ));
    assert!(matches!(
        second.register_bot("gasapp-bot:helper_bot:zz", now(), &mut OsRng),
        Err(GasAppError::Malformed)
    ));

    // Боту пишут, как любому аккаунту: контакт — по его ссылке.
    owner
        .add_contact_from_link(&bot.own_contact_link().expect("ссылка бота"), now())
        .expect("контакт");
    owner
        .send_message("helper_bot", "привет, бот", now(), &mut OsRng)
        .expect("сообщение боту");
    let device = bot.own_device_id().expect("устройство").expect("есть");
    assert_eq!(bot.receive_messages(&device, now()).expect("приём"), 1);

    // Чужого бота не удалить; своего — можно.
    assert!(matches!(
        plain.delete_bot("helper_bot", now()),
        Err(GasAppError::SessionNotFound)
    ));
    owner.delete_bot("helper_bot", now()).expect("удаление");
    assert!(owner.bots(now()).expect("боты").is_empty());
}

/// 🔐 Бот, назначенный администратором, ведёт закрытый канал: одобряет
/// заявки (передаёт ключ чтения) и удаляет подписчиков.
#[test]
fn a_bot_admin_approves_and_removes_subscribers() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, reader) = author_and_reader(&server, &dir);
    let (channel_id, invite) = closed_channel(&owner);

    let token = owner.create_bot("gate_bot", now()).expect("токен");
    let bot = Client::new(server.clone(), open_storage(&dir, "bot.db"));
    bot.register_bot(&token, now(), &mut OsRng).expect("бот");

    // Бот входит в канал, как все: по заявке, которую одобряет владелец.
    bot.request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка бота");
    approve_only_request(&owner, &channel_id);
    assert_eq!(bot.check_channel_joins(now()).expect("проверка").len(), 1);

    // Подписчик канал не ведёт.
    assert!(matches!(
        bot.channel_join_requests(&channel_id, now()),
        Err(GasAppError::Forbidden)
    ));

    let request = bot
        .channel_admin_request(&channel_id, &mut OsRng)
        .expect("заявка на администрирование");
    owner
        .add_channel_admin(&channel_id, &request, "Привратник", now(), &mut OsRng)
        .expect("назначение");
    bot.sync_channel(&channel_id, now()).expect("синхронизация");
    assert!(bot.channel(&channel_id).expect("канал").can_post());

    // Заявку читателя одобряет бот — и читатель входит.
    reader
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");
    let requests = bot
        .channel_join_requests(&channel_id, now())
        .expect("заявки");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].username, "reader");

    bot.answer_channel_join(
        &channel_id,
        &requests[0].account_id,
        true,
        now(),
        &mut OsRng,
    )
    .expect("одобрение ботом");
    assert_eq!(
        reader.check_channel_joins(now()).expect("проверка").len(),
        1
    );
    assert_eq!(texts(&reader, &channel_id), ["только для своих"]);

    // Бот пишет в канал, и читатель это принимает.
    post_text(&bot, &channel_id, "от бота");
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&reader, &channel_id), ["только для своих", "от бота"]);

    // Бот удаляет подписчика.
    bot.remove_channel_subscriber(
        &channel_id,
        &requests[0].account_id,
        false,
        now(),
        &mut OsRng,
    )
    .expect("удаление ботом");
    assert!(matches!(
        reader.sync_channel(&channel_id, now()),
        Err(GasAppError::SessionNotFound)
    ));

    // Удалён бот — канал он больше не ведёт: аккаунта нет.
    owner.delete_bot("gate_bot", now()).expect("удаление бота");
    assert!(bot.channel_join_requests(&channel_id, now()).is_err());
}

// ---------------------------------------------------------------------------
//  Смена ключа закрытого канала
// ---------------------------------------------------------------------------

/// Ещё один читатель со своим хранилищем.
fn extra_reader(server: &FakeServer, dir: &tempfile::TempDir, name: &str) -> Client<FakeServer> {
    let client = Client::new(server.clone(), open_storage(dir, &format!("{name}.db")));
    client
        .register(name, TEST_EMAIL, TEST_EMAIL_CODE, now(), &mut OsRng)
        .expect("регистрация");

    client
}

/// Читатель подаёт заявку, автор одобряет, читатель входит.
fn join_closed(
    author: &Client<FakeServer>,
    reader: &Client<FakeServer>,
    channel_id: &str,
    invite: &str,
) -> String {
    reader
        .request_channel_join(invite, now(), &mut OsRng)
        .expect("заявка");
    let requests = author
        .channel_join_requests(channel_id, now())
        .expect("заявки");
    let account_id = requests[0].account_id.clone();
    author
        .answer_channel_join(channel_id, &account_id, true, now(), &mut OsRng)
        .expect("одобрение");
    assert_eq!(reader.check_channel_joins(now()).expect("вход").len(), 1);

    account_id
}

/// Тело записи номер `seq` у поддельного сервера — как его хранит сервер.
fn stored_body(server: &FakeServer, channel_id: &str, seq: usize) -> Vec<u8> {
    hex::decode(&server.state.borrow().channels[channel_id].posts[seq - 1].body).expect("hex")
}

/// 🔐 Удаление подписчика меняет ключ канала: оставшиеся читают новые
/// записи, а удалённый не расшифрует их, даже получив шифротекст.
#[test]
fn removing_a_subscriber_changes_the_channel_key() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, stays) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let third = extra_reader(&server, &dir, "third");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &stays, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);
    join_closed(&author, &third, &channel_id, &invite);

    // Ключ, которым удалённый читал канал.
    let old_link = author.channel_link(&channel_id).expect("ссылка");
    let old_access = gasapp_protocol::channel::ChannelAccess::parse(&old_link).expect("доступ");

    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    assert!(!author.channel(&channel_id).expect("канал").rekey_pending);
    assert_eq!(server.state.borrow().channels[&channel_id].key_epoch, 1);

    let number = post_text(&author, &channel_id, "после удаления");
    let seq = usize::try_from(number).expect("номер");

    // Оставшиеся (их больше одной страницы выдачи ключей) читают.
    for reader in [&stays, &third] {
        assert_eq!(
            reader
                .sync_channel(&channel_id, now())
                .expect("синхронизация"),
            1
        );
        assert_eq!(
            texts(reader, &channel_id),
            ["только для своих", "после удаления"]
        );
    }

    // 🔐 Удалённый добыл шифротекст новой записи мимо сервера: прежний
    // ключ его не открывает, а ответа с новым ему никто не выдал.
    let body = stored_body(&server, &channel_id, seq);
    let (epoch, record) = gasapp_protocol::channel::split_epoch(&body).expect("эпоха");
    assert_eq!(epoch, 1);
    assert!(old_access.open_post(record, number, &[]).is_err());
    {
        let state = server.state.borrow();
        let channel = &state.channels[&channel_id];
        assert!(!channel.grants.contains_key(&removed));
        assert!(!channel.member_keys.contains_key(&removed));
    }

    // Правка старой записи тоже уходит под новым ключом.
    author
        .edit_channel_post(&channel_id, 1, "исправлено", now(), &mut OsRng)
        .expect("правка");
    let edited = stored_body(&server, &channel_id, 1);
    assert_eq!(
        gasapp_protocol::channel::split_epoch(&edited)
            .expect("эпоха")
            .0,
        1
    );
    stays
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&stays, &channel_id), ["исправлено", "после удаления"]);

    // Новый участник получает ключ действующей эпохи и по звену читает
    // всё — и старое, и новое.
    let late = extra_reader(&server, &dir, "late");
    join_closed(&author, &late, &channel_id, &invite);
    assert_eq!(texts(&late, &channel_id), ["исправлено", "после удаления"]);

    // Канал, у которого меняли ключ, открытым не сделать.
    assert!(matches!(
        author.set_channel_closed(&channel_id, false, now()),
        Err(GasAppError::Malformed)
    ));
}

/// Смена ключа не удалась (нет сети) — она остаётся долгом и
/// выполняется при обслуживании каналов.
#[test]
fn a_failed_rekey_is_retried() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &reader, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);

    server
        .state
        .borrow_mut()
        .channels
        .get_mut(&channel_id)
        .expect("канал")
        .rekey_failures = 1;

    // Подписчик удалён, ключ — ещё нет.
    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    assert!(author.channel(&channel_id).expect("канал").rekey_pending);
    assert_eq!(server.state.borrow().channels[&channel_id].key_epoch, 0);

    author
        .maintain_channel_keys(now(), &mut OsRng)
        .expect("обслуживание");
    assert!(!author.channel(&channel_id).expect("канал").rekey_pending);
    assert_eq!(server.state.borrow().channels[&channel_id].key_epoch, 1);

    post_text(&author, &channel_id, "новым ключом");
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(
        texts(&reader, &channel_id),
        ["только для своих", "новым ключом"]
    );
}

/// 🔐 Читатель, подписавшийся, пока канал был открытым, ключа новой
/// эпохи сам собой не получает: тот, кто ведёт канал, его не одобрял, а
/// список подписчиков открытого канала — слово сервера. Он входит
/// заново, по заявке.
#[test]
fn a_reader_from_before_closing_must_be_approved() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, early) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");

    // Открытый канал: ранний читатель входит по обычной ссылке.
    let (channel_id, _) = followed_channel(&author, &early);
    post_text(&author, &channel_id, "открытая");
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    author
        .set_channel_closed(&channel_id, true, now())
        .expect("закрыть");
    let invite = author
        .create_channel_invite(&channel_id, now(), &mut OsRng)
        .expect("ссылка");
    let removed = join_closed(&author, &leaves, &channel_id, &invite);

    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    post_text(&author, &channel_id, "после смены");

    // Он синхронизируется и называет ключ доставки — но удостоверения
    // у этого ключа нет, и обслуживание каналов ключа ему не выдаёт.
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    author
        .maintain_channel_keys(now(), &mut OsRng)
        .expect("обслуживание");
    assert_eq!(
        early
            .sync_channel(&channel_id, now())
            .expect("синхронизация"),
        0
    );
    assert_eq!(texts(&early, &channel_id), ["открытая"]);
    {
        let state = server.state.borrow();
        let channel = &state.channels[&channel_id];
        let account = account_of_name(&server, "reader");
        assert!(channel.member_keys.contains_key(&account));
        assert!(!channel.approvals.contains_key(&account));
        assert!(!channel.grants.contains_key(&account));
    }

    // По заявке его одобряют — и записи доходят.
    join_closed(&author, &early, &channel_id, &invite);
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&early, &channel_id), ["открытая", "после смены"]);
}

/// 🔐 Владелец, потерявший телефон, возвращает ключи всех эпох по
/// резервной копии: ключ доставки выводится из ключа подписи канала.
#[test]
fn the_owner_can_recover_epoch_keys_from_the_signing_key() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &reader, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);
    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    post_text(&author, &channel_id, "эпоха один");

    // Всё, что нужно владельцу на новом телефоне, — ключ подписи канала
    // (он в копии) и то, что лежит на сервере.
    let id = gasapp_protocol::channel::parse_channel_id(&channel_id).expect("id");
    let peek = open_storage(&dir, "author.db");
    let row = peek.channel(&id).expect("чтение").expect("канал");
    let signing_key = PrivateKeyBytes::new(row.signing_key.expect("ключ подписи"));
    let derived = gasapp_protocol::channel_join::delivery_secret(&id, &signing_key).expect("вывод");

    // Ключ доставки владельца — выведенный, а не случайный.
    assert_eq!(
        peek.channel_delivery(&id).expect("чтение"),
        Some((*derived.expose_secret(), true))
    );

    // Ответ владельцу на сервере открывается выведенным ключом и несёт
    // ключ действующей эпохи.
    let grant = {
        let state = server.state.borrow();
        let owner_account = state.accounts["author"].0.clone();

        hex::decode(&state.channels[&channel_id].grants[&owner_account]).expect("hex")
    };
    let (epoch, access) = gasapp_protocol::channel_join::open_grant(
        &id,
        &PublicKeyBytes::new(row.verify_key),
        &derived,
        &grant,
    )
    .expect("ответ открывается");
    assert_eq!(epoch, 1);
    assert_eq!(
        Some(access.secret),
        peek.channel_key(&id, 1).expect("чтение")
    );
}

// ---------------------------------------------------------------------------
//  Кнопки под сообщениями
// ---------------------------------------------------------------------------

/// Кнопки прикладываются к своему сообщению, показываются собеседнику,
/// а нажатие возвращается автору — и только с предложенными данными.
#[test]
fn buttons_under_a_message_are_shown_and_pressed() {
    use gasapp_protocol::keyboard::{Button, ButtonAction, Keyboard};

    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (bot, human) = author_and_reader(&server, &dir);
    human
        .add_contact_from_link(&bot.own_contact_link().expect("ссылка"), now())
        .expect("контакт");
    bot.add_contact_from_link(&human.own_contact_link().expect("ссылка"), now())
        .expect("контакт");
    let bot_device = bot.own_device_id().expect("устройство").expect("есть");
    let human_device = human.own_device_id().expect("устройство").expect("есть");

    let keyboard = Keyboard {
        rows: vec![vec![
            Button {
                label: "Да".to_owned(),
                action: ButtonAction::Callback(b"yes".to_vec()),
            },
            Button {
                label: "Сайт".to_owned(),
                action: ButtonAction::Url("https://example.org/".to_owned()),
            },
        ]],
    };

    let id = bot
        .send_message("reader", "Выберите", now(), &mut OsRng)
        .expect("сообщение");
    bot.send_keyboard("reader", &id, &keyboard, now(), &mut OsRng)
        .expect("кнопки");

    // Кнопки — не сообщение: в счёт принятых они не идут.
    assert_eq!(
        human.receive_messages(&human_device, now()).expect("приём"),
        1
    );

    // 🔐 Контакт добавлен по ссылке: входящее сообщение этого не отменяет,
    // и ответить ему можно.
    assert!(human.contacts().expect("контакты")[0].key_confirmed);
    assert_eq!(
        human.message_keyboard(&id).expect("кнопки"),
        Some(keyboard.clone())
    );

    // Чужому сообщению кнопки не приложить.
    assert!(matches!(
        human.send_keyboard("author", &id, &keyboard, now(), &mut OsRng),
        Err(GasAppError::Malformed)
    ));

    // Кнопка со ссылкой автору ничего не сообщает.
    let before = server.state.borrow().requests.len();
    assert_eq!(
        human
            .press_button(&id, 0, 1, now(), &mut OsRng)
            .expect("нажатие")
            .as_deref(),
        Some("https://example.org/")
    );
    assert_eq!(server.state.borrow().requests.len(), before);

    // Кнопка с данными — нажатие доходит автору, и в переписке его нет.
    assert_eq!(
        human
            .press_button(&id, 0, 0, now(), &mut OsRng)
            .expect("нажатие"),
        None
    );
    assert_eq!(bot.receive_messages(&bot_device, now()).expect("приём"), 0);
    let callbacks = bot.take_button_callbacks().expect("нажатия");
    assert_eq!(callbacks.len(), 1);
    assert_eq!(callbacks[0].message_id, id);
    assert_eq!(callbacks[0].data, b"yes");
    assert!(bot.take_button_callbacks().expect("нажатия").is_empty());

    // Кнопки, которой нет, нажать нельзя.
    assert!(matches!(
        human.press_button(&id, 3, 0, now(), &mut OsRng),
        Err(GasAppError::SessionNotFound)
    ));

    // Автор убирает кнопки — у собеседника их больше нет.
    bot.send_keyboard("reader", &id, &Keyboard::default(), now(), &mut OsRng)
        .expect("убрать");
    human.receive_messages(&human_device, now()).expect("приём");
    assert_eq!(human.message_keyboard(&id).expect("кнопки"), None);
    assert!(matches!(
        human.press_button(&id, 0, 0, now(), &mut OsRng),
        Err(GasAppError::SessionNotFound)
    ));
}

/// 🔐 Жалоба на канал уходит оператору; ключ чтения — только если
/// человек решил его приложить, и никогда — у канала со сменённым ключом.
#[test]
fn a_channel_report_shares_the_key_only_on_request() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, reader) = author_and_reader(&server, &dir);
    let (channel_id, link) = followed_channel(&author, &reader);

    reader
        .report_channel(&channel_id, 1, None, false, now())
        .expect("жалоба");
    reader
        .report_channel(&channel_id, 3, None, true, now())
        .expect("жалоба с ключом");
    assert!(matches!(
        reader.report_channel(&channel_id, 9, None, false, now()),
        Err(GasAppError::Malformed)
    ));
    assert_eq!(
        server.state.borrow().channels[&channel_id].reports,
        [(1, None), (3, Some(link))]
    );

    // Закрытый канал со сменённым ключом: ссылка не прикладывается.
    let leaves = extra_reader(&server, &dir, "leaver");
    let (closed_id, invite) = closed_channel(&author);
    join_closed(&author, &reader, &closed_id, &invite);
    let removed = join_closed(&author, &leaves, &closed_id, &invite);
    author
        .remove_channel_subscriber(&closed_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    reader
        .sync_channel(&closed_id, now())
        .expect("синхронизация");
    reader
        .report_channel(&closed_id, 2, None, true, now())
        .expect("жалоба");
    assert_eq!(
        server.state.borrow().channels[&closed_id].reports,
        [(2, None)]
    );
}

// ---------------------------------------------------------------------------
//  Закрытые каналы: враждебный сервер
// ---------------------------------------------------------------------------

/// Аккаунт по имени — как его знает поддельный сервер.
fn account_of_name(server: &FakeServer, name: &str) -> String {
    server.state.borrow().accounts[name].0.clone()
}

/// 🔐 Сервер подставил под аккаунт участника свой ключ доставки: ключ
/// новой эпохи под него не шифруется.
#[test]
fn a_substituted_delivery_key_gets_no_epoch_key() {
    use gasapp_protocol::channel_join::{self, JoinLink};
    use gasapp_protocol::x25519::X25519PrivateKey;

    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, victim) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &victim, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);
    let victim_account = account_of_name(&server, "reader");

    // Сервер заменяет ключ доставки жертвы своим: заявка составлена по
    // всем правилам, но подписана чужим ключом аккаунта.
    let link = JoinLink::parse(&invite).expect("ссылка");
    let attacker = X25519PrivateKey::generate(&mut OsRng).expose_secret();
    let forged = channel_join::seal_request(&link, &attacker, &mut OsRng).expect("заявка");
    server
        .state
        .borrow_mut()
        .channels
        .get_mut(&channel_id)
        .expect("канал")
        .member_keys
        .insert(victim_account.clone(), hex::encode(&forged.wire));

    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");

    let state = server.state.borrow();
    let channel = &state.channels[&channel_id];
    assert_eq!(channel.key_epoch, 1);
    // Ответ под подставленный ключ не выдан: у жертвы остался прежний,
    // нулевой эпохи, а сервер ключа новой эпохи не получил.
    assert_eq!(channel.grant_epochs.get(&victim_account), Some(&0));
    let grant = hex::decode(&channel.grants[&victim_account]).expect("hex");
    assert!(
        channel_join::open_grant(&link.channel_id, &link.verify_key, &forged.secret, &grant)
            .is_err()
    );
}

/// 🔐 Снятие администратора закрытого канала меняет ключ, а эпоху,
/// заведённую снятым администратором в сговоре с сервером, участники
/// не принимают.
#[test]
fn a_removed_admin_cannot_start_an_epoch() {
    use gasapp_protocol::channel::{self, ChannelAccess};
    use gasapp_protocol::channel_join;

    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (owner, reader) = author_and_reader(&server, &dir);
    let admin = extra_reader(&server, &dir, "deputy");
    let (channel_id, invite) = closed_channel(&owner);
    let id = channel::parse_channel_id(&channel_id).expect("id");

    join_closed(&owner, &reader, &channel_id, &invite);
    join_closed(&owner, &admin, &channel_id, &invite);

    let request = admin
        .channel_admin_request(&channel_id, &mut OsRng)
        .expect("заявка");
    let admins = owner
        .add_channel_admin(&channel_id, &request, "Зам", now(), &mut OsRng)
        .expect("назначение");
    admin
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    // Владелец снимает администратора — ключ канала меняется сразу.
    owner
        .remove_channel_admin(&channel_id, &admins[0].verify_key, now(), &mut OsRng)
        .expect("снятие");
    assert_eq!(server.state.borrow().channels[&channel_id].key_epoch, 1);
    reader
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    admin
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    // Снятый администратор (он остался подписчиком и знает ключ первой
    // эпохи) вместе с сервером заводит вторую — с ключом, который знает.
    let admin_storage = open_storage(&dir, "deputy.db");
    let admin_row = admin_storage.channel(&id).expect("чтение").expect("канал");
    let current = admin_storage
        .channel_key(&id, 1)
        .expect("чтение")
        .expect("ключ первой эпохи");
    let chosen = [0x66u8; 32];
    let record = channel_join::seal_epoch(
        &id,
        2,
        &chosen,
        &current,
        PrivateKeyBytes::new(admin_row.signing_key.expect("ключ подписи")),
        &mut OsRng,
    )
    .expect("звено");

    let reader_account = account_of_name(&server, "reader");
    {
        let mut state = server.state.borrow_mut();
        let fake = state.channels.get_mut(&channel_id).expect("канал");
        let delivery = channel_join::open_request(
            &id,
            &hex::decode(&fake.member_keys[&reader_account]).expect("hex"),
        )
        .expect("ключ доставки");
        let grant = channel_join::seal_epoch_grant(
            &ChannelAccess {
                channel_id: id,
                secret: chosen,
                verify_key: PublicKeyBytes::new(admin_row.verify_key),
            },
            2,
            &delivery,
            &mut OsRng,
        )
        .expect("ответ");

        fake.epochs.push(hex::encode(record));
        fake.key_epoch = 2;
        fake.grants
            .insert(reader_account.clone(), hex::encode(grant));
        fake.grant_epochs.insert(reader_account, 2);
    }

    // Читатель подложную эпоху не принимает: синхронизация отказывает,
    // а его ключ остаётся прежним.
    assert!(matches!(
        reader.sync_channel(&channel_id, now()),
        Err(GasAppError::InvalidSignature)
    ));
    let reader_storage = open_storage(&dir, "reader.db");
    assert_eq!(reader_storage.channel_key_epoch(&id).expect("эпоха"), 1);
}

/// 🔐 Закрытие канала меняет его ключ: прежняя ссылка несёт секрет
/// чтения, и новые записи им уже не открываются. Прежний подписчик
/// читает дальше, когда его одобрят по заявке.
#[test]
fn closing_a_channel_changes_its_key() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, early) = author_and_reader(&server, &dir);

    let (channel_id, link) = followed_channel(&author, &early);
    post_text(&author, &channel_id, "открытая");
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");

    // Ссылка открытого канала могла разойтись как угодно далеко.
    let old_access = gasapp_protocol::channel::ChannelAccess::parse(&link).expect("доступ");

    author
        .set_channel_closed(&channel_id, true, now())
        .expect("закрыть");
    assert!(author.channel(&channel_id).expect("канал").rekey_pending);
    author
        .maintain_channel_keys(now(), &mut OsRng)
        .expect("обслуживание");
    assert!(!author.channel(&channel_id).expect("канал").rekey_pending);
    assert_eq!(server.state.borrow().channels[&channel_id].key_epoch, 1);

    let number = post_text(&author, &channel_id, "после закрытия");
    let seq = usize::try_from(number).expect("номер");

    // Секрет из прежней ссылки новую запись не открывает.
    let body = stored_body(&server, &channel_id, seq);
    let (epoch, record) = gasapp_protocol::channel::split_epoch(&body).expect("эпоха");
    assert_eq!(epoch, 1);
    assert!(old_access.open_post(record, number, &[]).is_err());

    // Прежнего подписчика никто не одобрял: нового ключа у него нет.
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    author
        .maintain_channel_keys(now(), &mut OsRng)
        .expect("обслуживание");
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&early, &channel_id), ["открытая"]);
    // Экран канала объясняет, почему нового нет.
    assert!(early.channel(&channel_id).expect("канал").key_missing);

    // По ссылке-приглашению его одобряют, и он читает дальше.
    let invite = author
        .create_channel_invite(&channel_id, now(), &mut OsRng)
        .expect("ссылка");
    join_closed(&author, &early, &channel_id, &invite);
    early
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(texts(&early, &channel_id), ["открытая", "после закрытия"]);
    assert!(!early.channel(&channel_id).expect("канал").key_missing);
}

/// 🔐 Сервер называет выдуманного участника со своим ключом доставки:
/// удостоверения у такого ключа нет, и ключ новой эпохи под него не
/// шифруется — ни при смене ключа, ни при досылке (аудит 2026-10-10, N-0).
#[test]
fn an_invented_member_gets_no_epoch_key() {
    use gasapp_protocol::channel_join::{self, JoinLink};
    use gasapp_protocol::x25519::X25519PrivateKey;

    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, stays) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let ghost = extra_reader(&server, &dir, "ghost");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &stays, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);

    // Сервер записывает в участники аккаунт, которого никто не одобрял,
    // с ключом доставки, от которого знает секрет, — и даже с
    // удостоверением, но подписанным не тем, кто ведёт канал.
    let link = JoinLink::parse(&invite).expect("ссылка");
    let attacker = X25519PrivateKey::generate(&mut OsRng).expose_secret();
    let forged = channel_join::seal_request(&link, &attacker, &mut OsRng).expect("заявка");
    let fake_approval = channel_join::seal_approval(
        &link.channel_id,
        0,
        &forged.wire,
        PrivateKeyBytes::new([0x77; 32]),
    )
    .expect("удостоверение");
    let ghost_account = account_of_name(&server, "ghost");
    let ghost_device = ghost.own_device_id().expect("чтение").expect("устройство");
    {
        let mut state = server.state.borrow_mut();
        let channel = state.channels.get_mut(&channel_id).expect("канал");
        channel.subscribers.insert(ghost_device, 0);
        channel
            .member_keys
            .insert(ghost_account.clone(), hex::encode(&forged.wire));
        channel
            .approvals
            .insert(ghost_account.clone(), hex::encode(fake_approval));
    }

    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    author
        .maintain_channel_keys(now(), &mut OsRng)
        .expect("обслуживание");

    {
        let state = server.state.borrow();
        let channel = &state.channels[&channel_id];
        assert_eq!(channel.key_epoch, 1);
        assert!(!channel.grants.contains_key(&ghost_account));
        // Настоящий участник ключ получил — вместе с удостоверением на
        // новую эпоху.
        let real = account_of_name(&server, "reader");
        assert_eq!(channel.grant_epochs.get(&real), Some(&1));
    }

    post_text(&author, &channel_id, "после удаления");
    assert_eq!(
        stays
            .sync_channel(&channel_id, now())
            .expect("синхронизация"),
        1
    );
}

/// 🔐 Удалённого сервер снова называет участником — с прежним ключом
/// доставки и прежним, настоящим удостоверением. Оно выписано на эпоху,
/// которой больше нет, и ключа действующей эпохи удалённый не получает.
#[test]
fn a_removed_member_listed_again_gets_no_key() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, stays) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &stays, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);

    let (old_key, old_approval) = {
        let state = server.state.borrow();
        let channel = &state.channels[&channel_id];
        (
            channel.member_keys[&removed].clone(),
            channel.approvals[&removed].clone(),
        )
    };
    let removed_device = leaves.own_device_id().expect("чтение").expect("устройство");

    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    assert_eq!(server.state.borrow().channels[&channel_id].key_epoch, 1);

    // Сервер в сговоре с удалённым возвращает его в список.
    {
        let mut state = server.state.borrow_mut();
        let channel = state.channels.get_mut(&channel_id).expect("канал");
        channel.bans.remove(&removed);
        channel.subscribers.insert(removed_device, 0);
        channel.member_keys.insert(removed.clone(), old_key);
        channel.approvals.insert(removed.clone(), old_approval);
    }

    author
        .maintain_channel_keys(now(), &mut OsRng)
        .expect("обслуживание");
    assert!(!server.state.borrow().channels[&channel_id]
        .grants
        .contains_key(&removed));

    // И следующая смена ключа его тоже обходит.
    let third = extra_reader(&server, &dir, "third");
    let third_account = join_closed(&author, &third, &channel_id, &invite);
    author
        .remove_channel_subscriber(&channel_id, &third_account, false, now(), &mut OsRng)
        .expect("удаление");
    let state = server.state.borrow();
    let channel = &state.channels[&channel_id];
    assert_eq!(channel.key_epoch, 2);
    assert!(!channel.grants.contains_key(&removed));
    assert_eq!(
        channel
            .grant_epochs
            .get(&account_of_name(&server, "reader")),
        Some(&2)
    );
}

/// Участник, у которого ключ уже есть, подаёт заявку заново (например,
/// по подсказке экрана): пока её не одобрили, прежний ответ сервера не
/// принимается за новый, а после одобрения ключи следующих эпох
/// приходят под новый ключ доставки.
#[test]
fn a_member_who_asks_again_keeps_reading() {
    let dir = tempfile::tempdir().expect("каталог");
    let server = FakeServer::new();
    let (author, member) = author_and_reader(&server, &dir);
    let leaves = extra_reader(&server, &dir, "leaver");
    let (channel_id, invite) = closed_channel(&author);

    join_closed(&author, &member, &channel_id, &invite);
    let removed = join_closed(&author, &leaves, &channel_id, &invite);

    // Заявка подана заново и ещё не одобрена: вход не «срабатывает»
    // прежним ответом, и заявка остаётся ждать.
    member
        .request_channel_join(&invite, now(), &mut OsRng)
        .expect("заявка");
    assert!(member.check_channel_joins(now()).expect("вход").is_empty());
    assert_eq!(member.pending_channel_joins().expect("заявки").len(), 1);

    let requests = author
        .channel_join_requests(&channel_id, now())
        .expect("заявки");
    author
        .answer_channel_join(
            &channel_id,
            &requests[0].account_id,
            true,
            now(),
            &mut OsRng,
        )
        .expect("одобрение");
    assert_eq!(member.check_channel_joins(now()).expect("вход").len(), 1);
    assert!(member.pending_channel_joins().expect("заявки").is_empty());

    // Смена ключа: новый приходит под новый ключ доставки.
    author
        .remove_channel_subscriber(&channel_id, &removed, false, now(), &mut OsRng)
        .expect("удаление");
    post_text(&author, &channel_id, "после удаления");
    member
        .sync_channel(&channel_id, now())
        .expect("синхронизация");
    assert_eq!(
        texts(&member, &channel_id),
        ["только для своих", "после удаления"]
    );
}
