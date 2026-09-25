// SPDX-License-Identifier: Apache-2.0

//! Клиент: соединяет оркестрацию, сеть и хранилище.
//!
//! # Что здесь происходит
//!
//! Модуль [`crate::session`] умеет превращать bundle в конверт, но не
//! знает, откуда взять bundle и куда деть результат. Хранилище умеет
//! писать и читать, но не знает, что писать. Здесь они соединяются
//! в операции, которыми пользуется приложение: зарегистрироваться,
//! отправить, получить.
//!
//! # Порядок операций
//!
//! Он не произволен. Сессия сохраняется **до** отправки в сеть: при
//! обратном порядке обрыв связи после успешной отправки оставил бы
//! получателя с провёрнутым храповиком, а отправителя — со старым
//! состоянием, и переписка встала бы навсегда.
//!
//! Одноразовый предключ вычёркивается **после** успешной расшифровки:
//! вычеркнуть раньше значит потерять его при сбое и не прочитать
//! сообщение никогда.
//!
//! # Чего здесь нет
//!
//! Криптографии. Ни одного вызова примитивов — только последовательность
//! обращений к `aegis-protocol`. Это граница, за которой начинается
//! проверяемый фаззингом код.

use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use aegis_backup::RecoveryKey;
use aegis_media::attachment::{self, AttachmentKey};
use aegis_media::descriptor::{AttachmentDescriptor, AttachmentKind};
use aegis_media::scrub;
use aegis_net::api::{
    BundleResponse, DiscoveryResponse, PublishKeysRequest, RecoverAccountRequest, RegisterRequest,
    RegisterResponse,
};
use aegis_net::client::{ApiClient, Transport};
use aegis_net::pow;
use aegis_protocol::contact_link::ContactLink;
use aegis_protocol::content::Content;
use aegis_protocol::keys::{
    IdentityKey, IdentityKeyPair, KemPublicKey, PreKeyBundle, PreKeyId, SignedKemPreKey,
    SignedPreKey,
};
use aegis_protocol::prekeys::{self, PreKeySecrets};
use aegis_protocol::{Fingerprint, SafetyNumber};
use aegis_storage::{MessageStatus, Storage, StoredMessage, VaultFileRow};

use crate::backup::{BackupOutcome, BackupService, RestoreOutcome};
use crate::vault::{SealedVaultFile, Vault, VaultGuard};

mod kt;
mod network;
mod pq;
mod requests;
mod sealed;

use aegis_protocol::account_recovery::AccountRecoveryKey;
use aegis_protocol::pq_identity::PqIdentityKeyPair;
pub use aegis_storage::requests::ChatRequest;
use aegis_types::{
    canonical_username, AccountId, AegisError, ChatId, DeviceId, MessageId, Plaintext,
    PublicKeyBytes, Result, Timestamp,
};
pub use kt::{KtSelfCheck, KtVerdict};
pub use network::{SecurityReport, BACKUP_MAX_AGE_MILLIS, PROXY_SETTING};
use rand_core::{CryptoRng, RngCore};

use crate::session::{self, derive_chat_id};

/// Сложность proof-of-work по умолчанию.
///
/// Должна совпадать с серверной. Расхождение проявится как отказ
/// всех регистраций, поэтому значение продублировано осознанно и
/// проверяется тестом на совместимость.
const POW_DIFFICULTY: u32 = 20;

/// Зарегистрированный аккаунт устройства.
#[derive(Debug, Clone)]
pub struct Account {
    /// Идентификатор аккаунта, выданный сервером.
    pub account_id: AccountId,
    /// Идентификатор устройства.
    pub device_id: DeviceId,
    /// Занятое имя пользователя.
    pub username: String,
}

/// Сообщение в том виде, в каком его показывает приложение.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Идентификатор сообщения.
    pub message_id: MessageId,
    /// Расшифрованный текст.
    pub text: String,
    /// Время отправки.
    pub timestamp: Timestamp,
    /// Наше это сообщение или входящее.
    pub outgoing: bool,
    /// Статус доставки.
    pub status: MessageStatus,
}

/// Контакт в том виде, в каком его показывает приложение.
#[derive(Debug, Clone)]
// Четыре независимых признака для показа — не состояние, которое
// следовало бы свести в перечисление: контакт бывает сверен и заменён,
// подтверждён ссылкой и с неоднозначным именем одновременно.
#[allow(clippy::struct_excessive_bools)]
pub struct Contact {
    /// Идентификатор аккаунта.
    pub account_id: AccountId,
    /// Identity-ключ — единственное, что определяет собеседника.
    pub identity: PublicKeyBytes,
    /// Имя, если известно.
    pub username: Option<String>,
    /// Чат с контактом, если он заведён.
    pub chat_id: Option<ChatId>,
    /// Подтверждён ли контакт сверкой safety number.
    pub verified: bool,
    /// 🔐 Это имя уже известно под **другим** ключом.
    ///
    /// То есть либо собеседник переустановил приложение или
    /// восстановился из копии, либо кто-то занял его имя, либо
    /// подсунутая ссылка выдаёт чужой ключ за его.
    ///
    /// Отличить эти случаи не может ни сервер, ни приложение —
    /// только сверка safety number вживую. Поэтому здесь не отказ
    /// и не молчание, а признак: показать человеку, что ключ
    /// не тот, которым он пользовался раньше.
    ///
    /// ⚠️ Прежний контакт при этом **остаётся на месте**: счёт
    /// выводится из ключа, так что новый ключ заводит новую запись,
    /// а не переписывает старую. Верификация старой записи не
    /// переносится на новую никогда.
    pub key_changed: bool,
    /// 🔐 Ключ этого контакта заменён другим под тем же именем —
    /// сверкой нового вживую или явным его принятием
    /// ([`Client::accept_contact_identity`]).
    ///
    /// Переписка остаётся для чтения; отправлять в неё нельзя: имя
    /// ведёт теперь к другому ключу.
    pub replaced: bool,
    /// 🔐 Ключ подтверждён: сверкой safety number, ссылкой/QR самого
    /// контакта или журналом ключей (см. [`Contact::kt_confirmed`]).
    /// Без этого отправка запрещена ([`AegisError::PeerUnconfirmed`]).
    pub key_confirmed: bool,
    /// Ключ подтверждён только журналом ключей (§9.7) — без личной
    /// сверки. Интерфейс показывает это отдельно: личная сверка сильнее.
    pub kt_confirmed: bool,
}

/// Найденное сообщение вместе с чатом, которому оно принадлежит.
///
/// Чат нужен, чтобы по нажатию открыть переписку на этом сообщении:
/// поиск без перехода к результату бесполезен.
#[derive(Debug, Clone)]
pub struct SearchHit {
    /// Чат, в котором найдено сообщение.
    pub chat_id: ChatId,
    /// Само сообщение.
    pub message: ChatMessage,
}

/// Файл, который пользователь отправляет вложением.
///
/// Байты целиком в памяти: телефон всё равно читает файл перед
/// отправкой, а потоковая загрузка потребовала бы держать соединение
/// открытым через границу FFI — то есть отдать управление сетью
/// платформе, которая её и так предоставляет одним вызовом.
#[derive(Debug, Clone)]
pub struct AttachmentFile {
    /// Тип: от него зависит поведение получателя.
    pub kind: AttachmentKind,
    /// Содержимое файла в открытом виде.
    pub bytes: Vec<u8>,
    /// Имя файла.
    ///
    /// 🔐 Уходит зашифрованным: «результаты анализов.jpg» говорит
    /// о человеке больше, чем сам факт отправки.
    pub name: Option<String>,
    /// Описание для незрячих пользователей.
    pub description: Option<String>,
    /// Длительность — для голосовых и видео.
    pub duration_millis: Option<u32>,
    /// Огибающая громкости — для голосовых.
    pub waveform: Option<Vec<u8>>,
}

/// Что исчезло вместе с аккаунтом.
///
/// 🔐 Числа показываются человеку. «Готово» без них ничем не
/// отличается от «готово» при запросе, который ничего не удалил,
/// а удаление аккаунта — именно тот случай, где верить на слово
/// не за чем: проверить самому уже нечем.
///
/// Всё перечисленное — данные самого запрашивающего, и ни о ком,
/// кроме него, эти числа не говорят.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountDeletionReport {
    /// Сколько устройств было у аккаунта.
    pub devices: u64,
    /// Сколько недоставленных конвертов лежало в очередях.
    pub envelopes: u64,
    /// Сколько загруженных вложений удалено.
    ///
    /// ⚠️ Только загруженных **этим** аккаунтом. Присланные ему
    /// остаются: сервер не знает, кому они предназначались, — связь
    /// лежит внутри шифротекста. Они исчезают по общему сроку
    /// в тридцать суток.
    pub attachments: u64,
}

/// Версия формата выгрузки.
///
/// Читающая программа обязана уметь отличить этот формат от
/// следующего: выгрузка переживает и приложение, и его версию.
const EXPORT_FORMAT: &str = "aegis-export-v1";

/// Сколько сообщений на чат попадает в выгрузку.
///
/// Предел есть, потому что выгрузка целиком строится в памяти
/// и уходит через границу FFI одной строкой: переписка без предела
/// уронила бы приложение по памяти ровно у того, кому выгрузка
/// нужнее всего — у человека с длинной историей.
const MAX_EXPORTED_MESSAGES: u32 = 10_000;

/// Полный размер пула одноразовых предключей.
const fn prekeys_pool_size() -> u32 {
    aegis_protocol::ONE_TIME_PRE_KEY_POOL_SIZE
}

/// Что сделало обслуживание предключей.
///
/// Показывается в центре безопасности: исчерпанный пул одноразовых
/// предключей — это состояние, которое человек обязан иметь
/// возможность увидеть.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PreKeyMaintenance {
    /// Подписанный предключ был заменён новым.
    pub rotated_signed: bool,
    /// Сколько одноразовых предключей добавлено в пул.
    pub added_one_time: u32,
    /// Сколько осталось в пуле после обслуживания.
    pub remaining_one_time: u32,
}

/// Клиент AEGIS.
pub struct Client<T: Transport> {
    api: ApiClient<T>,
    storage: Storage,

    /// Состояние File Vault.
    ///
    /// 🔐 Живёт рядом с хранилищем, но независимо от него: ключ базы
    /// держится всё время работы приложения, ключ vault — только
    /// пока vault открыт (раздел 11.4). `Mutex` здесь по той же
    /// причине, что и у клиента: операции меняют состояние.
    vault: Mutex<VaultGuard>,

    /// Последний ответ discovery по имени — только в памяти.
    ///
    /// 🔐 Отправка спрашивает discovery на каждое сообщение. Если
    /// discovery отказывает (429 — чужой перебор по имени собеседника —
    /// или сбой), отправка берёт последний известный ответ, не старше
    /// [`DISCOVERY_FALLBACK_MILLIS`]: ключи в нём проверяются так же,
    /// как в свежем, и подписаны владельцем. Иначе посторонний отрезал
    /// бы человека от собеседников, выбирая бюджет его имени.
    discovered: Mutex<HashMap<String, (DiscoveryResponse, Timestamp)>>,
}

/// Сколько годен последний ответ discovery для отправки при отказе
/// discovery: сутки.
const DISCOVERY_FALLBACK_MILLIS: i64 = 24 * 60 * 60 * 1000;

impl<T: Transport> Client<T> {
    /// Создаёт клиент поверх транспорта и открытого хранилища.
    pub fn new(transport: T, storage: Storage) -> Self {
        Self {
            api: ApiClient::new(transport),
            storage,
            // Vault всегда начинается закрытым: открыть его может
            // только повторная аутентификация.
            vault: Mutex::new(VaultGuard::new(Timestamp::from_millis(0))),
            discovered: Mutex::new(HashMap::new()),
        }
    }

    /// Discovery для отправки: свежий ответ, а при отказе сети
    /// или сервера — последний известный (см. `Client::discovered`).
    fn discover_for_send(&self, name: &str, now: Timestamp) -> Result<DiscoveryResponse> {
        match self.api.discover(name) {
            Ok(found) => {
                if let Ok(mut cache) = self.discovered.lock() {
                    cache.insert(name.to_owned(), (found.clone(), now));
                }

                Ok(found)
            }
            Err(AegisError::Network) => self
                .discovered
                .lock()
                .ok()
                .and_then(|cache| cache.get(name).cloned())
                .filter(|(_, at)| {
                    now.as_millis().saturating_sub(at.as_millis()) <= DISCOVERY_FALLBACK_MILLIS
                })
                .map(|(found, _)| found)
                .ok_or(AegisError::Network),
            Err(error) => Err(error),
        }
    }

    /// Регистрирует новый аккаунт и публикует предключи.
    ///
    /// # Что происходит
    ///
    /// 1. Генерируется identity-пара и пулы предключей.
    /// 2. Решается proof-of-work.
    /// 3. Сервер выдаёт идентификаторы аккаунта и устройства.
    /// 4. Ключи сохраняются локально **до** публикации.
    /// 5. Публичные части предключей уходят на сервер.
    ///
    /// Порядок важен: ключи, опубликованные, но не сохранённые,
    /// означали бы, что нам пишут сообщения, которые мы не можем
    /// расшифровать.
    ///
    /// # Errors
    ///
    /// [`AegisError::Network`] — сервер недоступен;
    /// [`AegisError::Storage`] — не удалось сохранить ключи;
    /// [`AegisError::Crypto`] — не удалось подобрать proof-of-work.
    pub fn register<R: RngCore + CryptoRng>(
        &self,
        username: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Account> {
        // 🔐 Только каноничное имя: двойник «аlice» с кириллической «а»
        // сервером отвергается, но и уходить туда ему незачем.
        let username = &canonical_username(username)?;
        let identity = prekeys::generate_identity(rng)?;
        // 🔐 Пост-квантовая половина identity — со своим seed
        // (см. `aegis_protocol::pq_identity`).
        let pq = PqIdentityKeyPair::generate(rng);
        // 🔐 Ключ восстановления аккаунта: им новая установка вернёт
        // себе это имя (см. `aegis_protocol::account_recovery`).
        let recovery = AccountRecoveryKey::generate(rng)?;
        let device_id = DeviceId::generate();
        let (bundle, secrets) = prekeys::generate(&identity, &pq, device_id, now, rng)?;

        // 🔐 Челлендж выводится из самой регистрации — имени и ключей.
        //
        // Сервер вычисляет его сам и отвергает любой другой: так одно
        // решение годится ровно для одного аккаунта. Прежде челлендж был
        // случайным, и одно решение регистрировало сколько угодно.
        let identity_bytes = identity.public().public().as_bytes();
        let challenge = pow::registration_challenge(username, identity_bytes, identity_bytes);

        let nonce = pow::solve(&challenge, POW_DIFFICULTY).ok_or(AegisError::Crypto)?;

        let identity_hex = hex(identity_bytes);
        let response = self.api.register(&RegisterRequest {
            username: username.to_owned(),
            identity_key: identity_hex.clone(),
            device_identity_key: identity_hex,
            pq_identity_key: hex(&pq.public()),
            identity_binding: hex(&aegis_protocol::pq_identity::bind(&identity, &pq)?),
            recovery_key: Some(hex(recovery.public().as_bytes())),
            recovery_pq_key: Some(hex(&recovery.pq_public())),
            pow_challenge: hex(&challenge),
            pow_nonce: nonce,
        })?;

        self.storage.set_own_account_recovery(&recovery.secret())?;

        self.finish_enrollment(
            &identity, &pq, &bundle, &secrets, &response, username, now, rng,
        )
    }

    /// Возвращает аккаунт на новое устройство по резервной копии —
    /// **с прежним именем**.
    ///
    /// # Как
    ///
    /// 1. Копия восстанавливается в эту (пустую) базу: переписка,
    ///    контакты и секрет ключа восстановления аккаунта.
    /// 2. Создаётся **новая** identity: приватный identity-ключ между
    ///    устройствами не копируется (раздел 13.1).
    /// 3. Ключ восстановления подписывает запрос «перепривяжи аккаунт
    ///    с этим именем к новой identity»; сервер, проверив подпись,
    ///    удаляет прежние устройства и заводит новое.
    ///
    /// Собеседники увидят смену ключа — так и задумано (12.5).
    ///
    /// # Errors
    ///
    /// * [`AegisError::Crypto`] — не тот ключ копии;
    /// * [`AegisError::Malformed`] — цепочка копии разорвана;
    /// * [`AegisError::Uninitialized`] — в копии нет ключа восстановления
    ///   аккаунта или имени (копия сделана до их появления);
    /// * [`AegisError::Network`] — сервер отказал либо недоступен.
    pub fn recover_account<R: RngCore + CryptoRng>(
        &self,
        backup_key: &RecoveryKey,
        links: &[Vec<u8>],
        now: Timestamp,
        rng: &mut R,
    ) -> Result<(Account, RestoreOutcome)> {
        let outcome = BackupService::new(&self.storage).restore(backup_key, links, now)?;

        let username = outcome.username.clone().ok_or(AegisError::Uninitialized)?;
        let username = &canonical_username(&username)?;
        let secret = self
            .storage
            .own_account_recovery()?
            .ok_or(AegisError::Uninitialized)?;
        let recovery = AccountRecoveryKey::from_secret(&secret)?;

        let identity = prekeys::generate_identity(rng)?;
        let pq = PqIdentityKeyPair::generate(rng);
        let device_id = DeviceId::generate();
        let (bundle, secrets) = prekeys::generate(&identity, &pq, device_id, now, rng)?;

        let identity_bytes = identity.public().public().as_bytes();
        let pq_public = pq.public();
        let binding = aegis_protocol::pq_identity::bind(&identity, &pq)?;
        let request = aegis_protocol::account_recovery::RecoverRequest {
            username,
            identity_key: identity_bytes,
            device_identity_key: identity_bytes,
            pq_identity_key: &pq_public,
            identity_binding: &binding,
            issued_at_millis: now.as_millis(),
        };

        let response = self.api.recover_account(&RecoverAccountRequest {
            username: username.clone(),
            identity_key: hex(identity_bytes),
            device_identity_key: hex(identity_bytes),
            pq_identity_key: hex(&pq_public),
            identity_binding: hex(&binding),
            issued_at: now.as_millis(),
            signature: hex(&recovery.sign(&request)?),
        })?;

        let account = self.finish_enrollment(
            &identity, &pq, &bundle, &secrets, &response, username, now, rng,
        )?;

        Ok((account, outcome))
    }

    /// Завершает регистрацию или возвращение аккаунта: ключи
    /// в хранилище, предключи и ключ sealed sender — на сервер.
    #[allow(clippy::too_many_arguments)]
    fn finish_enrollment<R: RngCore + CryptoRng>(
        &self,
        identity: &IdentityKeyPair,
        pq: &PqIdentityKeyPair,
        bundle: &PreKeyBundle,
        secrets: &prekeys::PreKeySecrets,
        response: &RegisterResponse,
        username: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Account> {
        let account_id = parse_uuid(&response.account_id).map(AccountId::from_uuid)?;
        let server_device_id = parse_uuid(&response.device_id).map(DeviceId::from_uuid)?;

        // Сохранение до публикации: см. порядок операций выше.
        self.storage.save_own_keys(
            identity.private().expose_secret(),
            identity.public().public().as_bytes(),
            &secrets.to_bytes()?,
            // Идентификатор, выданный сервером. Прежде здесь стоял
            // литеральный ноль, из-за чего после перезапуска
            // приложение не знало своего устройства и не могло забрать
            // очередь сообщений.
            Some(&server_device_id.to_string()),
            Some(username),
            now,
        )?;
        self.storage.set_account_id(&account_id, now)?;
        self.storage.init_own_pq_identity(pq.seed())?;
        // Сервер записал половину вместе с аккаунтом.
        self.storage.mark_own_pq_identity_published(now)?;

        let mut request = publish_request(bundle);
        let (kem_public, kem_signature) = self.sealed_kem_publication(identity, rng)?;
        request.sealed_kem_public = Some(kem_public);
        request.sealed_kem_signature = Some(kem_signature);

        self.api.publish_keys(
            &server_device_id.to_string(),
            &request,
            &DeviceSigner::new(identity, now),
        )?;
        self.storage.mark_own_sealed_kem_published(now)?;

        // Журнал ключей: своё имя проверяется с этой эпохи — раньше
        // под ним стоял прежний ключ (или ничего), и чужим он не был.
        self.kt_start_self_check(now)?;

        Ok(Account {
            account_id,
            device_id: server_device_id,
            username: username.to_owned(),
        })
    }

    /// Отправляет сообщение контакту, найденному по имени.
    ///
    /// # Errors
    ///
    /// [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// [`AegisError::Network`] — сервер недоступен;
    /// [`AegisError::InvalidSignature`] — подписи в bundle не сходятся.
    pub fn send_message<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        text: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<MessageId> {
        let peer_username = &canonical_username(peer_username)?;

        // Секреты предключей при отправке не нужны: они участвуют
        // только в приёме, когда нам присылают конверт инициации.
        let (identity, _) = self.load_identity()?;

        let peer = self.discover_for_send(peer_username, now)?;
        let peer_identity = parse_public_key(&peer.identity_key)?;

        // 🔐 До шифрования: ключ, названный сервером, обязан быть тем,
        // что известен для этого имени (см. `check_advertised_identity`).
        self.check_advertised_identity(
            peer_username,
            &peer_identity,
            peer.pq_identity_key.as_deref(),
            now,
        )?;

        // 🔐 Пост-квантовая половина identity получателя — привязанная
        // и сверенная с запомненной (см. `client::pq`).
        let peer_pq = self.verified_peer_pq(&peer, &peer_identity, now)?;

        // 🔐 Ключ ML-KEM sealed sender получателя — с проверенной
        // гибридной подписью (см. `verified_sealed_kem`).
        let peer_kem = verified_sealed_kem(&peer, &peer_identity, &peer_pq)?;

        let chat_id = derive_chat_id(identity.public().public(), &peer_identity);

        // Идентификатор выбирается до шифрования и уезжает внутри
        // содержимого: по нему собеседник найдёт сообщение, когда придёт
        // правка, удаление или квитанция (см. `Content::Text::id`).
        let message_id = MessageId::generate();

        // Тело сообщения — структурированное содержимое, а не голый
        // текст: получатель обязан отличить текст от реакции и правки,
        // и это различие лежит под шифрованием.
        let plaintext = Plaintext::new(
            Content::Text {
                body: text.to_owned(),
                reply_to: None,
                id: *message_id.as_uuid().as_bytes(),
            }
            .to_bytes()?,
        );

        // Существующая сессия продолжается; иначе устанавливается новая.
        // Проверка идёт по хранилищу, а не по наличию контакта: сессия
        // может отсутствовать и у знакомого контакта — например, после
        // восстановления из резервной копии.
        let existing = self.storage.load_session(&chat_id)?;

        self.note_outgoing(&chat_id, existing.is_none())?;

        // Устройство собеседника: bundle и доставка адресуются по нему.
        // Берётся первое из списка — многоустройственная доставка
        // появится вместе с синхронизацией (раздел 13.1).
        let peer_device = peer
            .device_ids
            .first()
            .cloned()
            .ok_or(AegisError::SessionNotFound)?;
        let peer = peer_account(&peer_identity);

        // 🔐 Ключ доступа sealed sender уходит раньше текста — та же
        // логика, что в `send_content` (см. модуль `sealed`). Прежде
        // текст шёл собственной веткой прямо в `send_envelope`, и
        // основная переписка оставалась бы незапечатанной, даже когда
        // реакции и правки уже запечатаны.
        let session = match existing {
            Some(state) if self.storage.access_key_shared_with(&peer)? => state,
            other => self.send_own_access_key(
                &identity,
                &chat_id,
                other,
                &peer_identity,
                &peer_device,
                &peer_kem,
                now,
                rng,
            )?,
        };

        let outgoing = session::continue_session(&session, &plaintext)?;

        // Сессия сохраняется до отправки: см. порядок операций.
        self.storage
            .save_session(&chat_id, &outgoing.session, now)?;

        self.store_message(
            &chat_id,
            message_id,
            text,
            now,
            true,
            MessageStatus::Pending,
        )?;

        self.deliver(
            &identity,
            &peer_identity,
            &peer_device,
            &peer_kem,
            &outgoing.envelope,
            now,
            rng,
        )?;

        self.storage
            .set_message_status(&message_id, MessageStatus::Sent, now)?;
        self.storage.touch_chat(&chat_id, Some(&message_id), now)?;

        // Сверка журнала ключей с собеседником (§9.7) — не чаще раза
        // в сутки. Сбой не мешает сообщению: оно уже ушло.
        let _ = self.kt_gossip_head(peer_username, now, rng);

        Ok(message_id)
    }

    /// Отправляет реакцию на сообщение.
    ///
    /// Пустая строка снимает реакцию: отдельная операция «снять»
    /// означала бы два пути к одному состоянию, которые легко
    /// рассогласовать.
    ///
    /// # Errors
    ///
    /// Те же, что у [`Client::send_message`].
    pub fn send_reaction<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        target: &MessageId,
        emoji: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        // Чат здесь не нужен: своя копия таких сообщений не хранится.
        self.send_content(
            peer_username,
            &Content::Reaction {
                target: *target.as_uuid().as_bytes(),
                emoji: emoji.to_owned(),
            },
            now,
            rng,
        )?;

        Ok(())
    }

    /// Правит ранее отправленное сообщение.
    ///
    /// 🔐 Правка не скрывает исходный текст: получатель уже видел его
    /// и мог запомнить. Интерфейс обязан помечать правленые сообщения,
    /// иначе отправитель мог бы переписать разговор задним числом.
    ///
    /// # Errors
    ///
    /// Те же, что у [`Client::send_message`].
    pub fn edit_message<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        target: &MessageId,
        text: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        self.storage.edit_message(target, text, now)?;

        // Чат здесь не нужен: своя копия таких сообщений не хранится.
        self.send_content(
            peer_username,
            &Content::Edit {
                target: *target.as_uuid().as_bytes(),
                body: text.to_owned(),
            },
            now,
            rng,
        )?;

        Ok(())
    }

    /// Просит собеседника удалить сообщение.
    ///
    /// 🔐 Это просьба, а не гарантия: получатель уже видел сообщение
    /// и мог снять экран. Интерфейс обязан говорить «запрошено
    /// удаление», а не «удалено у собеседника».
    ///
    /// # Errors
    ///
    /// Те же, что у [`Client::send_message`].
    pub fn delete_for_everyone<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        target: &MessageId,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        // Своё удаляется сразу, не дожидаясь отправки: если сеть
        // недоступна, пользователь всё равно должен перестать видеть
        // сообщение у себя.
        self.storage.delete_message(target, now)?;

        // Чат здесь не нужен: своя копия таких сообщений не хранится.
        self.send_content(
            peer_username,
            &Content::Delete {
                target: *target.as_uuid().as_bytes(),
            },
            now,
            rng,
        )?;

        Ok(())
    }

    /// Сообщает, что пользователь печатает.
    ///
    /// 🔐 Молча ничего не делает, если передача присутствия выключена.
    /// Отказ с ошибкой был бы хуже: вызывающий код стал бы её
    /// показывать, и пользователь получал бы предупреждение за то,
    /// что не включил функцию, которую сознательно оставил выключенной.
    ///
    /// # Errors
    ///
    /// Те же, что у [`Client::send_message`], если отправка состоялась.
    pub fn send_typing<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        active: bool,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        if !self.storage.presence_sharing_enabled()? || self.request_pending_with(peer_username)? {
            return Ok(());
        }

        self.send_content(peer_username, &Content::Typing { active }, now, rng)?;

        Ok(())
    }

    /// Отправляет квитанцию о прочтении.
    ///
    /// 🔐 Как и индикатор набора, требует включённой настройки.
    ///
    /// Квитанция указывает последнее прочитанное сообщение, а не
    /// каждое: открытие чата с сотней непрочитанных иначе породило бы
    /// сто сообщений, и по их числу собеседник узнал бы, сколько
    /// накопилось.
    ///
    /// # Errors
    ///
    /// Те же, что у [`Client::send_message`], если отправка состоялась.
    pub fn send_read_receipt<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        until: &MessageId,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        // 🔐 Непринятому запросу квитанций нет: они подтвердили бы
        // незнакомцу, что человек в сети и прочёл, до его согласия.
        if !self.storage.presence_sharing_enabled()? || self.request_pending_with(peer_username)? {
            return Ok(());
        }

        // Чат здесь не нужен: своя копия таких сообщений не хранится.
        self.send_content(
            peer_username,
            &Content::ReadReceipt {
                until: *until.as_uuid().as_bytes(),
            },
            now,
            rng,
        )?;

        Ok(())
    }

    /// Включает или выключает передачу присутствия.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_presence_sharing(&self, enabled: bool) -> Result<()> {
        self.storage.set_presence_sharing(enabled)
    }

    /// Включена ли передача присутствия.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn presence_sharing_enabled(&self) -> Result<bool> {
        self.storage.presence_sharing_enabled()
    }
    /// Отправляет произвольное содержимое.
    ///
    /// Общий путь для текста, реакций, правок и удалений: разница
    /// только в теле, и дублировать вокруг него установку сессии
    /// значило бы завести несколько мест, где её можно сделать
    /// по-разному.
    ///
    /// Возвращает чат, в который ушло содержимое: вызывающему он нужен,
    /// чтобы сохранить свою копию сообщения, а выводить его второй раз
    /// значило бы повторить discovery.
    fn send_content<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        content: &Content,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<ChatId> {
        let peer_username = &canonical_username(peer_username)?;
        let (identity, _) = self.load_identity()?;

        let peer = self.discover_for_send(peer_username, now)?;
        let peer_identity = parse_public_key(&peer.identity_key)?;

        // 🔐 Та же проверка, что в `send_message`: реакция, правка
        // и вложение уходят тем же ключом, что и текст.
        self.check_advertised_identity(
            peer_username,
            &peer_identity,
            peer.pq_identity_key.as_deref(),
            now,
        )?;

        let peer_pq = self.verified_peer_pq(&peer, &peer_identity, now)?;
        let peer_kem = verified_sealed_kem(&peer, &peer_identity, &peer_pq)?;

        let chat_id = derive_chat_id(identity.public().public(), &peer_identity);

        let plaintext = Plaintext::new(content.to_bytes()?);

        let peer_device = peer
            .device_ids
            .first()
            .cloned()
            .ok_or(AegisError::SessionNotFound)?;
        let peer = peer_account(&peer_identity);

        // 🔐 Ключ доступа sealed sender уходит собеседнику раньше
        // содержимого (см. модуль `sealed`): новой сессии — первым
        // сообщением, существующей — если собеседник начинал сессию
        // заново и нашего ключа у него, возможно, нет. Иначе его ответы
        // так и шли бы незапечатанными, раскрывая серверу отправителя.
        let existing = self.storage.load_session(&chat_id)?;

        self.note_outgoing(&chat_id, existing.is_none())?;

        let session = match existing {
            Some(state) if self.storage.access_key_shared_with(&peer)? => state,
            other => self.send_own_access_key(
                &identity,
                &chat_id,
                other,
                &peer_identity,
                &peer_device,
                &peer_kem,
                now,
                rng,
            )?,
        };

        let outgoing = session::continue_session(&session, &plaintext)?;

        // Сессия сохраняется до отправки: см. порядок операций
        // в описании модуля.
        self.storage
            .save_session(&chat_id, &outgoing.session, now)?;

        self.deliver(
            &identity,
            &peer_identity,
            &peer_device,
            &peer_kem,
            &outgoing.envelope,
            now,
            rng,
        )?;

        Ok(chat_id)
    }

    /// Забирает и расшифровывает входящие сообщения.
    ///
    /// Возвращает число принятых сообщений. Служебные — ключ доступа
    /// sealed sender — не считаются: их число ушло бы в интерфейс
    /// как новые сообщения, которых пользователь не увидит.
    ///
    /// Конверты, которые не
    /// удалось расшифровать, пропускаются, а не прерывают приём:
    /// одно повреждённое сообщение не должно блокировать остальные.
    ///
    /// # Errors
    ///
    /// [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// [`AegisError::Network`] — сервер недоступен.
    // Длина — прямое следствие конвейера на один конверт: разворачивание,
    // расшифровка, привязка, разбор, применение, подтверждение. Шаги идут
    // строго подряд и делят состояние цикла; дробление на функции
    // протаскивало бы через каждую половину этого состояния.
    #[allow(clippy::too_many_lines)]
    pub fn receive_messages(&self, device_id: &str, now: Timestamp) -> Result<usize> {
        let (identity, mut secrets) = self.load_identity()?;
        let envelopes = self
            .api
            .fetch_envelopes(device_id, &DeviceSigner::new(&identity, now))?;

        let mut accepted = 0usize;

        // 🔐 Конверты, которые прочитать нельзя, подтверждаются (то есть
        // удаляются с сервера), а не оставляются в очереди. Сервер отдаёт
        // очередь с самых старых, по сотне: неподтверждённый мусор
        // возвращался бы каждым приёмом, и сотня таких конвертов —
        // повторы старых, чужие, испорченные — заслоняла бы настоящие
        // сообщения до истечения срока хранения, тридцать дней. Собрать
        // запечатанный конверт на открытый ключ получателя может любой.
        let mut dropped: Vec<String> = Vec::new();

        for envelope in envelopes {
            let Ok(wire) = unhex(&envelope.ciphertext) else {
                dropped.push(envelope.envelope_id.clone());
                continue;
            };

            // 🔐 Запечатанный конверт сначала разворачивается (см. модуль
            // `sealed`); неразворачиваемый пропускается так же, как
            // нерасшифровываемый обычный.
            let Some((raw, certificate)) =
                self.unwrap_wire(&identity, wire, envelope.queued_at_bucketed, now)
            else {
                dropped.push(envelope.envelope_id.clone());
                continue;
            };

            // Сессию ищем по всем известным чатам: конверт сообщения
            // не несёт идентификатора отправителя — это и есть защита
            // метаданных, за которую платится перебором сессий.
            let Some((incoming, known_chat)) = self.try_decrypt(&identity, &secrets, &raw, now)
            else {
                dropped.push(envelope.envelope_id.clone());
                continue;
            };

            // 🔐 Повтор принятого конверта инициации не трогает сессию.
            //
            // Конверт инициации самодостаточен: расшифровывается им
            // одним, пока жив наш подписанный предключ. Без одноразового
            // предключа — сервер волен его не выдать — ничто не мешало
            // оператору положить в очередь копию давно принятого конверта,
            // и она устанавливала сессию заново поверх действующей:
            // переписка молча вставала. Повтор подтверждается (иначе
            // приходил бы снова и снова) и пишется в журнал; сессия,
            // контакт и переписка не меняются.
            if let Some(initial) = incoming.initial {
                if self.storage.initial_accepted(initial.base_key.as_bytes())? {
                    self.storage
                        .log_security_event("initial_envelope_replayed", None, now)?;
                    self.api.acknowledge(
                        device_id,
                        &envelope.envelope_id,
                        &DeviceSigner::new(&identity, now),
                    )?;
                    continue;
                }
            }

            // 🔐 Сертификат обязан принадлежать собеседнику этой сессии,
            // иначе чужой сертификат, снятый с полученного конверта,
            // позволял бы выдать своё сообщение за чужое.
            if !self.certificate_bound(
                &identity,
                certificate.as_ref(),
                incoming.sender_identity.as_ref(),
                known_chat.as_ref(),
                now,
            )? {
                dropped.push(envelope.envelope_id.clone());
                continue;
            }

            // Чат берётся оттуда, где он известен: для инициации — из
            // identity отправителя, для сообщения в сессии — из самой
            // подошедшей сессии. Раньше сообщения второго вида молча
            // отбрасывались, потому что identity в них нет по замыслу,
            // и ответная переписка не работала вовсе.
            let chat_id = match (known_chat, incoming.sender_identity) {
                (Some(chat_id), _) => chat_id,
                (None, Some(peer)) => derive_chat_id(identity.public().public(), &peer),
                (None, None) => {
                    dropped.push(envelope.envelope_id.clone());
                    continue;
                }
            };

            // Собеседник этого конверта: из конверта инициации либо
            // из проверенного и привязанного сертификата.
            let sender = incoming.sender_identity.or_else(|| {
                certificate
                    .as_ref()
                    .map(|certificate| certificate.identity_key)
            });

            // 🔐 Запрос на переписку. Новый чат, начатый собеседником, —
            // запрос: отвечать (квитанциями, «печатает…») нельзя, пока
            // человек его не примет. Любое содержимое в чате, который
            // начали мы, значит, что собеседник откликнулся.
            match self.storage.chat_request_state(&chat_id)? {
                None if incoming.sender_identity.is_some() => {
                    self.storage
                        .set_chat_request_state(&chat_id, ChatRequest::Incoming)?;
                }
                Some(ChatRequest::Outgoing) => {
                    self.storage
                        .set_chat_request_state(&chat_id, ChatRequest::Settled)?;
                }
                _ => {}
            }

            if let Some(peer) = incoming.sender_identity {
                self.storage
                    .save_contact_identity(&peer_account(&peer), peer.as_bytes())?;

                // Собеседник начал новую сессию: у него, возможно, новое
                // устройство или восстановленная копия, и нашего ключа
                // доступа там нет. Следующая отправка передаст его заново.
                self.storage.forget_access_key_share(&peer_account(&peer))?;
            }

            self.storage
                .save_session(&chat_id, &incoming.session, now)?;

            // Запоминается вместе с сессией, которую конверт установил.
            if let Some(initial) = incoming.initial {
                self.storage.remember_initial(
                    initial.base_key.as_bytes(),
                    initial.signed_pre_key.as_bytes(),
                    now,
                )?;
            }

            // Разбор содержимого. Сообщение от собеседника с новой
            // версией клиента отвергается целиком, а не сохраняется
            // пустым: пользователь должен видеть, что что-то пришло
            // и не прочиталось, а не считать, что ему прислали пустоту.
            let Ok(content) = Content::from_bytes(incoming.plaintext.expose()) else {
                // Сессия уже продвинута и сохранена: повторно этот конверт
                // не расшифруется никогда, и держать его в очереди незачем.
                dropped.push(envelope.envelope_id.clone());
                continue;
            };

            // Служебное содержимое не считается принятым сообщением:
            // число уходит в интерфейс, и «1 новое сообщение» без
            // сообщения выглядело бы как потерянное.
            let counts = !matches!(content, Content::AccessKey { .. } | Content::KtHead { .. });

            match content {
                Content::Text { body, id, .. } => {
                    // Под идентификатором отправителя: иначе его правки
                    // и удаления здесь не нашли бы сообщения.
                    let message_id = MessageId::from_uuid(uuid::Uuid::from_bytes(id));

                    // 🔐 Занятый идентификатор — повтор или подделка:
                    // прежнее сообщение не заменяется (см.
                    // `Storage::insert_message`), новое не сохраняется.
                    if self.store_message(
                        &chat_id,
                        message_id,
                        &body,
                        now,
                        false,
                        MessageStatus::Delivered,
                    )? {
                        self.storage.touch_chat(&chat_id, Some(&message_id), now)?;
                    }
                }

                Content::Attachments {
                    body,
                    descriptors,
                    id,
                    ..
                } => {
                    let message_id = MessageId::from_uuid(uuid::Uuid::from_bytes(id));

                    // Описания — только к новому сообщению: к чужому,
                    // уже сохранённому, собеседник не приставит своих
                    // вложений.
                    if self.store_message(
                        &chat_id,
                        message_id,
                        &body,
                        now,
                        false,
                        MessageStatus::Delivered,
                    )? {
                        // 🔐 Описания сохраняются вместе с сообщением.
                        // Без них вложение недоступно: адрес файла
                        // на сервере и ключ к нему есть только здесь,
                        // а второй раз сообщение не придёт.
                        self.store_descriptors(&message_id, &descriptors, now)?;

                        self.storage.touch_chat(&chat_id, Some(&message_id), now)?;
                    }
                }

                Content::Edit { target, body } => {
                    // Правка применяется к существующему сообщению.
                    // Если его нет — собеседник правит то, чего мы
                    // не получали; создавать сообщение задним числом
                    // нельзя, оно появилось бы без контекста.
                    let target = MessageId::from_uuid(uuid::Uuid::from_bytes(target));

                    if self.written_by_peer(&target, &chat_id)? {
                        self.storage.edit_message(&target, &body, now)?;
                    }
                }

                Content::Delete { target } => {
                    // Удаление выполняется без подтверждения:
                    // отправитель просит убрать своё сообщение,
                    // и отказ означал бы, что «удалить у всех»
                    // не работает. Но только своё — см. `written_by_peer`.
                    let target = MessageId::from_uuid(uuid::Uuid::from_bytes(target));

                    if self.written_by_peer(&target, &chat_id)? {
                        self.storage.delete_message(&target, now)?;
                    }
                }

                Content::ReadReceipt { until } => {
                    // Квитанция отмечает прочитанными наши сообщения
                    // этого чата до названного включительно. Уходят
                    // квитанции, только если передачу присутствия
                    // включил собеседник, — решение за ним.
                    if let Some(own) = self.storage.get_account_id()? {
                        self.storage.mark_read_until(
                            &chat_id,
                            &own,
                            &MessageId::from_uuid(uuid::Uuid::from_bytes(until)),
                            now,
                        )?;
                    }
                }

                Content::AccessKey {
                    key,
                    sender_username,
                } => {
                    // 🔐 Ключ сохраняется только за собеседником,
                    // установленным криптографически: identity из PQXDH
                    // либо из привязанного сертификата. Сообщение
                    // в сессии без сертификата собеседника не называет,
                    // и сохранить ключ «за кем-то» значило бы угадывать.
                    if let Some(peer) = sender {
                        self.storage
                            .save_contact_access_key(&peer_account(&peer), &key, now)?;

                        // Имя, которым собеседнику можно ответить.
                        if let Some(name) = sender_username {
                            self.accept_claimed_username(&peer, &name, &chat_id, now)?;
                        }
                    }
                }

                Content::KtHead { epoch, head } => {
                    // 🔐 Своя вершина той же эпохи обязана совпасть:
                    // иначе сервер показывает одному из двоих свою ветку.
                    self.kt_compare_peer_head(epoch, &head, now)?;
                }

                Content::Reaction { .. } | Content::Typing { .. } => {
                    // Ничего не сохраняется, но по разным причинам.
                    //
                    // Реакции приходят и снимаются многократно: держать
                    // их в теле сообщения означало бы переписывать его
                    // при каждом нажатии. Им нужна отдельная таблица,
                    // которая появится вместе с показом в интерфейсе.
                    //
                    // 🔐 Индикаторы присутствия устаревают за секунды,
                    // и запись каждого нажатия клавиши собеседника
                    // создала бы на диске журнал его активности — ровно
                    // те метаданные, от хранения которых защищает весь
                    // остальной код. Они живут в памяти экрана.
                }
            }

            // Одноразовый предключ вычёркивается только теперь, после
            // успешной расшифровки: раньше — потеряли бы его при сбое.
            if let Some(consumed) = incoming.consumed_one_time {
                secrets.one_time.retain(|(id, _)| *id != consumed);
            }
            if let Some(consumed) = incoming.consumed_one_time_kem {
                secrets.one_time_kem.retain(|(id, _)| *id != consumed);
            }

            // 🔐 На диск — сразу, до подтверждения конверта.
            //
            // Прежде секреты сохранялись одним разом в конце пачки. Сбой
            // подтверждения на одном из следующих конвертов прерывал приём
            // ошибкой, и сохранение не наступало: конверт, уже подтверждённый
            // и удалённый с сервера, повторно не придёт, а приватная часть
            // его одноразового предключа оставалась на диске навсегда —
            // та самая, стирание которой и даёт первому сообщению прямую
            // секретность.
            if incoming.consumed_one_time.is_some() || incoming.consumed_one_time_kem.is_some() {
                self.persist_secrets(&secrets, now)?;
            }

            self.api.acknowledge(
                device_id,
                &envelope.envelope_id,
                &DeviceSigner::new(&identity, now),
            )?;
            if counts {
                accepted = accepted.saturating_add(1);
            }
        }

        self.persist_secrets(&secrets, now)?;

        if !dropped.is_empty() {
            for envelope_id in &dropped {
                self.api
                    .acknowledge(device_id, envelope_id, &DeviceSigner::new(&identity, now))?;
            }

            // Одно событие на приём, а не на конверт: сотня мусорных
            // конвертов не должна вытеснить из журнала остальные события.
            self.storage.log_security_event(
                "undecryptable_envelopes_dropped",
                Some(&dropped.len().to_string()),
                now,
            )?;
        }

        Ok(accepted)
    }

    /// Перечисляет чаты в порядке последней активности.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn chats(&self) -> Result<Vec<ChatId>> {
        Ok(self
            .storage
            .list_chats(MAX_CHATS_TO_PROBE)?
            .into_iter()
            .map(|row| row.chat_id)
            .collect())
    }

    /// Возвращает сообщения чата в порядке от старых к новым.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn messages(&self, chat_id: &ChatId, limit: u32) -> Result<Vec<ChatMessage>> {
        let stored = self.storage.load_messages(chat_id, limit)?;
        let own = self.storage.get_account_id()?;

        stored
            .into_iter()
            .map(|message| {
                let text = String::from_utf8_lossy(message.content.as_bytes()).into_owned();

                Ok(ChatMessage {
                    message_id: message.id,
                    text,
                    timestamp: message.timestamp,
                    outgoing: own.as_ref() == Some(&message.sender_id),
                    status: message.status,
                })
            })
            .collect()
    }

    /// Добавляет контакт по ссылке `aegis://contact/...`.
    ///
    /// # 🔐 Что здесь проверяется
    ///
    /// Ссылка приносит имя и ключ, но не доказывает их связь: сделать
    /// ссылку с чужим именем и своим ключом может кто угодно. Поэтому
    /// имя из ссылки не используется как есть — оно проверяется через
    /// сервер: если по этому имени зарегистрирован **другой** ключ,
    /// добавление отклоняется.
    ///
    /// Это не делает сервер доверенным. Сервер может соврать про имя,
    /// но не может подменить ключ: ключ пришёл со ссылки, то есть
    /// из канала, которого сервер не видел. Единственное, что даёт
    /// проверка, — не дать чужому имени приклеиться к ключу.
    ///
    /// Ссылка без имени добавляется как есть: проверять нечего, и
    /// пользователь увидит контакт без имени, что честно отражает
    /// то, что о нём известно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — ссылка не разбирается, либо имя
    /// в ней принадлежит другому ключу, либо контакт уже известен
    /// с другим ключом, либо ссылка — своя собственная;
    /// [`AegisError::Network`] — проверка имени не удалась;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn add_contact_from_link(&self, uri: &str, now: Timestamp) -> Result<Contact> {
        let link = ContactLink::parse(uri)?;

        // Своя же ссылка — не собеседник: «контакт» с собственным
        // ключом завёл бы чат с самим собой и safety number с собой.
        if self.is_own_identity(&link.identity)? {
            return Err(AegisError::Malformed);
        }

        let (account_id, username) = match &link.display_name {
            // Без имени спрашивать сервер не о чем: идентификатор
            // выводится из самого ключа тем же способом, что и для
            // входящих сообщений, — иначе один контакт получил бы
            // две записи в базе.
            None => (peer_account(&link.identity), None),

            Some(name) => {
                let name = &canonical_username(name)?;
                let peer = self.api.discover(name)?;
                let advertised = parse_public_key(&peer.identity_key)?;

                // 🔐 Ключ со ссылки — единственное, чему здесь есть
                // доверие. Расхождение означает, что либо ссылку
                // подделали, либо сервер называет чужой ключ; в обоих
                // случаях добавлять нечего.
                if advertised.as_bytes() != link.identity.as_bytes() {
                    return Err(AegisError::Malformed);
                }

                // 🔐 То же — для пост-квантовой половины: хеш в ссылке
                // пришёл от собеседника, ключ — от сервера.
                if let (Some(pq_public), Some(binding)) =
                    (&peer.pq_identity_key, &peer.identity_binding)
                {
                    let pq_public = unhex(pq_public)?;
                    aegis_protocol::pq_identity::verify_binding(
                        &advertised,
                        &pq_public,
                        &unhex(binding)?,
                    )?;

                    if aegis_protocol::pq_identity::pq_identity_hash(&pq_public)
                        != link.pq_identity_hash
                    {
                        return Err(AegisError::Malformed);
                    }
                }

                // Счёт — из ключа, как у всех прочих путей (входящее
                // сообщение, поиск по имени). Прежде здесь брался счёт
                // сервера, и один человек с одним ключом заводил две
                // записи: по ссылке и по первому сообщению.
                (peer_account(&link.identity), Some(name.clone()))
            }
        };

        let (identity, _) = self.load_identity()?;
        let chat_id = derive_chat_id(identity.public().public(), &link.identity);

        // 🔐 Смена ключа ищется по имени, а не по счёту.
        //
        // Счёт контакта выводится из первых шестнадцати байт
        // identity-ключа, поэтому сменившийся ключ даёт другой счёт:
        // тихо переписать прежнюю запись он не может — но и на неё
        // не попадает, так что по счёту смена не видна никогда.
        //
        // Видна она по имени. «То же имя при другом ключе» — это
        // и есть смена ключа, как её наблюдает получатель.
        //
        // ⚠️ Добавление не отменяется. Смена бывает законной —
        // переустановка, восстановление из копии, — и отказ
        // означал бы, что после переустановки с человеком нельзя
        // связаться вовсе. Отличить законную смену от подмены может
        // только сверка safety number вживую, поэтому здесь признак
        // для показа, а не решение.
        let key_changed = match username.as_deref() {
            None => false,
            Some(name) => {
                let known = self.storage.contact_identity_by_username(name)?;

                match known {
                    Some(previous) if previous != link.identity.as_bytes() => {
                        // Журнал безопасности: законная смена и подмена
                        // выглядят одинаково, и человек должен иметь
                        // возможность увидеть, когда она случилась.
                        self.storage
                            .log_security_event("contact_identity_changed", None, now)?;

                        true
                    }
                    _ => false,
                }
            }
        };

        self.storage.save_contact(
            &account_id,
            link.identity.as_bytes(),
            username.as_deref(),
            Some(&chat_id),
            now,
        )?;

        // 🔐 Ключ пришёл из ссылки или QR самого собеседника, а не от
        // сервера: сервер его только сверил (выше) и подменить не мог.
        self.storage.mark_contact_confirmed_by_link(&account_id)?;

        // Хеш пост-квантовой половины — тоже со ссылки: он главнее
        // запомненного с сервера. Расхождение — повод для журнала.
        if self
            .storage
            .contact_pq_hash(&account_id)?
            .is_some_and(|known| known != link.pq_identity_hash)
        {
            self.storage
                .log_security_event("pq_identity_changed", None, now)?;
        }
        self.storage
            .set_contact_pq_hash(&account_id, &link.pq_identity_hash)?;

        Ok(Contact {
            account_id,
            identity: link.identity,
            username,
            chat_id: Some(chat_id),
            verified: false,
            key_changed,
            replaced: false,
            key_confirmed: true,
            kt_confirmed: false,
        })
    }

    /// Находит собеседника по имени и записывает контактом — без отправки.
    ///
    /// Ключ, названный сервером, проходит те же проверки, что и при
    /// отправке: смена ключа известного имени — [`AegisError::IdentityChanged`].
    /// Незнакомое имя записывается **неподтверждённым**: интерфейс сразу
    /// показывает safety number для сверки, а не ждёт отказа отправки.
    ///
    /// # Errors
    ///
    /// [`AegisError::InvalidUsername`] — имя не по правилам либо своё;
    /// [`AegisError::Malformed`] — сервер назвал наш собственный ключ;
    /// [`AegisError::Network`] — имя не найдено или сеть недоступна;
    /// [`AegisError::IdentityChanged`] — сервер называет другой ключ.
    pub fn discover_contact(&self, name: &str, now: Timestamp) -> Result<Contact> {
        let name = &canonical_username(name)?;

        // Своё имя — не собеседник. Прежде поиск по нему заводил
        // контакт с собственным ключом: чат с самим собой, закрытый
        // для записи, и safety number с собой. Найдено на эмуляторе.
        if self.own_username()?.as_deref() == Some(name.as_str()) {
            return Err(AegisError::InvalidUsername);
        }

        let peer = self.api.discover(name)?;
        let advertised = parse_public_key(&peer.identity_key)?;

        // То же по ключу: сервер вправе назвать под чужим именем наш
        // собственный ключ, и контакт с ним был бы тем же чатом с собой.
        if self.is_own_identity(&advertised)? {
            return Err(AegisError::Malformed);
        }

        let confirmed = self.bind_advertised_identity(name, &advertised, now)?;

        // Пост-квантовая половина — запоминается сразу: safety number
        // считается по обеим, а сверять человек будет до первой отправки.
        self.verified_peer_pq(&peer, &advertised, now)?;

        let account = peer_account(&advertised);

        // Журнал ключей — сразу, чтобы интерфейс мог дать писать без
        // личной сверки, если ключ стоит в журнале дольше суток (§9.7).
        if !confirmed {
            if let Some(pq) = peer.pq_identity_key.as_deref() {
                if self.kt_verify_contact(name, &advertised, pq, now)? == KtVerdict::Verified {
                    self.storage.mark_contact_confirmed_by_kt(&account)?;
                }
            }
        }

        self.contacts()?
            .into_iter()
            .find(|contact| contact.account_id == account)
            .ok_or(AegisError::Storage)
    }

    /// Возвращает ссылку на собственный профиль.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — свои ключи не читаются;
    /// [`AegisError::Malformed`] — имя не подходит для ссылки.
    pub fn own_contact_link(&self) -> Result<String> {
        let (identity, _) = self.load_identity()?;
        let username = self.storage.load_own_keys()?.and_then(|keys| keys.username);

        ContactLink {
            identity: *identity.public().public(),
            pq_identity_hash: self.own_pq_hash()?,
            display_name: username,
        }
        .to_uri()
    }

    /// Отправляет файл вложением.
    ///
    /// # Что происходит по шагам
    ///
    /// 1. Файл шифруется случайным ключом и режется на чанки по 64 КБ.
    /// 2. Шифроблоб уходит на сервер и получает адрес.
    /// 3. Описание — адрес, ключ, имя, тип — уходит **внутри
    ///    сообщения**, то есть под сквозным шифрованием.
    ///
    /// 🔐 Ключ вложения не покидает сообщения. Сервер, хранящий блоб,
    /// расшифровать его не может: у него есть только байты и их длина.
    ///
    /// # Про порядок
    ///
    /// Сначала загрузка, потом сообщение. При обратном порядке
    /// получатель увидел бы описание файла, которого на сервере ещё
    /// нет, и открыл бы его ошибкой.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — файл больше предела либо описание
    /// не проходит проверку;
    /// [`AegisError::Network`] — загрузка или отправка не удалась;
    /// прочие — те же, что у [`Client::send_message`].
    pub fn send_attachment<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        device_id: &str,
        file: &AttachmentFile,
        body: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let descriptor = self.upload_attachment(device_id, file, now, rng)?;

        let encoded = descriptor.to_bytes()?;

        // Общий с получателем идентификатор — как у текста.
        let message_id = MessageId::generate();

        let chat_id = self.send_content(
            peer_username,
            &Content::Attachments {
                body: body.to_owned(),
                descriptors: vec![encoded.clone()],
                reply_to: None,
                id: *message_id.as_uuid().as_bytes(),
            },
            now,
            rng,
        )?;

        // Своя копия сообщения и описания: отправитель должен видеть
        // отправленный файл так же, как получатель, — и уметь открыть
        // его снова, не держа исходник на диске.
        //
        // Сохраняется после отправки: запись о неушедшем сообщении
        // показала бы в переписке то, чего собеседник не получал.
        self.store_message(&chat_id, message_id, body, now, true, MessageStatus::Sent)?;
        self.store_descriptors(&message_id, &[encoded], now)?;
        self.storage.touch_chat(&chat_id, Some(&message_id), now)?;

        Ok(())
    }

    /// Сохраняет описания вложений сообщения.
    ///
    /// Битые описания пропускаются, а не роняют приём: одно негодное
    /// вложение не должно отменять сообщение целиком — текст при нём
    /// пользователю всё равно нужен.
    fn store_descriptors(
        &self,
        message_id: &MessageId,
        descriptors: &[Vec<u8>],
        now: Timestamp,
    ) -> Result<()> {
        for encoded in descriptors {
            let Ok(descriptor) = AttachmentDescriptor::from_bytes(encoded) else {
                continue;
            };

            self.storage
                .save_attachment(&aegis_storage::StoredAttachment {
                    message_id: *message_id,
                    attachment_type: descriptor.kind.as_u8(),
                    description: descriptor.name.clone(),
                    size: i64::try_from(descriptor.size).unwrap_or(i64::MAX),
                    created_at: now,
                    descriptor: Some(encoded.clone()),
                })?;
        }

        Ok(())
    }

    /// Возвращает описания вложений сообщения.
    ///
    /// Пусто, если вложений нет либо они пришли до версии схемы 4,
    /// когда описания не сохранялись.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn attachments_of(&self, message_id: &MessageId) -> Result<Vec<AttachmentDescriptor>> {
        Ok(self
            .storage
            .load_attachments(message_id)?
            .into_iter()
            .filter_map(|row| row.descriptor)
            .filter_map(|encoded| AttachmentDescriptor::from_bytes(&encoded).ok())
            .collect())
    }

    /// Шифрует файл и кладёт его на сервер.
    ///
    /// Возвращает описание, готовое уехать внутри сообщения.
    ///
    /// Публичный, а не внутренний шаг [`Client::send_attachment`]:
    /// вложение к нескольким получателям загружается один раз,
    /// а описание рассылается всем — иначе один файл занимал бы
    /// на сервере столько места, сколько у него адресатов.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — файл больше предела;
    /// [`AegisError::Network`] — загрузка не удалась.
    pub fn upload_attachment<R: RngCore + CryptoRng>(
        &self,
        device_id: &str,
        file: &AttachmentFile,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<AttachmentDescriptor> {
        // 🔐 Метаданные удаляются до шифрования: GPS, модель камеры,
        // время съёмки, миниатюры, геометка видео (`aegis_media::scrub`).
        // Файл известного формата, который не разбирается, не уходит
        // вовсе — иначе ушёл бы со всеми метаданными.
        let scrubbed = scrub::scrub(&file.bytes)?;

        let size = u64::try_from(scrubbed.bytes.len()).map_err(|_| AegisError::Malformed)?;

        if size > MAX_ATTACHMENT_BYTES {
            return Err(AegisError::Malformed);
        }

        // 🔐 Длина дополняется до сетки Padmé: сервер видит длину блоба,
        // а точная длина узнаваема — по ней видно, что один и тот же
        // файл получили разные люди. Настоящая длина — в описании.
        let mut plaintext = scrubbed.bytes;
        plaintext.resize(attachment::padded_len(plaintext.len())?, 0);

        let key = AttachmentKey::generate(rng);

        // Чанки склеиваются в один блоб: сервер хранит его целиком,
        // а получатель режет обратно по известному размеру чанка.
        // Отдельная загрузка каждого чанка означала бы тысячу запросов
        // на стомегабайтный файл.
        let mut payload = Vec::new();

        for (index, chunk) in plaintext.chunks(attachment::CHUNK_SIZE).enumerate() {
            let index = u32::try_from(index).map_err(|_| AegisError::Malformed)?;

            payload.extend_from_slice(&attachment::seal_chunk(&key, index, chunk)?);
        }

        // 🔐 Загрузка анонимна: право на место — работа над этим блобом,
        // а не подпись устройства (см. `ApiClient::upload_attachment`).
        // Устройство и время больше не нужны; параметры оставлены ради
        // интерфейса FFI.
        let _ = (device_id, now);

        let nonce = aegis_net::pow::solve(
            &aegis_net::pow::upload_challenge(&payload),
            aegis_net::pow::upload_difficulty(payload.len()),
        )
        .ok_or(AegisError::Crypto)?;

        let location = self.api.upload_attachment(payload, nonce)?;

        let descriptor = AttachmentDescriptor {
            kind: file.kind,
            location,
            key: *key.expose(),
            size,
            // 🔐 У фото, видео и звука имя не передаётся: «IMG_20260924_
            // 183005.jpg» — это дата и секунда съёмки, «PXL_…» — модель
            // телефона. Имя документа выбирает человек, и оно остаётся.
            name: if scrubbed.format.is_media() {
                None
            } else {
                file.name.clone()
            },
            description: file.description.clone(),
            duration_millis: file.duration_millis,
            waveform: file.waveform.clone(),
            preview: None,
        };

        descriptor.validate()?;

        Ok(descriptor)
    }

    /// Скачивает и расшифровывает вложение по описанию.
    ///
    /// # 🔐 Почему размер проверяется до расшифровки
    ///
    /// Блоб приходит с сервера, а его длину называет описание,
    /// пришедшее от собеседника. Расхождение означает, что одно
    /// из двух подменили; продолжать расшифровку значило бы выделять
    /// память по числу, которому нет доверия.
    ///
    /// # Errors
    ///
    /// [`AegisError::Network`] — скачивание не удалось;
    /// [`AegisError::Crypto`] — блоб не расшифровывается: подменён
    /// либо ключ не тот;
    /// [`AegisError::Malformed`] — длина блоба не сходится с описанием.
    pub fn fetch_attachment(
        &self,
        device_id: &str,
        descriptor: &AttachmentDescriptor,
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        descriptor.validate()?;

        // 🔐 Без подписи: скачивание не должно связывать получателя
        // с отправителем (см. `aegis_net::client::download_attachment`).
        // Устройство и время больше не нужны; параметры оставлены,
        // чтобы не ломать интерфейс FFI.
        let _ = (device_id, now);

        let payload = self.api.download_attachment(&descriptor.location)?;

        // Длина блоба однозначно следует из размера файла: столько-то
        // полных чанков плюс остаток, и на каждый — свой тег.
        let expected = expected_payload_len(descriptor.size)?;

        if payload.len() != expected {
            return Err(AegisError::Malformed);
        }

        let key = AttachmentKey::from_bytes(descriptor.key);
        let mut plaintext = Vec::new();

        for (index, chunk) in payload.chunks(attachment::ENCRYPTED_CHUNK_SIZE).enumerate() {
            let index = u32::try_from(index).map_err(|_| AegisError::Malformed)?;

            plaintext.extend_from_slice(&attachment::open_chunk(&key, index, chunk)?);
        }

        // Дополнение Padmé отбрасывается: настоящая длина — в описании,
        // пришедшем внутри зашифрованного сообщения.
        plaintext.truncate(usize::try_from(descriptor.size).map_err(|_| AegisError::Malformed)?);

        Ok(plaintext)
    }

    /// Читает булеву настройку приложения.
    ///
    /// 🔐 Умолчание задаёт вызывающий и всегда указывает явно: оно
    /// разное у разных настроек. Блокировка снимков экрана включена
    /// по умолчанию, передача присутствия выключена — общий ответ
    /// означал бы, что одна из них защищает не так, как задумано.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn setting_bool(&self, key: &str, default: bool) -> Result<bool> {
        self.storage.setting_bool(key, default)
    }

    /// Записывает булеву настройку приложения.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_setting_bool(&self, key: &str, enabled: bool) -> Result<()> {
        self.storage.set_setting_bool(key, enabled)
    }

    /// Читает числовую настройку приложения.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn setting_int(&self, key: &str, default: i64) -> Result<i64> {
        self.storage.setting_int(key, default)
    }

    /// Записывает числовую настройку приложения.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_setting_int(&self, key: &str, value: i64) -> Result<()> {
        self.storage.set_setting_int(key, value)
    }

    /// Возвращает идентификатор этого устройства.
    ///
    /// [`None`] означает, что регистрация ещё не проходила: устройство
    /// заводит сервер, и до регистрации его нет.
    ///
    /// Нужен вызывающему для приёма сообщений и работы с вложениями:
    /// обе ручки адресуются по устройству.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn own_device_id(&self) -> Result<Option<String>> {
        Ok(self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id))
    }

    /// Возвращает собственное имя пользователя, если оно занято.
    ///
    /// [`None`] означает, что регистрация ещё не прошла: имя выдаёт
    /// сервер при регистрации, а до неё занимать нечего.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn own_username(&self) -> Result<Option<String>> {
        Ok(self.storage.load_own_keys()?.and_then(|keys| keys.username))
    }

    /// Safety number с контактом.
    ///
    /// # Что здесь было
    ///
    /// 🔴 Экран сверки считал safety number **двух случайных ключей**:
    /// `generateIdentityPublicKey()` дважды, то есть две свежие пары
    /// на каждое открытие. Цифры были разными при каждом показе,
    /// не совпадали у собеседников никогда и не имели отношения
    /// ни к одному из них.
    ///
    /// Единственная защита сквозного шифрования от подмены ключей
    /// сервером — сверка этих цифр человеком. Её не было, а экран,
    /// который выглядел как она, был.
    ///
    /// # Почему идентификатор выводится из ключа
    ///
    /// Отпечаток привязывается к владельцу идентификатором, и обе
    /// стороны обязаны взять для каждого участника **один и тот же**.
    /// Счёт собеседника для этого не годится: добавленный по имени,
    /// он серверный, а узнанный из входящего сообщения — выведенный
    /// из ключа. Возьми одна сторона первый, другая второй, и цифры
    /// разошлись бы на честном канале — ложная тревога о подмене.
    ///
    /// Одинаково обе стороны знают только сам ключ. Поэтому
    /// идентификатор каждого участника выводится из его ключа.
    ///
    /// # Почему одинаково у обоих
    ///
    /// [`SafetyNumber::new`] упорядочивает отпечатки, так что Алиса
    /// и Боб получают одну последовательность, хотя «свой» и «чужой»
    /// у них противоположны.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — такого контакта нет;
    /// [`AegisError::Uninitialized`] — свои ключи не созданы;
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn safety_number(&self, contact: &AccountId) -> Result<String> {
        let (identity, _) = self.load_identity()?;
        let own = *identity.public().public();

        let peer_bytes = self
            .storage
            .get_contact_identity(contact)?
            .ok_or(AegisError::Malformed)?;

        let peer = PublicKeyBytes::new(
            peer_bytes
                .as_slice()
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
        );

        // 🔐 Гибридные отпечатки: сверка покрывает и пост-квантовую
        // половину (см. `client::pq`).
        Ok(self.hybrid_safety_number(&own, &peer)?.to_display_block())
    }

    /// Отмечает контакт сверенным или снимает отметку.
    ///
    /// # Что здесь было
    ///
    /// 🔴 Ничего. Кнопка «Отметить сверенным» закрывала экран, и только.
    /// `Storage::set_contact_verified` вызывался из тестов и больше
    /// ниоткуда, а комментарий в хранилище обещал, что время сверки
    /// живёт в журнале безопасности, — туда не писал никто.
    ///
    /// # Про журнал
    ///
    /// 🔐 И отметка, и её снятие записываются. Отметка — решение
    /// человека «я лично сверил»; когда оно было принято и когда
    /// отозвано, должно быть видно потом, а не только сейчас.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — такого контакта нет;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_contact_verified(
        &self,
        contact: &AccountId,
        verified: bool,
        now: Timestamp,
    ) -> Result<()> {
        // Отметить можно только известный контакт: иначе в таблице
        // сверенных завелась бы запись без ключа, и сверка
        // относилась бы неизвестно к чему.
        if self.storage.get_contact_identity(contact)?.is_none() {
            return Err(AegisError::Malformed);
        }

        self.storage.set_contact_verified(contact, verified, now)?;

        self.storage.log_security_event(
            if verified {
                "contact_verified"
            } else {
                "contact_verification_revoked"
            },
            None,
            now,
        )?;

        // 🔐 Сверка вживую и есть выбор между ключами одного имени:
        // сверенный ключ остаётся за именем, остальные заменяются.
        if verified {
            self.keep_only_for_name(contact, now)?;
        }

        Ok(())
    }

    /// 🔐 Принимает ключ контакта без сверки: имя остаётся за ним.
    ///
    /// Путь для законной смены ключа — переустановки или
    /// восстановления у собеседника, — когда встретиться и сверить
    /// safety number нельзя. Прочие записи того же имени заменяются,
    /// и отправка по имени снова разрешена — этому ключу.
    ///
    /// ⚠️ Это решение человека, а не приложения: ядро не может
    /// отличить переустановку от подмены. Интерфейс обязан сказать
    /// об этом до нажатия. Решение пишется в журнал безопасности.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — такого контакта нет или у него нет имени;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn accept_contact_identity(&self, contact: &AccountId, now: Timestamp) -> Result<()> {
        self.keep_only_for_name(contact, now)?;

        self.storage
            .log_security_event("contact_identity_accepted", None, now)
    }

    /// Оставляет за именем контакта только его запись.
    fn keep_only_for_name(&self, contact: &AccountId, now: Timestamp) -> Result<()> {
        let row = self
            .storage
            .list_contacts(MAX_CONTACTS_TO_LIST)?
            .into_iter()
            .find(|row| &row.account_id == contact)
            .ok_or(AegisError::Malformed)?;

        let Some(name) = row.username else {
            // Без имени отправка по имени невозможна, и делить нечего.
            return Ok(());
        };

        self.storage.restore_contact(contact)?;
        self.storage.replace_other_contacts(&name, contact, now)?;

        Ok(())
    }

    /// 🔐 Ключ, который сервер назвал для имени, сверяется с известным.
    ///
    /// # Что здесь чинится
    ///
    /// Отправка адресуется по имени: ядро спрашивает сервер, какой
    /// ключ у `alice`, и шифрует ему. Прежде ответ сервера **не
    /// сверялся ни с чем**. Сервер — злонамеренный, взломанный или
    /// принуждённый — мог назвать свой ключ, и следующее же сообщение
    /// уходило ему. Сверка safety number этому не мешала: её отметка
    /// лежала в базе, а путь отправки её не читал. То есть сквозное
    /// шифрование держалось на честности сервера — ровно на том,
    /// от чего оно должно защищать (раздел 3, противник A1).
    ///
    /// # Правило
    ///
    /// Разрешено, только если:
    ///
    ///  * имя не известно ни под каким ключом — первый контакт; иного
    ///    источника ключа, кроме сервера, тут нет (доверие при первом
    ///    использовании, как у Signal); или
    ///  * за именем ровно одна действующая запись, и её ключ совпадает
    ///    с названным.
    ///
    /// Во всех остальных случаях — [`AegisError::IdentityChanged`], до
    /// шифрования. Если названный ключ новый, он записывается контактом
    /// под тем же именем: человек увидит два контакта с одним именем
    /// (`key_changed`) и выберет — сверкой вживую
    /// ([`Client::set_contact_verified`]) или явным принятием
    /// ([`Client::accept_contact_identity`]).
    ///
    /// Два действующих ключа под одним именем запрещают отправку
    /// **обоим**: иначе сообщение из одного чата молча уходило бы
    /// в другой — туда, куда указывает сервер, а не туда, где человек
    /// печатал.
    fn check_advertised_identity(
        &self,
        name: &str,
        advertised: &PublicKeyBytes,
        pq_identity_key: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        let confirmed = self.bind_advertised_identity(name, advertised, now)?;

        // 🔐 Ключ, который назвал только сервер, не годится для отправки:
        // сервер мог подставить свой, и первое же сообщение ушло бы ему.
        // Годится ключ, подтверждённый вне сервера, — сверкой safety
        // number или ссылкой/QR самого собеседника.
        if confirmed {
            return Ok(());
        }

        // …или журналом ключей (§9.7): тот же ключ под этим именем
        // стоит в журнале сейчас и стоял сутки назад, а владелец имени
        // проверяет свою запись сам. Сервер не может показать его
        // одному человеку, не показав всем, включая владельца.
        if let Some(pq) = pq_identity_key {
            if self.kt_verify_contact(name, advertised, pq, now)? == KtVerdict::Verified {
                self.storage
                    .mark_contact_confirmed_by_kt(&peer_account(advertised))?;

                return Ok(());
            }
        }

        Err(AegisError::PeerUnconfirmed)
    }

    /// Сверяет ключ, названный сервером, с известными для имени.
    ///
    /// Возвращает, подтверждён ли он вне сервера. Незнакомое имя
    /// записывается контактом — неподтверждённым: так интерфейс может
    /// показать safety number для сверки ещё до первого сообщения.
    fn bind_advertised_identity(
        &self,
        name: &str,
        advertised: &PublicKeyBytes,
        now: Timestamp,
    ) -> Result<bool> {
        let known = self.storage.active_contacts_by_username(name)?;

        // Заменённая запись под именем всегда соседствует с действующей
        // (той, что её заменила), поэтому «нет действующих» означает,
        // что имя не известно вовсе.
        if known.is_empty() {
            let (own, _) = self.load_identity()?;
            let chat_id = derive_chat_id(own.public().public(), advertised);

            self.storage.save_contact(
                &peer_account(advertised),
                advertised.as_bytes(),
                Some(name),
                Some(&chat_id),
                now,
            )?;

            return Ok(false);
        }

        // Все действующие записи — один и тот же ключ: имя однозначно.
        // Подтверждение любой из них подтверждает ключ.
        if known
            .iter()
            .all(|(_, identity, _)| identity.as_slice() == advertised.as_bytes())
        {
            return Ok(known.iter().any(|(_, _, confirmed)| *confirmed));
        }

        let advertised_known = known
            .iter()
            .any(|(_, identity, _)| identity.as_slice() == advertised.as_bytes());

        if !advertised_known {
            // Новый (или вернувшийся) ключ записывается, чтобы смена
            // была видна, а не только отказ.
            let (own, _) = self.load_identity()?;
            let account = peer_account(advertised);
            let chat_id = derive_chat_id(own.public().public(), advertised);

            self.storage.save_contact(
                &account,
                advertised.as_bytes(),
                Some(name),
                Some(&chat_id),
                now,
            )?;
            self.storage.restore_contact(&account)?;

            self.storage
                .log_security_event("contact_identity_changed", None, now)?;
        }

        Err(AegisError::IdentityChanged)
    }

    /// Принимает имя, которым назвался собеседник, — если оно его.
    ///
    /// 🔐 Заявленное имя сверяется с discovery: сервер обязан отдать
    /// по нему тот же identity-ключ, что у отправителя. Иначе
    /// назвавшийся чужим именем получил бы наш ответ — точнее, ответ
    /// ушёл бы настоящему владельцу имени, в другой чат, и человек
    /// не понял бы, кому написал.
    ///
    /// Сбой сети — не повод падать: имя примется со следующим
    /// сообщением, несущим ключ доступа.
    fn accept_claimed_username(
        &self,
        peer: &PublicKeyBytes,
        name: &str,
        chat_id: &ChatId,
        now: Timestamp,
    ) -> Result<()> {
        // Имя прислал собеседник — неканоничное не ищется вовсе.
        let Ok(name) = canonical_username(name) else {
            return Ok(());
        };
        let name = name.as_str();

        let Ok(found) = self.api.discover(name) else {
            return Ok(());
        };

        let Ok(advertised) = parse_public_key(&found.identity_key) else {
            return Ok(());
        };

        if advertised.as_bytes() != peer.as_bytes() {
            return Ok(());
        }

        self.storage.save_contact(
            &peer_account(peer),
            peer.as_bytes(),
            Some(name),
            Some(chat_id),
            now,
        )?;

        // Пост-квантовая половина собеседника, начавшего переписку:
        // без неё safety number не посчитать. Подмена здесь — запись
        // в журнал и отказ при отправке, но не повод потерять имя.
        let _ = self.verified_peer_pq(&found, &advertised, now);

        Ok(())
    }

    /// Перечисляет контакты, недавно добавленные первыми.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        let rows = self.storage.list_contacts(MAX_CONTACTS_TO_LIST)?;

        // 🔐 Имя, встречающееся больше одного раза, — это имя,
        // известное под разными ключами.
        //
        // Счёт контакта выводится из его identity-ключа, поэтому
        // сменившийся ключ не переписывает прежнюю запись, а заводит
        // новую. В списке это выглядит как два контакта с одним
        // именем — и ровно так смену ключа и видно.
        //
        // ⚠️ Который из двух настоящий, отсюда не определить.
        // Помечаются оба: выбор между ними — это сверка safety
        // number, а не догадка приложения.
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();

        // Заменённые записи имени не делят: выбор между ключами
        // уже сделан человеком.
        for row in rows.iter().filter(|row| !row.replaced) {
            if let Some(name) = row.username.as_deref() {
                let count = seen.entry(name).or_insert(0);
                *count = count.saturating_add(1);
            }
        }

        let ambiguous: BTreeSet<String> = seen
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(name, _)| name.to_owned())
            .collect();

        rows.into_iter()
            .map(|row| {
                let key_changed = !row.replaced
                    && row
                        .username
                        .as_deref()
                        .is_some_and(|name| ambiguous.contains(name));

                Ok(Contact {
                    account_id: row.account_id,
                    identity: PublicKeyBytes::new(
                        row.identity_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| AegisError::Malformed)?,
                    ),
                    username: row.username,
                    chat_id: row.chat_id,
                    verified: row.verified,
                    key_changed,
                    replaced: row.replaced,
                    key_confirmed: row.verified || row.confirmed_by_link || row.confirmed_by_kt,
                    kt_confirmed: row.confirmed_by_kt && !row.verified && !row.confirmed_by_link,
                })
            })
            .collect()
    }

    /// Ищет по расшифрованной переписке.
    ///
    /// 🔐 Поиск идёт по той же таблице сообщений, а не по отдельному
    /// индексу: индекс был бы второй копией переписки, которую тоже
    /// пришлось бы стирать при удалении и при истечении срока, —
    /// и о которой при этом легко забыть.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>> {
        let own = self.storage.get_account_id()?;

        self.storage
            .search_messages(query, limit)?
            .into_iter()
            .map(|message| {
                Ok(SearchHit {
                    chat_id: message.chat_id,
                    message: ChatMessage {
                        message_id: message.id,
                        text: String::from_utf8_lossy(message.content.as_bytes()).into_owned(),
                        timestamp: message.timestamp,
                        outgoing: own.as_ref() == Some(&message.sender_id),
                        status: message.status,
                    },
                })
            })
            .collect()
    }

    /// Перешифровывает хранилище новым ключом.
    ///
    /// 🔐 Только перевод на ключ, связанный с аппаратным хранилищем
    /// (P-5, раздел 23.6). Содержимое не меняется — меняется ключ,
    /// которым зашифрован файл.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — ключ не 32 байта;
    /// [`AegisError::Storage`] — смена не удалась.
    pub fn rekey_storage(&self, new_key: &[u8]) -> Result<()> {
        self.storage.rekey(new_key)
    }

    /// 🔐 Пополняет одноразовые предключи и ротирует подписанный.
    ///
    /// # Почему это обязательно вызывать
    ///
    /// Одноразовый предключ **расходуется** при каждом первом контакте:
    /// сервер выдаёт его тому, кто начинает переписку, и вычёркивает.
    /// Пул конечен ([`aegis_protocol::ONE_TIME_PRE_KEY_POOL_SIZE`] = 100), публикуется
    /// при регистрации и без пополнения не восстанавливается никогда.
    ///
    /// Когда пул пуст, `take_prekey_bundle` отдаёт bundle с
    /// `degraded = true`, и каждая новая переписка заводится **без**
    /// одноразового предключа — теряя и классическую, и
    /// пост-квантовую половину того вклада в forward secrecy, ради
    /// которого он существует. Сервер при этом отвечает успехом,
    /// и ни отправитель, ни получатель ничего не замечают.
    ///
    /// ⚠️ `GET /v1/keys/{device}/bundle` **не требует подписи** —
    /// иначе первый контакт был бы возможен только со знакомыми.
    /// Значит вычерпать чужой пул может кто угодно: ограничитель
    /// даёт 10 запросов в минуту, то есть сто ключей за десять минут.
    /// Без пополнения это ухудшение **навсегда**.
    ///
    /// # Почему ротация здесь же
    ///
    /// Подписанный предключ живёт [`aegis_protocol::SIGNED_PRE_KEY_ROTATION_DAYS`]
    /// дней по замыслу: срок ограничивает, сколько будущих
    /// рукопожатий раскроет его компрометация. Ключ, не меняющийся
    /// никогда, делает это окно бесконечным.
    ///
    /// Обе задачи решаются одним запросом `PUT /v1/keys/{device}`,
    /// и разделять их значило бы ходить на сервер дважды.
    ///
    /// # Когда вызывать
    ///
    /// После открытия хранилища и после приёма сообщений: первое
    /// покрывает редкий запуск, второе — активную переписку.
    /// Вызов дёшев, когда делать нечего: без нужды в пополнении
    /// и ротации он не обращается к сети вовсе.
    ///
    /// # Errors
    ///
    /// * [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован.
    /// * [`AegisError::Network`] — публикация не удалась. Секреты при
    ///   этом **не сохранены**: иначе клиент считал бы опубликованным
    ///   то, чего сервер не видел, и пул чинился бы только с виду.
    pub fn maintain_prekeys<R: RngCore + CryptoRng>(
        &self,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<PreKeyMaintenance> {
        let device_id = self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id)
            .ok_or(AegisError::SessionNotFound)?;

        let (identity, mut secrets) = self.load_identity()?;
        let pq = self.own_pq_identity()?;

        let rotated = secrets.needs_rotation(now);

        if rotated {
            prekeys::rotate_signed(&identity, &pq, &mut secrets, now, rng)?;
        }

        // 🔐 Остаток спрашивается у сервера, а не считается у себя.
        //
        // Одноразовый ключ вычёркивается, когда его **забирает
        // отправитель**, — владелец об этом не узнаёт, его локальный
        // список не меняется. Поэтому вычерпанный чужими пул
        // выглядит изнутри полным, и проверка по своим секретам
        // (`needs_refill`) не срабатывает никогда.
        //
        // Ровно так оно и было: `needs_refill` существовала, была
        // покрыта тестами и не вызывалась ниоткуда, а даже вызванная
        // ничего бы не исправила.
        let on_server = self
            .api
            .count_one_time_prekeys(&device_id, &DeviceSigner::new(&identity, now))
            .unwrap_or(0)
            .max(0);

        let target = i64::from(prekeys_pool_size());
        let deficit = usize::try_from(target.saturating_sub(on_server)).unwrap_or(0);

        let (added_one_time, added_kem) = if deficit > 0 {
            // ⚠️ Прежние приватные ключи не выбрасываются, даже те,
            // чьи публичные половины сервер уже отдал и удалил:
            // отправитель, успевший забрать ключ, пришлёт по нему
            // начальное сообщение, и без приватной половины оно
            // не расшифруется.
            prekeys::mint_one_time(&identity, &pq, &mut secrets, deficit, rng)?
        } else {
            (Vec::new(), Vec::new())
        };

        let added = u32::try_from(added_one_time.len()).unwrap_or(u32::MAX);

        // 🔐 Ключ доступа sealed sender — сразу, а не с первым
        // отправленным сообщением. Прежде аккаунт, ещё никому
        // не писавший, ключа не публиковал: запечатанными ему писали
        // и так (proof-of-work первого контакта), но центр безопасности
        // честно показывал «sealed sender: нет» — у каждого нового
        // пользователя.
        if !self.sealed_sender_enabled()? {
            self.ensure_access_key(&identity, now, rng)?;
        }

        // 🔐 Смена ключа ML-KEM sealed sender по сроку. Сменённый ключ
        // не опубликован и уходит на сервер тем же запросом ниже.
        self.rotate_sealed_kem_if_due(now, rng)?;

        // 🔐 Ключ ML-KEM sealed sender, ещё не бывший на сервере: у аккаунтов,
        // заведённых до гибридного sealed sender, его нет, и писать им
        // запечатанным невозможно, пока он не опубликован.
        let kem_unpublished = self
            .storage
            .own_sealed_kem()?
            .is_none_or(|(_, published)| published.is_none());

        // 🔐 Пост-квантовая половина identity, ещё не бывшая на сервере:
        // у аккаунтов, заведённых до гибридной identity.
        let pq_pending = self.pending_pq_publication(&identity)?;

        // Делать нечего — и сети это знать незачем.
        if !rotated && added == 0 && !kem_unpublished && pq_pending.is_none() {
            return Ok(PreKeyMaintenance {
                rotated_signed: false,
                added_one_time: 0,
                remaining_one_time: u32::try_from(on_server).unwrap_or(u32::MAX),
            });
        }

        let (signed_pre_key, signed_kem_pre_key) =
            prekeys::signed_published(&identity, &pq, &secrets)?;

        let request = PublishKeysRequest {
            signed_key_id: i32::try_from(signed_pre_key.id.as_u32()).unwrap_or(i32::MAX),
            signed_public: hex(signed_pre_key.public.as_bytes()),
            signed_signature: hex(&signed_pre_key.signature),
            kem_key_id: i32::try_from(signed_kem_pre_key.id.as_u32()).unwrap_or(i32::MAX),
            kem_public: hex(signed_kem_pre_key.public.as_bytes()),
            kem_signature: hex(&signed_kem_pre_key.signature),
            one_time: added_one_time
                .iter()
                .map(|(id, key)| {
                    (
                        i32::try_from(id.as_u32()).unwrap_or(i32::MAX),
                        hex(key.as_bytes()),
                    )
                })
                .collect(),
            // 🔐 Пост-квантовые одноразовые предключи уходят **с
            // подписью**: подмена такого ключа даёт атакующему
            // пост-квантовую половину общего секрета, и схема
            // держится только на том, что его подлинность
            // проверяема (раздел 6.2).
            one_time_kem: added_kem
                .iter()
                .map(|key| {
                    (
                        i32::try_from(key.id.as_u32()).unwrap_or(i32::MAX),
                        hex(key.public.as_bytes()),
                        hex(&key.signature),
                    )
                })
                .collect(),
            sealed_kem_public: None,
            sealed_kem_signature: None,
            pq_identity_key: pq_pending.as_ref().map(|(public, _)| public.clone()),
            identity_binding: pq_pending.as_ref().map(|(_, binding)| binding.clone()),
        };

        let mut request = request;
        let (kem_public, kem_signature) = self.sealed_kem_publication(&identity, rng)?;
        request.sealed_kem_public = Some(kem_public);
        request.sealed_kem_signature = Some(kem_signature);

        // ⚠️ Публикация до сохранения.
        //
        // Порядок обязателен: сохранив секреты первыми и не дойдя
        // до сервера, клиент считал бы пул пополненным, а сервер
        // продолжал бы выдавать пустые bundle. Пул чинился бы
        // только с виду — то есть не чинился бы вовсе.
        self.api
            .publish_keys(&device_id, &request, &DeviceSigner::new(&identity, now))?;

        // Ключ ML-KEM sealed sender ушёл на сервер этим запросом.
        //
        // ⚠️ Прежде отметка не ставилась: после смены ключа он
        // переотправлялся при каждом обслуживании, а срок следующей
        // смены (он считается от публикации) не наступал никогда.
        self.storage.mark_own_sealed_kem_published(now)?;
        if pq_pending.is_some() {
            self.storage.mark_own_pq_identity_published(now)?;
        }

        self.persist_secrets(&secrets, now)?;

        Ok(PreKeyMaintenance {
            rotated_signed: rotated,
            added_one_time: added,
            remaining_one_time: u32::try_from(on_server)
                .unwrap_or(u32::MAX)
                .saturating_add(added),
        })
    }

    /// 🔐 Собирает выгрузку данных пользователя (MASVS PRIVACY-3.1).
    ///
    /// # Что попадает в выгрузку
    ///
    /// То, что человек в приложение **положил**: имя аккаунта,
    /// контакты, переписка и настройки. Формат — JSON: его читает
    /// и человек, и чужая программа, а «право забрать свои данные»
    /// в закрытом формате правом не является.
    ///
    /// # ⚠️ Чего в выгрузке нет и не будет
    ///
    /// **Ключей.** Ни приватного identity-ключа, ни секретов
    /// предключей, ни состояния ратчета, ни ключа восстановления.
    /// Выгрузка — файл, который человек кладёт в облако, шлёт себе
    /// почтой и забывает в загрузках; ключ в нём означал бы, что
    /// всю защиту переписки можно обойти, взяв один этот файл.
    ///
    /// Восстановиться из выгрузки поэтому нельзя — для этого есть
    /// резервная копия (`create_backup`), и она зашифрована.
    /// Это разные задачи, и смешивать их нельзя: портируемость
    /// требует читаемости, восстановление требует секретности.
    ///
    /// **Содержимого хранилища файлов.** Оно и на диске лежит
    /// зашифрованным отдельным ключом; выгружать его открытым текстом
    /// значило бы отменить смысл хранилища.
    ///
    /// # ⚠️ Файл не зашифрован
    ///
    /// Это осознанно: зашифрованная выгрузка не переносима. Но тот,
    /// кто её получил, получил всю переписку — и интерфейс обязан
    /// сказать это до того, как человек выберет, куда сохранять.
    ///
    /// # Errors
    ///
    /// * [`AegisError::SessionNotFound`] — аккаунта нет, выгружать нечего.
    /// * [`AegisError::Storage`] — чтение не удалось.
    pub fn export_data(&self, now: Timestamp) -> Result<String> {
        let keys = self
            .storage
            .load_own_keys()?
            .ok_or(AegisError::SessionNotFound)?;

        let mut contacts = Vec::new();

        for contact in self.contacts()? {
            contacts.push(serde_json::json!({
                "username": contact.username,
                // Публичный ключ — тот самый, который человек сверял
                // с собеседником. Без него список контактов
                // не перенести: имя контакт называет себе сам.
                "identity_key": hex(contact.identity.as_bytes()),
                "verified": contact.verified,
                "chat_id": contact.chat_id.as_ref().map(ToString::to_string),
            }));
        }

        let mut chats = Vec::new();

        for chat_id in self.chats()? {
            let mut messages = Vec::new();

            for message in self.messages(&chat_id, MAX_EXPORTED_MESSAGES)? {
                messages.push(serde_json::json!({
                    "text": message.text,
                    "timestamp": message.timestamp.as_millis(),
                    "outgoing": message.outgoing,
                }));
            }

            chats.push(serde_json::json!({
                "chat_id": chat_id.to_string(),
                "messages": messages,
            }));
        }

        let settings: serde_json::Map<String, serde_json::Value> = self
            .storage
            .list_settings()?
            .into_iter()
            .map(|(key, value)| (key, serde_json::json!(value)))
            .collect();

        let document = serde_json::json!({
            // Версия формата первым полем: читающая программа обязана
            // знать, что делать, раньше, чем начнёт разбирать остальное.
            "format": EXPORT_FORMAT,
            "exported_at": now.as_millis(),
            "account": {
                "username": keys.username,
                "device_id": keys.device_id,
            },
            "contacts": contacts,
            "chats": chats,
            "settings": settings,
            // Сказано прямо в самом файле, а не только в интерфейсе:
            // файл переживёт тот экран, на котором его сделали.
            "not_included": [
                "private keys of any kind",
                "double ratchet state",
                "recovery key",
                "encrypted vault contents",
            ],
        });

        serde_json::to_string_pretty(&document).map_err(|_| AegisError::Storage)
    }

    /// 🔐 Удаляет аккаунт на сервере (MASVS PRIVACY-3.2).
    ///
    /// # Что делает и чего не делает
    ///
    /// Делает один подписанный запрос и возвращает то, что сервер
    /// сообщил об удалённом. **Локальные данные не трогает**: файл
    /// базы, аппаратный секрет и настройки принадлежат платформе,
    /// она их и убирает — ядро не знает ни пути к файлу, ни имени
    /// ключа в хранилище устройства.
    ///
    /// Порядок обязателен именно такой: сначала сервер, потом
    /// локальное. Наоборот — и при сбое сети человек остался бы
    /// без переписки, но с живым аккаунтом на сервере, а повторить
    /// удаление стало бы нечем: подпись требует ключа, который
    /// только что стёрли.
    ///
    /// # ⚠️ Уносит все устройства аккаунта
    ///
    /// Это удаление аккаунта, а не выход с одного телефона.
    ///
    /// # Errors
    ///
    /// * [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован,
    ///   удалять нечего.
    /// * [`AegisError::InvalidSignature`] — сервер не принял подпись
    ///   либо аккаунт уже удалён: он не различает эти случаи, чтобы
    ///   не отвечать на вопрос «существовал ли такой аккаунт».
    /// * [`AegisError::Network`] — сбой соединения. Аккаунт при этом
    ///   цел, и попытку можно повторить.
    pub fn delete_account(&self, now: Timestamp) -> Result<AccountDeletionReport> {
        let device_id = self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id)
            .ok_or(AegisError::SessionNotFound)?;

        let (identity, _) = self.load_identity()?;

        let response = self
            .api
            .delete_account(&device_id, &DeviceSigner::new(&identity, now))?;

        Ok(AccountDeletionReport {
            devices: response.devices,
            envelopes: response.envelopes,
            attachments: response.attachments,
        })
    }

    /// Заголовки подписи для рукопожатия сокета уведомлений.
    ///
    /// # Зачем отдельный метод
    ///
    /// Остальные запросы уходят из ядра, и подпись ставится по дороге.
    /// Сокет уведомлений ведёт платформа — на Android это сырой
    /// `Socket` с рукопожатием, собранным руками, — поэтому заголовки
    /// приходится отдавать наружу.
    ///
    /// 🔐 Наружу уходит подпись **одного конкретного запроса**: метода,
    /// пути и времени. Приватный ключ не покидает ядро, а подписью
    /// нельзя воспользоваться для другого пути — домен-разделитель
    /// и путь входят в подписываемое сообщение.
    ///
    /// # Почему это понадобилось
    ///
    /// До внутреннего пентеста (раздел 23.6) маршрут `/v1/ws/{device}`
    /// не требовал подписи, и это давало посторонним поток уведомлений
    /// о каждом входящем сообщении любого устройства — то есть точное
    /// время каждого входящего у выбранного человека.
    ///
    /// # Errors
    ///
    /// [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// [`AegisError::Crypto`] — подпись не построилась.
    pub fn socket_auth_headers(
        &self,
        device_id: &str,
        now: Timestamp,
    ) -> Result<Vec<(String, String)>> {
        let (identity, _) = self.load_identity()?;

        // Путь обязан совпадать с тем, что клиент поставит в строку
        // запроса, байт в байт: сервер подписывает `parts.uri.path()`.
        // Тела у рукопожатия нет: подписывается хеш пустого тела.
        aegis_net::auth::signature_headers(
            &DeviceSigner::new(&identity, now),
            "GET",
            &format!("/v1/ws/{device_id}"),
            b"",
        )
    }

    /// Удаляет истёкшие сообщения.
    ///
    /// 🔐 Вызывается сразу после открытия хранилища: таймер в
    /// приложении работает, только пока оно запущено, и сообщение,
    /// полученное перед долгим перерывом, пережило бы свой срок.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn purge_expired(&self, now: Timestamp) -> Result<usize> {
        self.storage.purge_expired(now)
    }

    /// Задаёт таймер исчезающих сообщений для чата.
    ///
    /// `None` выключает таймер. Уже сохранённые сообщения сохраняют
    /// свой срок: смена таймера не должна задним числом продлевать
    /// или сокращать жизнь тому, что уже получено.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_disappearing_timer(&self, chat_id: &ChatId, seconds: Option<u32>) -> Result<()> {
        self.storage.set_disappearing_timer(chat_id, seconds)
    }
    /// Пробует расшифровать конверт всеми известными сессиями.
    ///
    /// Возвращает результат вместе с чатом, если он уже известен.
    /// Для конверта инициации чат выводится из identity отправителя,
    /// для сообщения в установленной сессии — это тот чат, чья сессия
    /// подошла: сам конверт отправителя не называет, и это намеренно —
    /// иначе сервер узнавал бы, кто кому пишет.
    fn try_decrypt(
        &self,
        identity: &IdentityKeyPair,
        secrets: &PreKeySecrets,
        raw: &[u8],
        now: Timestamp,
    ) -> Option<(session::IncomingMessage, Option<ChatId>)> {
        // Сначала как конверт инициации: он самодостаточен и не требует
        // угадывать сессию.
        if let Ok(incoming) = session::receive(identity, secrets, None, raw, now) {
            return Some((incoming, None));
        }

        // Иначе перебираем существующие сессии.
        //
        // Именно сессии, а не чаты интерфейса: сессия появляется раньше
        // чата. Первым сообщением новой сессии приходит ключ доступа
        // sealed sender, и чата он не создаёт — перебор по списку чатов
        // такую сессию не находил, и следующее за ключом сообщение
        // молча терялось.
        let chats = self.storage.session_chat_ids(MAX_CHATS_TO_PROBE).ok()?;

        for chat_id in chats {
            let Ok(Some(state)) = self.storage.load_session(&chat_id) else {
                continue;
            };

            if let Ok(incoming) = session::receive(identity, secrets, Some(&state), raw, now) {
                return Some((incoming, Some(chat_id)));
            }
        }

        None
    }

    /// Загружает identity-пару и секреты предключей.
    /// Ключ — наш собственный identity-ключ.
    fn is_own_identity(&self, key: &PublicKeyBytes) -> Result<bool> {
        let (identity, _) = self.load_identity()?;

        Ok(identity.public().public().as_bytes() == key.as_bytes())
    }

    fn load_identity(&self) -> Result<(IdentityKeyPair, PreKeySecrets)> {
        let keys = self
            .storage
            .load_own_keys()?
            // Отсутствие ключей означает, что регистрация не проходила.
            // Это не сбой, но и продолжать нечем.
            .ok_or(AegisError::SessionNotFound)?;

        let private: [u8; 32] = keys
            .identity_private
            .as_slice()
            .try_into()
            .map_err(|_| AegisError::Storage)?;

        // Публичная часть выводится из приватной, а не читается из базы:
        // так расхождение между ними невозможно в принципе. Пара, где
        // публичный ключ не соответствует приватному, давала бы
        // необъяснимые отказы расшифровки.
        let private_key = aegis_protocol::x25519::X25519PrivateKey::from_bytes(
            aegis_types::PrivateKeyBytes::new(private),
        )?;
        let identity = IdentityKeyPair::new(
            IdentityKey::new(private_key.public_key().as_bytes()),
            aegis_types::Secret::new(private),
        );
        let secrets = PreKeySecrets::from_bytes(&keys.prekey_secrets)?;

        Ok((identity, secrets))
    }

    /// Перезаписывает секреты предключей после расходования.
    fn persist_secrets(&self, secrets: &PreKeySecrets, now: Timestamp) -> Result<()> {
        let keys = self
            .storage
            .load_own_keys()?
            .ok_or(AegisError::SessionNotFound)?;

        self.storage.save_own_keys(
            &keys.identity_private,
            &keys.identity_public,
            &secrets.to_bytes()?,
            keys.device_id.as_deref(),
            keys.username.as_deref(),
            now,
        )?;

        // Записи о принятых конвертах живут, пока жив принявший их
        // подписанный предключ (см. `Storage::forget_initials_except`).
        // Здесь — единственное место, где набор предключей меняется
        // на диске, поэтому и чистка здесь.
        let live: Vec<Vec<u8>> = core::iter::once(&secrets.signed_pre_key)
            .chain(
                secrets
                    .retired_signed
                    .iter()
                    .map(|retired| &retired.signed_pre_key),
            )
            .map(|key| key.public_key().as_bytes().as_bytes().to_vec())
            .collect();

        self.storage.forget_initials_except(&live)?;

        Ok(())
    }

    /// Написано ли сообщение собеседником этого чата.
    ///
    /// # 🔐 Зачем
    ///
    /// Правка и удаление приходят от собеседника и называют сообщение
    /// идентификатором. Прежде они применялись к любому найденному:
    /// пока идентификаторы у сторон не совпадали, это было незаметно,
    /// но с общими идентификаторами собеседник правил бы и удалял
    /// **наши** сообщения у нас — он знает их идентификаторы, потому что
    /// их получал, — а зная идентификатор из другого чата, трогал бы
    /// и чужую переписку. Здесь допускается только его собственное
    /// сообщение и только в чате с ним.
    ///
    /// Входящие сообщения помечены идентификатором чата вместо
    /// отправителя (см. `store_message`), поэтому «его» — это «в этом
    /// чате и не наше».
    fn written_by_peer(&self, message: &MessageId, chat_id: &ChatId) -> Result<bool> {
        let Some((chat, sender)) = self.storage.message_origin(message)? else {
            return Ok(false);
        };

        let own = self.storage.get_account_id()?;

        Ok(chat == *chat_id && own.as_ref() != Some(&sender))
    }

    /// Сохраняет новое сообщение в хранилище.
    ///
    /// Возвращает `false`, если идентификатор уже занят: существующее
    /// сообщение не заменяется (см. [`Storage::insert_message`]). Для
    /// своих сообщений это невозможно на практике — идентификатор
    /// только что создан случайно; для входящих — повтор или подделка.
    fn store_message(
        &self,
        chat_id: &ChatId,
        message_id: MessageId,
        text: &str,
        now: Timestamp,
        outgoing: bool,
        status: MessageStatus,
    ) -> Result<bool> {
        let sender = if outgoing {
            self.storage
                .get_account_id()?
                .ok_or(AegisError::SessionNotFound)?
        } else {
            // Входящие помечаются идентификатором чата: аккаунт
            // отправителя из конверта не выводится, а выдумывать его
            // означало бы записать в базу неправду.
            AccountId::from_uuid(*chat_id.as_uuid())
        };

        self.storage.insert_message(&StoredMessage {
            id: message_id,
            chat_id: *chat_id,
            sender_id: sender,
            timestamp: now,
            content: aegis_types::Ciphertext::new(text.as_bytes().to_vec()),
            status,
            message_type: 0,

            // 🔐 Срок берётся из таймера чата в момент сохранения.
            //
            // Не при чтении: смена таймера не должна задним числом
            // продлевать жизнь уже полученным сообщениям — иначе
            // выключение таймера воскресило бы то, что пользователь
            // считал обречённым на исчезновение.
            expires_at: self.storage.expiry_for_chat(chat_id, now)?,
        })
    }

    // --- Резервное копирование и File Vault (M6) ---

    /// Делает резервную копию.
    ///
    /// 🔐 `recovery_key` используется и забывается: клиент его
    /// не сохраняет (раздел 12.3).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение или запись базы не удались;
    /// [`AegisError::Crypto`] — сбой вывода ключей или шифрования.
    pub fn create_backup<R: RngCore + CryptoRng>(
        &self,
        recovery_key: &RecoveryKey,
        device_label: Option<&str>,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<BackupOutcome> {
        BackupService::new(&self.storage).create(recovery_key, device_label, now, rng)
    }

    /// Восстанавливает данные из цепочки копий.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — цепочка разорвана либо собрана
    /// не в том порядке;
    /// [`AegisError::Crypto`] — не тот recovery key;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn restore_backup(
        &self,
        recovery_key: &RecoveryKey,
        links: &[Vec<u8>],
        now: Timestamp,
    ) -> Result<RestoreOutcome> {
        BackupService::new(&self.storage).restore(recovery_key, links, now)
    }

    /// Читает метаданные копии, не расшифровывая тело.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — файл не разбирается;
    /// [`AegisError::Crypto`] — не тот recovery key.
    pub fn inspect_backup(
        recovery_key: &RecoveryKey,
        archive: &[u8],
    ) -> Result<aegis_backup::ArchiveMeta> {
        BackupService::inspect(recovery_key, archive)
    }

    /// Когда делалась последняя копия.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn last_backup_at(&self) -> Result<Option<Timestamp>> {
        BackupService::new(&self.storage).last_backup_at()
    }

    /// Настроено ли резервное копирование.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn backup_configured(&self) -> Result<bool> {
        BackupService::new(&self.storage).is_configured()
    }

    /// Забывает цепочку копий — при смене recovery key.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn forget_backup_chain(&self) -> Result<()> {
        BackupService::new(&self.storage).forget_chain()
    }

    /// Уплотняет базу, если пришёл срок.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — уплотнение не удалось.
    pub fn maintain_storage(&self, now: Timestamp) -> Result<bool> {
        BackupService::new(&self.storage).maintain(now)
    }

    /// Читает последние события журнала безопасности.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn security_events(&self, limit: u32) -> Result<Vec<(String, String, Timestamp)>> {
        self.storage.recent_security_events(limit)
    }

    /// Открывает File Vault после повторной аутентификации.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — PIN или соль не той формы;
    /// [`AegisError::Crypto`] — сбой вывода ключей.
    pub fn unlock_vault(&self, pin: &str, salt: &[u8], now: Timestamp) -> Result<()> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Vault::new(&self.storage, &mut keeper).unlock(pin, salt, now)
    }

    /// Заводит проверочное значение vault по заведомо верному PIN —
    /// тому, которым только что открылась база (см.
    /// [`Vault::establish_verifier`]).
    ///
    /// # Errors
    ///
    /// [`AegisError::Crypto`] — сбой вывода ключа;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn establish_vault_verifier<R: RngCore + CryptoRng>(
        &self,
        pin: &str,
        salt: &[u8],
        rng: &mut R,
    ) -> Result<()> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Vault::new(&self.storage, &mut keeper).establish_verifier(pin, salt, rng)
    }

    /// Закрывает vault и обнуляет его ключ.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — состояние vault недоступно.
    pub fn seal_vault(&self) -> Result<()> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;
        keeper.seal();

        Ok(())
    }

    /// 🔐 Реакция на уход приложения в фон: vault закрывается.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — состояние vault недоступно.
    pub fn on_background(&self) -> Result<()> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;
        keeper.on_background();

        Ok(())
    }

    /// Открыт ли vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — состояние vault недоступно.
    pub fn vault_is_open(&self, now: Timestamp) -> Result<bool> {
        let keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Ok(keeper.is_open(now))
    }

    /// Сколько файлов лежит в vault.
    ///
    /// Доступно и при закрытом vault: число файлов не выдаёт, какие
    /// они (см. `Vault::file_count`).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn vault_file_count(&self) -> Result<u32> {
        self.storage.vault_file_count()
    }

    /// Перечисляет файлы vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn vault_files(&self, limit: u32, now: Timestamp) -> Result<Vec<VaultFileRow>> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Vault::new(&self.storage, &mut keeper).files(limit, now)
    }

    /// Кладёт файл в vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::Crypto`] — сбой шифрования;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn add_vault_file<R: RngCore + CryptoRng>(
        &self,
        name: &str,
        plaintext: &[u8],
        location: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<SealedVaultFile> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Vault::new(&self.storage, &mut keeper).add_file(name, plaintext, location, now, rng)
    }

    /// Достаёт файл из vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::SessionNotFound`] — записи о файле нет;
    /// [`AegisError::Crypto`] — блоб подменён либо ключ не подходит.
    pub fn open_vault_file(
        &self,
        file_id: &MessageId,
        ciphertext: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Vault::new(&self.storage, &mut keeper).open_file(file_id, ciphertext, now)
    }

    /// Убирает файл из vault, возвращая путь к его блобу.
    ///
    /// # Errors
    ///
    /// [`AegisError::Locked`] — vault закрыт;
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn delete_vault_file(&self, file_id: &MessageId, now: Timestamp) -> Result<Option<String>> {
        let mut keeper = self.vault.lock().map_err(|_| AegisError::Storage)?;

        Vault::new(&self.storage, &mut keeper).delete_file(file_id, now)
    }
}

/// Сколько чатов перебирается при поиске подходящей сессии.
const MAX_CHATS_TO_PROBE: u32 = 256;

/// Предел размера вложения в байтах.
///
/// Совпадает с пределом `aegis-media` и с ограничением серверной
/// схемы: расхождение означало бы отказ уже после того, как
/// стомегабайтный файл ушёл по сети.
const MAX_ATTACHMENT_BYTES: u64 = 100 * 1024 * 1024;

/// Сколько байт занимает зашифрованный файл заданного размера.
///
/// Каждый полный чанк даёт `CHUNK_SIZE + TAG_LEN`; остаток — свою
/// длину плюс тег. Пустой файл вложением не отправляется, поэтому
/// нулевой размер сюда не приходит.
fn expected_payload_len(size: u64) -> Result<usize> {
    // Шифруется дополненный до сетки Padmé файл (см. `upload_attachment`).
    let size = attachment::padded_len(usize::try_from(size).map_err(|_| AegisError::Malformed)?)?;
    let chunks = attachment::chunk_count(size)?;
    let chunks = usize::try_from(chunks).map_err(|_| AegisError::Malformed)?;

    let tags = chunks
        .checked_mul(attachment::TAG_LEN)
        .ok_or(AegisError::Malformed)?;

    size.checked_add(tags).ok_or(AegisError::Malformed)
}

/// Сколько контактов отдаётся списку.
///
/// Тот же предел, что и у чатов: список на экране пролистывают, а не
/// читают целиком, и выгружать в память больше нечего.
const MAX_CONTACTS_TO_LIST: u32 = 256;

/// Выводит идентификатор аккаунта из identity-ключа контакта.
/// Safety number двух identity-ключей.
///
/// Вынесено отдельно, чтобы тест мог сравнить результат обеих
/// сторон, не поднимая двух клиентов.
///
/// 🔐 Идентификатор каждого участника выводится из **его** ключа
/// (см. [`Client::safety_number`]): только так обе стороны берут
/// для него одно и то же.
#[must_use]
pub fn safety_number_of(own: &PublicKeyBytes, peer: &PublicKeyBytes) -> String {
    let own_print = Fingerprint::compute(own, peer_account(own).as_bytes());
    let peer_print = Fingerprint::compute(peer, peer_account(peer).as_bytes());

    SafetyNumber::new(&own_print, &peer_print).to_display_block()
}

fn peer_account(identity: &PublicKeyBytes) -> AccountId {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(identity.as_bytes().get(..16).unwrap_or(&[0u8; 16]));

    AccountId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

/// Собирает запрос на публикацию предключей.
fn publish_request(bundle: &PreKeyBundle) -> PublishKeysRequest {
    PublishKeysRequest {
        pq_identity_key: None,
        identity_binding: None,
        signed_key_id: i32::try_from(bundle.signed_pre_key.id.as_u32()).unwrap_or(i32::MAX),
        signed_public: hex(bundle.signed_pre_key.public.as_bytes()),
        signed_signature: hex(&bundle.signed_pre_key.signature),
        kem_key_id: i32::try_from(bundle.signed_kem_pre_key.id.as_u32()).unwrap_or(i32::MAX),
        kem_public: hex(bundle.signed_kem_pre_key.public.as_bytes()),
        kem_signature: hex(&bundle.signed_kem_pre_key.signature),
        one_time: bundle
            .one_time_pre_key
            .iter()
            .map(|(id, key)| {
                (
                    i32::try_from(id.as_u32()).unwrap_or(i32::MAX),
                    hex(key.as_bytes()),
                )
            })
            .collect(),
        // 🔐 Подпись уходит настоящая, а не пустая строка.
        //
        // Прежде здесь стояло `String::new()`: сервер сохранял
        // одноразовый пост-квантовый предключ без подписи, и
        // проверить его подлинность было нечем в принципе.
        one_time_kem: bundle
            .one_time_kem_pre_key
            .iter()
            .map(|key| {
                (
                    i32::try_from(key.id.as_u32()).unwrap_or(i32::MAX),
                    hex(key.public.as_bytes()),
                    hex(&key.signature),
                )
            })
            .collect(),
        // Ключ sealed sender дописывает вызывающий: для него нужен
        // identity-ключ, а не только набор предключей.
        sealed_kem_public: None,
        sealed_kem_signature: None,
    }
}

/// 🔐 Ключ ML-KEM sealed sender получателя из ответа discovery — только
/// с верной подписью его identity-ключа.
///
/// Ключ раздаёт сервер. Без проверки подписи он подставил бы свой,
/// и пост-квантовая половина внешнего слоя была бы у него.
///
/// Ключа нет — отказ, а не запечатывание одной кривой: откат на X25519
/// вернул бы уязвимость «записать сейчас, раскрыть отправителя потом»,
/// и навязать его мог бы сервер, просто не отдав ключ.
///
/// # Errors
///
/// [`AegisError::Uninitialized`] — получатель ещё не опубликовал ключ
/// (его приложение не обновилось); [`AegisError::Crypto`] — подпись
/// не сходится или ключ не разбирается.
fn verified_sealed_kem(
    peer: &aegis_net::api::DiscoveryResponse,
    peer_identity: &PublicKeyBytes,
    peer_pq: &[u8],
) -> Result<Vec<u8>> {
    let (Some(public), Some(signature)) = (&peer.sealed_kem_public, &peer.sealed_kem_signature)
    else {
        return Err(AegisError::Uninitialized);
    };

    let public = unhex(public)?;
    let signature = unhex(signature)?;

    aegis_protocol::sealed_sender::verify_sealed_kem_key(
        peer_identity,
        peer_pq,
        &public,
        &signature,
    )?;

    Ok(public)
}

/// Разбирает bundle, пришедший с сервера.
fn parse_bundle(response: &BundleResponse) -> Result<PreKeyBundle> {
    let device_id = parse_uuid(&response.device_id).map(DeviceId::from_uuid)?;

    Ok(PreKeyBundle {
        device_id,
        identity_key: IdentityKey::new(parse_public_key(&response.identity_key)?),
        // 🔐 Без пост-квантовой половины bundle не принимается:
        // гибридные подписи проверить нечем, а откат на одну
        // классическую мог бы навязать сервер.
        pq_identity: unhex(
            response
                .pq_identity_key
                .as_ref()
                .ok_or(AegisError::Uninitialized)?,
        )?,
        identity_binding: unhex(
            response
                .identity_binding
                .as_ref()
                .ok_or(AegisError::Uninitialized)?,
        )?,
        signed_pre_key: SignedPreKey {
            id: PreKeyId::new(response.signed_key_id.unsigned_abs()),
            public: parse_public_key(&response.signed_public)?,
            signature: unhex(&response.signed_signature)?,
        },
        one_time_pre_key: response
            .one_time
            .as_ref()
            .map(|(id, key)| {
                Ok::<_, AegisError>((PreKeyId::new(id.unsigned_abs()), parse_public_key(key)?))
            })
            .transpose()?,
        signed_kem_pre_key: SignedKemPreKey {
            id: PreKeyId::new(response.kem_key_id.unsigned_abs()),
            public: KemPublicKey::new(unhex(&response.kem_public)?),
            signature: unhex(&response.kem_signature)?,
        },
        // 🔐 Подпись одноразового пост-квантового предключа больше
        // не отбрасывается. Прежде здесь стояло `|(id, key, _)|`,
        // и третий элемент — подпись — исчезал ровно тут: сервер
        // её присылал, сетевой слой разбирал, а дальше её не было.
        one_time_kem_pre_key: response
            .one_time_kem
            .as_ref()
            .map(|(id, key, signature)| {
                Ok::<_, AegisError>(SignedKemPreKey {
                    id: PreKeyId::new(id.unsigned_abs()),
                    public: KemPublicKey::new(unhex(key)?),
                    signature: unhex(signature)?,
                })
            })
            .transpose()?,
    })
}

/// Кодирует байты в hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        // Запись в String не может дать ошибку, но результат
        // игнорируется явно: `unwrap` запрещён линтами.
        let _ = write!(out, "{byte:02x}");

        out
    })
}

/// Разбирает hex-строку.
pub(crate) fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(AegisError::Malformed);
    }

    (0..text.len())
        .step_by(2)
        .map(|index| {
            let end = index.checked_add(2).ok_or(AegisError::Malformed)?;
            let pair = text.get(index..end).ok_or(AegisError::Malformed)?;

            u8::from_str_radix(pair, 16).map_err(|_| AegisError::Malformed)
        })
        .collect()
}

/// Разбирает публичный ключ из hex.
fn parse_public_key(text: &str) -> Result<PublicKeyBytes> {
    let bytes: [u8; 32] = unhex(text)?
        .as_slice()
        .try_into()
        .map_err(|_| AegisError::Malformed)?;

    Ok(PublicKeyBytes::new(bytes))
}

/// Разбирает UUID из строки.
fn parse_uuid(text: &str) -> Result<uuid::Uuid> {
    uuid::Uuid::parse_str(text).map_err(|_| AegisError::Malformed)
}

/// Подписывает запросы ключом устройства.
///
/// Что подписывается — метод, путь, время выпуска и SHA-256 тела —
/// собирает сетевой слой из того, что уходит в сеть
/// (`aegis_net::auth::RequestSigner`); здесь только подпись.
///
/// 🔐 Прежде ядро собирало подписываемое сообщение само: без тела —
/// подпись `PUT` предключей подходила к любым предключам, — и с путём,
/// который отдельно собирал ещё и сетевой клиент. Теперь подписано
/// ровно отправленное.
pub(crate) struct DeviceSigner<'a> {
    identity: &'a IdentityKeyPair,
    now: Timestamp,
}

impl<'a> DeviceSigner<'a> {
    pub(crate) const fn new(identity: &'a IdentityKeyPair, now: Timestamp) -> Self {
        Self { identity, now }
    }
}

impl aegis_net::auth::RequestSigner for DeviceSigner<'_> {
    fn issued_at(&self) -> i64 {
        self.now.as_millis()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let private = aegis_types::PrivateKeyBytes::new(*self.identity.private().expose_secret());

        Ok(aegis_protocol::xeddsa::montgomery::sign(&private, message)?.to_vec())
    }
}
