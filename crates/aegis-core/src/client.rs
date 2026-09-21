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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use aegis_backup::RecoveryKey;
use aegis_media::attachment::{self, AttachmentKey};
use aegis_media::descriptor::{AttachmentDescriptor, AttachmentKind};
use aegis_net::api::{BundleResponse, PublishKeysRequest, RegisterRequest};
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

mod network;
mod sealed;

use aegis_types::{
    AccountId, AegisError, ChatId, DeviceId, MessageId, Plaintext, PublicKeyBytes, Result,
    Timestamp,
};
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
}

impl<T: Transport> Client<T> {
    /// Создаёт клиент поверх транспорта и открытого хранилища.
    pub fn new(transport: T, storage: Storage) -> Self {
        Self {
            api: ApiClient::new(transport),
            storage,
            // Vault всегда начинается закрытым: открыть его может
            // только повторная аутентификация.
            vault: Mutex::new(VaultGuard::new(Timestamp::from_millis(0))),
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
        let identity = prekeys::generate_identity(rng)?;
        let device_id = DeviceId::generate();
        let (bundle, secrets) = prekeys::generate(&identity, device_id, now, rng)?;

        // Челлендж выбирает клиент: сервер проверяет только сложность,
        // а состояние про выданные челленджи не хранит — иначе
        // регистрация стала бы мишенью для DoS.
        let mut challenge = [0u8; pow::CHALLENGE_LEN];
        rng.fill_bytes(&mut challenge);

        let nonce = pow::solve(&challenge, POW_DIFFICULTY).ok_or(AegisError::Crypto)?;

        let identity_hex = hex(identity.public().public().as_bytes());
        let response = self.api.register(&RegisterRequest {
            username: username.to_owned(),
            identity_key: identity_hex.clone(),
            device_identity_key: identity_hex,
            pow_challenge: hex(&challenge),
            pow_nonce: nonce,
        })?;

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

        self.api.publish_keys(
            &server_device_id.to_string(),
            &publish_request(&bundle),
            auth_headers(
                &identity,
                "PUT",
                &format!("/v1/keys/{server_device_id}"),
                now,
            )?,
        )?;

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
        // Секреты предключей при отправке не нужны: они участвуют
        // только в приёме, когда нам присылают конверт инициации.
        let (identity, _) = self.load_identity()?;

        let peer = self.api.discover(peer_username)?;
        let peer_identity = parse_public_key(&peer.identity_key)?;

        let chat_id = derive_chat_id(identity.public().public(), &peer_identity);
        // Тело сообщения — структурированное содержимое, а не голый
        // текст: получатель обязан отличить текст от реакции и правки,
        // и это различие лежит под шифрованием.
        let plaintext = Plaintext::new(
            Content::Text {
                body: text.to_owned(),
                reply_to: None,
            }
            .to_bytes()?,
        );

        // Существующая сессия продолжается; иначе устанавливается новая.
        // Проверка идёт по хранилищу, а не по наличию контакта: сессия
        // может отсутствовать и у знакомого контакта — например, после
        // восстановления из резервной копии.
        let existing = self.storage.load_session(&chat_id)?;

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
                now,
                rng,
            )?,
        };

        let outgoing = session::continue_session(&session, &plaintext)?;

        // Сессия сохраняется до отправки: см. порядок операций.
        self.storage
            .save_session(&chat_id, &outgoing.session, now)?;

        let message_id = MessageId::generate();
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
            &outgoing.envelope,
            now,
            rng,
        )?;

        self.storage
            .set_message_status(&message_id, MessageStatus::Sent, now)?;
        self.storage.touch_chat(&chat_id, Some(&message_id), now)?;

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
        if !self.storage.presence_sharing_enabled()? {
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
        if !self.storage.presence_sharing_enabled()? {
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
        let (identity, _) = self.load_identity()?;

        let peer = self.api.discover(peer_username)?;
        let peer_identity = parse_public_key(&peer.identity_key)?;
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

        let session = match existing {
            Some(state) if self.storage.access_key_shared_with(&peer)? => state,
            other => self.send_own_access_key(
                &identity,
                &chat_id,
                other,
                &peer_identity,
                &peer_device,
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
        let envelopes = self.api.fetch_envelopes(
            device_id,
            auth_headers(&identity, "GET", &format!("/v1/messages/{device_id}"), now)?,
        )?;

        let mut accepted = 0usize;

        for envelope in envelopes {
            let Ok(wire) = unhex(&envelope.ciphertext) else {
                continue;
            };

            // 🔐 Запечатанный конверт сначала разворачивается (см. модуль
            // `sealed`); неразворачиваемый пропускается так же, как
            // нерасшифровываемый обычный.
            let Some((raw, certificate)) =
                self.unwrap_wire(&identity, wire, envelope.queued_at_bucketed, now)
            else {
                continue;
            };

            // Сессию ищем по всем известным чатам: конверт сообщения
            // не несёт идентификатора отправителя — это и есть защита
            // метаданных, за которую платится перебором сессий.
            let Some((incoming, known_chat)) = self.try_decrypt(&identity, &secrets, &raw, now)
            else {
                continue;
            };

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
                (None, None) => continue,
            };

            // Собеседник этого конверта: из конверта инициации либо
            // из проверенного и привязанного сертификата.
            let sender = incoming.sender_identity.or_else(|| {
                certificate
                    .as_ref()
                    .map(|certificate| certificate.identity_key)
            });

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

            // Разбор содержимого. Сообщение от собеседника с новой
            // версией клиента отвергается целиком, а не сохраняется
            // пустым: пользователь должен видеть, что что-то пришло
            // и не прочиталось, а не считать, что ему прислали пустоту.
            let Ok(content) = Content::from_bytes(incoming.plaintext.expose()) else {
                continue;
            };

            // Служебное содержимое не считается принятым сообщением:
            // число уходит в интерфейс, и «1 новое сообщение» без
            // сообщения выглядело бы как потерянное.
            let counts = !matches!(content, Content::AccessKey { .. });

            match content {
                Content::Text { body, .. } => {
                    let message_id = MessageId::generate();
                    self.store_message(
                        &chat_id,
                        message_id,
                        &body,
                        now,
                        false,
                        MessageStatus::Delivered,
                    )?;
                    self.storage.touch_chat(&chat_id, Some(&message_id), now)?;
                }

                Content::Attachments {
                    body, descriptors, ..
                } => {
                    let message_id = MessageId::generate();
                    self.store_message(
                        &chat_id,
                        message_id,
                        &body,
                        now,
                        false,
                        MessageStatus::Delivered,
                    )?;

                    // 🔐 Описания сохраняются вместе с сообщением.
                    // Без них вложение недоступно: адрес файла
                    // на сервере и ключ к нему есть только здесь,
                    // а второй раз сообщение не придёт.
                    self.store_descriptors(&message_id, &descriptors, now)?;

                    self.storage.touch_chat(&chat_id, Some(&message_id), now)?;
                }

                Content::Edit { target, body } => {
                    // Правка применяется к существующему сообщению.
                    // Если его нет — собеседник правит то, чего мы
                    // не получали; создавать сообщение задним числом
                    // нельзя, оно появилось бы без контекста.
                    self.storage.edit_message(
                        &MessageId::from_uuid(uuid::Uuid::from_bytes(target)),
                        &body,
                        now,
                    )?;
                }

                Content::Delete { target } => {
                    // 🔐 Удаление выполняется без подтверждения:
                    // отправитель просит убрать своё сообщение,
                    // и отказ означал бы, что «удалить у всех»
                    // не работает.
                    self.storage.delete_message(
                        &MessageId::from_uuid(uuid::Uuid::from_bytes(target)),
                        now,
                    )?;
                }

                Content::AccessKey { key } => {
                    // 🔐 Ключ сохраняется только за собеседником,
                    // установленным криптографически: identity из PQXDH
                    // либо из привязанного сертификата. Сообщение
                    // в сессии без сертификата собеседника не называет,
                    // и сохранить ключ «за кем-то» значило бы угадывать.
                    if let Some(peer) = sender {
                        self.storage
                            .save_contact_access_key(&peer_account(&peer), &key, now)?;
                    }
                }

                Content::Reaction { .. } | Content::Typing { .. } | Content::ReadReceipt { .. } => {
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

            self.api.acknowledge(
                device_id,
                &envelope.envelope_id,
                auth_headers(
                    &identity,
                    "DELETE",
                    &format!("/v1/messages/{device_id}/{}", envelope.envelope_id),
                    now,
                )?,
            )?;
            if counts {
                accepted = accepted.saturating_add(1);
            }
        }

        self.persist_secrets(&secrets, now)?;

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
    /// с другим ключом;
    /// [`AegisError::Network`] — проверка имени не удалась;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn add_contact_from_link(&self, uri: &str, now: Timestamp) -> Result<Contact> {
        let link = ContactLink::parse(uri)?;

        let (account_id, username) = match &link.display_name {
            // Без имени спрашивать сервер не о чем: идентификатор
            // выводится из самого ключа тем же способом, что и для
            // входящих сообщений, — иначе один контакт получил бы
            // две записи в базе.
            None => (peer_account(&link.identity), None),

            Some(name) => {
                let peer = self.api.discover(name)?;
                let advertised = parse_public_key(&peer.identity_key)?;

                // 🔐 Ключ со ссылки — единственное, чему здесь есть
                // доверие. Расхождение означает, что либо ссылку
                // подделали, либо сервер называет чужой ключ; в обоих
                // случаях добавлять нечего.
                if advertised.as_bytes() != link.identity.as_bytes() {
                    return Err(AegisError::Malformed);
                }

                (
                    AccountId::from_uuid(parse_uuid(&peer.account_id)?),
                    Some(name.clone()),
                )
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

        Ok(Contact {
            account_id,
            identity: link.identity,
            username,
            chat_id: Some(chat_id),
            verified: false,
            key_changed,
        })
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

        let chat_id = self.send_content(
            peer_username,
            &Content::Attachments {
                body: body.to_owned(),
                descriptors: vec![encoded.clone()],
                reply_to: None,
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
        let message_id = MessageId::generate();
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
        let size = u64::try_from(file.bytes.len()).map_err(|_| AegisError::Malformed)?;

        if size > MAX_ATTACHMENT_BYTES {
            return Err(AegisError::Malformed);
        }

        let key = AttachmentKey::generate(rng);

        // Чанки склеиваются в один блоб: сервер хранит его целиком,
        // а получатель режет обратно по известному размеру чанка.
        // Отдельная загрузка каждого чанка означала бы тысячу запросов
        // на стомегабайтный файл.
        let mut payload = Vec::new();

        for (index, chunk) in file.bytes.chunks(attachment::CHUNK_SIZE).enumerate() {
            let index = u32::try_from(index).map_err(|_| AegisError::Malformed)?;

            payload.extend_from_slice(&attachment::seal_chunk(&key, index, chunk)?);
        }

        let (identity, _) = self.load_identity()?;
        let location = self.api.upload_attachment(
            device_id,
            payload,
            auth_headers(
                &identity,
                "POST",
                &format!("/v1/attachments/{device_id}"),
                now,
            )?,
        )?;

        let descriptor = AttachmentDescriptor {
            kind: file.kind,
            location,
            key: *key.expose(),
            size,
            name: file.name.clone(),
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

        let (identity, _) = self.load_identity()?;
        let path = format!("/v1/attachments/{device_id}/{}", descriptor.location);

        let payload = self.api.download_attachment(
            device_id,
            &descriptor.location,
            auth_headers(&identity, "GET", &path, now)?,
        )?;

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

        Ok(safety_number_of(&own, &peer))
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

        for row in &rows {
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
                let key_changed = row
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
    /// Пул конечен ([`ONE_TIME_PRE_KEY_POOL_SIZE`] = 100), публикуется
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
    /// Подписанный предключ живёт [`SIGNED_PRE_KEY_ROTATION_DAYS`]
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

        let rotated = secrets.needs_rotation(now);

        if rotated {
            prekeys::rotate_signed(&identity, &mut secrets, now, rng)?;
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
            .count_one_time_prekeys(
                &device_id,
                auth_headers(
                    &identity,
                    "GET",
                    &format!("/v1/keys/{device_id}/count"),
                    now,
                )?,
            )
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
            prekeys::mint_one_time(&identity, &mut secrets, deficit, rng)?
        } else {
            (Vec::new(), Vec::new())
        };

        let added = u32::try_from(added_one_time.len()).unwrap_or(u32::MAX);

        // Делать нечего — и сети это знать незачем.
        if !rotated && added == 0 {
            return Ok(PreKeyMaintenance {
                rotated_signed: false,
                added_one_time: 0,
                remaining_one_time: u32::try_from(on_server).unwrap_or(u32::MAX),
            });
        }

        let (signed_pre_key, signed_kem_pre_key) = prekeys::signed_published(&identity, &secrets)?;

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
        };

        // ⚠️ Публикация до сохранения.
        //
        // Порядок обязателен: сохранив секреты первыми и не дойдя
        // до сервера, клиент считал бы пул пополненным, а сервер
        // продолжал бы выдавать пустые bundle. Пул чинился бы
        // только с виду — то есть не чинился бы вовсе.
        self.api.publish_keys(
            &device_id,
            &request,
            auth_headers(&identity, "PUT", &format!("/v1/keys/{device_id}"), now)?,
        )?;

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

        let auth = auth_headers(
            &identity,
            "DELETE",
            &format!("/v1/accounts/{device_id}"),
            now,
        )?;

        let response = self.api.delete_account(&device_id, auth)?;

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
        auth_headers(&identity, "GET", &format!("/v1/ws/{device_id}"), now)
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
        )
    }

    /// Сохраняет сообщение в хранилище.
    fn store_message(
        &self,
        chat_id: &ChatId,
        message_id: MessageId,
        text: &str,
        now: Timestamp,
        outgoing: bool,
        status: MessageStatus,
    ) -> Result<()> {
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

        self.storage.save_message(&StoredMessage {
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
    let size = usize::try_from(size).map_err(|_| AegisError::Malformed)?;
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
    }
}

/// Разбирает bundle, пришедший с сервера.
fn parse_bundle(response: &BundleResponse) -> Result<PreKeyBundle> {
    let device_id = parse_uuid(&response.device_id).map(DeviceId::from_uuid)?;

    Ok(PreKeyBundle {
        device_id,
        identity_key: IdentityKey::new(parse_public_key(&response.identity_key)?),
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
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    bytes.iter().fold(String::new(), |mut out, byte| {
        // Запись в String не может дать ошибку, но результат
        // игнорируется явно: `unwrap` запрещён линтами.
        let _ = write!(out, "{byte:02x}");

        out
    })
}

/// Разбирает hex-строку.
fn unhex(text: &str) -> Result<Vec<u8>> {
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

/// Домен-разделитель подписи запроса.
///
/// Обязан совпадать с серверным (`aegis-server-api/authz`). Клиент
/// под Apache-2.0, сервер под AGPL-3.0, поэтому общей константы быть
/// не может — расхождение ловит тест на совместимость.
const AUTH_DOMAIN: &[u8] = b"AEGIS_AUTH_v1";

/// Собирает подписанные заголовки для запроса.
///
/// # Что подписывается
///
/// Метод, путь и время выпуска — то есть **конкретный запрос**.
/// Подпись под свободным челленджем годилась бы для любого действия:
/// перехватив её у чтения очереди, атакующий предъявил бы её при
/// подмене предключей.
///
/// # Errors
///
/// [`AegisError::Crypto`] — подпись не построилась.
fn auth_headers(
    identity: &IdentityKeyPair,
    method: &str,
    path: &str,
    now: Timestamp,
) -> Result<Vec<(String, String)>> {
    let issued_at = now.as_millis();

    let mut message = Vec::new();
    message.extend_from_slice(AUTH_DOMAIN);
    message.push(b'\n');
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(path.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(issued_at.to_string().as_bytes());

    let private = aegis_types::PrivateKeyBytes::new(*identity.private().expose_secret());
    let signature = aegis_protocol::xeddsa::montgomery::sign(&private, &message)?;

    Ok(vec![
        ("x-aegis-signature".to_owned(), hex(&signature)),
        ("x-aegis-issued-at".to_owned(), issued_at.to_string()),
    ])
}
