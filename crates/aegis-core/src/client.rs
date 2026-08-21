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

use aegis_net::api::{
    BundleResponse, PublishKeysRequest, RegisterRequest, SendRequest,
};
use aegis_net::client::{ApiClient, Transport};
use aegis_net::pow;
use aegis_protocol::keys::{
    IdentityKey, IdentityKeyPair, KemPublicKey, PreKeyBundle, PreKeyId, SignedKemPreKey,
    SignedPreKey,
};
use aegis_protocol::prekeys::{self, PreKeySecrets};
use aegis_storage::{MessageStatus, Storage, StoredMessage};
use aegis_types::{
    AccountId, AegisError, ChatId, DeviceId, MessageId, Plaintext, PublicKeyBytes, Result,
    Timestamp,
};
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

/// Клиент AEGIS.
pub struct Client<T: Transport> {
    api: ApiClient<T>,
    storage: Storage,
}

impl<T: Transport> Client<T> {
    /// Создаёт клиент поверх транспорта и открытого хранилища.
    pub const fn new(transport: T, storage: Storage) -> Self {
        Self {
            api: ApiClient::new(transport),
            storage,
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
            0,
            Some(username),
            now,
        )?;
        self.storage.set_account_id(&account_id, now)?;

        self.api
            .publish_keys(
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
        let plaintext = Plaintext::new(text.as_bytes().to_vec());

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

        let (outgoing, device_id) = if let Some(state) = existing {
            (
                session::continue_session(&state, &plaintext)?,
                peer_device,
            )
        } else {
            let bundle_response = self.api.fetch_bundle(&peer_device)?;
            let bundle = parse_bundle(&bundle_response)?;

            (
                session::start_session(&identity, &bundle, &plaintext, rng)?,
                peer_device,
            )
        };

        // Сессия сохраняется до отправки: см. порядок операций.
        self.storage.save_session(&chat_id, &outgoing.session, now)?;

        let message_id = MessageId::generate();
        self.store_message(&chat_id, message_id, text, now, true, MessageStatus::Pending)?;

        self.api.send_envelope(&SendRequest {
            destination_device_id: device_id,
            ciphertext: hex(&outgoing.envelope),
        })?;

        self.storage
            .set_message_status(&message_id, MessageStatus::Sent)?;
        self.storage.touch_chat(&chat_id, Some(&message_id), now)?;

        Ok(message_id)
    }

    /// Забирает и расшифровывает входящие сообщения.
    ///
    /// Возвращает число принятых сообщений. Конверты, которые не
    /// удалось расшифровать, пропускаются, а не прерывают приём:
    /// одно повреждённое сообщение не должно блокировать остальные.
    ///
    /// # Errors
    ///
    /// [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// [`AegisError::Network`] — сервер недоступен.
    pub fn receive_messages(&self, device_id: &str, now: Timestamp) -> Result<usize> {
        let (identity, mut secrets) = self.load_identity()?;
        let envelopes = self.api.fetch_envelopes(
            device_id,
            auth_headers(&identity, "GET", &format!("/v1/messages/{device_id}"), now)?,
        )?;

        let mut accepted = 0usize;

        for envelope in envelopes {
            let Ok(raw) = unhex(&envelope.ciphertext) else {
                continue;
            };

            // Сессию ищем по всем известным чатам: конверт сообщения
            // не несёт идентификатора отправителя — это и есть защита
            // метаданных, за которую платится перебором сессий.
            let Some((incoming, known_chat)) = self.try_decrypt(&identity, &secrets, &raw, now)
            else {
                continue;
            };

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

            if let Some(peer) = incoming.sender_identity {
                self.storage
                    .save_contact_identity(&peer_account(&peer), peer.as_bytes())?;
            }

            self.storage.save_session(&chat_id, &incoming.session, now)?;

            let text = String::from_utf8_lossy(incoming.plaintext.expose()).into_owned();
            let message_id = MessageId::generate();
            self.store_message(
                &chat_id,
                message_id,
                &text,
                now,
                false,
                MessageStatus::Delivered,
            )?;
            self.storage.touch_chat(&chat_id, Some(&message_id), now)?;

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
            accepted = accepted.saturating_add(1);
        }

        self.persist_secrets(&secrets, now)?;

        Ok(accepted)
    }

    /// Возвращает сообщения чата в порядке от старых к новым.
    ///
    /// # Errors
    ///
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

        // Иначе перебираем сессии известных чатов.
        let chats = self.storage.list_chats(MAX_CHATS_TO_PROBE).ok()?;

        for chat in chats {
            let Ok(Some(state)) = self.storage.load_session(&chat.chat_id) else {
                continue;
            };

            if let Ok(incoming) = session::receive(identity, secrets, Some(&state), raw, now) {
                return Some((incoming, Some(chat.chat_id)));
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
            keys.device_id,
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
        })
    }
}

/// Сколько чатов перебирается при поиске подходящей сессии.
const MAX_CHATS_TO_PROBE: u32 = 256;

/// Выводит идентификатор аккаунта из identity-ключа контакта.
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
            .map(|(id, key)| (i32::try_from(id.as_u32()).unwrap_or(i32::MAX), hex(key.as_bytes())))
            .collect(),
        one_time_kem: bundle
            .one_time_kem_pre_key
            .iter()
            .map(|(id, key)| (
                    i32::try_from(id.as_u32()).unwrap_or(i32::MAX),
                    hex(key.as_bytes()),
                    String::new(),
                ))
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
        one_time_kem_pre_key: response
            .one_time_kem
            .as_ref()
            .map(|(id, key, _)| {
                Ok::<_, AegisError>((
                    PreKeyId::new(id.unsigned_abs()),
                    KemPublicKey::new(unhex(key)?),
                ))
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
