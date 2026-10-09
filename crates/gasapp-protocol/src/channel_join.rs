// SPDX-License-Identifier: Apache-2.0

//! Закрытый канал: вход по заявке, которую одобряют.
//!
//! # Модель
//!
//! Ссылка открытого канала несёт секрет чтения: кто её получил, тот
//! читает. Ссылка закрытого канала (`gasapp://channel-join/…`) секрета
//! не несёт — только канал, ключ подписи владельца и метку приглашения.
//! Дальше три шага:
//!
//! 1. **Заявка.** Приложение заявителя создаёт одноразовую пару X25519
//!    и подписывает её открытую половину ключом своего аккаунта. Заявка
//!    уходит на сервер вместе с меткой из ссылки.
//! 2. **Одобрение.** Владелец либо администратор видит заявку, проверяет
//!    подпись и шифрует секрет чтения под ключ из заявки (свой
//!    одноразовый ключ, общий секрет, HKDF, AES-256-GCM).
//! 3. **Вход.** Заявитель забирает ответ, расшифровывает секрет и дальше
//!    читает канал как обычно — проверяя описание ключом владельца из
//!    ссылки.
//!
//! # 🔐 Что это даёт и чего НЕ даёт
//!
//! * Сервер секрета чтения не получает: заявка несёт открытый ключ,
//!   ответ — шифротекст под него.
//! * Подложный ответ бесполезен: с чужим секретом описание канала не
//!   расшифруется и не сойдётся с ключом владельца из ссылки.
//! * ⚠️ **Сервер может подменить заявку своей** — со своим одноразовым
//!   ключом и своим ключом аккаунта. Подпись в заявке защищает лишь
//!   тогда, когда одобряющий знает ключ аккаунта заявителя не от
//!   сервера: заявитель — его сверенный контакт. Иначе одобряющий
//!   доверяет серверу в том, чья это заявка.
//! * ⚠️ **Удалённый участник секрет помнит.** Сервер перестаёт отдавать
//!   ему записи, но секрет канала прежний. Смены ключа нет.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result};

use crate::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::channel::ChannelAdmin;
use crate::channel::{hex_value, parse_channel_id, push_hex, ChannelAccess, ChannelId, SECRET_LEN};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::xeddsa::{montgomery, SIGNATURE_LEN};
use crate::xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey};

/// Схема и путь ссылки-приглашения закрытого канала.
pub const JOIN_LINK_PREFIX: &str = "gasapp://channel-join/";

/// Длина метки приглашения.
pub const INVITE_LEN: usize = 16;

/// Длина заявки: версия, одноразовый ключ, ключ аккаунта, подпись.
pub const REQUEST_LEN: usize = 1 + 32 + 32 + SIGNATURE_LEN;

/// Длина ответа: версия, одноразовый ключ, nonce, номер эпохи и секрет
/// с тегом.
pub const GRANT_LEN: usize = 1 + 32 + NONCE_LEN + 4 + SECRET_LEN + TAG_LEN;

/// Длина звена цепочки ключей: версия, эпоха, ключ подписавшего, nonce,
/// подпись, прежний секрет с тегом.
pub const EPOCH_RECORD_LEN: usize = 1 + 4 + 32 + NONCE_LEN + SIGNATURE_LEN + SECRET_LEN + TAG_LEN;

const WIRE_VERSION: u8 = 1;

const REQUEST_DOMAIN: &[u8] = b"GASAPP_CHANNEL_v1_JOIN";
const GRANT_INFO: &[u8] = b"GASAPP_CHANNEL_v1_GRANT";
const GRANT_AAD: &[u8] = b"GASAPP_CHANNEL_v1_GRANT_AAD";
const DELIVERY_INFO: &[u8] = b"GASAPP_CHANNEL_v1_DELIVERY";
const EPOCH_INFO: &[u8] = b"GASAPP_CHANNEL_v1_EPOCH";
const EPOCH_DOMAIN: &[u8] = b"GASAPP_CHANNEL_v1_EPOCH_SIG";

/// Ссылка-приглашение закрытого канала. Секрета чтения в ней нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinLink {
    /// Канал.
    pub channel_id: ChannelId,
    /// Публичный ключ подписи владельца: им проверяется описание.
    pub verify_key: PublicKeyBytes,
    /// Метка приглашения. Сервер знает её хеш и принимает заявку только
    /// с действующей меткой.
    pub invite: [u8; INVITE_LEN],
}

impl JoinLink {
    /// Новая ссылка к каналу — со случайной меткой.
    pub fn new<R: RngCore + CryptoRng>(access: &ChannelAccess, rng: &mut R) -> Self {
        let mut invite = [0u8; INVITE_LEN];
        rng.fill_bytes(&mut invite);

        Self {
            channel_id: access.channel_id,
            verify_key: access.verify_key,
            invite,
        }
    }

    /// Ссылка в виде строки.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut uri = String::with_capacity(JOIN_LINK_PREFIX.len().saturating_add(120));
        uri.push_str(JOIN_LINK_PREFIX);
        push_hex(&mut uri, &self.channel_id);
        uri.push('.');
        uri.push_str(&crate::contact_link::encode_base32(
            self.verify_key.as_bytes(),
        ));
        uri.push('.');
        push_hex(&mut uri, &self.invite);

        uri
    }

    /// Разбирает ссылку-приглашение.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — это не ссылка закрытого канала.
    pub fn parse(input: &str) -> Result<Self> {
        let rest = input
            .trim()
            .strip_prefix(JOIN_LINK_PREFIX)
            .ok_or(GasAppError::Malformed)?;

        let mut parts = rest.split('.');
        let channel = parts.next().ok_or(GasAppError::Malformed)?;
        let key = parts.next().ok_or(GasAppError::Malformed)?;
        let invite = parts.next().ok_or(GasAppError::Malformed)?;

        if parts.next().is_some() {
            return Err(GasAppError::Malformed);
        }

        Ok(Self {
            channel_id: parse_channel_id(channel)?,
            verify_key: PublicKeyBytes::new(crate::contact_link::decode_key(key)?),
            invite: parse_invite(invite)?,
        })
    }

    /// Хеш метки — то, что владелец отдаёт серверу, заводя ссылку.
    #[must_use]
    pub fn invite_hash(&self) -> [u8; 32] {
        Sha256::digest(self.invite).into()
    }
}

fn parse_invite(text: &str) -> Result<[u8; INVITE_LEN]> {
    let digits = text.as_bytes();

    if digits.len() != INVITE_LEN.saturating_mul(2) {
        return Err(GasAppError::Malformed);
    }

    let mut invite = [0u8; INVITE_LEN];

    for (slot, pair) in invite.iter_mut().zip(digits.chunks_exact(2)) {
        let high = hex_value(*pair.first().ok_or(GasAppError::Malformed)?)?;
        let low = hex_value(*pair.get(1).ok_or(GasAppError::Malformed)?)?;

        *slot = (high << 4) | low;
    }

    Ok(invite)
}

/// Новая заявка: то, что уходит на сервер, и то, что остаётся у
/// заявителя до ответа.
pub struct NewJoinRequest {
    /// Заявка для сервера.
    pub wire: Vec<u8>,
    /// Одноразовый приватный ключ: им расшифровывается ответ.
    pub secret: PrivateKeyBytes,
}

/// Проверенная заявка глазами одобряющего.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinRequest {
    /// Одноразовый ключ, под который шифруется ответ.
    pub ephemeral: PublicKeyBytes,
    /// Ключ аккаунта, подписавший заявку. ⚠️ Подпись сходится с ним —
    /// но чей это ключ, знает только тот, кто сверял его с человеком.
    pub identity: PublicKeyBytes,
}

fn request_message(channel_id: &ChannelId, ephemeral: &PublicKeyBytes) -> Vec<u8> {
    let mut message = Vec::with_capacity(REQUEST_DOMAIN.len().saturating_add(16 + 32));
    message.extend_from_slice(REQUEST_DOMAIN);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(ephemeral.as_bytes());

    message
}

/// Заявка под готовый одноразовый ключ: открытая половина за подписью
/// ключа аккаунта. Она же — «ключ доставки» участника: под неё ему
/// шифруют ключ следующей эпохи.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — один из ключей негоден.
pub fn request_wire(
    channel_id: &ChannelId,
    identity_private: &PrivateKeyBytes,
    ephemeral: &PrivateKeyBytes,
) -> Result<Vec<u8>> {
    let public = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(*ephemeral.expose_secret()))?
        .public_key()
        .as_bytes();
    let identity = montgomery::public_key(identity_private)?;
    let signature = montgomery::sign(identity_private, &request_message(channel_id, &public))?;

    let mut wire = Vec::with_capacity(REQUEST_LEN);
    wire.push(WIRE_VERSION);
    wire.extend_from_slice(public.as_bytes());
    wire.extend_from_slice(identity.as_bytes());
    wire.extend_from_slice(&signature);

    Ok(wire)
}

/// Составляет заявку в канал из ссылки и подписывает её ключом аккаунта.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — ключ аккаунта не годится для подписи.
pub fn seal_request<R: RngCore + CryptoRng>(
    link: &JoinLink,
    identity_private: &PrivateKeyBytes,
    rng: &mut R,
) -> Result<NewJoinRequest> {
    let secret = X25519PrivateKey::generate(rng).expose_secret();

    Ok(NewJoinRequest {
        wire: request_wire(&link.channel_id, identity_private, &secret)?,
        secret,
    })
}

/// Секрет ключа доставки того, кто ведёт канал, — из его ключа подписи.
///
/// Выводится, а не хранится: ключ подписи лежит в резервной копии, и
/// после восстановления владелец либо администратор открывает ответ с
/// ключом действующей эпохи без чьей-либо помощи.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — сбой вывода ключа.
pub fn delivery_secret(
    channel_id: &ChannelId,
    signing_key: &PrivateKeyBytes,
) -> Result<PrivateKeyBytes> {
    let mut secret = Zeroizing::new([0u8; 32]);
    aead::hkdf_sha256(
        Some(channel_id),
        signing_key.expose_secret(),
        DELIVERY_INFO,
        &mut *secret,
    )?;

    Ok(PrivateKeyBytes::new(*secret))
}

/// Разбирает заявку и проверяет подпись: одноразовый ключ выпущен
/// владельцем названного ключа аккаунта — и для этого канала.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не заявка;
/// [`GasAppError::InvalidSignature`] — подпись не сходится.
pub fn open_request(channel_id: &ChannelId, wire: &[u8]) -> Result<JoinRequest> {
    if wire.len() != REQUEST_LEN || wire.first() != Some(&WIRE_VERSION) {
        return Err(GasAppError::Malformed);
    }

    let ephemeral = key_at(wire, 1)?;
    let identity = key_at(wire, 33)?;
    let signature = wire.get(65..).ok_or(GasAppError::Malformed)?;

    montgomery::verify(
        &identity,
        &request_message(channel_id, &ephemeral),
        signature,
    )
    .map_err(|_| GasAppError::InvalidSignature)?;

    Ok(JoinRequest {
        ephemeral,
        identity,
    })
}

fn key_at(wire: &[u8], at: usize) -> Result<PublicKeyBytes> {
    let bytes: [u8; 32] = wire
        .get(at..at.saturating_add(32))
        .ok_or(GasAppError::Malformed)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;

    Ok(PublicKeyBytes::new(bytes))
}

/// Ключ, которым шифруется ответ: общий секрет двух одноразовых ключей,
/// привязанный к каналу и к обоим ключам.
fn grant_key(
    shared: &[u8; 32],
    channel_id: &ChannelId,
    requester: &PublicKeyBytes,
    approver: &PublicKeyBytes,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut info = Vec::with_capacity(GRANT_INFO.len().saturating_add(64));
    info.extend_from_slice(GRANT_INFO);
    info.extend_from_slice(requester.as_bytes());
    info.extend_from_slice(approver.as_bytes());

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    aead::hkdf_sha256(Some(channel_id), shared, &info, &mut *key)?;

    Ok(key)
}

fn grant_aad(channel_id: &ChannelId, verify_key: &PublicKeyBytes) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GRANT_AAD.len().saturating_add(16 + 32));
    aad.extend_from_slice(GRANT_AAD);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(verify_key.as_bytes());

    aad
}

/// Одобряет заявку: шифрует секрет чтения канала под её ключ.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — ключ из заявки негоден либо сбой шифрования.
pub fn seal_grant<R: RngCore + CryptoRng>(
    access: &ChannelAccess,
    request: &JoinRequest,
    rng: &mut R,
) -> Result<Vec<u8>> {
    seal_epoch_grant(access, 0, request, rng)
}

/// Шифрует под ключ участника секрет эпохи `epoch` (он лежит в
/// `access.secret`). Так раздаётся и первый ключ, и ключ после смены.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — ключ из заявки негоден либо сбой шифрования.
pub fn seal_epoch_grant<R: RngCore + CryptoRng>(
    access: &ChannelAccess,
    epoch: u32,
    request: &JoinRequest,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let ephemeral = X25519PrivateKey::generate(rng);
    let public = ephemeral.public_key().as_bytes();
    let shared =
        Zeroizing::new(ephemeral.diffie_hellman(&X25519PublicKey::from_bytes(request.ephemeral)?)?);
    let key = grant_key(&shared, &access.channel_id, &request.ephemeral, &public)?;

    // 🔐 Под один ключ доставки ответы шифруются много раз (каждая смена
    // ключа), но общий секрет каждый раз свой: одноразовый ключ
    // отвечающего новый. Nonce случайный — чтобы не опираться и на это.
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut plain = Zeroizing::new([0u8; 4 + SECRET_LEN]);
    let (head, tail) = plain.split_at_mut(4);
    head.copy_from_slice(&epoch.to_be_bytes());
    tail.copy_from_slice(&access.secret);

    let sealed = aead::seal_with_key(
        &key,
        &nonce,
        plain.as_slice(),
        &grant_aad(&access.channel_id, &access.verify_key),
    )?;

    let mut wire = Vec::with_capacity(GRANT_LEN);
    wire.push(WIRE_VERSION);
    wire.extend_from_slice(public.as_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&sealed);

    Ok(wire)
}

/// Открывает ответ на заявку: номер эпохи и доступ с её секретом.
///
/// ⚠️ Ответ сам по себе не доказывает, что секрет верный: его прислал
/// сервер. Доказательство — описание канала, которое расшифруется
/// секретом нулевой эпохи (до него ведёт цепочка, [`open_epoch`]) и
/// сойдётся с ключом владельца.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не ответ; [`GasAppError::Crypto`] —
/// он зашифрован не под эту заявку.
pub fn open_grant(
    channel_id: &ChannelId,
    verify_key: &PublicKeyBytes,
    secret: &PrivateKeyBytes,
    wire: &[u8],
) -> Result<(u32, ChannelAccess)> {
    if wire.len() != GRANT_LEN || wire.first() != Some(&WIRE_VERSION) {
        return Err(GasAppError::Malformed);
    }

    let approver = key_at(wire, 1)?;
    let nonce: [u8; NONCE_LEN] = wire
        .get(33..33 + NONCE_LEN)
        .ok_or(GasAppError::Malformed)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;
    let sealed = wire.get(33 + NONCE_LEN..).ok_or(GasAppError::Malformed)?;

    let ephemeral = X25519PrivateKey::from_bytes(PrivateKeyBytes::new(*secret.expose_secret()))?;
    let requester = ephemeral.public_key().as_bytes();
    let shared = Zeroizing::new(ephemeral.diffie_hellman(&X25519PublicKey::from_bytes(approver)?)?);
    let key = grant_key(&shared, channel_id, &requester, &approver)?;

    let opened = Zeroizing::new(aead::open_with_key(
        &key,
        &nonce,
        sealed,
        &grant_aad(channel_id, verify_key),
    )?);
    let (epoch, channel_secret) = opened.split_at_checked(4).ok_or(GasAppError::Malformed)?;

    Ok((
        u32::from_be_bytes(epoch.try_into().map_err(|_| GasAppError::Malformed)?),
        ChannelAccess {
            channel_id: *channel_id,
            secret: channel_secret
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
            verify_key: *verify_key,
        },
    ))
}

fn epoch_key(
    channel_id: &ChannelId,
    secret: &[u8; SECRET_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    aead::hkdf_sha256(Some(channel_id), secret, EPOCH_INFO, &mut *key)?;

    Ok(key)
}

fn epoch_aad(channel_id: &ChannelId, epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(EPOCH_INFO.len().saturating_add(16 + 4));
    aad.extend_from_slice(EPOCH_INFO);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(&epoch.to_be_bytes());

    aad
}

fn epoch_message(
    channel_id: &ChannelId,
    epoch: u32,
    signer: &PublicKeyBytes,
    nonce: &[u8],
    sealed: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(EPOCH_DOMAIN.len().saturating_add(EPOCH_RECORD_LEN));
    message.extend_from_slice(EPOCH_DOMAIN);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(signer.as_bytes());
    message.extend_from_slice(nonce);
    message.extend_from_slice(sealed);

    message
}

/// Звено цепочки ключей: секрет прежней эпохи, зашифрованный секретом
/// новой эпохи `epoch`, за подписью того, кто сменил ключ.
///
/// По звеньям участник с новым ключом доходит до всех прежних — читать
/// историю. Обратно пройти нельзя: из старого секрета новый не следует.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — нулевая эпоха; [`GasAppError::Crypto`] —
/// ключ подписи негоден либо сбой шифрования.
pub fn seal_epoch<R: RngCore + CryptoRng>(
    channel_id: &ChannelId,
    epoch: u32,
    secret: &[u8; SECRET_LEN],
    previous: &[u8; SECRET_LEN],
    signing_key: PrivateKeyBytes,
    rng: &mut R,
) -> Result<Vec<u8>> {
    if epoch == 0 {
        return Err(GasAppError::Malformed);
    }

    let signing = XEdDSAPrivateKey::from_bytes(signing_key)?;
    let signer = signing.public_key().as_bytes();

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let sealed = aead::seal_with_key(
        &*epoch_key(channel_id, secret)?,
        &nonce,
        previous,
        &epoch_aad(channel_id, epoch),
    )?;
    let signature = signing.sign(&epoch_message(channel_id, epoch, &signer, &nonce, &sealed));

    let mut wire = Vec::with_capacity(EPOCH_RECORD_LEN);
    wire.push(WIRE_VERSION);
    wire.extend_from_slice(&epoch.to_be_bytes());
    wire.extend_from_slice(signer.as_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&signature);
    wire.extend_from_slice(&sealed);

    Ok(wire)
}

/// Кто подписал звено — без проверки подписи.
///
/// Нужен входящему в канал: список администраторов лежит в описании
/// канала, а оно открывается секретом нулевой эпохи, до которого ещё
/// надо дойти по звеньям. Сначала цепочка проходится «кем бы ни была
/// подписана», затем подписавшие сверяются с описанием.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не звено.
pub fn epoch_signer(wire: &[u8]) -> Result<PublicKeyBytes> {
    if wire.len() != EPOCH_RECORD_LEN || wire.first() != Some(&WIRE_VERSION) {
        return Err(GasAppError::Malformed);
    }

    key_at(wire, 5)
}

/// Открывает звено эпохи `epoch` её секретом и возвращает секрет
/// предыдущей эпохи.
///
/// 🔐 Звено обязан подписать владелец (`owner`) либо администратор из
/// `admins`: рядовой участник, даже зная ключ, новую эпоху завести не
/// может — иначе удалённый подписчик в сговоре с сервером подсунул бы
/// каналу ключ, который знает сам.
///
/// ⚠️ Годится и снятый администратор: звенья, которые он подписал, пока
/// вёл канал, должны читаться и после его снятия, а номера эпохи, до
/// которой его ключ действует, в описании канала нет. Снятый
/// администратор в сговоре с сервером может завести каналу эпоху с
/// ключом, который знает сам.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не звено либо не той эпохи;
/// [`GasAppError::InvalidSignature`] — подписал не тот, кто ведёт канал;
/// [`GasAppError::Crypto`] — не тот секрет либо данные изменены.
pub fn open_epoch(
    channel_id: &ChannelId,
    owner: &PublicKeyBytes,
    admins: &[ChannelAdmin],
    epoch: u32,
    secret: &[u8; SECRET_LEN],
    wire: &[u8],
) -> Result<[u8; SECRET_LEN]> {
    if wire.len() != EPOCH_RECORD_LEN || wire.first() != Some(&WIRE_VERSION) {
        return Err(GasAppError::Malformed);
    }

    let named = u32::from_be_bytes(
        wire.get(1..5)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(GasAppError::Malformed)?,
    );

    if named != epoch || epoch == 0 {
        return Err(GasAppError::Malformed);
    }

    let signer = key_at(wire, 5)?;
    let nonce: [u8; NONCE_LEN] = wire
        .get(37..37 + NONCE_LEN)
        .ok_or(GasAppError::Malformed)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)?;
    let signature = wire
        .get(37 + NONCE_LEN..37 + NONCE_LEN + SIGNATURE_LEN)
        .ok_or(GasAppError::Malformed)?;
    let sealed = wire
        .get(37 + NONCE_LEN + SIGNATURE_LEN..)
        .ok_or(GasAppError::Malformed)?;

    if signer != *owner && !admins.iter().any(|admin| admin.verify_key == signer) {
        return Err(GasAppError::InvalidSignature);
    }

    XEdDSAPublicKey::from_bytes(signer)
        .and_then(|key| {
            key.verify_strict(
                &epoch_message(channel_id, epoch, &signer, &nonce, sealed),
                signature,
            )
        })
        .map_err(|_| GasAppError::InvalidSignature)?;

    let opened = Zeroizing::new(aead::open_with_key(
        &*epoch_key(channel_id, secret)?,
        &nonce,
        sealed,
        &epoch_aad(channel_id, epoch),
    )?);

    opened
        .as_slice()
        .try_into()
        .map_err(|_| GasAppError::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::channel;

    fn identity() -> PrivateKeyBytes {
        X25519PrivateKey::generate(&mut OsRng).expose_secret()
    }

    #[test]
    fn a_link_round_trips_and_carries_no_secret() {
        let created = channel::create(&mut OsRng);
        let link = JoinLink::new(&created.access, &mut OsRng);
        let uri = link.to_uri();

        assert_eq!(JoinLink::parse(&uri).unwrap(), link);
        assert!(uri.starts_with(JOIN_LINK_PREFIX));
        assert!(!uri.contains(&crate::contact_link::encode_base32(&created.access.secret)));
        // Ссылка закрытого канала — не ссылка открытого, и наоборот.
        assert!(ChannelAccess::parse(&uri).is_err());
        assert!(JoinLink::parse(&created.access.to_uri()).is_err());
    }

    #[test]
    fn malformed_links_are_refused() {
        let created = channel::create(&mut OsRng);
        let uri = JoinLink::new(&created.access, &mut OsRng).to_uri();

        assert!(JoinLink::parse(&format!("{uri}.extra")).is_err());
        assert!(JoinLink::parse(&uri[..uri.len() - 2]).is_err());
        assert!(JoinLink::parse(&format!("{}zz", &uri[..uri.len() - 2])).is_err());
        assert!(JoinLink::parse("gasapp://channel-join/").is_err());
    }

    #[test]
    fn an_approved_request_yields_the_channel() {
        let created = channel::create(&mut OsRng);
        let link = JoinLink::new(&created.access, &mut OsRng);
        let account = identity();

        let request = seal_request(&link, &account, &mut OsRng).unwrap();
        assert_eq!(request.wire.len(), REQUEST_LEN);

        let opened = open_request(&link.channel_id, &request.wire).unwrap();
        assert_eq!(opened.identity, montgomery::public_key(&account).unwrap());

        let grant = seal_grant(&created.access, &opened, &mut OsRng).unwrap();
        assert_eq!(grant.len(), GRANT_LEN);

        let (epoch, access) =
            open_grant(&link.channel_id, &link.verify_key, &request.secret, &grant).unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(access, created.access);
    }

    #[test]
    fn a_request_is_bound_to_its_channel_and_key() {
        let created = channel::create(&mut OsRng);
        let other = channel::create(&mut OsRng);
        let link = JoinLink::new(&created.access, &mut OsRng);
        let request = seal_request(&link, &identity(), &mut OsRng).unwrap();

        // Заявка в один канал не годится для другого.
        assert!(matches!(
            open_request(&other.access.channel_id, &request.wire),
            Err(GasAppError::InvalidSignature)
        ));

        // Подменённый одноразовый ключ ломает подпись.
        let mut forged = request.wire.clone();
        forged[5] ^= 1;
        assert!(matches!(
            open_request(&link.channel_id, &forged),
            Err(GasAppError::InvalidSignature)
        ));

        assert!(matches!(
            open_request(&link.channel_id, &request.wire[..REQUEST_LEN - 1]),
            Err(GasAppError::Malformed)
        ));
    }

    #[test]
    fn a_grant_opens_only_for_its_request() {
        let created = channel::create(&mut OsRng);
        let link = JoinLink::new(&created.access, &mut OsRng);
        let mine = seal_request(&link, &identity(), &mut OsRng).unwrap();
        let theirs = seal_request(&link, &identity(), &mut OsRng).unwrap();

        let grant = seal_grant(
            &created.access,
            &open_request(&link.channel_id, &theirs.wire).unwrap(),
            &mut OsRng,
        )
        .unwrap();

        assert!(matches!(
            open_grant(&link.channel_id, &link.verify_key, &mine.secret, &grant),
            Err(GasAppError::Crypto)
        ));

        // Изменённый ответ не открывается.
        let mut damaged = grant.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(matches!(
            open_grant(&link.channel_id, &link.verify_key, &theirs.secret, &damaged),
            Err(GasAppError::Crypto)
        ));

        // Ответ привязан к ключу владельца из ссылки.
        let mut other_owner = link;
        other_owner.verify_key = channel::create(&mut OsRng).access.verify_key;
        assert!(matches!(
            open_grant(
                &other_owner.channel_id,
                &other_owner.verify_key,
                &theirs.secret,
                &grant
            ),
            Err(GasAppError::Crypto)
        ));
    }

    #[test]
    fn the_invite_hash_is_sha256_of_the_tag() {
        let created = channel::create(&mut OsRng);
        let mut link = JoinLink::new(&created.access, &mut OsRng);
        link.invite = [0x5a; INVITE_LEN];

        // Тот же вектор, что в тестах сервера.
        assert_eq!(
            link.invite_hash().to_vec(),
            Sha256::digest([0x5au8; 16]).to_vec()
        );
    }

    #[test]
    fn a_rekey_reaches_members_and_leads_back_through_the_chain() {
        let created = channel::create(&mut OsRng);
        let id = created.access.channel_id;
        let owner = created.access.verify_key;
        let link = JoinLink::new(&created.access, &mut OsRng);
        let member = seal_request(&link, &identity(), &mut OsRng).unwrap();
        let delivery = open_request(&id, &member.wire).unwrap();

        // Эпоха 1: новый секрет, звено к нулевому, ответ участнику.
        let mut next = created.access.clone();
        next.secret = [0x11; SECRET_LEN];
        let record = seal_epoch(
            &id,
            1,
            &next.secret,
            &created.access.secret,
            PrivateKeyBytes::new(*created.signing_key.expose_secret()),
            &mut OsRng,
        )
        .unwrap();
        assert_eq!(record.len(), EPOCH_RECORD_LEN);

        let grant = seal_epoch_grant(&next, 1, &delivery, &mut OsRng).unwrap();
        let (epoch, access) = open_grant(&id, &owner, &member.secret, &grant).unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(access.secret, next.secret);

        // По звену новый ключ ведёт к прежнему — и только он.
        assert_eq!(
            open_epoch(&id, &owner, &[], 1, &access.secret, &record).unwrap(),
            created.access.secret
        );
        assert!(matches!(
            open_epoch(&id, &owner, &[], 1, &created.access.secret, &record),
            Err(GasAppError::Crypto)
        ));
        assert!(matches!(
            open_epoch(&id, &owner, &[], 2, &access.secret, &record),
            Err(GasAppError::Malformed)
        ));
    }

    #[test]
    fn only_those_who_run_the_channel_start_an_epoch() {
        let created = channel::create(&mut OsRng);
        let id = created.access.channel_id;
        let owner = created.access.verify_key;
        let (admin_key, admin_vk) = channel::admin_keypair(&mut OsRng);
        let (stranger_key, _) = channel::admin_keypair(&mut OsRng);
        let secret = [0x22; SECRET_LEN];
        let seal = |key: &PrivateKeyBytes| {
            seal_epoch(
                &id,
                1,
                &secret,
                &created.access.secret,
                PrivateKeyBytes::new(*key.expose_secret()),
                &mut OsRng,
            )
            .unwrap()
        };

        // 🔐 Знать прежний секрет мало: звено подписывает тот, кто ведёт канал.
        assert!(matches!(
            open_epoch(&id, &owner, &[], 1, &secret, &seal(&stranger_key)),
            Err(GasAppError::InvalidSignature)
        ));

        let active = ChannelAdmin {
            verify_key: admin_vk,
            until: None,
        };
        let by_admin = seal(&admin_key);
        assert!(open_epoch(&id, &owner, &[active], 1, &secret, &by_admin).is_ok());

        // Звено снятого администратора читается: он подписал его, пока
        // вёл канал.
        let removed = ChannelAdmin {
            verify_key: admin_vk,
            until: Some(5),
        };
        assert!(open_epoch(&id, &owner, &[removed], 1, &secret, &by_admin).is_ok());
        assert_eq!(epoch_signer(&by_admin).unwrap(), admin_vk);

        // Изменённое звено не принимается.
        let mut damaged = by_admin.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(open_epoch(&id, &owner, &[active], 1, &secret, &damaged).is_err());
    }

    #[test]
    fn a_writer_delivery_key_follows_from_the_signing_key() {
        let created = channel::create(&mut OsRng);
        let id = created.access.channel_id;
        let signing = PrivateKeyBytes::new(*created.signing_key.expose_secret());

        let first = delivery_secret(&id, &signing).unwrap();
        let second = delivery_secret(&id, &signing).unwrap();
        assert_eq!(first.expose_secret(), second.expose_secret());

        // Тот же ключ подписи в другом канале даёт другой ключ доставки.
        let other = delivery_secret(&[9; 16], &signing).unwrap();
        assert_ne!(first.expose_secret(), other.expose_secret());

        // Заявка под выведенный ключ проходит ту же проверку, что и обычная.
        let account = identity();
        let wire = request_wire(&id, &account, &first).unwrap();
        let request = open_request(&id, &wire).unwrap();
        let grant = seal_grant(&created.access, &request, &mut OsRng).unwrap();
        let (_, access) = open_grant(&id, &created.access.verify_key, &first, &grant).unwrap();
        assert_eq!(access, created.access);
    }
}
