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
use crate::channel::{hex_value, parse_channel_id, push_hex, ChannelAccess, ChannelId, SECRET_LEN};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::xeddsa::{montgomery, SIGNATURE_LEN};

/// Схема и путь ссылки-приглашения закрытого канала.
pub const JOIN_LINK_PREFIX: &str = "gasapp://channel-join/";

/// Длина метки приглашения.
pub const INVITE_LEN: usize = 16;

/// Длина заявки: версия, одноразовый ключ, ключ аккаунта, подпись.
pub const REQUEST_LEN: usize = 1 + 32 + 32 + SIGNATURE_LEN;

/// Длина ответа: версия, одноразовый ключ, nonce, секрет с тегом.
pub const GRANT_LEN: usize = 1 + 32 + NONCE_LEN + SECRET_LEN + TAG_LEN;

const WIRE_VERSION: u8 = 1;

const REQUEST_DOMAIN: &[u8] = b"GASAPP_CHANNEL_v1_JOIN";
const GRANT_INFO: &[u8] = b"GASAPP_CHANNEL_v1_GRANT";
const GRANT_AAD: &[u8] = b"GASAPP_CHANNEL_v1_GRANT_AAD";

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
    let ephemeral = X25519PrivateKey::generate(rng);
    let public = ephemeral.public_key().as_bytes();
    let identity = montgomery::public_key(identity_private)?;
    let signature = montgomery::sign(
        identity_private,
        &request_message(&link.channel_id, &public),
    )?;

    let mut wire = Vec::with_capacity(REQUEST_LEN);
    wire.push(WIRE_VERSION);
    wire.extend_from_slice(public.as_bytes());
    wire.extend_from_slice(identity.as_bytes());
    wire.extend_from_slice(&signature);

    Ok(NewJoinRequest {
        wire,
        secret: ephemeral.expose_secret(),
    })
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
    let ephemeral = X25519PrivateKey::generate(rng);
    let public = ephemeral.public_key().as_bytes();
    let shared =
        Zeroizing::new(ephemeral.diffie_hellman(&X25519PublicKey::from_bytes(request.ephemeral)?)?);
    let key = grant_key(&shared, &access.channel_id, &request.ephemeral, &public)?;

    // Ключ одноразовый, так что nonce мог бы быть и постоянным; случайный
    // оставлен, чтобы не опираться на это рассуждение.
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let sealed = aead::seal_with_key(
        &key,
        &nonce,
        &access.secret,
        &grant_aad(&access.channel_id, &access.verify_key),
    )?;

    let mut wire = Vec::with_capacity(GRANT_LEN);
    wire.push(WIRE_VERSION);
    wire.extend_from_slice(public.as_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&sealed);

    Ok(wire)
}

/// Открывает ответ на заявку и возвращает доступ к каналу.
///
/// ⚠️ Ответ сам по себе не доказывает, что секрет верный: его прислал
/// сервер. Доказательство — описание канала, которое этим секретом
/// расшифруется и сойдётся с ключом владельца из ссылки.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не ответ; [`GasAppError::Crypto`] —
/// он зашифрован не под эту заявку.
pub fn open_grant(link: &JoinLink, secret: &PrivateKeyBytes, wire: &[u8]) -> Result<ChannelAccess> {
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
    let key = grant_key(&shared, &link.channel_id, &requester, &approver)?;

    let opened = Zeroizing::new(aead::open_with_key(
        &key,
        &nonce,
        sealed,
        &grant_aad(&link.channel_id, &link.verify_key),
    )?);

    Ok(ChannelAccess {
        channel_id: link.channel_id,
        secret: opened
            .as_slice()
            .try_into()
            .map_err(|_| GasAppError::Malformed)?,
        verify_key: link.verify_key,
    })
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

        let access = open_grant(&link, &request.secret, &grant).unwrap();
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
            open_grant(&link, &mine.secret, &grant),
            Err(GasAppError::Crypto)
        ));

        // Изменённый ответ не открывается.
        let mut damaged = grant.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(matches!(
            open_grant(&link, &theirs.secret, &damaged),
            Err(GasAppError::Crypto)
        ));

        // Ответ привязан к ключу владельца из ссылки.
        let mut other_owner = link;
        other_owner.verify_key = channel::create(&mut OsRng).access.verify_key;
        assert!(matches!(
            open_grant(&other_owner, &theirs.secret, &grant),
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
}
