// SPDX-License-Identifier: Apache-2.0

//! Связывание нового устройства с аккаунтом по QR-коду
//! (`docs/protocol/MULTI-DEVICE.md`, §3).
//!
//! ```text
//! Новое B: ключи IK_B/PQ_B, эфемерные E_B (X25519) и K_B (ML-KEM-768)
//!          → запрос в ящик сервера, QR = (nonce, срок, хеш запроса)
//! Основное A: сканирует QR, берёт запрос, сверяет хеш, подписывает
//!          список устройств с B и шлёт B «грант» — гибридный конверт
//! B: открывает грант, проверяет список, регистрирует устройство
//! ```
//!
//! 🔐 Почему так:
//!
//! * **хеш запроса в QR** — сервер не подменит ключи B: QR снят с экрана
//!   рядом, мимо сети;
//! * **закрытый ключ аккаунта не передаётся** — в гранте только открытые
//!   ключи аккаунта и список устройств, подписанный основным;
//! * **X25519 + ML-KEM-768** — конверт пост-квантово стойкий, как PQXDH;
//! * **код сверки** ([`GrantSeal::code`]) — шесть цифр на обоих экранах.
//!   Сервер видит открытые ключи запроса и мог бы зашифровать B свой
//!   грант (подключить B к чужому аккаунту); код у такого гранта другой;
//! * **срок 60 секунд** — внутри запроса и QR, проверяется обеими
//!   сторонами; дальний срок тоже отвергается.

use std::fmt::Write as _;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use gasapp_types::{GasAppError, PublicKeyBytes, Result};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::device_list::{SignedDeviceList, DEVICE_ID_LEN};
use crate::keys::IdentityKeyPair;
use crate::mlkem::{MlKem768PrivateKey, MlKem768PublicKey};
use crate::pq_identity::{PqIdentityKeyPair, PQ_PUBLIC_LEN};
use crate::x25519::{X25519PrivateKey, X25519PublicKey};

/// Версия формата QR и запроса.
pub const LINK_VERSION: u8 = 1;

/// Сколько живёт QR, миллисекунды (план, 13.2).
pub const LINK_TTL_MILLIS: i64 = 60_000;

/// Допуск расхождения часов двух устройств, миллисекунды.
const CLOCK_SLACK_MILLIS: i64 = 5_000;

/// Длина одноразового идентификатора ящика.
pub const NONCE_LEN: usize = 16;

/// Схема ссылки в QR.
pub const LINK_SCHEME: &str = "gasapp://link/";

/// Предел полезной нагрузки приложения в гранте (контакты, настройки).
pub const MAX_EXTRA_BYTES: usize = 1024 * 1024;

const REQUEST_MAGIC: &[u8; 4] = b"GLR1";
const GRANT_MAGIC: &[u8; 4] = b"GLG1";
const COMMIT_DOMAIN: &[u8] = b"GASAPP_LINK_REQUEST_v1";
const KEY_INFO: &[u8] = b"GASAPP_LINK_GRANT_v1";
const CODE_INFO: &[u8] = b"GASAPP_LINK_CODE_v1";
const AEAD_NONCE_LEN: usize = 12;
const KEM_PUBLIC_LEN: usize = MlKem768PublicKey::LEN;
const KEM_CIPHERTEXT_LEN: usize = MlKem768PublicKey::CIPHERTEXT_LEN;
const MAX_USERNAME_BYTES: usize = 64;
/// Длина запроса: магия, версия, ящик, срок, устройство, ключи.
const REQUEST_LEN: usize =
    4 + 1 + NONCE_LEN + 8 + DEVICE_ID_LEN + 32 + PQ_PUBLIC_LEN + 32 + KEM_PUBLIC_LEN;
/// Длина содержимого QR: версия, ящик, срок, хеш.
const CODE_LEN: usize = 1 + NONCE_LEN + 8 + 32;
/// Длина заголовка конверта: магия, эфемерный ключ, шифротекст ML-KEM, nonce.
const SEALED_HEADER_LEN: usize = 4 + 32 + KEM_CIPHERTEXT_LEN + AEAD_NONCE_LEN;

/// Запрос нового устройства — открытые ключи; кладётся в ящик сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// Одноразовый идентификатор ящика.
    pub nonce: [u8; NONCE_LEN],
    /// Срок, миллисекунды Unix.
    pub expires_at_millis: i64,
    /// Идентификатор нового устройства (UUID).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Identity-ключ нового устройства.
    pub identity: PublicKeyBytes,
    /// Пост-квантовая половина его identity.
    pub pq_identity: Vec<u8>,
    /// Эфемерный X25519 — для конверта.
    pub ephemeral: PublicKeyBytes,
    /// Эфемерный ML-KEM-768 — для конверта.
    pub kem_public: Vec<u8>,
}

impl LinkRequest {
    /// Байты запроса.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REQUEST_LEN);
        out.extend_from_slice(REQUEST_MAGIC);
        out.push(LINK_VERSION);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expires_at_millis.to_be_bytes());
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.pq_identity);
        out.extend_from_slice(self.ephemeral.as_bytes());
        out.extend_from_slice(&self.kem_public);
        out
    }

    /// Разбирает запрос.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — не тот формат или версия.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        if &reader.array::<4>()? != REQUEST_MAGIC || reader.array::<1>()? != [LINK_VERSION] {
            return Err(GasAppError::Malformed);
        }
        let request = Self {
            nonce: reader.array()?,
            expires_at_millis: i64::from_be_bytes(reader.array()?),
            device_id: reader.array()?,
            identity: PublicKeyBytes::new(reader.array()?),
            pq_identity: reader.take(PQ_PUBLIC_LEN)?.to_vec(),
            ephemeral: PublicKeyBytes::new(reader.array()?),
            kem_public: reader.take(KEM_PUBLIC_LEN)?.to_vec(),
        };
        reader.finish()?;
        Ok(request)
    }

    /// Хеш запроса — то, что попадает в QR.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(COMMIT_DOMAIN);
        hash.update(self.encode());
        hash.finalize().into()
    }

    /// Что показывает QR.
    #[must_use]
    pub fn code(&self) -> LinkCode {
        LinkCode {
            nonce: self.nonce,
            expires_at_millis: self.expires_at_millis,
            commitment: self.commitment(),
        }
    }
}

/// Эфемерные секреты запроса — только в памяти нового устройства.
pub struct LinkSecrets {
    ephemeral: X25519PrivateKey,
    kem: MlKem768PrivateKey,
    request: LinkRequest,
}

impl LinkSecrets {
    /// Запрос, к которому относятся секреты.
    #[must_use]
    pub const fn request(&self) -> &LinkRequest {
        &self.request
    }
}

/// Создаёт запрос на новом устройстве (`device_id`, `identity`, `pq` —
/// уже сгенерированные ключи этого устройства).
pub fn new_request<R: RngCore + CryptoRng>(
    device_id: [u8; DEVICE_ID_LEN],
    identity: &IdentityKeyPair,
    pq: &PqIdentityKeyPair,
    now_millis: i64,
    rng: &mut R,
) -> LinkSecrets {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ephemeral = X25519PrivateKey::generate(rng);
    let kem = MlKem768PrivateKey::generate(rng);
    let request = LinkRequest {
        nonce,
        expires_at_millis: now_millis.saturating_add(LINK_TTL_MILLIS),
        device_id,
        identity: *identity.public().public(),
        pq_identity: pq.public(),
        ephemeral: ephemeral.public_key().as_bytes(),
        kem_public: kem.public_key().as_bytes(),
    };
    LinkSecrets {
        ephemeral,
        kem,
        request,
    }
}

/// Содержимое QR: ящик, срок и хеш запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkCode {
    /// Ящик на сервере.
    pub nonce: [u8; NONCE_LEN],
    /// Срок, миллисекунды Unix.
    pub expires_at_millis: i64,
    /// Хеш запроса.
    pub commitment: [u8; 32],
}

impl LinkCode {
    /// Ссылка для QR: `gasapp://link/<hex>`.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut bytes = Vec::with_capacity(CODE_LEN);
        bytes.push(LINK_VERSION);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.expires_at_millis.to_be_bytes());
        bytes.extend_from_slice(&self.commitment);
        let mut uri = String::with_capacity(
            LINK_SCHEME
                .len()
                .saturating_add(bytes.len().saturating_mul(2)),
        );
        uri.push_str(LINK_SCHEME);
        for byte in bytes {
            let _ = write!(uri, "{byte:02x}");
        }
        uri
    }

    /// Разбирает ссылку из QR — строго: только эта схема и ровно эти байты.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — не ссылка связывания.
    pub fn parse(uri: &str) -> Result<Self> {
        let hex = uri
            .trim()
            .strip_prefix(LINK_SCHEME)
            .ok_or(GasAppError::Malformed)?;
        let bytes = decode_hex(hex)?;
        let mut reader = Reader(&bytes);
        if reader.array::<1>()? != [LINK_VERSION] {
            return Err(GasAppError::Malformed);
        }
        let code = Self {
            nonce: reader.array()?,
            expires_at_millis: i64::from_be_bytes(reader.array()?),
            commitment: reader.array()?,
        };
        reader.finish()?;
        Ok(code)
    }

    /// Проверяет срок QR.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — срок вышел или дальше допустимого.
    pub fn check_fresh(&self, now_millis: i64) -> Result<()> {
        let latest = now_millis
            .saturating_add(LINK_TTL_MILLIS)
            .saturating_add(CLOCK_SLACK_MILLIS);
        if self.expires_at_millis < now_millis.saturating_sub(CLOCK_SLACK_MILLIS)
            || self.expires_at_millis > latest
        {
            return Err(GasAppError::Malformed);
        }
        Ok(())
    }
}

/// Основное устройство: проверяет запрос из ящика по QR.
///
/// # Errors
///
/// * [`GasAppError::Malformed`] — срок вышел, запрос не разбирается, не тот
///   ящик или срок запроса расходится с QR;
/// * [`GasAppError::InvalidSignature`] — хеш запроса не совпал с QR:
///   запрос подменён.
pub fn check_request(
    code: &LinkCode,
    request_bytes: &[u8],
    now_millis: i64,
) -> Result<LinkRequest> {
    code.check_fresh(now_millis)?;
    let request = LinkRequest::decode(request_bytes)?;
    if request.nonce != code.nonce || request.expires_at_millis != code.expires_at_millis {
        return Err(GasAppError::Malformed);
    }
    if request.commitment() != code.commitment {
        return Err(GasAppError::InvalidSignature);
    }
    Ok(request)
}

/// Что основное устройство передаёт новому.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkGrant {
    /// Аккаунт (UUID).
    pub account_id: [u8; 16],
    /// Имя аккаунта.
    pub username: String,
    /// Identity-ключ аккаунта (открытый).
    pub account_identity: PublicKeyBytes,
    /// Пост-квантовая половина identity аккаунта (открытая).
    pub account_pq: Vec<u8>,
    /// Подписанный список устройств с новым устройством.
    pub device_list: Vec<u8>,
    /// Данные приложения: контакты, настройки.
    pub extra: Vec<u8>,
}

impl LinkGrant {
    fn encode(&self) -> Result<Vec<u8>> {
        let name = self.username.as_bytes();
        if name.is_empty() || name.len() > MAX_USERNAME_BYTES || self.extra.len() > MAX_EXTRA_BYTES
        {
            return Err(GasAppError::Malformed);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.account_id);
        put_bytes(&mut out, name)?;
        out.extend_from_slice(self.account_identity.as_bytes());
        put_bytes(&mut out, &self.account_pq)?;
        put_bytes(&mut out, &self.device_list)?;
        put_bytes(&mut out, &self.extra)?;
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        let account_id = reader.array()?;
        let username = String::from_utf8(reader.bytes(MAX_USERNAME_BYTES)?.to_vec())
            .map_err(|_| GasAppError::Malformed)?;
        let grant = Self {
            account_id,
            username,
            account_identity: PublicKeyBytes::new(reader.array()?),
            account_pq: reader.bytes(PQ_PUBLIC_LEN)?.to_vec(),
            device_list: reader.bytes(MAX_EXTRA_BYTES)?.to_vec(),
            extra: reader.bytes(MAX_EXTRA_BYTES)?.to_vec(),
        };
        reader.finish()?;
        Ok(grant)
    }
}

/// Запечатанный грант и код сверки.
pub struct GrantSeal {
    /// Конверт для ящика сервера.
    pub sealed: Vec<u8>,
    /// Шесть цифр — основное показывает их рядом с вопросом «Подключить?».
    pub code: String,
}

/// Основное устройство: запечатывает грант для проверенного запроса.
///
/// # Errors
///
/// * [`GasAppError::Malformed`] — грант не проходит пределы;
/// * [`GasAppError::Crypto`] — ключ запроса негоден или сбой шифра.
pub fn seal_grant<R: RngCore + CryptoRng>(
    request: &LinkRequest,
    grant: &LinkGrant,
    rng: &mut R,
) -> Result<GrantSeal> {
    let plain = Zeroizing::new(grant.encode()?);
    let ephemeral = X25519PrivateKey::generate(rng);
    let classical =
        Zeroizing::new(ephemeral.diffie_hellman(&X25519PublicKey::from_bytes(request.ephemeral)?)?);
    let (post_quantum, kem_ciphertext) =
        MlKem768PublicKey::from_bytes(&request.kem_public)?.encapsulate(rng);
    let post_quantum = Zeroizing::new(post_quantum);
    let ephemeral_public = ephemeral.public_key().as_bytes();
    let commitment = request.commitment();
    let (key, code) = derive(
        &classical,
        &post_quantum,
        &commitment,
        &ephemeral_public,
        &kem_ciphertext,
    )?;

    let mut nonce = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| GasAppError::Crypto)?;
    let aad = aad(&commitment);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| GasAppError::Crypto)?;

    let mut sealed = Vec::with_capacity(SEALED_HEADER_LEN.saturating_add(ciphertext.len()));
    sealed.extend_from_slice(GRANT_MAGIC);
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&kem_ciphertext);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(GrantSeal { sealed, code })
}

/// Открытый грант на новом устройстве.
pub struct OpenedGrant {
    /// Что передало основное устройство.
    pub grant: LinkGrant,
    /// Проверенный список устройств — с этим устройством.
    pub device_list: SignedDeviceList,
    /// Код сверки — должен совпасть с кодом на основном.
    pub code: String,
}

/// Новое устройство: открывает грант и проверяет список устройств.
///
/// # Errors
///
/// * [`GasAppError::Malformed`] — конверт или грант не разбираются;
/// * [`GasAppError::Crypto`] — конверт не для этого запроса или подменён;
/// * [`GasAppError::InvalidSignature`] — список не подписан ключом
///   аккаунта из гранта либо в нём нет этого устройства с его ключами.
pub fn open_grant(secrets: &LinkSecrets, sealed: &[u8]) -> Result<OpenedGrant> {
    let mut reader = Reader(sealed);
    if &reader.array::<4>()? != GRANT_MAGIC {
        return Err(GasAppError::Malformed);
    }
    let ephemeral_public = PublicKeyBytes::new(reader.array()?);
    let kem_ciphertext = reader.take(KEM_CIPHERTEXT_LEN)?;
    let nonce: [u8; AEAD_NONCE_LEN] = reader.array()?;
    let ciphertext = reader.0;

    let classical = Zeroizing::new(
        secrets
            .ephemeral
            .diffie_hellman(&X25519PublicKey::from_bytes(ephemeral_public)?)?,
    );
    let post_quantum = Zeroizing::new(secrets.kem.decapsulate(kem_ciphertext)?);
    let commitment = secrets.request.commitment();
    let (key, code) = derive(
        &classical,
        &post_quantum,
        &commitment,
        &ephemeral_public,
        kem_ciphertext,
    )?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| GasAppError::Crypto)?;
    let aad = aad(&commitment);
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| GasAppError::Crypto)?,
    );
    let grant = LinkGrant::decode(&plain)?;

    let device_list = SignedDeviceList::verify(
        &grant.device_list,
        &grant.account_identity,
        &grant.account_pq,
    )?;
    let me = &secrets.request;
    let listed = device_list
        .list
        .device(&me.device_id)
        .is_some_and(|entry| entry.identity == me.identity && entry.pq_identity == me.pq_identity);
    if !listed {
        return Err(GasAppError::InvalidSignature);
    }
    Ok(OpenedGrant {
        grant,
        device_list,
        code,
    })
}

fn aad(commitment: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(36);
    aad.extend_from_slice(GRANT_MAGIC);
    aad.extend_from_slice(commitment);
    aad
}

/// Ключ конверта и код сверки из обоих общих секретов.
fn derive(
    classical: &[u8; 32],
    post_quantum: &[u8; 32],
    commitment: &[u8; 32],
    ephemeral: &PublicKeyBytes,
    kem_ciphertext: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, String)> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(classical);
    ikm.extend_from_slice(post_quantum);
    // Информация связывает ключ с этим конвертом: эфемерным ключом и
    // шифротекстом ML-KEM.
    let mut info = Vec::with_capacity(
        KEY_INFO
            .len()
            .saturating_add(32)
            .saturating_add(kem_ciphertext.len()),
    );
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(ephemeral.as_bytes());
    info.extend_from_slice(kem_ciphertext);

    let mut key = Zeroizing::new([0u8; 32]);
    crate::aead::hkdf_sha256(Some(commitment), &ikm, &info, key.as_mut())?;

    let mut code_bytes = [0u8; 4];
    let mut code_info = Vec::with_capacity(CODE_INFO.len().saturating_add(info.len()));
    code_info.extend_from_slice(CODE_INFO);
    code_info.extend_from_slice(&info);
    crate::aead::hkdf_sha256(Some(commitment), &ikm, &code_info, &mut code_bytes)?;
    let number = u32::from_be_bytes(code_bytes)
        .checked_rem(1_000_000)
        .unwrap_or(0);
    Ok((key, format!("{number:06}")))
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| GasAppError::Malformed)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if text.len() & 1 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GasAppError::Malformed);
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or(GasAppError::Malformed)
        })
        .collect()
}

/// Читатель байтов без индексации.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.0.len() < count {
            return Err(GasAppError::Malformed);
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| GasAppError::Malformed)
    }

    fn bytes(&mut self, limit: usize) -> Result<&'a [u8]> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| GasAppError::Malformed)?;
        if length > limit {
            return Err(GasAppError::Malformed);
        }
        self.take(length)
    }

    fn finish(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(GasAppError::Malformed)
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::device_list::{DeviceEntry, DeviceList};
    use crate::prekeys::generate_identity;
    use rand_core::OsRng;

    const NOW: i64 = 1_764_000_000_000;

    struct Keys {
        identity: IdentityKeyPair,
        pq: PqIdentityKeyPair,
    }

    fn keys() -> Keys {
        Keys {
            identity: generate_identity(&mut OsRng).unwrap(),
            pq: PqIdentityKeyPair::generate(&mut OsRng),
        }
    }

    fn entry(keys: &Keys, id: u8) -> DeviceEntry {
        DeviceEntry {
            device_id: [id; DEVICE_ID_LEN],
            identity: *keys.identity.public().public(),
            pq_identity: keys.pq.public(),
        }
    }

    /// Основное устройство (оно же ключ аккаунта) подключает новое.
    fn grant_for(account: &Keys, request: &LinkRequest, new: &Keys) -> LinkGrant {
        let list = DeviceList {
            account_identity: *account.identity.public().public(),
            version: 2,
            issued_at_millis: NOW,
            devices: vec![entry(account, 1), entry(new, 2)],
        }
        .sign(&account.identity, &account.pq)
        .unwrap();
        assert_eq!(
            list.list.device(&request.device_id).map(|d| d.identity),
            Some(request.identity)
        );
        LinkGrant {
            account_id: [7; 16],
            username: "anna_k".into(),
            account_identity: *account.identity.public().public(),
            account_pq: account.pq.public(),
            device_list: list.to_bytes(),
            extra: b"contacts".to_vec(),
        }
    }

    #[test]
    fn a_device_is_linked_end_to_end() {
        let account = keys();
        let new = keys();
        let secrets = new_request([2; DEVICE_ID_LEN], &new.identity, &new.pq, NOW, &mut OsRng);

        // QR → основное устройство.
        let uri = secrets.request().code().to_uri();
        let code = LinkCode::parse(&uri).unwrap();
        let request = check_request(&code, &secrets.request().encode(), NOW + 10_000).unwrap();

        let grant = grant_for(&account, &request, &new);
        let seal = seal_grant(&request, &grant, &mut OsRng).unwrap();

        let opened = open_grant(&secrets, &seal.sealed).unwrap();
        assert_eq!(opened.grant, grant);
        assert_eq!(opened.code, seal.code);
        assert_eq!(opened.code.len(), 6);
    }

    /// 🔐 QR старше 60 секунд и QR с дальним сроком отвергаются.
    #[test]
    fn a_stale_or_far_future_code_is_refused() {
        let new = keys();
        let secrets = new_request([2; DEVICE_ID_LEN], &new.identity, &new.pq, NOW, &mut OsRng);
        let code = secrets.request().code();
        let request = secrets.request().encode();

        assert!(check_request(
            &code,
            &request,
            NOW + LINK_TTL_MILLIS + CLOCK_SLACK_MILLIS + 1
        )
        .is_err());

        let mut far = code;
        far.expires_at_millis = NOW + 10 * LINK_TTL_MILLIS;
        assert!(far.check_fresh(NOW).is_err());
    }

    /// 🔐 Сервер подменил запрос в ящике (свои ключи) — хеш в QR не сходится.
    #[test]
    fn a_swapped_request_is_refused() {
        let new = keys();
        let server = keys();
        let secrets = new_request([2; DEVICE_ID_LEN], &new.identity, &new.pq, NOW, &mut OsRng);
        let code = secrets.request().code();

        let mut swapped = secrets.request().clone();
        swapped.identity = *server.identity.public().public();
        assert!(matches!(
            check_request(&code, &swapped.encode(), NOW),
            Err(GasAppError::InvalidSignature)
        ));
    }

    /// 🔐 Сервер видит открытые ключи запроса и запечатывает свой грант:
    /// грант открывается, но список не того аккаунта… а если сервер
    /// подписал свой список со своим аккаунтом — расходится код сверки.
    #[test]
    fn a_server_made_grant_shows_a_different_code() {
        let account = keys();
        let attacker = keys();
        let new = keys();
        let secrets = new_request([2; DEVICE_ID_LEN], &new.identity, &new.pq, NOW, &mut OsRng);
        let request = secrets.request().clone();

        let genuine =
            seal_grant(&request, &grant_for(&account, &request, &new), &mut OsRng).unwrap();
        let forged =
            seal_grant(&request, &grant_for(&attacker, &request, &new), &mut OsRng).unwrap();
        let opened = open_grant(&secrets, &forged.sealed).unwrap();
        assert_ne!(opened.code, genuine.code);
    }

    /// 🔐 Грант со списком, где этого устройства нет, отвергается.
    #[test]
    fn a_grant_without_this_device_is_refused() {
        let account = keys();
        let new = keys();
        let other = keys();
        let secrets = new_request([2; DEVICE_ID_LEN], &new.identity, &new.pq, NOW, &mut OsRng);
        let request = secrets.request().clone();

        let grant = grant_for(&account, &request, &new);
        let mut wrong = grant.clone();
        wrong.device_list = DeviceList {
            account_identity: *account.identity.public().public(),
            version: 2,
            issued_at_millis: NOW,
            devices: vec![entry(&account, 1), entry(&other, 2)],
        }
        .sign(&account.identity, &account.pq)
        .unwrap()
        .to_bytes();
        let sealed = seal_grant(&request, &wrong, &mut OsRng).unwrap();
        assert!(matches!(
            open_grant(&secrets, &sealed.sealed),
            Err(GasAppError::InvalidSignature)
        ));

        // Подменённый байт конверта.
        let mut tampered = seal_grant(&request, &grant, &mut OsRng).unwrap().sealed;
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert!(open_grant(&secrets, &tampered).is_err());
    }

    #[test]
    fn link_uris_are_parsed_strictly() {
        let new = keys();
        let secrets = new_request([2; DEVICE_ID_LEN], &new.identity, &new.pq, NOW, &mut OsRng);
        let uri = secrets.request().code().to_uri();
        assert!(LinkCode::parse(&uri).is_ok());
        for bad in [
            uri.replace("gasapp://link/", "gasapp://contact/"),
            format!("{uri}00"),
            uri.replacen("01", "02", 1),
            "gasapp://link/zz".to_owned(),
        ] {
            assert!(LinkCode::parse(&bad).is_err(), "{bad}");
        }
    }
}
