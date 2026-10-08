// SPDX-License-Identifier: Apache-2.0

//! Каналы: лента записей одного автора для многих читателей.
//!
//! # Модель
//!
//! Канал похож на канал в Telegram — автор пишет, остальные читают, —
//! но сервер GasApp остаётся тем же, чем он был: хранилищем
//! шифротекста. Отсюда устройство:
//!
//! * **Ключ чтения** выводится из секрета канала. Секрет лежит в
//!   ссылке-приглашении (`gasapp://channel/…`) и на сервер не попадает:
//!   название, описание и записи сервер видит шифротекстом.
//! * **Ключ подписи** (Ed25519) есть только у автора. Публичная
//!   половина тоже лежит в ссылке, и читатель проверяет ею каждую
//!   запись. Читатели знают ключ чтения, но записать от имени автора
//!   не могут: шифротекст без подписи автора отвергается.
//! * **Номер записи** автор кладёт внутрь шифротекста. Сервер нумерует
//!   записи сам, и читатель сверяет оба номера: переставить записи
//!   местами или выдать одну за другую сервер не может.
//!
//! # 🔐 Чего это НЕ даёт — честно
//!
//! * **Это не сквозное шифрование переписки.** Ключ чтения один на всех
//!   и не меняется: кто получил ссылку, читает весь канал — прошлые
//!   записи и будущие. Отозвать доступ у одного читателя нельзя;
//!   утёкшая ссылка — утёкший канал. Прямой секретности и
//!   восстановления после компрометации здесь нет.
//! * **Сервер может утаить записи**: не отдать последние или отдать
//!   не все подряд сверху. Подделать, изменить или переставить — нет.
//! * **Пост-квантовой защиты нет**: подпись автора — Ed25519.
//!   Квантовый противник подделает запись. Конфиденциальность
//!   (AES-256-GCM на симметричном ключе) от него не страдает.
//!
//! Канал — для объявлений и публикаций, которые автор готов раздать
//! всем, у кого есть ссылка. Личное пишут в переписке.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use gasapp_types::{GasAppError, PrivateKeyBytes, PublicKeyBytes, Result};

use crate::aead::{self, KEY_LEN, NONCE_LEN};
use crate::xeddsa::{XEdDSAPrivateKey, XEdDSAPublicKey, SIGNATURE_LEN};

/// Схема и путь ссылки на канал.
pub const LINK_PREFIX: &str = "gasapp://channel/";

/// Длина идентификатора канала.
pub const CHANNEL_ID_LEN: usize = 16;

/// Длина секрета канала.
pub const SECRET_LEN: usize = 32;

/// Предел названия канала, в знаках.
pub const MAX_TITLE_CHARS: usize = 64;

/// Предел описания канала, в знаках.
pub const MAX_DESCRIPTION_CHARS: usize = 500;

/// Предел текста записи, в байтах UTF-8.
///
/// Запись дополняется до бакета (`padding`), и вместе с подписью обязана
/// уложиться в серверный предел 64 КБ: 16 000 байт текста попадают
/// в бакет 32 КБ.
pub const MAX_POST_BYTES: usize = 16_000;

/// Версия формата записи.
const WIRE_VERSION: u8 = 1;

/// Вид записи: описание канала.
const KIND_META: u8 = 1;

/// Вид записи: публикация.
const KIND_POST: u8 = 2;

/// Заголовок провода: версия, вид, nonce, подпись.
const HEADER_LEN: usize = 2 + NONCE_LEN + SIGNATURE_LEN;

const KEY_INFO: &[u8] = b"GASAPP_CHANNEL_v1_KEY";
const AAD_DOMAIN: &[u8] = b"GASAPP_CHANNEL_v1_AAD";
const SIGNATURE_DOMAIN: &[u8] = b"GASAPP_CHANNEL_v1_SIG";

/// Идентификатор канала — 16 случайных байт (UUID на сервере).
pub type ChannelId = [u8; CHANNEL_ID_LEN];

/// То, что нужно читателю: всё содержимое ссылки-приглашения.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelAccess {
    /// Идентификатор канала.
    pub channel_id: ChannelId,
    /// Секрет, из которого выводится ключ чтения.
    pub secret: [u8; SECRET_LEN],
    /// Публичный ключ подписи автора.
    pub verify_key: PublicKeyBytes,
}

impl core::fmt::Debug for ChannelAccess {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Секрет в отладочный вывод не попадает.
        formatter
            .debug_struct("ChannelAccess")
            .field("channel_id", &self.channel_id)
            .finish_non_exhaustive()
    }
}

/// Новый канал: доступ читателя и ключ подписи автора.
pub struct NewChannel {
    /// То, что уйдёт в ссылку.
    pub access: ChannelAccess,
    /// Приватный ключ подписи — остаётся на устройстве автора.
    pub signing_key: PrivateKeyBytes,
}

/// Описание канала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMeta {
    /// Название.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Когда автор записал это описание, миллисекунды эпохи. Читатель
    /// не принимает описание старше уже известного: сервер не подсунет
    /// прежнее название.
    pub updated_at_millis: i64,
}

/// Запись канала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPost {
    /// Номер записи, который назначил автор. Обязан совпасть с номером
    /// сервера — сверяет [`ChannelAccess::open_post`].
    pub number: u64,
    /// Время публикации по часам автора, миллисекунды эпохи.
    pub created_at_millis: i64,
    /// Текст.
    pub text: String,
}

/// Создаёт канал: идентификатор, секрет чтения и пару подписи.
pub fn create<R: RngCore + CryptoRng>(rng: &mut R) -> NewChannel {
    let mut channel_id = [0u8; CHANNEL_ID_LEN];
    rng.fill_bytes(&mut channel_id);

    let mut secret = [0u8; SECRET_LEN];
    rng.fill_bytes(&mut secret);

    let signing = XEdDSAPrivateKey::generate(rng);

    NewChannel {
        access: ChannelAccess {
            channel_id,
            secret,
            verify_key: signing.public_key().as_bytes(),
        },
        signing_key: signing.expose_secret(),
    }
}

impl ChannelAccess {
    /// Ссылка-приглашение: идентификатор, секрет и ключ подписи.
    ///
    /// 🔐 Ссылка — это и есть доступ. Кто её получил, читает канал.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut uri = String::with_capacity(LINK_PREFIX.len().saturating_add(140));
        uri.push_str(LINK_PREFIX);
        for byte in self.channel_id {
            uri.push(hex_digit(byte >> 4));
            uri.push(hex_digit(byte & 0x0f));
        }
        uri.push('.');
        uri.push_str(&crate::contact_link::encode_base32(&self.secret));
        uri.push('.');
        uri.push_str(&crate::contact_link::encode_base32(
            self.verify_key.as_bytes(),
        ));

        uri
    }

    /// Разбирает ссылку-приглашение.
    ///
    /// Лишние части, параметры и чужая схема отвергаются — по тем же
    /// причинам, что и в ссылке контакта (`contact_link`).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — не ссылка на канал.
    pub fn parse(input: &str) -> Result<Self> {
        let rest = input
            .trim()
            .strip_prefix(LINK_PREFIX)
            .ok_or(GasAppError::Malformed)?;

        let mut parts = rest.split('.');
        let id_part = parts.next().ok_or(GasAppError::Malformed)?;
        let secret_part = parts.next().ok_or(GasAppError::Malformed)?;
        let verify_part = parts.next().ok_or(GasAppError::Malformed)?;

        if parts.next().is_some() {
            return Err(GasAppError::Malformed);
        }

        Ok(Self {
            channel_id: parse_channel_id(id_part)?,
            secret: crate::contact_link::decode_key(secret_part)?,
            verify_key: PublicKeyBytes::new(crate::contact_link::decode_key(verify_part)?),
        })
    }

    /// Идентификатор канала в виде UUID — так его знает сервер.
    #[must_use]
    pub fn channel_uuid(&self) -> String {
        format_uuid(&self.channel_id)
    }

    /// Ключ чтения.
    fn read_key(&self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        aead::hkdf_sha256(Some(&self.channel_id), &self.secret, KEY_INFO, &mut *key)?;

        Ok(key)
    }

    /// Расшифровывает и проверяет описание канала.
    ///
    /// # Errors
    ///
    /// [`GasAppError::InvalidSignature`] — подпись не автора;
    /// [`GasAppError::Crypto`] — не тот ключ либо данные изменены;
    /// [`GasAppError::Malformed`] — формат не тот.
    pub fn open_meta(&self, wire: &[u8]) -> Result<ChannelMeta> {
        let content = self.open(KIND_META, wire)?;

        let (stamp, rest) = split(&content, 8)?;
        let (title_len, rest) = split(rest, 2)?;
        let title_len = usize::from(u16::from_be_bytes(
            title_len.try_into().map_err(|_| GasAppError::Malformed)?,
        ));
        let (title, description) = split(rest, title_len)?;

        let meta = ChannelMeta {
            title: text(title)?,
            description: text(description)?,
            updated_at_millis: i64::from_be_bytes(
                stamp.try_into().map_err(|_| GasAppError::Malformed)?,
            ),
        };

        validate_meta(&meta.title, &meta.description)?;

        Ok(meta)
    }

    /// Расшифровывает и проверяет запись; `server_seq` — номер, под
    /// которым её отдал сервер.
    ///
    /// # Errors
    ///
    /// [`GasAppError::InvalidSignature`] — подпись не автора либо номер
    /// автора не совпал с номером сервера (запись переставлена);
    /// [`GasAppError::Crypto`] — не тот ключ либо данные изменены;
    /// [`GasAppError::Malformed`] — формат не тот.
    pub fn open_post(&self, wire: &[u8], server_seq: u64) -> Result<ChannelPost> {
        let content = self.open(KIND_POST, wire)?;

        let (number, rest) = split(&content, 8)?;
        let (stamp, body) = split(rest, 8)?;

        let post = ChannelPost {
            number: u64::from_be_bytes(number.try_into().map_err(|_| GasAppError::Malformed)?),
            created_at_millis: i64::from_be_bytes(
                stamp.try_into().map_err(|_| GasAppError::Malformed)?,
            ),
            text: text(body)?,
        };

        // 🔐 Подпись верна, но запись стоит не на своём месте: сервер
        // выдал её под чужим номером.
        if post.number != server_seq {
            return Err(GasAppError::InvalidSignature);
        }

        Ok(post)
    }

    /// Проверяет подпись автора и расшифровывает содержимое.
    fn open(&self, kind: u8, wire: &[u8]) -> Result<Vec<u8>> {
        let (header, ciphertext) = split(wire, HEADER_LEN)?;
        let (prefix, rest) = split(header, 2)?;
        let (nonce, signature) = split(rest, NONCE_LEN)?;

        if prefix != [WIRE_VERSION, kind] {
            return Err(GasAppError::Malformed);
        }

        // Подпись — раньше расшифровки: чужой шифротекст до AEAD не доходит.
        XEdDSAPublicKey::from_bytes(self.verify_key)
            .and_then(|key| {
                key.verify_strict(
                    &signed_message(kind, &self.channel_id, nonce, ciphertext),
                    signature,
                )
            })
            .map_err(|_| GasAppError::InvalidSignature)?;

        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| GasAppError::Malformed)?;
        let padded = aead::open_with_key(
            &*self.read_key()?,
            &nonce,
            ciphertext,
            &aad(kind, &self.channel_id),
        )?;

        Ok(crate::padding::unpad(&padded)?.to_vec())
    }
}

/// Автор канала: доступ читателя плюс ключ подписи.
pub struct ChannelAuthor<'a> {
    access: &'a ChannelAccess,
    signing: XEdDSAPrivateKey,
}

impl<'a> ChannelAuthor<'a> {
    /// Собирает автора из сохранённого ключа подписи.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — ключ не от этого канала.
    pub fn new(access: &'a ChannelAccess, signing_key: PrivateKeyBytes) -> Result<Self> {
        let signing = XEdDSAPrivateKey::from_bytes(signing_key)?;

        if signing.public_key().as_bytes() != access.verify_key {
            return Err(GasAppError::Crypto);
        }

        Ok(Self { access, signing })
    }

    /// Шифрует и подписывает описание канала.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — название пустое либо что-то длиннее
    /// предела; [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_meta<R: RngCore + CryptoRng>(
        &self,
        meta: &ChannelMeta,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        validate_meta(&meta.title, &meta.description)?;

        let title = meta.title.as_bytes();
        let title_len = u16::try_from(title.len()).map_err(|_| GasAppError::Malformed)?;

        let mut content = Vec::with_capacity(
            title
                .len()
                .saturating_add(meta.description.len())
                .saturating_add(10),
        );
        content.extend_from_slice(&meta.updated_at_millis.to_be_bytes());
        content.extend_from_slice(&title_len.to_be_bytes());
        content.extend_from_slice(title);
        content.extend_from_slice(meta.description.as_bytes());

        self.seal(KIND_META, &content, rng)
    }

    /// Шифрует и подписывает запись.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — текст пустой либо длиннее
    /// [`MAX_POST_BYTES`]; [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_post<R: RngCore + CryptoRng>(
        &self,
        post: &ChannelPost,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if post.text.trim().is_empty() || post.text.len() > MAX_POST_BYTES {
            return Err(GasAppError::Malformed);
        }

        let mut content = Vec::with_capacity(post.text.len().saturating_add(16));
        content.extend_from_slice(&post.number.to_be_bytes());
        content.extend_from_slice(&post.created_at_millis.to_be_bytes());
        content.extend_from_slice(post.text.as_bytes());

        self.seal(KIND_POST, &content, rng)
    }

    fn seal<R: RngCore + CryptoRng>(
        &self,
        kind: u8,
        content: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        // 🔐 Случайный nonce при долгоживущем ключе. У GCM это безопасно,
        // пока записей под одним ключом много меньше 2³²; канал с
        // миллиардами записей вне этой модели.
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        // Дополнение до бакета скрывает длину записи от сервера.
        let padded = crate::padding::pad(content)?;
        let ciphertext = aead::seal_with_key(
            &*self.access.read_key()?,
            &nonce,
            &padded,
            &aad(kind, &self.access.channel_id),
        )?;

        let signature = self.signing.sign(&signed_message(
            kind,
            &self.access.channel_id,
            &nonce,
            &ciphertext,
        ));

        let mut wire = Vec::with_capacity(HEADER_LEN.saturating_add(ciphertext.len()));
        wire.push(WIRE_VERSION);
        wire.push(kind);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&signature);
        wire.extend_from_slice(&ciphertext);

        Ok(wire)
    }
}

/// Проверяет название и описание.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — название пустое, что-то длиннее предела
/// либо содержит управляющие символы.
pub fn validate_meta(title: &str, description: &str) -> Result<()> {
    let title_ok = !title.trim().is_empty()
        && title.chars().count() <= MAX_TITLE_CHARS
        && !title.chars().any(char::is_control);

    // В описании перевод строки допустим, прочие управляющие — нет.
    let description_ok = description.chars().count() <= MAX_DESCRIPTION_CHARS
        && !description
            .chars()
            .any(|symbol| symbol.is_control() && symbol != '\n');

    if title_ok && description_ok {
        Ok(())
    } else {
        Err(GasAppError::Malformed)
    }
}

/// Разбирает идентификатор канала из 32 шестнадцатеричных знаков.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — не 32 шестнадцатеричных знака.
pub fn parse_channel_id(text: &str) -> Result<ChannelId> {
    // UUID с дефисами принимается тоже: так его пишет сервер.
    let digits: Vec<u8> = text.bytes().filter(|byte| *byte != b'-').collect();

    if digits.len() != CHANNEL_ID_LEN.saturating_mul(2) {
        return Err(GasAppError::Malformed);
    }

    let mut id = [0u8; CHANNEL_ID_LEN];

    for (slot, pair) in id.iter_mut().zip(digits.chunks_exact(2)) {
        let high = hex_value(*pair.first().ok_or(GasAppError::Malformed)?)?;
        let low = hex_value(*pair.get(1).ok_or(GasAppError::Malformed)?)?;

        *slot = (high << 4) | low;
    }

    Ok(id)
}

/// Идентификатор канала в каноничном виде UUID (`8-4-4-4-12`, строчные).
#[must_use]
pub fn format_uuid(id: &ChannelId) -> String {
    let mut out = String::with_capacity(36);

    for (index, byte) in id.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }

    out
}

fn hex_digit(nibble: u8) -> char {
    char::from(
        *b"0123456789abcdef"
            .get(usize::from(nibble & 0x0f))
            .unwrap_or(&b'0'),
    )
}

fn hex_value(symbol: u8) -> Result<u8> {
    match symbol {
        b'0'..=b'9' => Ok(symbol.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(symbol.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(symbol.saturating_sub(b'A').saturating_add(10)),
        _ => Err(GasAppError::Malformed),
    }
}

/// Делит срез на голову длины `at` и остаток — без паники.
fn split(bytes: &[u8], at: usize) -> Result<(&[u8], &[u8])> {
    if bytes.len() < at {
        return Err(GasAppError::Malformed);
    }

    Ok(bytes.split_at(at))
}

fn text(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| GasAppError::Malformed)
}

/// Связанные данные AEAD: вид записи и канал. Описание не расшифруется
/// как публикация, запись одного канала — как запись другого.
fn aad(kind: u8, channel_id: &ChannelId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len().saturating_add(1 + CHANNEL_ID_LEN));
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(kind);
    aad.extend_from_slice(channel_id);

    aad
}

/// То, что подписывает автор: домен, вид, канал, nonce и шифротекст.
fn signed_message(kind: u8, channel_id: &ChannelId, nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNATURE_DOMAIN
            .len()
            .saturating_add(1 + CHANNEL_ID_LEN + NONCE_LEN)
            .saturating_add(ciphertext.len()),
    );
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.push(kind);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(nonce);
    message.extend_from_slice(ciphertext);

    message
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    fn post(number: u64, text: &str) -> ChannelPost {
        ChannelPost {
            number,
            created_at_millis: 1_700_000_000_000,
            text: text.to_owned(),
        }
    }

    fn meta(title: &str) -> ChannelMeta {
        ChannelMeta {
            title: title.to_owned(),
            description: "Новости и объявления.\nБез спама.".to_owned(),
            updated_at_millis: 1_700_000_000_000,
        }
    }

    #[test]
    fn a_post_round_trips() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let wire = author
            .seal_post(&post(7, "привет, канал"), &mut OsRng)
            .unwrap();

        assert_eq!(
            channel.access.open_post(&wire, 7).unwrap(),
            post(7, "привет, канал")
        );
    }

    #[test]
    fn meta_round_trips() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let wire = author.seal_meta(&meta("Gas News"), &mut OsRng).unwrap();

        assert_eq!(channel.access.open_meta(&wire).unwrap(), meta("Gas News"));
    }

    #[test]
    fn the_link_round_trips() {
        let channel = create(&mut OsRng);
        let uri = channel.access.to_uri();

        assert!(uri.starts_with(LINK_PREFIX));
        assert_eq!(ChannelAccess::parse(&uri).unwrap(), channel.access);
        // Ссылку набирают руками и пересылают с пробелами по краям.
        assert_eq!(
            ChannelAccess::parse(&format!("  {uri}\n")).unwrap(),
            channel.access
        );
    }

    #[test]
    fn foreign_links_are_rejected() {
        let channel = create(&mut OsRng);
        let uri = channel.access.to_uri();

        for bad in [
            String::new(),
            "https://example.org/".to_owned(),
            uri.replace("channel", "contact"),
            format!("{uri}.EXTRA"),
            format!("{uri}?name=x"),
            uri.get(..uri.len() - 3).unwrap().to_owned(),
        ] {
            assert!(ChannelAccess::parse(&bad).is_err(), "{bad:?}");
        }
    }

    /// 🔐 Читатель знает ключ чтения, но записать от имени автора не может.
    #[test]
    fn a_reader_cannot_forge_a_post() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let genuine = author.seal_post(&post(1, "настоящая"), &mut OsRng).unwrap();

        // Читатель собирает свою запись тем же ключом чтения, подписав
        // её собственным ключом.
        let impostor = create(&mut OsRng);
        let forged_access = ChannelAccess {
            verify_key: impostor.access.verify_key,
            ..channel.access.clone()
        };
        let impostor_author = ChannelAuthor::new(&forged_access, impostor.signing_key).unwrap();
        let forged = impostor_author
            .seal_post(&post(1, "подделка"), &mut OsRng)
            .unwrap();

        assert!(matches!(
            channel.access.open_post(&forged, 1),
            Err(GasAppError::InvalidSignature)
        ));
        assert!(channel.access.open_post(&genuine, 1).is_ok());
    }

    /// 🔐 Сервер не переставит записи: номер автора сверяется с номером
    /// сервера.
    #[test]
    fn a_reordered_post_is_rejected() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let wire = author.seal_post(&post(3, "третья"), &mut OsRng).unwrap();

        assert!(matches!(
            channel.access.open_post(&wire, 4),
            Err(GasAppError::InvalidSignature)
        ));
    }

    /// Изменённый шифротекст не проходит.
    #[test]
    fn a_tampered_post_is_rejected() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let mut wire = author.seal_post(&post(1, "текст"), &mut OsRng).unwrap();

        let last = wire.len() - 1;
        wire[last] ^= 0x01;

        assert!(channel.access.open_post(&wire, 1).is_err());
    }

    /// Запись одного канала не читается в другом, описание — как запись.
    #[test]
    fn records_do_not_cross_channels_or_kinds() {
        let first = create(&mut OsRng);
        let second = create(&mut OsRng);
        let author = ChannelAuthor::new(&first.access, first.signing_key).unwrap();

        let wire = author.seal_post(&post(1, "текст"), &mut OsRng).unwrap();
        let described = author.seal_meta(&meta("Канал"), &mut OsRng).unwrap();

        assert!(second.access.open_post(&wire, 1).is_err());
        assert!(first.access.open_meta(&wire).is_err());
        assert!(first.access.open_post(&described, 1).is_err());
    }

    /// Сервер не узнаёт длину записи: короткая и чуть более длинная
    /// дают шифротекст одного размера.
    #[test]
    fn length_is_hidden_within_a_bucket() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let short = author.seal_post(&post(1, "да"), &mut OsRng).unwrap();
        let longer = author
            .seal_post(&post(2, "да, конечно, приходите"), &mut OsRng)
            .unwrap();

        assert_eq!(short.len(), longer.len());
    }

    /// Самая длинная запись укладывается в серверный предел 64 КБ.
    #[test]
    fn the_longest_post_fits_the_server_limit() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let wire = author
            .seal_post(&post(1, &"я".repeat(8_000)), &mut OsRng)
            .unwrap();

        assert!(wire.len() <= 65_536, "{}", wire.len());
        assert!(author
            .seal_post(&post(1, &"a".repeat(MAX_POST_BYTES + 1)), &mut OsRng)
            .is_err());
    }

    #[test]
    fn empty_posts_and_titles_are_refused() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        assert!(author.seal_post(&post(1, "  \n "), &mut OsRng).is_err());
        assert!(author.seal_meta(&meta("  "), &mut OsRng).is_err());
        assert!(author
            .seal_meta(&meta(&"x".repeat(MAX_TITLE_CHARS + 1)), &mut OsRng)
            .is_err());
    }

    /// Ключ подписи от другого канала не принимается.
    #[test]
    fn a_foreign_signing_key_is_refused() {
        let first = create(&mut OsRng);
        let second = create(&mut OsRng);

        assert!(ChannelAuthor::new(&first.access, second.signing_key).is_err());
    }

    #[test]
    fn the_uuid_form_round_trips() {
        let id: ChannelId = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let uuid = format_uuid(&id);

        assert_eq!(uuid, "12345678-9abc-def0-0123-456789abcdef");
        assert_eq!(parse_channel_id(&uuid).unwrap(), id);
    }
}
