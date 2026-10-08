// SPDX-License-Identifier: Apache-2.0

//! Каналы: лента записей одного автора для многих читателей.
//!
//! # Модель
//!
//! Канал похож на канал в Telegram — автор пишет, остальные читают;
//! записи с текстом и медиа, правка, удаление, закреп. Но сервер GasApp
//! остаётся тем же, чем он был: хранилищем шифротекста. Отсюда
//! устройство:
//!
//! * **Ключ чтения** выводится из секрета канала. Секрет лежит в
//!   ссылке-приглашении (`gasapp://channel/…`): название, описание
//!   и записи сервер видит шифротекстом.
//! * **Ключ подписи** (Ed25519) есть только у владельца. Публичная
//!   половина тоже лежит в ссылке, и читатель проверяет ею описание
//!   канала. Читатели знают ключ чтения, но изменить канал от имени
//!   автора не могут.
//! * **Администраторы** подписывают записи своими ключами. Чьи ключи
//!   годятся, сказано в описании канала, а его подписывает только
//!   владелец: каждая запись несёт ключ подписавшего, и читатель
//!   принимает её, если это ключ владельца либо администратора из
//!   списка. Снятому администратору владелец ставит границу — номер
//!   последней записи на момент снятия: записи с большим номером под
//!   его ключом не принимаются.
//! * **Номер записи** автор кладёт внутрь шифротекста. Сервер нумерует
//!   записи сам, и читатель сверяет оба номера: переставить записи
//!   местами или выдать одну за другую сервер не может.
//! * **Номер редакции** растёт с каждой правкой. Читатель не принимает
//!   редакцию старше известной: сервер не вернёт прежний текст.
//! * **Удаление** — отдельная запись, подписанная автором. Сервер не
//!   может «удалить» запись у читателей сам: без подписи автора
//!   отметка не принимается.
//!
//! Медиа (фото, файлы, аватар канала) шифруются так же, как вложения
//! в переписке (`gasapp-media`): случайным ключом, чанками. В записи
//! лежит описание — адрес блоба, ключ, размер. Сам модуль описаний не
//! разбирает: для него это непрозрачные байты.
//!
//! # 🔐 Чего это НЕ даёт — честно
//!
//! * **Это не сквозное шифрование переписки.** Ключ чтения один на всех
//!   и не меняется: кто получил ссылку, читает весь канал — прошлые
//!   записи и будущие. Отозвать доступ у одного читателя нельзя;
//!   утёкшая ссылка — утёкший канал. Прямой секретности и
//!   восстановления после компрометации здесь нет.
//! * **Публичный канал сервер читает.** Чтобы канал находился по
//!   `@имени`, автор отдаёт серверу ссылку. Подлинность записей от
//!   этого не страдает — ключа подписи у сервера по-прежнему нет.
//! * **Сервер может утаить записи**: не отдать последние, не отдать
//!   правку или отметку об удалении. Подделать, изменить или
//!   переставить — нет.
//! * **Удалённое остаётся у тех, кто успел загрузить** — как в любом
//!   канале.
//! * **Снятый администратор в сговоре с сервером** может переписать
//!   записи, вышедшие до его снятия: его ключ остаётся годным для их
//!   номеров, иначе они перестали бы читаться. Новых записей под его
//!   ключом читатели не примут. Ключ владельца отозвать нельзя вовсе.
//! * **Пост-квантовой защиты подлинности нет**: подпись автора —
//!   Ed25519. Конфиденциальность (AES-256-GCM на симметричном ключе)
//!   от квантового противника не страдает.
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
/// Запись дополняется до бакета (`padding`), и вместе с подписью
/// и описаниями вложений обязана уложиться в серверный предел 64 КБ:
/// 16 000 байт текста и десять описаний попадают в бакет 32 КБ.
pub const MAX_POST_BYTES: usize = 16_000;

/// Сколько вложений может нести одна запись.
pub const MAX_POST_ATTACHMENTS: usize = 10;

/// Предел одного описания вложения, в байтах.
///
/// Описание — адрес, ключ, размер, имя (до 255 байт), подпись для
/// незрячих. Килобайта хватает с запасом; больше — не описание.
pub const MAX_ATTACHMENT_DESCRIPTOR_BYTES: usize = 1_024;

/// Версия формата записи.
const WIRE_VERSION: u8 = 2;

/// Вид записи: описание канала.
const KIND_META: u8 = 1;

/// Вид записи: публикация.
const KIND_POST: u8 = 2;

/// Вид записи: отметка об удалении публикации.
const KIND_TOMBSTONE: u8 = 3;

/// Длина публичного ключа подписавшего в заголовке.
const SIGNER_LEN: usize = 32;

/// Заголовок провода: версия, вид, ключ подписавшего, nonce, подпись.
const HEADER_LEN: usize = 2 + SIGNER_LEN + NONCE_LEN + SIGNATURE_LEN;

/// Сколько администраторов — действующих и снятых — помнит описание
/// канала.
///
/// Снятые остаются в списке: без них их прежние записи перестали бы
/// приниматься. Предел держит описание в серверных 16 КБ.
pub const MAX_ADMINS: usize = 16;

/// Схема и путь заявки на администрирование.
pub const ADMIN_REQUEST_PREFIX: &str = "gasapp://channel-admin/";

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
    /// Номер закреплённой записи; `0` — закрепа нет.
    pub pinned: u64,
    /// Описание вложения с аватаром канала; пусто — аватара нет.
    pub avatar: Vec<u8>,
    /// Администраторы: чьи ключи, кроме ключа владельца, подписывают
    /// записи. Не больше [`MAX_ADMINS`].
    pub admins: Vec<ChannelAdmin>,
}

/// Администратор канала в описании, подписанном владельцем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelAdmin {
    /// Публичный ключ, которым администратор подписывает записи.
    pub verify_key: PublicKeyBytes,
    /// `None` — действующий. `Some(n)` — снят: его ключ годится только
    /// для записей с номером не больше `n`.
    pub until: Option<u64>,
}

impl ChannelAdmin {
    /// Годится ли ключ этого администратора для записи с таким номером.
    #[must_use]
    pub fn covers(&self, number: u64) -> bool {
        self.until.is_none_or(|until| number <= until)
    }
}

/// Заявка на администрирование: то, что будущий администратор
/// показывает владельцу канала.
///
/// В ней нет секретов: публичный ключ, которым он будет подписывать
/// записи, и устройство, которому сервер разрешит публиковать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminRequest {
    /// Канал, в который просятся.
    pub channel_id: ChannelId,
    /// Публичный ключ подписи будущего администратора.
    pub verify_key: PublicKeyBytes,
    /// Его устройство — по нему сервер находит аккаунт.
    pub device_id: [u8; 16],
}

impl AdminRequest {
    /// Заявка в виде строки — для QR-кода и копирования.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut uri = String::with_capacity(ADMIN_REQUEST_PREFIX.len().saturating_add(120));
        uri.push_str(ADMIN_REQUEST_PREFIX);
        push_hex(&mut uri, &self.channel_id);
        uri.push('.');
        uri.push_str(&crate::contact_link::encode_base32(
            self.verify_key.as_bytes(),
        ));
        uri.push('.');
        push_hex(&mut uri, &self.device_id);

        uri
    }

    /// Разбирает заявку.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — это не заявка на администрирование.
    pub fn parse(input: &str) -> Result<Self> {
        let rest = input
            .trim()
            .strip_prefix(ADMIN_REQUEST_PREFIX)
            .ok_or(GasAppError::Malformed)?;

        let mut parts = rest.split('.');
        let channel = parts.next().ok_or(GasAppError::Malformed)?;
        let key = parts.next().ok_or(GasAppError::Malformed)?;
        let device = parts.next().ok_or(GasAppError::Malformed)?;

        if parts.next().is_some() {
            return Err(GasAppError::Malformed);
        }

        Ok(Self {
            channel_id: parse_channel_id(channel)?,
            verify_key: PublicKeyBytes::new(crate::contact_link::decode_key(key)?),
            device_id: parse_channel_id(device)?,
        })
    }
}

/// Запись канала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPost {
    /// Номер записи, который назначил автор. Обязан совпасть с номером
    /// сервера — сверяет [`ChannelAccess::open_post`].
    pub number: u64,
    /// Номер редакции: `0` у только что опубликованной записи, растёт
    /// с каждой правкой.
    pub revision: u32,
    /// Время публикации по часам автора, миллисекунды эпохи.
    pub created_at_millis: i64,
    /// Время последней правки; `0` — запись не правили.
    pub edited_at_millis: i64,
    /// Текст. Может быть пустым, если есть вложения.
    pub text: String,
    /// Описания вложений (`gasapp_media::descriptor`), как есть.
    pub attachments: Vec<Vec<u8>>,
}

/// Отметка об удалении записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelTombstone {
    /// Номер удалённой записи.
    pub number: u64,
    /// Номер редакции: больше, чем у любой редакции самой записи.
    pub revision: u32,
    /// Когда автор удалил запись, миллисекунды эпохи.
    pub deleted_at_millis: i64,
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
        // 🔐 Описание — только от владельца: в нём список тех, кому
        // верить. Администратор, подписавший описание, вписал бы в
        // администраторы кого угодно.
        let (content, _) = self.open(KIND_META, wire, &[])?;
        let mut reader = Reader::new(&content);

        let updated_at_millis = reader.i64()?;
        let title = text(reader.block16()?)?;
        let description = text(reader.block16()?)?;
        let pinned = reader.u64()?;
        let avatar = reader.block16()?.to_vec();

        let count = usize::from(reader.u8()?);
        if count > MAX_ADMINS {
            return Err(GasAppError::Malformed);
        }

        let mut admins = Vec::with_capacity(count);
        for _ in 0..count {
            let verify_key = PublicKeyBytes::new(
                reader
                    .take(SIGNER_LEN)?
                    .try_into()
                    .map_err(|_| GasAppError::Malformed)?,
            );
            let active = match reader.u8()? {
                1 => true,
                0 => false,
                _ => return Err(GasAppError::Malformed),
            };
            let until = reader.u64()?;

            admins.push(ChannelAdmin {
                verify_key,
                until: (!active).then_some(until),
            });
        }
        reader.finish()?;

        let meta = ChannelMeta {
            title,
            description,
            updated_at_millis,
            pinned,
            avatar,
            admins,
        };

        validate_meta(&meta.title, &meta.description)?;

        if meta.avatar.len() > MAX_ATTACHMENT_DESCRIPTOR_BYTES {
            return Err(GasAppError::Malformed);
        }

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
    pub fn open_post(
        &self,
        wire: &[u8],
        server_seq: u64,
        admins: &[ChannelAdmin],
    ) -> Result<ChannelPost> {
        let (content, signer) = self.open(KIND_POST, wire, admins)?;
        let mut reader = Reader::new(&content);

        let number = reader.u64()?;
        let revision = reader.u32()?;
        let created_at_millis = reader.i64()?;
        let edited_at_millis = reader.i64()?;
        let body = text(reader.block32()?)?;

        let count = usize::from(reader.u8()?);
        if count > MAX_POST_ATTACHMENTS {
            return Err(GasAppError::Malformed);
        }

        let mut attachments = Vec::with_capacity(count);
        for _ in 0..count {
            let descriptor = reader.block16()?;
            if descriptor.is_empty() || descriptor.len() > MAX_ATTACHMENT_DESCRIPTOR_BYTES {
                return Err(GasAppError::Malformed);
            }
            attachments.push(descriptor.to_vec());
        }
        reader.finish()?;

        // 🔐 Подпись верна, но запись стоит не на своём месте: сервер
        // выдал её под чужим номером. Либо её подписал администратор,
        // снятый раньше, чем появился этот номер.
        if number != server_seq || !self.may_sign(&signer, number, admins) {
            return Err(GasAppError::InvalidSignature);
        }

        let post = ChannelPost {
            number,
            revision,
            created_at_millis,
            edited_at_millis,
            text: body,
            attachments,
        };
        validate_post(&post)?;

        Ok(post)
    }

    /// Расшифровывает и проверяет отметку об удалении записи
    /// `server_seq`.
    ///
    /// # Errors
    ///
    /// Те же, что у [`ChannelAccess::open_post`].
    pub fn open_tombstone(
        &self,
        wire: &[u8],
        server_seq: u64,
        admins: &[ChannelAdmin],
    ) -> Result<ChannelTombstone> {
        let (content, signer) = self.open(KIND_TOMBSTONE, wire, admins)?;
        let mut reader = Reader::new(&content);

        let tombstone = ChannelTombstone {
            number: reader.u64()?,
            revision: reader.u32()?,
            deleted_at_millis: reader.i64()?,
        };
        reader.finish()?;

        // 🔐 Отметка об удалении одной записи не удаляет другую, и
        // снятый администратор не удаляет записи, вышедшие после него.
        if tombstone.number != server_seq || !self.may_sign(&signer, tombstone.number, admins) {
            return Err(GasAppError::InvalidSignature);
        }

        Ok(tombstone)
    }

    /// Годится ли ключ `signer` для записи с номером `number`: это
    /// ключ владельца либо администратора, чья граница её покрывает.
    fn may_sign(&self, signer: &PublicKeyBytes, number: u64, admins: &[ChannelAdmin]) -> bool {
        *signer == self.verify_key
            || admins
                .iter()
                .any(|admin| admin.verify_key == *signer && admin.covers(number))
    }

    /// Проверяет подпись и расшифровывает содержимое; возвращает его
    /// вместе с ключом подписавшего.
    ///
    /// Подписавший обязан быть владельцем либо одним из `admins` — без
    /// оглядки на границу снятия: её сверяет вызывающий, когда узнаёт
    /// номер записи из расшифрованного.
    fn open(
        &self,
        kind: u8,
        wire: &[u8],
        admins: &[ChannelAdmin],
    ) -> Result<(Vec<u8>, PublicKeyBytes)> {
        let (header, ciphertext) = split(wire, HEADER_LEN)?;
        let (prefix, rest) = split(header, 2)?;
        let (signer, rest) = split(rest, SIGNER_LEN)?;
        let (nonce, signature) = split(rest, NONCE_LEN)?;

        if prefix != [WIRE_VERSION, kind] {
            return Err(GasAppError::Malformed);
        }

        let signer = PublicKeyBytes::new(signer.try_into().map_err(|_| GasAppError::Malformed)?);

        // 🔐 Ключ в записи назвал тот, кто её прислал. Сама по себе
        // верная подпись под ним ничего не значит: записью считается
        // только подписанное владельцем либо тем, кого владелец назвал.
        if signer != self.verify_key && !admins.iter().any(|admin| admin.verify_key == signer) {
            return Err(GasAppError::InvalidSignature);
        }

        // Подпись — раньше расшифровки: чужой шифротекст до AEAD не доходит.
        XEdDSAPublicKey::from_bytes(signer)
            .and_then(|key| {
                key.verify_strict(
                    &signed_message(kind, &self.channel_id, &signer, nonce, ciphertext),
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

        Ok((crate::padding::unpad(&padded)?.to_vec(), signer))
    }
}

/// Тот, кто пишет в канал, — владелец либо администратор: доступ
/// читателя плюс свой ключ подписи.
pub struct ChannelAuthor<'a> {
    access: &'a ChannelAccess,
    signing: XEdDSAPrivateKey,
}

/// Новая пара подписи для администратора: приватная половина остаётся
/// на его устройстве, публичная уходит владельцу в заявке.
pub fn admin_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (PrivateKeyBytes, PublicKeyBytes) {
    let signing = XEdDSAPrivateKey::generate(rng);

    (signing.expose_secret(), signing.public_key().as_bytes())
}

/// Публичная половина сохранённого ключа подписи.
///
/// # Errors
///
/// [`GasAppError::Crypto`] — это не ключ подписи.
pub fn verify_key_of(signing_key: PrivateKeyBytes) -> Result<PublicKeyBytes> {
    Ok(XEdDSAPrivateKey::from_bytes(signing_key)?
        .public_key()
        .as_bytes())
}

impl<'a> ChannelAuthor<'a> {
    /// Собирает автора из сохранённого ключа подписи — владельца либо
    /// администратора. Примут ли читатели подписанное этим ключом,
    /// решает описание канала, а не эта функция.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — это не ключ подписи.
    pub fn new(access: &'a ChannelAccess, signing_key: PrivateKeyBytes) -> Result<Self> {
        Ok(Self {
            access,
            signing: XEdDSAPrivateKey::from_bytes(signing_key)?,
        })
    }

    /// Публичный ключ, которым подписывает этот автор.
    #[must_use]
    pub fn verify_key(&self) -> PublicKeyBytes {
        self.signing.public_key().as_bytes()
    }

    /// Владелец ли это: его ли ключ лежит в ссылке канала.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.verify_key() == self.access.verify_key
    }

    /// Шифрует и подписывает описание канала.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Forbidden`] — описание подписывает только
    /// владелец; [`GasAppError::Malformed`] — название пустое либо
    /// что-то длиннее предела; [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_meta<R: RngCore + CryptoRng>(
        &self,
        meta: &ChannelMeta,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if !self.is_owner() {
            return Err(GasAppError::Forbidden);
        }

        validate_meta(&meta.title, &meta.description)?;

        if meta.avatar.len() > MAX_ATTACHMENT_DESCRIPTOR_BYTES || meta.admins.len() > MAX_ADMINS {
            return Err(GasAppError::Malformed);
        }

        let mut content = Vec::with_capacity(
            meta.title
                .len()
                .saturating_add(meta.description.len())
                .saturating_add(meta.avatar.len())
                .saturating_add(32),
        );
        content.extend_from_slice(&meta.updated_at_millis.to_be_bytes());
        put_block16(&mut content, meta.title.as_bytes())?;
        put_block16(&mut content, meta.description.as_bytes())?;
        content.extend_from_slice(&meta.pinned.to_be_bytes());
        put_block16(&mut content, &meta.avatar)?;
        content.push(u8::try_from(meta.admins.len()).map_err(|_| GasAppError::Malformed)?);
        for admin in &meta.admins {
            content.extend_from_slice(admin.verify_key.as_bytes());
            content.push(u8::from(admin.until.is_none()));
            content.extend_from_slice(&admin.until.unwrap_or(0).to_be_bytes());
        }

        self.seal(KIND_META, &content, rng)
    }

    /// Шифрует и подписывает запись — новую или исправленную.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — запись пуста (ни текста, ни
    /// вложений) либо что-то длиннее предела;
    /// [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_post<R: RngCore + CryptoRng>(
        &self,
        post: &ChannelPost,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        validate_post(post)?;

        let attachments: usize = post.attachments.iter().map(Vec::len).sum();
        let mut content = Vec::with_capacity(
            post.text
                .len()
                .saturating_add(attachments)
                .saturating_add(64),
        );
        content.extend_from_slice(&post.number.to_be_bytes());
        content.extend_from_slice(&post.revision.to_be_bytes());
        content.extend_from_slice(&post.created_at_millis.to_be_bytes());
        content.extend_from_slice(&post.edited_at_millis.to_be_bytes());
        content.extend_from_slice(
            &u32::try_from(post.text.len())
                .map_err(|_| GasAppError::Malformed)?
                .to_be_bytes(),
        );
        content.extend_from_slice(post.text.as_bytes());
        content.push(u8::try_from(post.attachments.len()).map_err(|_| GasAppError::Malformed)?);
        for descriptor in &post.attachments {
            put_block16(&mut content, descriptor)?;
        }

        self.seal(KIND_POST, &content, rng)
    }

    /// Шифрует и подписывает отметку об удалении записи.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] — сбой шифрования.
    pub fn seal_tombstone<R: RngCore + CryptoRng>(
        &self,
        tombstone: &ChannelTombstone,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut content = Vec::with_capacity(20);
        content.extend_from_slice(&tombstone.number.to_be_bytes());
        content.extend_from_slice(&tombstone.revision.to_be_bytes());
        content.extend_from_slice(&tombstone.deleted_at_millis.to_be_bytes());

        self.seal(KIND_TOMBSTONE, &content, rng)
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

        let signer = self.verify_key();
        let signature = self.signing.sign(&signed_message(
            kind,
            &self.access.channel_id,
            &signer,
            &nonce,
            &ciphertext,
        ));

        let mut wire = Vec::with_capacity(HEADER_LEN.saturating_add(ciphertext.len()));
        wire.push(WIRE_VERSION);
        wire.push(kind);
        wire.extend_from_slice(signer.as_bytes());
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

/// Проверяет запись: не пуста и укладывается в пределы.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — нет ни текста, ни вложений, либо
/// превышен один из пределов.
pub fn validate_post(post: &ChannelPost) -> Result<()> {
    let has_text = !post.text.trim().is_empty();

    let attachments_ok = post.attachments.len() <= MAX_POST_ATTACHMENTS
        && post.attachments.iter().all(|descriptor| {
            !descriptor.is_empty() && descriptor.len() <= MAX_ATTACHMENT_DESCRIPTOR_BYTES
        });

    if (has_text || !post.attachments.is_empty())
        && post.text.len() <= MAX_POST_BYTES
        && attachments_ok
    {
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

pub(crate) fn push_hex(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
}

fn hex_digit(nibble: u8) -> char {
    char::from(
        *b"0123456789abcdef"
            .get(usize::from(nibble & 0x0f))
            .unwrap_or(&b'0'),
    )
}

pub(crate) fn hex_value(symbol: u8) -> Result<u8> {
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

/// Дописывает блок с двухбайтовой длиной впереди.
fn put_block16(out: &mut Vec<u8>, block: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u16::try_from(block.len())
            .map_err(|_| GasAppError::Malformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(block);

    Ok(())
}

/// Последовательное чтение содержимого записи — без паники на
/// обрезанных данных.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, tail) = split(self.rest, len)?;
        self.rest = tail;

        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or(GasAppError::Malformed)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        ))
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        ))
    }

    /// Блок с двухбайтовой длиной впереди.
    fn block16(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);

        self.take(len)
    }

    /// Блок с четырёхбайтовой длиной впереди.
    fn block32(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| GasAppError::Malformed)?;

        self.take(len)
    }

    /// Содержимое прочитано целиком: хвоста, который автор не
    /// описывал, быть не должно.
    fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(GasAppError::Malformed)
        }
    }
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

/// То, что подписывает автор: домен, вид, канал, ключ подписавшего,
/// nonce и шифротекст.
fn signed_message(
    kind: u8,
    channel_id: &ChannelId,
    signer: &PublicKeyBytes,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNATURE_DOMAIN
            .len()
            .saturating_add(1 + CHANNEL_ID_LEN + SIGNER_LEN + NONCE_LEN)
            .saturating_add(ciphertext.len()),
    );
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.push(kind);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(signer.as_bytes());
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
            revision: 0,
            created_at_millis: 1_700_000_000_000,
            edited_at_millis: 0,
            text: text.to_owned(),
            attachments: Vec::new(),
        }
    }

    fn meta(title: &str) -> ChannelMeta {
        ChannelMeta {
            title: title.to_owned(),
            description: "Новости и объявления.\nБез спама.".to_owned(),
            updated_at_millis: 1_700_000_000_000,
            pinned: 0,
            avatar: Vec::new(),
            admins: Vec::new(),
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
            channel.access.open_post(&wire, 7, &[]).unwrap(),
            post(7, "привет, канал")
        );
    }

    /// Запись с вложениями и без текста — законная запись (фото).
    #[test]
    fn a_post_with_attachments_round_trips() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let photo = ChannelPost {
            revision: 3,
            edited_at_millis: 1_700_000_100_000,
            text: String::new(),
            attachments: vec![vec![1, 2, 3], vec![9; 400]],
            ..post(2, "")
        };
        let wire = author.seal_post(&photo, &mut OsRng).unwrap();

        assert_eq!(channel.access.open_post(&wire, 2, &[]).unwrap(), photo);
    }

    #[test]
    fn meta_round_trips() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let described = ChannelMeta {
            pinned: 12,
            avatar: vec![5; 120],
            ..meta("Gas News")
        };
        let wire = author.seal_meta(&described, &mut OsRng).unwrap();

        assert_eq!(channel.access.open_meta(&wire).unwrap(), described);
    }

    #[test]
    fn a_tombstone_round_trips() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let tombstone = ChannelTombstone {
            number: 4,
            revision: 2,
            deleted_at_millis: 1_700_000_200_000,
        };

        let wire = author.seal_tombstone(&tombstone, &mut OsRng).unwrap();

        assert_eq!(
            channel.access.open_tombstone(&wire, 4, &[]).unwrap(),
            tombstone
        );
    }

    /// 🔐 Отметка об удалении одной записи не удаляет другую, и запись
    /// не выдаётся за отметку.
    #[test]
    fn a_tombstone_is_bound_to_its_post() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let wire = author
            .seal_tombstone(
                &ChannelTombstone {
                    number: 4,
                    revision: 1,
                    deleted_at_millis: 0,
                },
                &mut OsRng,
            )
            .unwrap();
        let live = author.seal_post(&post(5, "живая"), &mut OsRng).unwrap();

        assert!(matches!(
            channel.access.open_tombstone(&wire, 5, &[]),
            Err(GasAppError::InvalidSignature)
        ));
        assert!(channel.access.open_tombstone(&live, 5, &[]).is_err());
        assert!(channel.access.open_post(&wire, 4, &[]).is_err());
    }

    /// 🔐 Читатель знает ключ чтения, но удалить запись за автора не может.
    #[test]
    fn a_reader_cannot_forge_a_tombstone() {
        let channel = create(&mut OsRng);
        let impostor = create(&mut OsRng);
        let forged_access = ChannelAccess {
            verify_key: impostor.access.verify_key,
            ..channel.access.clone()
        };
        let impostor_author = ChannelAuthor::new(&forged_access, impostor.signing_key).unwrap();
        let forged = impostor_author
            .seal_tombstone(
                &ChannelTombstone {
                    number: 1,
                    revision: 9,
                    deleted_at_millis: 0,
                },
                &mut OsRng,
            )
            .unwrap();

        assert!(matches!(
            channel.access.open_tombstone(&forged, 1, &[]),
            Err(GasAppError::InvalidSignature)
        ));
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
            channel.access.open_post(&forged, 1, &[]),
            Err(GasAppError::InvalidSignature)
        ));
        assert!(channel.access.open_post(&genuine, 1, &[]).is_ok());
    }

    /// 🔐 Сервер не переставит записи: номер автора сверяется с номером
    /// сервера.
    #[test]
    fn a_reordered_post_is_rejected() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let wire = author.seal_post(&post(3, "третья"), &mut OsRng).unwrap();

        assert!(matches!(
            channel.access.open_post(&wire, 4, &[]),
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

        assert!(channel.access.open_post(&wire, 1, &[]).is_err());
    }

    /// Запись одного канала не читается в другом, описание — как запись.
    #[test]
    fn records_do_not_cross_channels_or_kinds() {
        let first = create(&mut OsRng);
        let second = create(&mut OsRng);
        let author = ChannelAuthor::new(&first.access, first.signing_key).unwrap();

        let wire = author.seal_post(&post(1, "текст"), &mut OsRng).unwrap();
        let described = author.seal_meta(&meta("Канал"), &mut OsRng).unwrap();

        assert!(second.access.open_post(&wire, 1, &[]).is_err());
        assert!(first.access.open_meta(&wire).is_err());
        assert!(first.access.open_post(&described, 1, &[]).is_err());
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

    /// Самая большая запись — предельный текст и десять предельных
    /// описаний — укладывается в серверный предел 64 КБ.
    #[test]
    fn the_largest_post_fits_the_server_limit() {
        let channel = create(&mut OsRng);
        let author = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let largest = ChannelPost {
            text: "я".repeat(8_000),
            attachments: vec![vec![7; MAX_ATTACHMENT_DESCRIPTOR_BYTES]; MAX_POST_ATTACHMENTS],
            ..post(1, "")
        };
        let wire = author.seal_post(&largest, &mut OsRng).unwrap();

        assert!(wire.len() <= 65_536, "{}", wire.len());
        assert_eq!(channel.access.open_post(&wire, 1, &[]).unwrap(), largest);

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

        let crowded = ChannelPost {
            attachments: vec![vec![1]; MAX_POST_ATTACHMENTS + 1],
            ..post(1, "много")
        };
        assert!(author.seal_post(&crowded, &mut OsRng).is_err());
    }

    /// Чужой ключ подписи собрать автора даёт, но читатели подписанное
    /// им не принимают: такого ключа нет ни у владельца, ни в списке.
    #[test]
    fn a_foreign_signing_key_signs_nothing_readers_accept() {
        let first = create(&mut OsRng);
        let second = create(&mut OsRng);
        let stranger = ChannelAuthor::new(&first.access, second.signing_key).unwrap();

        assert!(!stranger.is_owner());
        assert!(matches!(
            stranger.seal_meta(&meta("Чужое"), &mut OsRng),
            Err(GasAppError::Forbidden)
        ));

        let wire = stranger.seal_post(&post(1, "чужая"), &mut OsRng).unwrap();
        assert!(matches!(
            first.access.open_post(&wire, 1, &[]),
            Err(GasAppError::InvalidSignature)
        ));
    }

    fn admin_of(access: &ChannelAccess) -> (ChannelAuthor<'_>, ChannelAdmin) {
        let (signing_key, verify_key) = admin_keypair(&mut OsRng);

        (
            ChannelAuthor::new(access, signing_key).unwrap(),
            ChannelAdmin {
                verify_key,
                until: None,
            },
        )
    }

    /// Администратор из списка владельца пишет, правит и удаляет.
    #[test]
    fn a_listed_admin_posts_and_deletes() {
        let channel = create(&mut OsRng);
        let (admin, entry) = admin_of(&channel.access);

        let wire = admin.seal_post(&post(4, "от админа"), &mut OsRng).unwrap();
        let mark = admin
            .seal_tombstone(
                &ChannelTombstone {
                    number: 4,
                    revision: 1,
                    deleted_at_millis: 0,
                },
                &mut OsRng,
            )
            .unwrap();

        assert_eq!(
            channel.access.open_post(&wire, 4, &[entry]).unwrap().text,
            "от админа"
        );
        assert!(channel.access.open_tombstone(&mark, 4, &[entry]).is_ok());

        // Без списка — никто.
        assert!(matches!(
            channel.access.open_post(&wire, 4, &[]),
            Err(GasAppError::InvalidSignature)
        ));
        assert!(channel.access.open_tombstone(&mark, 4, &[]).is_err());
    }

    /// 🔐 Снятый администратор: прежние записи читаются, новые — нет.
    #[test]
    fn a_removed_admin_cannot_sign_later_posts() {
        let channel = create(&mut OsRng);
        let (admin, entry) = admin_of(&channel.access);
        let removed = ChannelAdmin {
            until: Some(5),
            ..entry
        };

        let old = admin.seal_post(&post(5, "до снятия"), &mut OsRng).unwrap();
        let new = admin.seal_post(&post(6, "после"), &mut OsRng).unwrap();
        let mark = admin
            .seal_tombstone(
                &ChannelTombstone {
                    number: 6,
                    revision: 1,
                    deleted_at_millis: 0,
                },
                &mut OsRng,
            )
            .unwrap();

        assert!(channel.access.open_post(&old, 5, &[removed]).is_ok());
        assert!(matches!(
            channel.access.open_post(&new, 6, &[removed]),
            Err(GasAppError::InvalidSignature)
        ));
        assert!(matches!(
            channel.access.open_tombstone(&mark, 6, &[removed]),
            Err(GasAppError::InvalidSignature)
        ));
    }

    /// 🔐 Описание подписывает только владелец: администратор не
    /// впишет в список сам себя или кого-то ещё.
    #[test]
    fn only_the_owner_signs_the_admin_list() {
        let channel = create(&mut OsRng);
        let owner = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();
        let (admin, entry) = admin_of(&channel.access);

        let listed = ChannelMeta {
            admins: vec![
                entry,
                ChannelAdmin {
                    verify_key: PublicKeyBytes::new([7; 32]),
                    until: Some(42),
                },
            ],
            ..meta("Канал")
        };
        let wire = owner.seal_meta(&listed, &mut OsRng).unwrap();
        assert_eq!(channel.access.open_meta(&wire).unwrap(), listed);

        assert!(matches!(
            admin.seal_meta(&listed, &mut OsRng),
            Err(GasAppError::Forbidden)
        ));

        let crowded = ChannelMeta {
            admins: vec![entry; MAX_ADMINS + 1],
            ..meta("Канал")
        };
        assert!(owner.seal_meta(&crowded, &mut OsRng).is_err());
    }

    /// Самое большое описание укладывается в серверный предел 16 КБ.
    #[test]
    fn the_largest_meta_fits_the_server_limit() {
        let channel = create(&mut OsRng);
        let owner = ChannelAuthor::new(&channel.access, channel.signing_key).unwrap();

        let largest = ChannelMeta {
            title: "я".repeat(MAX_TITLE_CHARS),
            description: "я".repeat(MAX_DESCRIPTION_CHARS),
            updated_at_millis: 1,
            pinned: u64::MAX,
            avatar: vec![1; MAX_ATTACHMENT_DESCRIPTOR_BYTES],
            admins: vec![
                ChannelAdmin {
                    verify_key: PublicKeyBytes::new([9; 32]),
                    until: Some(u64::MAX),
                };
                MAX_ADMINS
            ],
        };
        let wire = owner.seal_meta(&largest, &mut OsRng).unwrap();

        assert!(wire.len() <= 16_384, "{}", wire.len());
        assert_eq!(channel.access.open_meta(&wire).unwrap(), largest);
    }

    #[test]
    fn an_admin_request_round_trips() {
        let request = AdminRequest {
            channel_id: [0xab; 16],
            verify_key: PublicKeyBytes::new([0x11; 32]),
            device_id: [0xcd; 16],
        };
        let uri = request.to_uri();

        assert!(uri.starts_with(ADMIN_REQUEST_PREFIX));
        assert_eq!(AdminRequest::parse(&format!(" {uri}\n")).unwrap(), request);

        for bad in [
            String::new(),
            uri.replace("channel-admin", "channel"),
            format!("{uri}.x"),
            uri.get(..uri.len() - 2).unwrap().to_owned(),
        ] {
            assert!(AdminRequest::parse(&bad).is_err(), "{bad:?}");
        }
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
