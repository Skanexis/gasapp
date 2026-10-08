// SPDX-License-Identifier: Apache-2.0

//! Backup bundle: что именно попадает в резервную копию.
//!
//! # 🔐 Чего здесь нет и почему
//!
//! В бандле **нет полей** для состояния храповика, приватного
//! identity-ключа и секретов предключей. Это не забывчивость,
//! а решение раздела 12.5, закреплённое формой типов: положить
//! ratchet state в копию нельзя, потому что его некуда положить.
//!
//! Причина в том, что старая копия содержит **старое** состояние
//! храповика. Восстановление из неё вернуло бы устройство к уже
//! использованным message key — то есть два разных сообщения
//! зашифровались бы одним ключом. В AEAD это раскрывает не только
//! оба открытых текста, но и подключ аутентификации: подделка тегов
//! становится возможной. Цена отказа — собеседники увидят
//! «safety number changed» после восстановления, и это правильное
//! поведение, которое объясняет отдельный экран.
//!
//! Приватного identity-ключа тут нет по той же логике: у каждого
//! устройства своя identity (раздел 13.1), и восстановление
//! на новом устройстве заводит новую, а не копирует старую.
//!
//! # Что здесь есть
//!
//! История сообщений — **открытым текстом**, как она лежит внутри базы
//! (шифрует её SQLCipher, а в копии — шифрование копии целиком ключом
//! восстановления), контакты с их identity-ключами и отметками
//! верификации, состояния чатов, метаданные вложений и настройки.
//! Плюс **надгробия** удалённых сообщений — см. [`BackupBundle::tombstones`].
//!
//! # Про разбор
//!
//! 🔐 Файл копии приходит из облака или с диска, то есть его
//! содержимое подконтрольно кому угодно. Тег AEAD доказывает,
//! что файл собран владельцем recovery key, но не то, что бандл
//! внутри осмыслен: копия могла быть собрана сломанной версией
//! приложения. Поэтому каждая длина сверяется с остатком буфера,
//! а число записей и размеры полей ограничены сверху — иначе
//! заголовок «здесь миллиард сообщений» съел бы память
//! до первой осмысленной проверки.

use gasapp_types::{GasAppError, Result};

/// Версия формата бандла.
///
/// 2 — добавлен секрет ключа восстановления аккаунта (в конце).
/// 3 — добавлены каналы (в конце).
/// Бандлы версий 1 и 2 читаются: недостающего в них просто нет.
const BUNDLE_VERSION: u8 = 3;

/// Версия с секретом восстановления аккаунта, но без каналов.
const BUNDLE_VERSION_2: u8 = 2;

/// Первая версия: без секрета восстановления аккаунта.
const BUNDLE_VERSION_1: u8 = 1;

/// Длина ключей и секретов канала.
const CHANNEL_KEY_LEN: usize = 32;

/// Сколько каналов и подписей к администраторам вмещает копия.
const MAX_CHANNELS: usize = 4_096;

/// Длина секрета ключа восстановления аккаунта.
pub const ACCOUNT_RECOVERY_LEN: usize = 64;

/// 🔐 Секрет ключа восстановления аккаунта
/// (`gasapp_protocol::account_recovery`).
///
/// Им новая установка, восстановив копию, возвращает себе аккаунт
/// с прежним именем. Не identity-ключ: тот между устройствами
/// не копируется. `Debug` не печатает содержимое.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountRecoverySecret(pub [u8; ACCOUNT_RECOVERY_LEN]);

impl core::fmt::Debug for AccountRecoverySecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AccountRecoverySecret(<скрыто>)")
    }
}

impl Drop for AccountRecoverySecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Метка присутствия необязательного поля.
const PRESENT: u8 = 1;

/// Метка отсутствия.
const ABSENT: u8 = 0;

/// Длина идентификатора: UUID в 16 байт.
pub const ID_LEN: usize = 16;

/// Предел числа записей одной категории.
///
/// Миллион сообщений — заведомо больше, чем бывает у человека,
/// и заведомо меньше, чем нужно, чтобы исчерпать память телефона
/// при разборе.
pub const MAX_RECORDS: usize = 1_000_000;

/// Предел длины одного поля переменной длины.
pub const MAX_FIELD_LEN: usize = 16 * 1024 * 1024;

/// Предел длины строки в символах.
pub const MAX_STRING_LEN: usize = 1024;

/// Сообщение в копии.
///
/// Содержимое — открытый текст, ровно так же, как внутри базы.
///
/// ⚠️ Прежде здесь было написано, что содержимое «лежит шифротекстом»
/// и открытый текст «не появляется на этом пути ни на мгновение».
/// В базе текст открытый (её шифрует SQLCipher целиком), и в копию
/// он попадает открытым; защищает его шифрование всей копии ключом
/// восстановления (Argon2id + AEAD).
///
/// 🔐 `Debug` написан вручную и текста не печатает: прежде он был
/// выведен, и любой `{:?}` над копией выдавал переписку целиком.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageRecord {
    /// Идентификатор сообщения.
    pub id: [u8; ID_LEN],
    /// Чат.
    pub chat_id: [u8; ID_LEN],
    /// Отправитель.
    pub sender_id: [u8; ID_LEN],
    /// Время отправки в миллисекундах.
    pub timestamp_millis: i64,
    /// Содержимое — **открытый текст** (см. выше: шифруется копия
    /// целиком, а не это поле). Прежде здесь было «зашифрованное».
    pub content: Vec<u8>,
    /// Статус доставки.
    pub status: u8,
    /// Тип сообщения.
    pub message_type: u8,
    /// Момент истечения, если сообщение исчезающее.
    pub expires_at_millis: Option<i64>,
}

/// Контакт в копии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRecord {
    /// Идентификатор аккаунта.
    pub account_id: [u8; ID_LEN],
    /// Identity-ключ контакта.
    ///
    /// 🔐 Публичный. Именно он определяет, с кем идёт переписка,
    /// и именно поэтому он в копии: без него восстановленный список
    /// контактов был бы списком имён, которым нельзя доверять.
    pub identity_key: Vec<u8>,
    /// Имя пользователя, если известно.
    pub username: Option<String>,
    /// Чат с контактом.
    pub chat_id: Option<[u8; ID_LEN]>,
    /// Отметка личной верификации.
    pub verified: bool,
    /// Когда контакт добавлен.
    pub added_at_millis: Option<i64>,
}

/// Состояние чата в копии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRecord {
    /// Идентификатор чата.
    pub chat_id: [u8; ID_LEN],
    /// Время последней активности.
    pub last_activity_millis: Option<i64>,
    /// Таймер исчезающих сообщений в секундах.
    pub disappearing_timer_seconds: Option<u32>,
}

/// Метаданные вложения в копии.
///
/// 🔐 `Debug` написан вручную и описания не печатает: в нём ключ файла.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentRecord {
    /// Сообщение, к которому относится вложение.
    pub message_id: [u8; ID_LEN],
    /// Тип вложения.
    pub attachment_type: u8,
    /// Подпись или имя файла.
    pub description: Option<String>,
    /// Размер в байтах.
    pub size: i64,
    /// Когда вложение появилось.
    pub created_at_millis: i64,
    /// Сериализованное описание — адрес блоба и ключ расшифровки.
    pub descriptor: Option<Vec<u8>>,
}

impl core::fmt::Debug for MessageRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MessageRecord")
            .field("id", &self.id)
            .field("chat_id", &self.chat_id)
            .field("sender_id", &self.sender_id)
            .field("timestamp_millis", &self.timestamp_millis)
            // Только длина: сам текст — переписка.
            .field("content", &format_args!("<{} байт>", self.content.len()))
            .field("status", &self.status)
            .field("message_type", &self.message_type)
            .field("expires_at_millis", &self.expires_at_millis)
            .finish()
    }
}

impl core::fmt::Debug for AttachmentRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachmentRecord")
            .field("message_id", &self.message_id)
            .field("attachment_type", &self.attachment_type)
            .field("description", &self.description)
            .field("size", &self.size)
            .field("created_at_millis", &self.created_at_millis)
            // Только есть ли описание: его байты — ключ файла.
            .field("descriptor", &self.descriptor.as_ref().map(|_| "<скрыто>"))
            .finish()
    }
}

/// Хеш пост-квантовой половины identity контакта.
///
/// 🔐 В копии, чтобы восстановление не заучивало его заново с сервера:
/// у сверенного контакта сервер иначе смог бы подменить пост-квантовую
/// половину (сверка покрывала её по хешу, а хеш был бы забыт).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactPqRecord {
    /// Контакт.
    pub account_id: [u8; ID_LEN],
    /// Хеш его пост-квантовой половины.
    pub pq_identity_hash: [u8; 32],
}

/// Канал в копии: ключи и то, чего нельзя забрать с сервера.
///
/// 🔐 `signing_key` — приватный ключ подписи владельца либо
/// администратора. Он в копии, потому что больше ему быть негде: без
/// него потеря телефона означала потерю канала навсегда. Копия
/// зашифрована ключом восстановления; `Debug` ключей не печатает.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelRecord {
    /// Идентификатор канала.
    pub channel_id: [u8; ID_LEN],
    /// Секрет чтения из ссылки-приглашения.
    pub secret: [u8; CHANNEL_KEY_LEN],
    /// Публичный ключ подписи владельца.
    pub verify_key: [u8; CHANNEL_KEY_LEN],
    /// Свой ключ подписи, если человек ведёт канал.
    pub signing_key: Option<[u8; CHANNEL_KEY_LEN]>,
    /// Название — чтобы канал был узнаваем до первой синхронизации.
    pub title: String,
    /// «Без звука».
    pub muted: bool,
    /// Жетон подписчика.
    pub sub_token: Option<[u8; CHANNEL_KEY_LEN]>,
    /// Когда канал был добавлен.
    pub joined_at_millis: i64,
    /// Имена, которыми владелец подписал администраторов: ключ и имя.
    pub admin_labels: Vec<([u8; CHANNEL_KEY_LEN], String)>,
}

impl core::fmt::Debug for ChannelRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ChannelRecord")
            .field("channel_id", &self.channel_id)
            .field("signs", &self.signing_key.is_some())
            .finish_non_exhaustive()
    }
}

/// Настройка в копии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingRecord {
    /// Ключ настройки.
    pub key: String,
    /// Значение.
    pub value: i64,
}

/// Содержимое резервной копии.
///
/// Одна и та же структура описывает и полный снимок, и инкремент:
/// разница не в форме, а в наполнении. Инкремент несёт только то,
/// что изменилось с прошлого раза, и надгробия удалённого.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupBundle {
    /// Идентификатор аккаунта.
    pub account_id: Option<[u8; ID_LEN]>,
    /// Имя пользователя.
    pub username: Option<String>,
    /// Когда собран бандл, в миллисекундах.
    pub created_at_millis: i64,
    /// Сообщения.
    pub messages: Vec<MessageRecord>,
    /// Контакты.
    pub contacts: Vec<ContactRecord>,
    /// Состояния чатов.
    pub chats: Vec<ChatRecord>,
    /// Метаданные вложений.
    pub attachments: Vec<AttachmentRecord>,
    /// Настройки.
    pub settings: Vec<SettingRecord>,

    /// Надгробия: сообщения, удалённые с прошлого инкремента.
    ///
    /// # 🔐 Зачем они нужны
    ///
    /// Без надгробий восстановление воскрешало бы удалённое.
    /// Для исчезающих сообщений это не неудобство, а отказ функции:
    /// сообщение, которое пользователь видел исчезнувшим, вернулось
    /// бы из копии. Надгробие — единственный способ передать факт
    /// удаления цепочке инкрементов, которая по построению только
    /// дописывается.
    pub tombstones: Vec<[u8; ID_LEN]>,

    /// Секрет ключа восстановления аккаунта — в полном снимке
    /// и в инкрементах, собранных после его появления.
    pub account_recovery: Option<AccountRecoverySecret>,

    /// Хеши пост-квантовых половин контактов (версия 2).
    pub contact_pq_hashes: Vec<ContactPqRecord>,

    /// Каналы (версия 3) — всегда все, а не изменившиеся.
    ///
    /// `None` — копию собрала версия, не знавшая каналов: при слиянии
    /// и восстановлении каналы не трогаются. `Some` — полный набор на
    /// момент копии: канал, которого в нём нет, человек убрал.
    pub channels: Option<Vec<ChannelRecord>>,
}

impl BackupBundle {
    /// Сколько всего записей в бандле.
    ///
    /// Нужен интерфейсу: показать «восстановлено N из M».
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.messages
            .len()
            .saturating_add(self.contacts.len())
            .saturating_add(self.chats.len())
            .saturating_add(self.attachments.len())
            .saturating_add(self.settings.len())
            .saturating_add(self.tombstones.len())
            .saturating_add(self.channels.as_ref().map_or(0, Vec::len))
    }

    /// Пуст ли бандл по данным.
    ///
    /// Инкремент без изменений выгружать незачем.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.record_count() == 0
    }

    /// Сериализует бандл.
    ///
    /// # Формат
    ///
    /// Ручная раскладка по образцу остальных форматов проекта
    /// (`gasapp-media/descriptor`): явные длины и метки присутствия,
    /// все числа — big-endian. Причина та же: копия переживает
    /// смену версии приложения, и молчаливое добавление поля
    /// сериализатором сломало бы разбор у старой версии незаметно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — какое-то поле не помещается
    /// в объявленные пределы.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        let mut out = Vec::new();
        out.push(BUNDLE_VERSION);

        write_optional_id(&mut out, self.account_id.as_ref());
        write_optional_str(&mut out, self.username.as_deref())?;
        out.extend_from_slice(&self.created_at_millis.to_be_bytes());

        write_count(&mut out, self.messages.len())?;
        for message in &self.messages {
            out.extend_from_slice(&message.id);
            out.extend_from_slice(&message.chat_id);
            out.extend_from_slice(&message.sender_id);
            out.extend_from_slice(&message.timestamp_millis.to_be_bytes());
            write_bytes(&mut out, &message.content)?;
            out.push(message.status);
            out.push(message.message_type);
            write_optional_i64(&mut out, message.expires_at_millis);
        }

        write_count(&mut out, self.contacts.len())?;
        for contact in &self.contacts {
            out.extend_from_slice(&contact.account_id);
            write_bytes(&mut out, &contact.identity_key)?;
            write_optional_str(&mut out, contact.username.as_deref())?;
            write_optional_id(&mut out, contact.chat_id.as_ref());
            out.push(u8::from(contact.verified));
            write_optional_i64(&mut out, contact.added_at_millis);
        }

        write_count(&mut out, self.chats.len())?;
        for chat in &self.chats {
            out.extend_from_slice(&chat.chat_id);
            write_optional_i64(&mut out, chat.last_activity_millis);
            match chat.disappearing_timer_seconds {
                None => out.push(ABSENT),
                Some(seconds) => {
                    out.push(PRESENT);
                    out.extend_from_slice(&seconds.to_be_bytes());
                }
            }
        }

        write_count(&mut out, self.attachments.len())?;
        for attachment in &self.attachments {
            out.extend_from_slice(&attachment.message_id);
            out.push(attachment.attachment_type);
            write_optional_str(&mut out, attachment.description.as_deref())?;
            out.extend_from_slice(&attachment.size.to_be_bytes());
            out.extend_from_slice(&attachment.created_at_millis.to_be_bytes());
            match &attachment.descriptor {
                None => out.push(ABSENT),
                Some(descriptor) => {
                    out.push(PRESENT);
                    write_bytes(&mut out, descriptor)?;
                }
            }
        }

        write_count(&mut out, self.settings.len())?;
        for setting in &self.settings {
            write_bytes(&mut out, setting.key.as_bytes())?;
            out.extend_from_slice(&setting.value.to_be_bytes());
        }

        write_count(&mut out, self.tombstones.len())?;
        for tombstone in &self.tombstones {
            out.extend_from_slice(tombstone);
        }

        match &self.account_recovery {
            None => out.push(ABSENT),
            Some(secret) => {
                out.push(PRESENT);
                out.extend_from_slice(&secret.0);
            }
        }

        write_count(&mut out, self.contact_pq_hashes.len())?;
        for record in &self.contact_pq_hashes {
            out.extend_from_slice(&record.account_id);
            out.extend_from_slice(&record.pq_identity_hash);
        }

        match &self.channels {
            None => out.push(ABSENT),
            Some(channels) => {
                out.push(PRESENT);
                write_count(&mut out, channels.len())?;
                for channel in channels {
                    write_channel(&mut out, channel)?;
                }
            }
        }

        Ok(out)
    }

    /// Разбирает бандл.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — незнакомая версия, обрыв буфера,
    /// лишний хвост либо превышение пределов.
    // Длина — прямое следствие числа полей: линейный разбор в порядке
    // записи. Дробление по разделам разнесло бы порядок полей, который
    // и есть формат.
    #[allow(clippy::too_many_lines)]
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let mut cursor = Cursor { raw, offset: 0 };

        let version = cursor.take_u8()?;

        if !matches!(
            version,
            BUNDLE_VERSION | BUNDLE_VERSION_2 | BUNDLE_VERSION_1
        ) {
            return Err(GasAppError::Malformed);
        }

        let account_id = cursor.take_optional_id()?;
        let username = cursor.take_optional_str()?;
        let created_at_millis = cursor.take_i64()?;

        let message_count = cursor.take_count()?;
        let mut messages = Vec::with_capacity(message_count.min(1024));
        for _ in 0..message_count {
            messages.push(MessageRecord {
                id: cursor.take_id()?,
                chat_id: cursor.take_id()?,
                sender_id: cursor.take_id()?,
                timestamp_millis: cursor.take_i64()?,
                content: cursor.take_bytes()?.to_vec(),
                status: cursor.take_u8()?,
                message_type: cursor.take_u8()?,
                expires_at_millis: cursor.take_optional_i64()?,
            });
        }

        let contact_count = cursor.take_count()?;
        let mut contacts = Vec::with_capacity(contact_count.min(1024));
        for _ in 0..contact_count {
            contacts.push(ContactRecord {
                account_id: cursor.take_id()?,
                identity_key: cursor.take_bytes()?.to_vec(),
                username: cursor.take_optional_str()?,
                chat_id: cursor.take_optional_id()?,
                verified: cursor.take_bool()?,
                added_at_millis: cursor.take_optional_i64()?,
            });
        }

        let chat_count = cursor.take_count()?;
        let mut chats = Vec::with_capacity(chat_count.min(1024));
        for _ in 0..chat_count {
            let chat_id = cursor.take_id()?;
            let last_activity_millis = cursor.take_optional_i64()?;
            let disappearing_timer_seconds = if cursor.take_bool()? {
                Some(cursor.take_u32()?)
            } else {
                None
            };

            chats.push(ChatRecord {
                chat_id,
                last_activity_millis,
                disappearing_timer_seconds,
            });
        }

        let attachment_count = cursor.take_count()?;
        let mut attachments = Vec::with_capacity(attachment_count.min(1024));
        for _ in 0..attachment_count {
            let message_id = cursor.take_id()?;
            let attachment_type = cursor.take_u8()?;
            let description = cursor.take_optional_str()?;
            let size = cursor.take_i64()?;
            let created_at_millis = cursor.take_i64()?;
            let descriptor = if cursor.take_bool()? {
                Some(cursor.take_bytes()?.to_vec())
            } else {
                None
            };

            attachments.push(AttachmentRecord {
                message_id,
                attachment_type,
                description,
                size,
                created_at_millis,
                descriptor,
            });
        }

        let setting_count = cursor.take_count()?;
        let mut settings = Vec::with_capacity(setting_count.min(1024));
        for _ in 0..setting_count {
            let key = String::from_utf8(cursor.take_bytes()?.to_vec())
                .map_err(|_| GasAppError::Malformed)?;
            let value = cursor.take_i64()?;

            settings.push(SettingRecord { key, value });
        }

        let tombstone_count = cursor.take_count()?;
        let mut tombstones = Vec::with_capacity(tombstone_count.min(1024));
        for _ in 0..tombstone_count {
            tombstones.push(cursor.take_id()?);
        }

        let (account_recovery, contact_pq_hashes) = take_version_two_tail(&mut cursor, version)?;
        let channels = take_version_three_tail(&mut cursor, version)?;

        // 🔐 Хвост — ошибка, а не мусор: он означает, что копию собрала
        // версия, понимающая формат иначе, и молча проигнорировать
        // непонятое значило бы восстановить не всё, отчитавшись
        // об успехе.
        if !cursor.is_empty() {
            return Err(GasAppError::Malformed);
        }

        let bundle = Self {
            account_id,
            username,
            created_at_millis,
            messages,
            contacts,
            chats,
            attachments,
            settings,
            tombstones,
            account_recovery,
            contact_pq_hashes,
            channels,
        };

        bundle.validate()?;

        Ok(bundle)
    }

    /// Проверяет бандл на соответствие пределам.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — превышен предел записей, длины
    /// поля либо длины строки.
    pub fn validate(&self) -> Result<()> {
        for count in [
            self.messages.len(),
            self.contacts.len(),
            self.chats.len(),
            self.attachments.len(),
            self.settings.len(),
            self.tombstones.len(),
        ] {
            if count > MAX_RECORDS {
                return Err(GasAppError::Malformed);
            }
        }

        check_optional_str(self.username.as_deref())?;

        for message in &self.messages {
            check_field(message.content.len())?;
        }

        for contact in &self.contacts {
            check_field(contact.identity_key.len())?;
            check_optional_str(contact.username.as_deref())?;
        }

        for attachment in &self.attachments {
            check_optional_str(attachment.description.as_deref())?;
            if let Some(descriptor) = &attachment.descriptor {
                check_field(descriptor.len())?;
            }
        }

        for setting in &self.settings {
            check_string(&setting.key)?;
        }

        for channel in self.channels.iter().flatten() {
            check_string(&channel.title)?;

            if channel.admin_labels.len() > MAX_CHANNELS {
                return Err(GasAppError::Malformed);
            }
            for (_, label) in &channel.admin_labels {
                check_string(label)?;
            }
        }

        if self
            .channels
            .as_ref()
            .is_some_and(|list| list.len() > MAX_CHANNELS)
        {
            return Err(GasAppError::Malformed);
        }

        Ok(())
    }

    /// Накладывает инкремент поверх уже собранного состояния.
    ///
    /// # Правила слияния
    ///
    /// Записи заменяются по идентификатору: более поздний инкремент
    /// побеждает. Надгробия применяются **после** записей — иначе
    /// сообщение, удалённое и заново пришедшее в одном инкременте,
    /// осталось бы удалённым.
    ///
    /// Метаданные аккаунта берутся из инкремента, только если он их
    /// несёт: пустое поле означает «не менялось», а не «стало пустым».
    pub fn merge(&mut self, increment: Self) {
        if increment.account_id.is_some() {
            self.account_id = increment.account_id;
        }
        if increment.username.is_some() {
            self.username = increment.username;
        }
        self.created_at_millis = increment.created_at_millis;

        merge_by(&mut self.messages, increment.messages, |record| record.id);
        merge_by(&mut self.contacts, increment.contacts, |record| {
            record.account_id
        });
        merge_by(&mut self.chats, increment.chats, |record| record.chat_id);
        merge_by(&mut self.settings, increment.settings, |record| {
            record.key.clone()
        });

        // У вложений нет собственного идентификатора: они привязаны
        // к сообщению, и ключ слияния — пара «сообщение, тип».
        merge_by(&mut self.attachments, increment.attachments, |record| {
            (record.message_id, record.attachment_type)
        });

        for tombstone in &increment.tombstones {
            self.messages.retain(|message| message.id != *tombstone);
            self.attachments
                .retain(|attachment| attachment.message_id != *tombstone);
        }

        // Надгробия накапливаются: следующий инкремент цепочки может
        // прийти после того, который снова добавил это сообщение.
        self.tombstones.extend(increment.tombstones);
        self.tombstones.sort_unstable();
        self.tombstones.dedup();

        if increment.account_recovery.is_some() {
            self.account_recovery = increment.account_recovery;
        }
        merge_by(
            &mut self.contact_pq_hashes,
            increment.contact_pq_hashes,
            |record| record.account_id,
        );

        // Каналы инкремент несёт целиком: его набор заменяет прежний.
        // Так канал, который человек убрал, не возвращается из старого
        // звена цепочки. Инкремент прежней версии каналов не знает —
        // и не трогает.
        if increment.channels.is_some() {
            self.channels = increment.channels;
        }
    }
}

fn write_optional_key(out: &mut Vec<u8>, key: Option<&[u8; CHANNEL_KEY_LEN]>) {
    match key {
        None => out.push(ABSENT),
        Some(key) => {
            out.push(PRESENT);
            out.extend_from_slice(key);
        }
    }
}

fn write_channel(out: &mut Vec<u8>, channel: &ChannelRecord) -> Result<()> {
    out.extend_from_slice(&channel.channel_id);
    out.extend_from_slice(&channel.secret);
    out.extend_from_slice(&channel.verify_key);
    write_optional_key(out, channel.signing_key.as_ref());
    write_bytes(out, channel.title.as_bytes())?;
    out.push(u8::from(channel.muted));
    write_optional_key(out, channel.sub_token.as_ref());
    out.extend_from_slice(&channel.joined_at_millis.to_be_bytes());

    write_count(out, channel.admin_labels.len())?;
    for (key, label) in &channel.admin_labels {
        out.extend_from_slice(key);
        write_bytes(out, label.as_bytes())?;
    }

    Ok(())
}

fn take_key(cursor: &mut Cursor<'_>) -> Result<[u8; CHANNEL_KEY_LEN]> {
    cursor
        .take_exact(CHANNEL_KEY_LEN)?
        .try_into()
        .map_err(|_| GasAppError::Malformed)
}

fn take_optional_key(cursor: &mut Cursor<'_>) -> Result<Option<[u8; CHANNEL_KEY_LEN]>> {
    if cursor.take_bool()? {
        Ok(Some(take_key(cursor)?))
    } else {
        Ok(None)
    }
}

fn take_text(cursor: &mut Cursor<'_>) -> Result<String> {
    String::from_utf8(cursor.take_bytes()?.to_vec()).map_err(|_| GasAppError::Malformed)
}

/// Хвост формата версии 3: каналы. У версий 1 и 2 его нет.
fn take_version_three_tail(
    cursor: &mut Cursor<'_>,
    version: u8,
) -> Result<Option<Vec<ChannelRecord>>> {
    if version < BUNDLE_VERSION || !cursor.take_bool()? {
        return Ok(None);
    }

    let count = cursor.take_count()?;
    if count > MAX_CHANNELS {
        return Err(GasAppError::Malformed);
    }

    let mut channels = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let channel_id = cursor.take_id()?;
        let secret = take_key(cursor)?;
        let verify_key = take_key(cursor)?;
        let signing_key = take_optional_key(cursor)?;
        let title = take_text(cursor)?;
        let muted = cursor.take_bool()?;
        let sub_token = take_optional_key(cursor)?;
        let joined_at_millis = cursor.take_i64()?;

        let labels = cursor.take_count()?;
        if labels > MAX_CHANNELS {
            return Err(GasAppError::Malformed);
        }
        let mut admin_labels = Vec::with_capacity(labels.min(64));
        for _ in 0..labels {
            admin_labels.push((take_key(cursor)?, take_text(cursor)?));
        }

        channels.push(ChannelRecord {
            channel_id,
            secret,
            verify_key,
            signing_key,
            title,
            muted,
            sub_token,
            joined_at_millis,
            admin_labels,
        });
    }

    Ok(Some(channels))
}

/// Хвост формата версии 2: секрет восстановления аккаунта и хеши
/// пост-квантовых половин контактов. У версии 1 его нет.
fn take_version_two_tail(
    cursor: &mut Cursor<'_>,
    version: u8,
) -> Result<(Option<AccountRecoverySecret>, Vec<ContactPqRecord>)> {
    if version < BUNDLE_VERSION_2 {
        return Ok((None, Vec::new()));
    }

    let account_recovery = if cursor.take_bool()? {
        let mut secret = [0u8; ACCOUNT_RECOVERY_LEN];
        for byte in &mut secret {
            *byte = cursor.take_u8()?;
        }
        Some(AccountRecoverySecret(secret))
    } else {
        None
    };

    let count = cursor.take_count()?;
    let mut contact_pq_hashes = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let account_id = cursor.take_id()?;
        let mut pq_identity_hash = [0u8; 32];
        for byte in &mut pq_identity_hash {
            *byte = cursor.take_u8()?;
        }
        contact_pq_hashes.push(ContactPqRecord {
            account_id,
            pq_identity_hash,
        });
    }

    Ok((account_recovery, contact_pq_hashes))
}

/// Заменяет записи с совпадающим ключом и добавляет новые.
fn merge_by<T, K, F>(existing: &mut Vec<T>, incoming: Vec<T>, key: F)
where
    K: PartialEq,
    F: Fn(&T) -> K,
{
    for record in incoming {
        let incoming_key = key(&record);

        if let Some(slot) = existing.iter_mut().find(|item| key(item) == incoming_key) {
            *slot = record;
        } else {
            existing.push(record);
        }
    }
}

/// Проверяет длину поля переменной длины.
fn check_field(length: usize) -> Result<()> {
    if length > MAX_FIELD_LEN {
        return Err(GasAppError::Malformed);
    }

    Ok(())
}

/// Проверяет длину строки в символах.
fn check_string(value: &str) -> Result<()> {
    // Символы, а не байты: предел в байтах отсекал бы имена
    // на кириллице вдвое короче латинских.
    if value.chars().count() > MAX_STRING_LEN {
        return Err(GasAppError::Malformed);
    }

    Ok(())
}

/// Проверяет необязательную строку.
fn check_optional_str(value: Option<&str>) -> Result<()> {
    match value {
        None => Ok(()),
        Some(text) => check_string(text),
    }
}

/// Дописывает число записей.
fn write_count(out: &mut Vec<u8>, count: usize) -> Result<()> {
    if count > MAX_RECORDS {
        return Err(GasAppError::Malformed);
    }

    let value = u32::try_from(count).map_err(|_| GasAppError::Malformed)?;
    out.extend_from_slice(&value.to_be_bytes());

    Ok(())
}

/// Дописывает блок с длиной впереди.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    check_field(bytes.len())?;

    let length = u32::try_from(bytes.len()).map_err(|_| GasAppError::Malformed)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);

    Ok(())
}

/// Дописывает необязательную строку.
fn write_optional_str(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => {
            out.push(ABSENT);

            Ok(())
        }
        Some(text) => {
            check_string(text)?;
            out.push(PRESENT);

            write_bytes(out, text.as_bytes())
        }
    }
}

/// Дописывает необязательный идентификатор.
fn write_optional_id(out: &mut Vec<u8>, value: Option<&[u8; ID_LEN]>) {
    match value {
        None => out.push(ABSENT),
        Some(id) => {
            out.push(PRESENT);
            out.extend_from_slice(id);
        }
    }
}

/// Дописывает необязательное число.
fn write_optional_i64(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        None => out.push(ABSENT),
        Some(number) => {
            out.push(PRESENT);
            out.extend_from_slice(&number.to_be_bytes());
        }
    }
}

/// Чтение по буферу с проверкой границ на каждом шаге.
///
/// 🔐 Существует ради того, чтобы ни одно чтение не полагалось
/// на длину из файла копии без сверки с остатком буфера.
struct Cursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn is_empty(&self) -> bool {
        self.offset >= self.raw.len()
    }

    fn take_u8(&mut self) -> Result<u8> {
        let byte = *self.raw.get(self.offset).ok_or(GasAppError::Malformed)?;
        self.offset = self.offset.saturating_add(1);

        Ok(byte)
    }

    fn take_bool(&mut self) -> Result<bool> {
        match self.take_u8()? {
            ABSENT => Ok(false),
            PRESENT => Ok(true),
            // Третьего значения нет: любое другое означает, что файл
            // собран не тем форматом, который здесь разбирают.
            _ => Err(GasAppError::Malformed),
        }
    }

    fn take_exact(&mut self, count: usize) -> Result<&[u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(GasAppError::Malformed)?;
        let slice = self
            .raw
            .get(self.offset..end)
            .ok_or(GasAppError::Malformed)?;
        self.offset = end;

        Ok(slice)
    }

    fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        ))
    }

    fn take_i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.take_exact(8)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        ))
    }

    fn take_optional_i64(&mut self) -> Result<Option<i64>> {
        if self.take_bool()? {
            Ok(Some(self.take_i64()?))
        } else {
            Ok(None)
        }
    }

    fn take_id(&mut self) -> Result<[u8; ID_LEN]> {
        self.take_exact(ID_LEN)?
            .try_into()
            .map_err(|_| GasAppError::Malformed)
    }

    fn take_optional_id(&mut self) -> Result<Option<[u8; ID_LEN]>> {
        if self.take_bool()? {
            Ok(Some(self.take_id()?))
        } else {
            Ok(None)
        }
    }

    /// Читает число записей и сверяет его с пределом.
    ///
    /// 🔐 Сверка до выделения памяти: «здесь миллиард записей»
    /// не должно приводить к попытке выделить под них место.
    fn take_count(&mut self) -> Result<usize> {
        let count = usize::try_from(self.take_u32()?).map_err(|_| GasAppError::Malformed)?;

        if count > MAX_RECORDS {
            return Err(GasAppError::Malformed);
        }

        // Каждая запись занимает как минимум байт: объявленное число
        // записей, превышающее остаток буфера, — заведомая ложь.
        if count > self.raw.len().saturating_sub(self.offset) {
            return Err(GasAppError::Malformed);
        }

        Ok(count)
    }

    fn take_bytes(&mut self) -> Result<&[u8]> {
        let length = u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| GasAppError::Malformed)?,
        );
        let count = usize::try_from(length).map_err(|_| GasAppError::Malformed)?;

        check_field(count)?;

        self.take_exact(count)
    }

    fn take_optional_str(&mut self) -> Result<Option<String>> {
        if !self.take_bool()? {
            return Ok(None);
        }

        let text =
            String::from_utf8(self.take_bytes()?.to_vec()).map_err(|_| GasAppError::Malformed)?;
        check_string(&text)?;

        Ok(Some(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 Ни текст сообщения, ни описание вложения не печатаются в `Debug`.
    #[test]
    fn records_debug_does_not_print_text_or_file_keys() {
        let mut record = message(1);
        record.content = b"PAROL-OT-SEIFA".to_vec();
        let attachment = AttachmentRecord {
            message_id: [1; ID_LEN],
            attachment_type: 1,
            description: None,
            size: 10,
            created_at_millis: 0,
            descriptor: Some(vec![0xB9; 48]),
        };

        let rendered = format!("{record:?} {attachment:?}");

        assert!(!rendered.contains("PAROL"), "текст напечатан: {rendered}");
        assert!(
            !rendered.contains(&format!("{:?}", b"PAROL-OT-SEIFA".to_vec())),
            "текст напечатан байтами: {rendered}"
        );
        assert!(
            !rendered.contains("185, 185, 185"),
            "описание вложения напечатано: {rendered}"
        );
    }

    fn message(id: u8) -> MessageRecord {
        MessageRecord {
            id: [id; ID_LEN],
            chat_id: [0x11; ID_LEN],
            sender_id: [0x22; ID_LEN],
            timestamp_millis: 1_760_000_000_000,
            content: vec![id, 0xAA, 0xBB],
            status: 1,
            message_type: 0,
            expires_at_millis: Some(1_760_000_600_000),
        }
    }

    fn populated() -> BackupBundle {
        BackupBundle {
            account_id: Some([0x33; ID_LEN]),
            username: Some("alice".to_owned()),
            created_at_millis: 1_760_000_000_000,
            messages: vec![message(1), message(2)],
            contacts: vec![ContactRecord {
                account_id: [0x44; ID_LEN],
                identity_key: vec![0x55; 32],
                username: Some("bob".to_owned()),
                chat_id: Some([0x11; ID_LEN]),
                verified: true,
                added_at_millis: Some(1_759_000_000_000),
            }],
            chats: vec![ChatRecord {
                chat_id: [0x11; ID_LEN],
                last_activity_millis: Some(1_760_000_000_000),
                disappearing_timer_seconds: Some(86_400),
            }],
            attachments: vec![AttachmentRecord {
                message_id: [1; ID_LEN],
                attachment_type: 1,
                description: Some("фото".to_owned()),
                size: 4096,
                created_at_millis: 1_760_000_000_000,
                descriptor: Some(vec![0x66; 64]),
            }],
            settings: vec![SettingRecord {
                key: "presence_sharing".to_owned(),
                value: 1,
            }],
            tombstones: vec![[9; ID_LEN]],
            account_recovery: Some(AccountRecoverySecret([7; ACCOUNT_RECOVERY_LEN])),
            contact_pq_hashes: vec![ContactPqRecord {
                account_id: [3; ID_LEN],
                pq_identity_hash: [6; 32],
            }],
            channels: Some(vec![channel(1), channel(2)]),
        }
    }

    fn channel(id: u8) -> ChannelRecord {
        ChannelRecord {
            channel_id: [id; ID_LEN],
            secret: [0x21; 32],
            verify_key: [0x22; 32],
            signing_key: (id == 1).then_some([0x23; 32]),
            title: format!("Канал {id}"),
            muted: id == 2,
            sub_token: Some([0x24; 32]),
            joined_at_millis: 1_760_000_000_000,
            admin_labels: vec![([0x25; 32], "anna".to_owned())],
        }
    }

    /// 🔐 Ключ подписи канала в копию входит — и в `Debug` не попадает.
    #[test]
    fn channel_keys_are_kept_and_not_printed() {
        let bundle = populated();
        let decoded =
            BackupBundle::from_bytes(&bundle.to_bytes().expect("сериализация")).expect("разбор");
        let channels = decoded.channels.expect("каналы");

        assert_eq!(channels[0].signing_key, Some([0x23; 32]));
        assert_eq!(channels[1].signing_key, None);

        let printed = format!("{:?}", channels[0]);
        assert!(
            !printed.contains("35, 35"),
            "ключ подписи в отладочном выводе"
        );
        assert!(
            !printed.contains("33, 33"),
            "секрет чтения в отладочном выводе"
        );
    }

    /// Инкремент несёт каналы целиком: убранный канал не возвращается,
    /// а инкремент прежней версии каналов не трогает.
    #[test]
    fn channels_are_replaced_as_a_whole() {
        let mut base = populated();

        base.merge(BackupBundle {
            channels: None,
            ..BackupBundle::default()
        });
        assert_eq!(base.channels.as_ref().map(Vec::len), Some(2));

        base.merge(BackupBundle {
            channels: Some(vec![channel(2)]),
            ..BackupBundle::default()
        });
        assert_eq!(base.channels, Some(vec![channel(2)]));

        base.merge(BackupBundle {
            channels: Some(Vec::new()),
            ..BackupBundle::default()
        });
        assert_eq!(base.channels, Some(Vec::new()));
    }

    /// Бандл версии 2 (без каналов) по-прежнему читается.
    #[test]
    fn version_two_bundles_still_parse() {
        let mut expected = populated();
        expected.channels = None;

        let mut encoded = expected.to_bytes().expect("сериализация");
        encoded[0] = BUNDLE_VERSION_2;
        // Версия 2 кончалась хешами: метки каналов (1 байт) в ней нет.
        encoded.truncate(encoded.len() - 1);

        assert_eq!(
            BackupBundle::from_bytes(&encoded).expect("разбор"),
            expected
        );
    }

    /// Бандл переживает сериализацию без потерь.
    #[test]
    fn bundle_round_trips() {
        let bundle = populated();
        let encoded = bundle.to_bytes().expect("сериализация");

        let decoded = BackupBundle::from_bytes(&encoded).expect("разбор");

        assert_eq!(decoded, bundle);
    }

    /// Пустой бандл тоже разбирается.
    #[test]
    fn empty_bundle_round_trips() {
        let bundle = BackupBundle::default();
        let encoded = bundle.to_bytes().expect("сериализация");

        assert_eq!(BackupBundle::from_bytes(&encoded).expect("разбор"), bundle);
        assert!(bundle.is_empty());
    }

    /// 🔐 В структуре бандла нет места состоянию храповика.
    ///
    /// Тест проверяет не поведение, а форму: раздел 12.5 запрещает
    /// класть ratchet state в копию, и запрет держится тем, что поля
    /// для него не существует. Перечисление полей через
    /// деструктуризацию **ломает компиляцию**, если поле добавят, —
    /// то есть решение 12.5 нельзя обойти незаметно.
    #[test]
    fn bundle_has_no_field_for_ratchet_state() {
        let BackupBundle {
            account_id: _,
            username: _,
            created_at_millis: _,
            messages: _,
            contacts: _,
            chats: _,
            attachments: _,
            settings: _,
            tombstones: _,
            // Секрет ключа восстановления аккаунта — не ratchet state
            // и не identity-ключ: им подписывается только запрос
            // «перепривяжи имя к новой identity» (13.1 соблюдён).
            account_recovery: _,
            // Хеши пост-квантовых половин контактов — открытые данные.
            contact_pq_hashes: _,
            // Ключи каналов — не ratchet state: это долгоживущие ключи
            // лент, которым негде больше храниться (ADR-033).
            channels: _,
        } = BackupBundle::default();
    }

    /// Бандл версии 1 (без секрета восстановления) по-прежнему читается.
    #[test]
    fn version_one_bundles_still_parse() {
        let mut expected = populated();
        expected.account_recovery = None;
        expected.contact_pq_hashes.clear();
        expected.channels = None;

        let mut encoded = expected.to_bytes().expect("сериализация");
        encoded[0] = BUNDLE_VERSION_1;
        // Версия 1 кончалась надгробиями: меток секрета, счётчика
        // хешей и каналов (1 + 4 + 1 байт) в ней нет.
        encoded.truncate(encoded.len() - 6);

        assert_eq!(
            BackupBundle::from_bytes(&encoded).expect("разбор"),
            expected
        );
    }

    /// Секрет восстановления переживает круг «записать — прочесть»,
    /// а `Debug` его не печатает.
    #[test]
    fn account_recovery_round_trips_and_is_hidden() {
        let bundle = populated();
        let decoded =
            BackupBundle::from_bytes(&bundle.to_bytes().expect("сериализация")).expect("разбор");

        assert_eq!(decoded.account_recovery, bundle.account_recovery);
        assert!(!format!("{bundle:?}").contains("7, 7, 7"));
    }

    /// Незнакомая версия отвергается.
    #[test]
    fn unknown_version_is_rejected() {
        let mut encoded = populated().to_bytes().expect("сериализация");
        if let Some(version) = encoded.first_mut() {
            *version = 99;
        }

        assert!(matches!(
            BackupBundle::from_bytes(&encoded),
            Err(GasAppError::Malformed)
        ));
    }

    /// Лишний хвост отвергается.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = populated().to_bytes().expect("сериализация");
        encoded.push(0);

        assert!(matches!(
            BackupBundle::from_bytes(&encoded),
            Err(GasAppError::Malformed)
        ));
    }

    /// Обрыв буфера в любом месте не приводит к панике.
    ///
    /// 🔐 Файл копии приходит извне; разбор обязан отвечать ошибкой
    /// на любой обрубок, а не падать.
    #[test]
    fn truncation_never_panics() {
        let encoded = populated().to_bytes().expect("сериализация");

        for length in 0..encoded.len() {
            let slice = encoded.get(..length).expect("срез в пределах");

            assert!(
                BackupBundle::from_bytes(slice).is_err(),
                "обрубок длиной {length} разобрался как корректный бандл"
            );
        }
    }

    /// 🔐 Заявленное число записей сверяется с остатком буфера.
    ///
    /// Без этой проверки заголовок «здесь миллион сообщений»
    /// заставил бы выделить память под них до первой сверки.
    #[test]
    fn absurd_record_count_is_rejected() {
        let bundle = BackupBundle::default();
        let mut encoded = bundle.to_bytes().expect("сериализация");

        // Первое поле счётчика идёт после версии, метки аккаунта,
        // метки имени и восьми байт времени.
        let offset = 1 + 1 + 1 + 8;
        if let Some(slot) = encoded.get_mut(offset..offset + 4) {
            slot.copy_from_slice(&100_000u32.to_be_bytes());
        }

        assert!(matches!(
            BackupBundle::from_bytes(&encoded),
            Err(GasAppError::Malformed)
        ));
    }

    /// Слияние заменяет запись по идентификатору, а не дублирует её.
    #[test]
    fn merge_replaces_by_id() {
        let mut base = BackupBundle {
            messages: vec![message(1)],
            ..BackupBundle::default()
        };

        let mut updated = message(1);
        updated.status = 3;

        base.merge(BackupBundle {
            messages: vec![updated.clone(), message(2)],
            ..BackupBundle::default()
        });

        assert_eq!(base.messages.len(), 2, "запись продублировалась");
        assert_eq!(base.messages.first(), Some(&updated));
    }

    /// 🔐 Надгробие убирает сообщение и его вложения из состояния.
    ///
    /// Это и есть механизм, из-за которого восстановление
    /// не воскрешает исчезнувшее.
    #[test]
    fn tombstone_removes_message_and_attachments() {
        let mut base = BackupBundle {
            messages: vec![message(1), message(2)],
            attachments: vec![AttachmentRecord {
                message_id: [1; ID_LEN],
                attachment_type: 1,
                description: None,
                size: 1,
                created_at_millis: 0,
                descriptor: None,
            }],
            ..BackupBundle::default()
        };

        base.merge(BackupBundle {
            tombstones: vec![[1; ID_LEN]],
            ..BackupBundle::default()
        });

        assert_eq!(base.messages.len(), 1);
        assert_eq!(
            base.messages.first().map(|record| record.id),
            Some([2; ID_LEN])
        );
        assert!(base.attachments.is_empty(), "вложение пережило надгробие");
    }

    /// Надгробие применяется после записей того же инкремента.
    ///
    /// Сообщение, пришедшее заново в том же инкременте, в котором
    /// стоит его надгробие, считается удалённым: инкремент описывает
    /// итог периода, а не последовательность событий внутри него.
    #[test]
    fn tombstone_applies_after_records_of_same_increment() {
        let mut base = BackupBundle::default();

        base.merge(BackupBundle {
            messages: vec![message(1)],
            tombstones: vec![[1; ID_LEN]],
            ..BackupBundle::default()
        });

        assert!(base.messages.is_empty());
    }

    /// Пустые метаданные инкремента не затирают прежние.
    #[test]
    fn merge_keeps_account_metadata_when_increment_omits_it() {
        let mut base = BackupBundle {
            account_id: Some([0x33; ID_LEN]),
            username: Some("alice".to_owned()),
            ..BackupBundle::default()
        };

        base.merge(BackupBundle::default());

        assert_eq!(base.account_id, Some([0x33; ID_LEN]));
        assert_eq!(base.username.as_deref(), Some("alice"));
    }

    /// Слишком длинная строка отвергается при сериализации.
    #[test]
    fn oversized_string_is_rejected() {
        let bundle = BackupBundle {
            username: Some("a".repeat(MAX_STRING_LEN + 1)),
            ..BackupBundle::default()
        };

        assert!(matches!(bundle.to_bytes(), Err(GasAppError::Malformed)));
    }
}
