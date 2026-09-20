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
//! История сообщений (в том виде, в каком она лежит в базе —
//! шифротекстом), контакты с их identity-ключами и отметками
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

use aegis_types::{AegisError, Result};

/// Версия формата бандла.
const BUNDLE_VERSION: u8 = 1;

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
/// Содержимое лежит шифротекстом — ровно так же, как в базе.
/// Копия не расшифровывает переписку, чтобы зашифровать её заново:
/// открытый текст не появляется на этом пути ни на мгновение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    /// Идентификатор сообщения.
    pub id: [u8; ID_LEN],
    /// Чат.
    pub chat_id: [u8; ID_LEN],
    /// Отправитель.
    pub sender_id: [u8; ID_LEN],
    /// Время отправки в миллисекундах.
    pub timestamp_millis: i64,
    /// Зашифрованное содержимое.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// (`aegis-media/descriptor`): явные длины и метки присутствия,
    /// все числа — big-endian. Причина та же: копия переживает
    /// смену версии приложения, и молчаливое добавление поля
    /// сериализатором сломало бы разбор у старой версии незаметно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — какое-то поле не помещается
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

        Ok(out)
    }

    /// Разбирает бандл.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — незнакомая версия, обрыв буфера,
    /// лишний хвост либо превышение пределов.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let mut cursor = Cursor { raw, offset: 0 };

        if cursor.take_u8()? != BUNDLE_VERSION {
            return Err(AegisError::Malformed);
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
                .map_err(|_| AegisError::Malformed)?;
            let value = cursor.take_i64()?;

            settings.push(SettingRecord { key, value });
        }

        let tombstone_count = cursor.take_count()?;
        let mut tombstones = Vec::with_capacity(tombstone_count.min(1024));
        for _ in 0..tombstone_count {
            tombstones.push(cursor.take_id()?);
        }

        // 🔐 Хвост — ошибка, а не мусор: он означает, что копию собрала
        // версия, понимающая формат иначе, и молча проигнорировать
        // непонятое значило бы восстановить не всё, отчитавшись
        // об успехе.
        if !cursor.is_empty() {
            return Err(AegisError::Malformed);
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
        };

        bundle.validate()?;

        Ok(bundle)
    }

    /// Проверяет бандл на соответствие пределам.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — превышен предел записей, длины
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
                return Err(AegisError::Malformed);
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
    }
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
        return Err(AegisError::Malformed);
    }

    Ok(())
}

/// Проверяет длину строки в символах.
fn check_string(value: &str) -> Result<()> {
    // Символы, а не байты: предел в байтах отсекал бы имена
    // на кириллице вдвое короче латинских.
    if value.chars().count() > MAX_STRING_LEN {
        return Err(AegisError::Malformed);
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
        return Err(AegisError::Malformed);
    }

    let value = u32::try_from(count).map_err(|_| AegisError::Malformed)?;
    out.extend_from_slice(&value.to_be_bytes());

    Ok(())
}

/// Дописывает блок с длиной впереди.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    check_field(bytes.len())?;

    let length = u32::try_from(bytes.len()).map_err(|_| AegisError::Malformed)?;
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
        let byte = *self.raw.get(self.offset).ok_or(AegisError::Malformed)?;
        self.offset = self.offset.saturating_add(1);

        Ok(byte)
    }

    fn take_bool(&mut self) -> Result<bool> {
        match self.take_u8()? {
            ABSENT => Ok(false),
            PRESENT => Ok(true),
            // Третьего значения нет: любое другое означает, что файл
            // собран не тем форматом, который здесь разбирают.
            _ => Err(AegisError::Malformed),
        }
    }

    fn take_exact(&mut self, count: usize) -> Result<&[u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AegisError::Malformed)?;
        let slice = self
            .raw
            .get(self.offset..end)
            .ok_or(AegisError::Malformed)?;
        self.offset = end;

        Ok(slice)
    }

    fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
        ))
    }

    fn take_i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.take_exact(8)?
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
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
            .map_err(|_| AegisError::Malformed)
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
        let count = usize::try_from(self.take_u32()?).map_err(|_| AegisError::Malformed)?;

        if count > MAX_RECORDS {
            return Err(AegisError::Malformed);
        }

        // Каждая запись занимает как минимум байт: объявленное число
        // записей, превышающее остаток буфера, — заведомая ложь.
        if count > self.raw.len().saturating_sub(self.offset) {
            return Err(AegisError::Malformed);
        }

        Ok(count)
    }

    fn take_bytes(&mut self) -> Result<&[u8]> {
        let length = u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
        );
        let count = usize::try_from(length).map_err(|_| AegisError::Malformed)?;

        check_field(count)?;

        self.take_exact(count)
    }

    fn take_optional_str(&mut self) -> Result<Option<String>> {
        if !self.take_bool()? {
            return Ok(None);
        }

        let text =
            String::from_utf8(self.take_bytes()?.to_vec()).map_err(|_| AegisError::Malformed)?;
        check_string(&text)?;

        Ok(Some(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
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
        } = BackupBundle::default();
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
            Err(AegisError::Malformed)
        ));
    }

    /// Лишний хвост отвергается.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = populated().to_bytes().expect("сериализация");
        encoded.push(0);

        assert!(matches!(
            BackupBundle::from_bytes(&encoded),
            Err(AegisError::Malformed)
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
            Err(AegisError::Malformed)
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

        assert!(matches!(bundle.to_bytes(), Err(AegisError::Malformed)));
    }
}
