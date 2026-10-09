// SPDX-License-Identifier: Apache-2.0

//! Кнопки под сообщениями и нажатия, ждущие обработки.
//!
//! * `message_keyboards` — клавиатура сообщения: и та, что прислал
//!   собеседник (её показывает интерфейс), и та, что отправили мы (по
//!   ней проверяется пришедшее нажатие).
//! * `button_callbacks` — нажатия кнопок наших сообщений. Их забирает
//!   программа бота; у обычного приложения очередь не растёт: кнопок
//!   оно не отправляет, а нажатие без своей клавиатуры не принимается.
//!
//! 🔐 Клавиатура удаляется вместе с сообщением: подписи кнопок — такой
//! же текст собеседника, как само сообщение.

use gasapp_types::{ChatId, GasAppError, MessageId, Result, Timestamp};
use rusqlite::{params, OptionalExtension as _};

use crate::{storage_error, Storage};

/// Сколько нажатий хранится, пока их не забрали: остальные отбрасываются.
pub const MAX_PENDING_CALLBACKS: i64 = 1000;

/// Клавиатура сообщения в базе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKeyboard {
    /// Чат сообщения.
    pub chat_id: ChatId,
    /// Наше ли это сообщение.
    pub outgoing: bool,
    /// Клавиатура в закодированном виде.
    pub keyboard: Vec<u8>,
}

/// Нажатие кнопки, ждущее обработки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCallback {
    /// Чат, в котором нажали.
    pub chat_id: ChatId,
    /// Сообщение, под которым нажали.
    pub message_id: MessageId,
    /// Данные кнопки.
    pub data: Vec<u8>,
    /// Когда нажатие получено.
    pub received_at: Timestamp,
}

fn chat_from(blob: &[u8]) -> Result<ChatId> {
    uuid::Uuid::from_slice(blob)
        .map(ChatId::from_uuid)
        .map_err(|_| GasAppError::Storage)
}

fn message_from(blob: &[u8]) -> Result<MessageId> {
    uuid::Uuid::from_slice(blob)
        .map(MessageId::from_uuid)
        .map_err(|_| GasAppError::Storage)
}

impl Storage {
    /// Сохраняет клавиатуру сообщения; пустая — убирает её.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn put_message_keyboard(
        &self,
        message_id: &MessageId,
        chat_id: &ChatId,
        outgoing: bool,
        keyboard: &[u8],
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        if keyboard.is_empty() {
            connection
                .execute(
                    "DELETE FROM message_keyboards WHERE message_id = ?",
                    params![message_id.as_bytes().as_slice()],
                )
                .map_err(storage_error)?;
        } else {
            connection
                .execute(
                    "INSERT OR REPLACE INTO message_keyboards
                         (message_id, chat_id, outgoing, keyboard)
                     VALUES (?, ?, ?, ?)",
                    params![
                        message_id.as_bytes().as_slice(),
                        chat_id.as_bytes().as_slice(),
                        outgoing,
                        keyboard
                    ],
                )
                .map_err(storage_error)?;
        }

        Ok(())
    }

    /// Клавиатура сообщения, если оно ещё есть.
    ///
    /// Клавиатура удалённого сообщения не отдаётся и при этом же
    /// обращении стирается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы либо испорченная строка.
    pub fn message_keyboard(&self, message_id: &MessageId) -> Result<Option<StoredKeyboard>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        // 🔐 Сообщения удаляются многими путями (у всех, по таймеру,
        // вместе с чатом): клавиатуры без сообщения стираются здесь, а
        // не в каждом из них.
        connection
            .execute(
                "DELETE FROM message_keyboards
                  WHERE message_id NOT IN (SELECT message_id FROM messages)",
                [],
            )
            .map_err(storage_error)?;

        let row: Option<(Vec<u8>, bool, Vec<u8>)> = connection
            .query_row(
                "SELECT chat_id, outgoing, keyboard FROM message_keyboards WHERE message_id = ?",
                params![message_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_error)?;

        row.map(|(chat, outgoing, keyboard)| {
            Ok(StoredKeyboard {
                chat_id: chat_from(&chat)?,
                outgoing,
                keyboard,
            })
        })
        .transpose()
    }

    /// Ставит нажатие в очередь. Сверх предела нажатия отбрасываются:
    /// очередь, которую никто не забирает, не должна расти без конца.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn push_button_callback(&self, callback: &StoredCallback) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let waiting: i64 = connection
            .query_row("SELECT count(*) FROM button_callbacks", [], |row| {
                row.get(0)
            })
            .map_err(storage_error)?;

        if waiting >= MAX_PENDING_CALLBACKS {
            return Ok(());
        }

        connection
            .execute(
                "INSERT INTO button_callbacks (chat_id, message_id, data, received_at)
                 VALUES (?, ?, ?, ?)",
                params![
                    callback.chat_id.as_bytes().as_slice(),
                    callback.message_id.as_bytes().as_slice(),
                    callback.data,
                    callback.received_at.as_millis()
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Забирает нажатия из очереди, от старых к новым.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы либо испорченная строка.
    pub fn take_button_callbacks(&self) -> Result<Vec<StoredCallback>> {
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, i64)> = {
            let mut statement = transaction
                .prepare(
                    "SELECT chat_id, message_id, data, received_at
                       FROM button_callbacks ORDER BY id",
                )
                .map_err(storage_error)?;

            let rows = statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .map_err(storage_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)?;

            rows
        };

        transaction
            .execute("DELETE FROM button_callbacks", [])
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;

        rows.into_iter()
            .map(|(chat, message, data, received_at)| {
                Ok(StoredCallback {
                    chat_id: chat_from(&chat)?,
                    message_id: message_from(&message)?,
                    data,
                    received_at: Timestamp::from_millis(received_at),
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("keyboards.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");

        (storage, dir)
    }

    #[test]
    fn a_keyboard_without_its_message_is_not_kept() {
        let (storage, _dir) = open_temp();
        let message = MessageId::generate();
        let chat = ChatId::generate();

        // Сообщения с таким идентификатором в базе нет — клавиатура
        // сохраняется, но не отдаётся и стирается.
        storage
            .put_message_keyboard(&message, &chat, false, b"keys")
            .unwrap();
        assert_eq!(storage.message_keyboard(&message).unwrap(), None);
    }

    #[test]
    fn callbacks_are_taken_once_and_in_order() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let press = |data: &[u8], at: i64| StoredCallback {
            chat_id: chat,
            message_id: MessageId::generate(),
            data: data.to_vec(),
            received_at: Timestamp::from_millis(at),
        };

        storage.push_button_callback(&press(b"first", 1)).unwrap();
        storage.push_button_callback(&press(b"second", 2)).unwrap();

        let taken = storage.take_button_callbacks().unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].data, b"first");
        assert_eq!(taken[1].data, b"second");
        assert!(storage.take_button_callbacks().unwrap().is_empty());
    }
}
