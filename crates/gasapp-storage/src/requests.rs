// SPDX-License-Identifier: Apache-2.0

//! Запросы на переписку.
//!
//! # Зачем
//!
//! Первое сообщение от незнакомца открывало переписку сразу: интерфейс
//! слал ему квитанции о прочтении и «печатает…», то есть подтверждал,
//! что человек в сети и прочёл, — ещё до того, как тот решил, хочет ли
//! вообще разговаривать. Теперь такая переписка — запрос: читать можно,
//! но ничего не уходит в ответ, пока человек его не примет.
//!
//! Состояние — у чата (`chat_states.request_state`, схема 11):
//!
//! * [`ChatRequest::Settled`] — обычная переписка;
//! * [`ChatRequest::Incoming`] — запрос от незнакомца, ещё не принят;
//! * [`ChatRequest::Outgoing`] — переписку начали мы, собеседник ещё
//!   не ответил.

use gasapp_types::{ChatId, GasAppError, Result, Timestamp};
use rusqlite::params;

use crate::{checkpoint_truncate, storage_error, Storage};

/// Состояние запроса на переписку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatRequest {
    /// Обычная переписка.
    Settled,
    /// Запрос от незнакомца: читать можно, отвечать — после принятия.
    Incoming,
    /// Мы начали переписку, собеседник ещё не ответил.
    Outgoing,
}

impl ChatRequest {
    const fn to_db(self) -> i64 {
        match self {
            Self::Settled => 0,
            Self::Incoming => 1,
            Self::Outgoing => 2,
        }
    }

    fn from_db(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::Settled),
            1 => Ok(Self::Incoming),
            2 => Ok(Self::Outgoing),
            _ => Err(GasAppError::Storage),
        }
    }
}

impl Storage {
    /// Состояние запроса чата; `None` — чата ещё нет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось либо значение повреждено.
    pub fn chat_request_state(&self, chat_id: &ChatId) -> Result<Option<ChatRequest>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let row = connection.query_row(
            "SELECT request_state FROM chat_states WHERE chat_id = ?",
            params![chat_id.as_bytes()],
            |row| row.get::<_, i64>(0),
        );

        match row {
            Ok(value) => ChatRequest::from_db(value).map(Some),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Записывает состояние запроса, заводя строку чата при нужде.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_chat_request_state(&self, chat_id: &ChatId, state: ChatRequest) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "
            INSERT INTO chat_states (chat_id, request_state)
            VALUES (?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                request_state = excluded.request_state
            ",
                params![chat_id.as_bytes(), state.to_db()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Удаляет переписку целиком: сообщения с вложениями, сессию,
    /// состояние чата и — если собеседник ничем не подтверждён — его
    /// запись в контактах.
    ///
    /// Для отклонённого запроса: незнакомец, которому отказали,
    /// не должен оставаться ни в списке чатов, ни в контактах. Контакт,
    /// чей ключ сверен или пришёл по его ссылке, остаётся: эту работу
    /// человек сделал сам, и отказ от переписки её не отменяет.
    ///
    /// Сообщения удаляются с надгробиями — иначе вернулись бы
    /// из резервной копии (см. [`Storage::delete_message`]).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — удаление не удалось.
    pub fn delete_chat(&self, chat_id: &ChatId, now: Timestamp) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.unchecked_transaction().map_err(storage_error)?;
        let chat = chat_id.as_bytes();

        transaction
            .execute(
                "INSERT OR REPLACE INTO backup_tombstones (message_id, deleted_at)
                 SELECT message_id, ? FROM messages WHERE chat_id = ?",
                params![now.as_millis(), chat],
            )
            .map_err(storage_error)?;

        transaction
            .execute(
                "DELETE FROM attachments
                 WHERE message_id IN (SELECT message_id FROM messages WHERE chat_id = ?)",
                params![chat],
            )
            .map_err(storage_error)?;

        for statement in [
            "DELETE FROM messages WHERE chat_id = ?",
            "DELETE FROM sessions WHERE chat_id = ?",
            "DELETE FROM chat_states WHERE chat_id = ?",
            // Доказательство для жалобы — запись о том, что собеседник
            // писал; уходит вместе с перепиской. Блокировка остаётся.
            "DELETE FROM report_certificates WHERE chat_id = ?",
            "DELETE FROM known_contacts
             WHERE chat_id = ?
               AND confirmed_by_link = 0
               AND account_id NOT IN (SELECT account_id FROM verified_contacts)",
        ] {
            transaction
                .execute(statement, params![chat])
                .map_err(storage_error)?;
        }

        transaction.commit().map_err(storage_error)?;

        checkpoint_truncate(&connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("временный каталог");
        let path = directory
            .path()
            .join("gasapp.db")
            .to_string_lossy()
            .into_owned();
        let storage = Storage::new(&path, &[0x5Au8; 32]).expect("база открывается");

        (storage, directory)
    }

    #[test]
    fn request_state_round_trips() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::from_uuid(uuid::Uuid::from_bytes([7; 16]));

        assert_eq!(storage.chat_request_state(&chat).expect("чтение"), None);

        for state in [
            ChatRequest::Incoming,
            ChatRequest::Outgoing,
            ChatRequest::Settled,
        ] {
            storage
                .set_chat_request_state(&chat, state)
                .expect("запись");
            assert_eq!(
                storage.chat_request_state(&chat).expect("чтение"),
                Some(state)
            );
        }
    }

    /// Строка, заведённая активностью, — обычная переписка.
    #[test]
    fn a_chat_touched_by_activity_is_settled() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::from_uuid(uuid::Uuid::from_bytes([8; 16]));

        storage
            .touch_chat(&chat, None, Timestamp::from_millis(1))
            .expect("запись");

        assert_eq!(
            storage.chat_request_state(&chat).expect("чтение"),
            Some(ChatRequest::Settled)
        );
    }
}
