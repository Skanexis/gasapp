// SPDX-License-Identifier: Apache-2.0

//! Настройки чатов в списке: закреплённые наверху, «без звука» — и
//! удаление переписки у себя.

use gasapp_types::{ChatId, GasAppError, Result, Timestamp};
use rusqlite::params;

use crate::{checkpoint_truncate, storage_error, uuid_from_slice, Storage};

/// Настройки одного чата.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatPrefs {
    /// Чат.
    pub chat_id: ChatId,
    /// Когда закреплён (0 — не закреплён): позже закреплённый — выше.
    pub pinned_at: i64,
    /// Без звука: новое не зовёт значком вкладки.
    pub muted: bool,
}

impl Storage {
    /// Закрепить чат наверху списка (`None` — открепить).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_chat_pinned(&self, chat_id: &ChatId, pinned_at: Option<Timestamp>) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .execute(
                "INSERT INTO chat_prefs (chat_id, pinned_at) VALUES (?1, ?2)
                 ON CONFLICT(chat_id) DO UPDATE SET pinned_at = ?2",
                params![chat_id.as_bytes(), pinned_at.map_or(0, |at| at.as_millis())],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    /// Чат «без звука» или снова со звуком.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_chat_muted(&self, chat_id: &ChatId, muted: bool) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .execute(
                "INSERT INTO chat_prefs (chat_id, muted) VALUES (?1, ?2)
                 ON CONFLICT(chat_id) DO UPDATE SET muted = ?2",
                params![chat_id.as_bytes(), i64::from(muted)],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    /// Настройки всех чатов, где что-то задано.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn chat_prefs(&self) -> Result<Vec<ChatPrefs>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare_cached(
                "SELECT chat_id, pinned_at, muted FROM chat_prefs WHERE pinned_at > 0 OR muted != 0",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(storage_error)?;
        let mut prefs = Vec::new();
        for row in rows {
            let (chat, pinned_at, muted) = row.map_err(storage_error)?;
            prefs.push(ChatPrefs {
                chat_id: ChatId::from_uuid(uuid_from_slice(&chat)?),
                pinned_at,
                muted: muted != 0,
            });
        }
        Ok(prefs)
    }

    /// Удаляет переписку у себя: сообщения с вложениями, реакции и ответы,
    /// строку в списке и её настройки. Сессия и контакт остаются — писать
    /// можно сразу, собеседник ничего не узнаёт. Сообщения — с надгробиями,
    /// иначе вернулись бы из резервной копии.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — удаление не удалось.
    pub fn clear_chat(&self, chat_id: &ChatId, now: Timestamp) -> Result<()> {
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
        for statement in [
            "DELETE FROM attachments
              WHERE message_id IN (SELECT message_id FROM messages WHERE chat_id = ?1)",
            "DELETE FROM message_reactions
              WHERE message_id IN (SELECT message_id FROM messages WHERE chat_id = ?1)",
            "DELETE FROM message_replies
              WHERE message_id IN (SELECT message_id FROM messages WHERE chat_id = ?1)",
            "DELETE FROM messages WHERE chat_id = ?1",
            "DELETE FROM chat_states WHERE chat_id = ?1",
            "DELETE FROM chat_prefs WHERE chat_id = ?1",
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
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("prefs.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");
        (storage, dir)
    }

    #[test]
    fn pins_and_mutes_are_kept_per_chat() {
        let (storage, _dir) = open_temp();
        let (first, second) = (ChatId::generate(), ChatId::generate());
        storage
            .set_chat_pinned(&first, Some(Timestamp::from_millis(7)))
            .unwrap();
        storage.set_chat_muted(&first, true).unwrap();
        storage.set_chat_muted(&second, true).unwrap();
        storage.set_chat_muted(&second, false).unwrap();

        assert_eq!(
            storage.chat_prefs().unwrap(),
            vec![ChatPrefs {
                chat_id: first,
                pinned_at: 7,
                muted: true
            }]
        );

        storage.set_chat_pinned(&first, None).unwrap();
        storage
            .clear_chat(&first, Timestamp::from_millis(9))
            .unwrap();
        assert!(storage.chat_prefs().unwrap().is_empty());
    }
}
