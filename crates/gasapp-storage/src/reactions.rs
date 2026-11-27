// SPDX-License-Identifier: Apache-2.0

//! Реакции на сообщения и ответы (цитаты).
//!
//! Реакция — одна от каждой стороны на сообщение: новая заменяет прежнюю,
//! пустая снимает. Ответ — ссылка сообщения на то, на которое оно отвечает.

use gasapp_types::{ChatId, GasAppError, MessageId, Result, Timestamp};
use rusqlite::params;

use crate::{storage_error, uuid_from_slice, Storage};

/// Реакция в переписке.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReaction {
    /// Сообщение, на которое реакция.
    pub message_id: MessageId,
    /// Своя ли.
    pub mine: bool,
    /// Эмодзи.
    pub emoji: String,
}

impl Storage {
    /// Ставит реакцию (`None` — снимает).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_reaction(
        &self,
        message_id: &MessageId,
        mine: bool,
        emoji: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        match emoji {
            Some(emoji) => connection.execute(
                "INSERT OR REPLACE INTO message_reactions (message_id, mine, emoji, updated_at)
                 VALUES (?, ?, ?, ?)",
                params![
                    message_id.as_bytes(),
                    i64::from(mine),
                    emoji,
                    now.as_millis()
                ],
            ),
            None => connection.execute(
                "DELETE FROM message_reactions WHERE message_id = ? AND mine = ?",
                params![message_id.as_bytes(), i64::from(mine)],
            ),
        }
        .map_err(storage_error)?;
        Ok(())
    }

    /// Реакции на сообщения чата — одним запросом.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn reactions_in_chat(&self, chat_id: &ChatId) -> Result<Vec<StoredReaction>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare_cached(
                "SELECT r.message_id, r.mine, r.emoji FROM message_reactions r
                   JOIN messages m ON m.message_id = r.message_id
                  WHERE m.chat_id = ?
                  ORDER BY r.updated_at",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![chat_id.as_bytes()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage_error)?;
        let mut reactions = Vec::new();
        for row in rows {
            let (id, mine, emoji) = row.map_err(storage_error)?;
            reactions.push(StoredReaction {
                message_id: MessageId::from_uuid(uuid_from_slice(&id)?),
                mine: mine != 0,
                emoji,
            });
        }
        Ok(reactions)
    }

    /// Запоминает, на какое сообщение отвечает это.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_reply(&self, message_id: &MessageId, reply_to: &MessageId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO message_replies (message_id, reply_to) VALUES (?, ?)",
                params![message_id.as_bytes(), reply_to.as_bytes()],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    /// Ответы в чате: сообщение → то, на которое оно отвечает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn replies_in_chat(&self, chat_id: &ChatId) -> Result<Vec<(MessageId, MessageId)>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare_cached(
                "SELECT r.message_id, r.reply_to FROM message_replies r
                   JOIN messages m ON m.message_id = r.message_id
                  WHERE m.chat_id = ?",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![chat_id.as_bytes()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(storage_error)?;
        let mut replies = Vec::new();
        for row in rows {
            let (id, to) = row.map_err(storage_error)?;
            replies.push((
                MessageId::from_uuid(uuid_from_slice(&id)?),
                MessageId::from_uuid(uuid_from_slice(&to)?),
            ));
        }
        Ok(replies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageStatus, StoredMessage};
    use gasapp_types::{AccountId, Ciphertext};

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("reactions.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");
        (storage, dir)
    }

    fn message(storage: &Storage, chat: ChatId) -> MessageId {
        let id = MessageId::generate();
        storage
            .save_message(&StoredMessage {
                id,
                chat_id: chat,
                sender_id: AccountId::generate(),
                timestamp: Timestamp::from_millis(1),
                content: Ciphertext::new(vec![1]),
                status: MessageStatus::Sent,
                message_type: 0,
                expires_at: None,
            })
            .unwrap();
        id
    }

    #[test]
    fn one_reaction_per_side_and_replies_per_chat() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let first = message(&storage, chat);
        let second = message(&storage, chat);
        let elsewhere = message(&storage, ChatId::generate());

        let now = Timestamp::from_millis(5);
        storage.set_reaction(&first, true, Some("👍"), now).unwrap();
        storage.set_reaction(&first, true, Some("❤️"), now).unwrap();
        storage
            .set_reaction(&first, false, Some("😂"), now)
            .unwrap();
        storage
            .set_reaction(&elsewhere, false, Some("🔥"), now)
            .unwrap();
        let reactions = storage.reactions_in_chat(&chat).unwrap();
        assert_eq!(reactions.len(), 2);
        assert!(reactions.iter().any(|r| r.mine && r.emoji == "❤️"));

        storage.set_reaction(&first, true, None, now).unwrap();
        assert_eq!(storage.reactions_in_chat(&chat).unwrap().len(), 1);

        storage.set_reply(&second, &first).unwrap();
        // Ответ не переписывается.
        storage.set_reply(&second, &elsewhere).unwrap();
        assert_eq!(
            storage.replies_in_chat(&chat).unwrap(),
            vec![(second, first)]
        );
    }
}
