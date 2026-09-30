// SPDX-License-Identifier: Apache-2.0

//! Блокировка собеседника и доказательство для жалобы на него.
//!
//! # Блокировка
//!
//! Блокируется чат, а не имя: идентификатор чата выводится из ключей
//! обеих сторон (`derive_chat_id`), поэтому удалённая переписка блокировку
//! не снимает — новый конверт того же собеседника придёт в тот же чат
//! и будет отброшен. Сменивший ключ (новый аккаунт) — уже другой чат:
//! за ним, как за любым незнакомцем, первое сообщение — запрос.
//!
//! Сервер о блокировке не знает: она живёт только здесь. Узнай он о ней,
//! он узнал бы, что двое были знакомы.
//!
//! # Доказательство для жалобы
//!
//! Жалоба на отправителя доказывается его сертификатом — подписанным
//! сервером и снятым получателем с запечатанного конверта (сервер
//! проверяет свою подпись, `/v1/sealed/report`). Без него жалоба была бы
//! словом жалобщика, и любой навесил бы её на неугодного. Поэтому для
//! каждого чата хранится последний сертификат, чья привязка к сессии
//! проверена при приёме.

use aegis_types::{AegisError, ChatId, Result, Timestamp};
use rusqlite::params;

use crate::{storage_error, Storage};

/// Заблокированный чат — для списка «Заблокированные».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedChat {
    /// Чат.
    pub chat_id: ChatId,
    /// Имя собеседника на момент блокировки, если было известно.
    ///
    /// Хранится здесь, а не берётся из контактов: отклонённый запрос
    /// удаляет незнакомца из контактов, а в списке его узнавать надо.
    pub username: Option<String>,
    /// Когда заблокирован.
    pub blocked_at: Timestamp,
}

impl Storage {
    /// Блокирует чат. Повторная блокировка обновляет имя и время.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn block_chat(
        &self,
        chat_id: &ChatId,
        username: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO blocked_chats (chat_id, username, blocked_at)
                 VALUES (?, ?, ?)",
                params![chat_id.as_bytes(), username, now.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Снимает блокировку. Незаблокированный чат — не ошибка.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn unblock_chat(&self, chat_id: &ChatId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "DELETE FROM blocked_chats WHERE chat_id = ?",
                params![chat_id.as_bytes()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Заблокирован ли чат.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn is_chat_blocked(&self, chat_id: &ChatId) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blocked_chats WHERE chat_id = ?)",
                params![chat_id.as_bytes()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(storage_error)
    }

    /// Все заблокированные чаты — свежие первыми.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn blocked_chats(&self) -> Result<Vec<BlockedChat>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut statement = connection
            .prepare(
                "SELECT chat_id, username, blocked_at FROM blocked_chats
                 ORDER BY blocked_at DESC",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(storage_error)?;

        rows.map(|row| {
            let (chat, username, blocked_at) = row.map_err(storage_error)?;
            let bytes: [u8; 16] = chat.try_into().map_err(|_| AegisError::Storage)?;

            Ok(BlockedChat {
                chat_id: ChatId::from_uuid(uuid::Uuid::from_bytes(bytes)),
                username,
                blocked_at: Timestamp::from_millis(blocked_at),
            })
        })
        .collect()
    }

    /// Запоминает сертификат отправителя этого чата — для жалобы.
    ///
    /// Вызывается только после проверки подписи сервера и привязки
    /// сертификата к сессии чата.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_report_certificate(
        &self,
        chat_id: &ChatId,
        certificate: &[u8],
        now: Timestamp,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO report_certificates (chat_id, certificate, received_at)
                 VALUES (?, ?, ?)",
                params![chat_id.as_bytes(), certificate, now.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Сертификат для жалобы; `None` — от собеседника не приходило
    /// ни одного запечатанного конверта, и доказать жалобу нечем.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn report_certificate(&self, chat_id: &ChatId) -> Result<Option<Vec<u8>>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        match connection.query_row(
            "SELECT certificate FROM report_certificates WHERE chat_id = ?",
            params![chat_id.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(certificate) => Ok(Some(certificate)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("blocks.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");

        (storage, dir)
    }

    #[test]
    fn a_chat_is_blocked_until_unblocked() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let other = ChatId::generate();

        assert!(!storage.is_chat_blocked(&chat).expect("чтение"));

        storage
            .block_chat(&chat, Some("mallory"), Timestamp::from_millis(10))
            .expect("блокировка");
        assert!(storage.is_chat_blocked(&chat).expect("чтение"));
        assert!(!storage.is_chat_blocked(&other).expect("чтение"));
        assert_eq!(
            storage.blocked_chats().expect("список"),
            vec![BlockedChat {
                chat_id: chat,
                username: Some("mallory".to_owned()),
                blocked_at: Timestamp::from_millis(10),
            }]
        );

        storage.unblock_chat(&chat).expect("разблокировка");
        assert!(!storage.is_chat_blocked(&chat).expect("чтение"));
        assert!(storage.blocked_chats().expect("список").is_empty());
        storage
            .unblock_chat(&chat)
            .expect("повторная разблокировка — не ошибка");
    }

    /// 🔐 Удалённая переписка блокировку не снимает: новый конверт того же
    /// собеседника приходит в тот же чат.
    #[test]
    fn deleting_the_chat_keeps_the_block() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();

        storage
            .block_chat(&chat, None, Timestamp::from_millis(1))
            .expect("блокировка");
        storage
            .delete_chat(&chat, Timestamp::from_millis(2))
            .expect("удаление");

        assert!(storage.is_chat_blocked(&chat).expect("чтение"));
    }

    #[test]
    fn the_latest_certificate_is_kept_for_a_report() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();

        assert_eq!(storage.report_certificate(&chat).expect("чтение"), None);

        storage
            .save_report_certificate(&chat, b"old", Timestamp::from_millis(1))
            .expect("запись");
        storage
            .save_report_certificate(&chat, b"new", Timestamp::from_millis(2))
            .expect("запись");

        assert_eq!(
            storage.report_certificate(&chat).expect("чтение"),
            Some(b"new".to_vec())
        );
    }
}
