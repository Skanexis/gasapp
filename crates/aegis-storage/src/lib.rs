// SPDX-License-Identifier: Apache-2.0

//! Зашифрованное локальное хранилище на SQLCipher.
//!
//! Реализация использует SQLCipher через rusqlite с функцией `bundled_sqlcipher`.
//! Ключ шифрования предоставляется из иерархии ключей (раздел 7.1 дорожной карты).
//!
//! Хранилище содержит таблицы для сессий, предварительных ключей, известных устройств,
//! контактов, чатов, сообщений и т.д., а такжеappend-only журнал безопасности.

use aegis_types::{
    AccountId, ChatId, DeviceId, MessageId, Timestamp, Result, AegisError, Secret,
};
use aegis_protocol::{
    Fingerprint, ProtocolVersion, SafetyNumber,
    engine::{InitialMessage, InitiatedSession},
    keys::{IdentityKey, IdentityKeyPair, KemPublicKey, PreKeyBundle, PreKeyId, SessionState,
           SignedPreKey, SignedKemPreKey},
};
use chrono::{Utc, DateTime};
use rusqlite::{params, Connection, OpenFlags};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::{Mutex, RwLock};
use zeroize::Zeroize;
use hex;

// Размер ключа для SQLCipher в байтах (256 бит).
const SQLCIPHER_KEY_SIZE: usize = 32;

// PRAGMA настройки для SQLCipher, как указано в дорожной карте.
const SQLCIPHER_PRAGMAS: &[&str] = &[
    "PRAGMA cipher_page_size = 4096;",
    "PRAGMA kdf_iter = 256000;", // но мы передаём raw key, KDF не используется
    "PRAGMA cipher_hmac_algorithm = HMAC_SHA512;",
    "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
    "PRAGMA cipher_memory_security = ON;",    -- обнуление памяти
    "PRAGMA secure_delete = ON;",             -- перезапись удалённых страниц
    "PRAGMA journal_mode = WAL;",
    "PRAGMA auto_vacuum = FULL;",
    "PRAGMA temp_store = MEMORY;",            -- временные таблицы в памяти
];

/// Структура для хранения состояния хранилища.
pub struct Storage {
    /// Подключение к зашифрованной базе данных.
    connection: Mutex<Connection>,
    /// Флаг, указывающий, что хранилище инициализировано и готово к использованию.
    initialized: RwLock<bool>,
}

impl Storage {
    /// Создает новое хранилище и инициализирует базу данных.
    ///
    /// # Arguments
    /// * `path` - путь к файлу базы данных.
    /// * `encryption_key` - 32-байтовый ключ для SQLCipher из иерархии ключей.
    ///
    /// // Returns
    /// * `Result<Self>` - инициализированное хранилище или ошибка.
    pub fn new(path: &str, encryption_key: &[u8; SQLCIPHER_KEY_SIZE]) -> Result<Self> {
        // Проверяем размер ключа
        if encryption_key.len() != SQLCIPHER_KEY_SIZE {
            return Err(AegisError::Crypto);
        }

        // Открываем соединение с базой данных
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Применяем PRAGMA настройки для SQLCipher
        for pragma in SQLCIPHER_PRAGMAS {
            connection.execute(pragma, [])?;
        }

        // Устанавливаем ключ шифрования как raw hex
        let key_hex = hex::encode(encryption_key);
        connection.execute(
            &format!("PRAGMA key = \"x'{}'\";", key_hex),
            [],
        )?;

        // Создаем таблицы, если они еще не существуют
        Self::create_tables(&connection)?;

        Ok(Storage {
            connection: Mutex::new(connection),
            initialized: RwLock::new(true),
        })
    }

    /// Создает все необходимые таблицы в базе данных.
    fn create_tables(connection: &Connection) -> Result<()> {
        // Таблица для хранения информации об аккаунте (один запись)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                account_id BLOB NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            )
            ",
            [],
        )?;

        // Таблица для сессий (по chat_id)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS sessions (
                chat_id BLOB PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )
            ",
            [],
        )?;

        // Таблица для предварительных ключей bundles (по account_id, device_id)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS prekey_bundles (
                account_id BLOB NOT NULL,
                device_id BLOB NOT NULL,
                bundle BLOB NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (account_id, device_id)
            )
            ",
            [],
        )?;

        // Таблица для использованных одноразовых предварительных ключей
        connection.execute(
            "
            CREATE TABLE IF NOTUSED_OP_KS (
                account_id BLOB NOT NULL,
                device_id BLOB NOT NULL,
                opk_id INTEGER NOT NULL,
                used_at INTEGER NOT NULL,
                PRIMARY KEY (account_id, device_id, opk_id)
            )
            ",
            [],
        )?;

        // Таблица для использованных одноразовых пост-квантовых предварительных ключей
        connection.execute(
            "
            CREATE TABLE IF NOTUSED_PQOP_KS (
                account_id BLOB NOT NULL,
                device_id BLOB NOT NULL,
                pqopk_id INTEGER NOT NULL,
                used_at INTEGER NOT NULL,
                PRIMARY KEY (account_id, device_id, pqopk_id)
            )
            ",
            [],
        )?;

        // Таблица для известных устройств (device_id -> device_name)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS known_devices (
                device_id BLOB PRIMARY KEY,
                device_name TEXT NOT NULL
            )
            ",
            [],
        )?;

        // Таблица для известных контактов (account_id -> identity_key)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS known_contacts (
                account_id BLOB PRIMARY KEY,
                identity_key BLOB NOT NULL
            )
            ",
            [],
        )?;

        // Таблица для безопасных номеров (account_id -> safety_number)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS safety_numbers (
                account_id BLOB PRIMARY KEY,
                safety_number BLOB NOT NULL
            )
            ",
            [],
        )?;

        // Таблица для отметок о верификации контактов
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS verified_contacts (
                account_id BLOB PRIMARY KEY
            )
            ",
            [],
        )?;

        // Таблица для состояний чатов
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS chat_states (
                chat_id BLOB PRIMARY KEY,
                last_message_id BLOB,
                last_activity INTEGER,
                disappearing_timer INTEGER,
                last_typing_notification INTEGER
            )
            ",
            [],
        )?;

        // Таблица для последней синхронизации с сервером
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS last_sync (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                timestamp INTEGER
            )
            ",
            [],
        )?;

        // Таблица для флага резервного копирования
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS backup_overdue (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                overdue BOOLEAN NOT NULL
            )
            ",
            [],
        )?;
        // Убедимся, что есть одна строка с надписью false по умолчанию
        connection.execute(
            "
            INSERT OR IGNORE INTO backup_overdue (id, overdue) VALUES (1, 0)
            ",
            [],
        )?;

        // Таблица для сообщений
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS messages (
                message_id BLOB PRIMARY KEY,
                chat_id BLOB NOT NULL,
                sender_id BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                content BLOB NOT NULL,
                status INTEGER NOT NULL,
                message_type INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            ",
            [],
        )?;

        // Таблица для вложений (метаданные)
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id BLOB NOT NULL,
                attachment_type INTEGER NOT NULL,
                description TEXT,
                size INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(message_id)
            )
            ",
            [],
        )?;

        // Append-only журнал безопасности
        connection.execute(
            "
            CREATE TABLE IF NOT EXISTS security_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT
            )
            ",
            [],
        )?;

        Ok(())
    }

    // --- Account methods ---

    /// Сохраняет идентификатор аккаунта.
    pub fn set_account_id(&self, account_id: &AccountId) -> Result<()> {
        let mut conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let account_bytes = account_id.as_bytes();
        conn.execute(
            "
            INSERT OR REPLACE INTO account (id, account_id, created_at)
            VALUES (1, ?, ?)
            ",
            params![account_bytes, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    /// Получает идентификатор аккаунта, если он существует.
    pub fn get_account_id(&self) -> Result<Option<AccountId>> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut stmt = conn.prepare(
            "SELECT account_id FROM account WHERE id = 1"
        )?;
        let mut rows = stmt.query_map([], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(AccountId::from_uuid(uuid::Uuid::from_slice(&bytes)?))
        })?;
        let account_id = rows.next().transpose()?;
        Ok(account_id)
    }

    // --- Session methods ---

    /// Сохраняет состояние сессии для указанного чата.
    pub fn save_session(&self, chat_id: &ChatId, state: &SessionState) -> Result<()> {
        let mut conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let state_bytes = state.serialized().expose_secret().to_vec();
        conn.execute(
            "
            INSERT OR REPLACE INTO sessions (chat_id, state, updated_at)
            VALUES (?, ?, ?)
            ",
            params![chat_id.as_bytes(), state_bytes, Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    /// Получает состояние сессии для указанного чата, если оно существует.
    pub fn load_session(&self, chat_id: &ChatId) -> Result<Option<SessionState>> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut stmt = conn.prepare(
            "SELECT state FROM sessions WHERE chat_id = ?"
        )?;
        let mut rows = stmt.query_map(params![chat_id.as_bytes()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let secret_bytes = Secret::new(bytes);
            Ok(SessionState::from_serialized(secret_bytes))
        })?;
        let session = rows.next().transpose()?;
        Ok(session)
    }

    // TODO: Implement other methods (prekey bundles, used OPKs, known devices, etc.)

    /// Записывает событие в журнал безопасности.
    pub fn log_security_event(&self, event_type: &str, details: Option<&str>) -> Result<()> {
        let timestamp = Utc::now().timestamp_millis();
        let mut conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        conn.execute(
            "INSERT INTO security_log (timestamp, event_type, details) VALUES (?, ?, ?)",
            params![timestamp, event_type, details.unwrap_or("")],
        )?;
        Ok(())
    }

    /// Очищает все данные из хранилища (используется для тестов и сброса).
    #[cfg(test)]
    pub fn clear(&self) -> Result<()> {
        let mut conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        // Отключаем внешние ключи temporarily, чтобы удалить таблицы в правильном порядке
        conn.execute("PRAGMA foreign_keys = OFF;", [])?;
        // Получаем список всех таблиц и удаляем их
        let tables = vec![
            "account", "sessions", "prekey_bundles", "UNUSED_OP_KS", "UNUSED_PQOP_KS",
            "known_devices", "known_contacts", "safety_numbers", "verified_contacts",
            "chat_states", "last_sync", "backup_overdue", "messages", "attachments", "security_log",
        ];
        for table in tables {
            conn.execute(&format!("DELETE FROM {};", table), [])?;
        }
        conn.execute("PRAGMA foreign_keys = ON;", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::Secret;
    use std::sync::Arc;

    #[test]
    fn test_storage_new() {
        // Генерируем случайный ключ для шифрования
        let mut key = [0u8; SQLCIPHER_KEY_SIZE];
        rand_core::OsRng.fill_bytes(&mut key);
        let key = Secret::new(key);

        // Временная директория для тестовой базы данных
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().into_owned();

        // Создаем хранилище
        let storage = Storage::new(&db_path, &key.expose_secret());
        assert!(storage.is_ok());

        // Проверяем, что хранилище инициализировано
        let storage = storage.unwrap();
        let initialized = storage.initialized.read().unwrap();
        assert!(*initialized);

        // Проверяем, что мы можем записать событие в журнал безопасности
        let result = storage.log_security_event("test_event", Some("test details"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_account_id() {
        let mut key = [0u8; SQLCIPHER_KEY_SIZE];
        rand_core::OsRng.fill_bytes(&mut key);
        let key = Secret::new(key);

        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db").to_string_lossy().into_owned();

        let storage = Storage::new(&db_path, &key.expose_secret()).unwrap();

        // Initially, no account ID
        let account_id = storage.get_account_id().unwrap();
        assert!(account_id.is_none());

        // Set an account ID
        let account_id_to_set = AccountId::generate();
        storage.set_account_id(&account_id_to_set).unwrap();

        // Retrieve it
        let retrieved = storage.get_account_id().unwrap().unwrap();
        assert_eq!(retrieved, account_id_to_set);

        // Update it
        let new_account_id = AccountId::generate();
        storage.set_account_id(&new_account_id).unwrap();
        let updated = storage.get_account_id().unwrap().unwrap();
        assert_eq!(updated, new_account_id);
        assert_ne!(updated, account_id_to_set);
    }
}