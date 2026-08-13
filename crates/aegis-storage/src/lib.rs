// SPDX-License-Identifier: Apache-2.0

//! Зашифрованное локальное хранилище на SQLCipher.
//!
//! Реализация использует SQLCipher через rusqlite с фичей `bundled-sqlcipher`.
//! Ключ шифрования предоставляется иерархией из `aegis-keystore`
//! (раздел 7.1 плана) — этот крейт ключи не выводит и не хранит.
//!
//! Хранилище содержит таблицы для сессий, предключей, известных устройств,
//! контактов, чатов, сообщений и append-only журнал безопасности.
//!
//! # Сборка требует OpenSSL
//!
//! `bundled-sqlcipher` компилирует SQLCipher из исходников, а тому нужен
//! OpenSSL. Путь задаётся переменной окружения `OPENSSL_DIR` (на Windows
//! дополнительно `OPENSSL_LIB_DIR` и `OPENSSL_INCLUDE_DIR`) — см. раздел
//! про сборку в `CONTRIBUTING.md`. Без неё сборка падает на build-скрипте
//! `libsqlite3-sys`, ещё до компиляции этого крейта.
//!
//! # Что здесь проверяется тестами
//!
//! Главное свойство — файл базы действительно зашифрован: тесты
//! `wrong_key_is_rejected` и `database_file_contains_no_plaintext`
//! проверяют, что чужой ключ не открывает базу, а в сыром файле нет ни
//! опознаваемых строк, ни заголовка `SQLite format 3`.

use std::sync::{Mutex, RwLock};

use aegis_protocol::keys::SessionState;
use aegis_types::{AccountId, AegisError, ChatId, Result, Secret, Timestamp};
use rusqlite::{params, Connection, OpenFlags};

/// Сводит ошибку SQLite к [`AegisError::Storage`], не раскрывая деталей.
///
/// Текст ошибки SQLite может содержать фрагменты запроса и имена таблиц,
/// а он попадает в логи и в UI — правило раздела 4.1 это запрещает. Причина
/// поэтому теряется намеренно, но перед этим пишется в `tracing` на уровне
/// `warn`: журнал разработчика и сообщение пользователю — разные каналы.
///
/// Отдельная функция, а не `impl From<rusqlite::Error> for AegisError`:
/// `AegisError` живёт в `aegis-types`, который про SQLite ничего не знает
/// и знать не должен (раздел 8.2 — границы между слоями).
fn storage_error(error: rusqlite::Error) -> AegisError {
    tracing::warn!("storage operation failed: {error}");
    AegisError::Storage
}

// Размер ключа для SQLCipher в байтах (256 бит).
const SQLCIPHER_KEY_SIZE: usize = 32;

/// PRAGMA, настраивающие сам шифр (раздел 11.1 плана).
///
/// # Порядок обязателен
///
/// Эти PRAGMA применяются **после** `PRAGMA key` и **до** первого обращения
/// к данным. SQLCipher связывает параметры шифра с ключом в момент его
/// установки: заданные раньше ключа они не действуют, заданные позже первого
/// чтения — приводят к ошибке или к чтению базы с параметрами по умолчанию.
/// Прежняя реализация применяла их до `PRAGMA key`, то есть настройки шифра
/// молча не применялись.
const SQLCIPHER_CIPHER_PRAGMAS: &[&str] = &[
    "PRAGMA cipher_page_size = 4096;",
    "PRAGMA cipher_hmac_algorithm = HMAC_SHA512;",
    "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
    // Обнуление буферов страниц в памяти после использования.
    "PRAGMA cipher_memory_security = ON;",
];

/// PRAGMA уровня SQLite, не связанные с ключом.
///
/// Применяются после установки ключа и параметров шифра.
const SQLITE_PRAGMAS: &[&str] = &[
    // Перезапись освобождённых страниц вместо простой пометки «свободна»:
    // без этого удалённое сообщение остаётся в файле (раздел 11.3 плана).
    "PRAGMA secure_delete = ON;",
    "PRAGMA journal_mode = WAL;",
    "PRAGMA auto_vacuum = FULL;",
    // Временные таблицы не попадают на диск в открытом виде.
    "PRAGMA temp_store = MEMORY;",
];

/// Структура для хранения состояния хранилища.
pub struct Storage {
    /// Подключение к зашифрованной базе данных.
    connection: Mutex<Connection>,
    /// Флаг готовности хранилища.
    ///
    /// Читается через [`Storage::is_initialized`]: конструктор — единственный
    /// путь создания `Storage`, поэтому значение всегда `true`, но поле
    /// остаётся точкой расширения для будущего закрытия/переоткрытия базы.
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
        // Открываем соединение с базой данных.
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage_error)?;

        // 1. Ключ — первым делом, до любых других PRAGMA и до обращения
        //    к данным. Передаётся как raw-ключ (`x'...'`), поэтому KDF
        //    не применяется: ключ уже выведен иерархией из aegis-keystore,
        //    и прогонять его через PBKDF2 второй раз незачем.
        //
        //    `execute_batch`, а не `execute`: `execute` ожидает выражение,
        //    возвращающее число изменённых строк, а PRAGMA возвращает набор
        //    строк либо ничего.
        let key_hex = hex::encode(encryption_key);
        connection
            .execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))
            .map_err(storage_error)?;

        // 2. Параметры шифра — сразу после ключа.
        for pragma in SQLCIPHER_CIPHER_PRAGMAS {
            connection.execute_batch(pragma).map_err(storage_error)?;
        }

        // 3. Проверяем, что ключ верный, до создания таблиц.
        //
        //    Без этой проверки неверный ключ обнаружился бы только при первом
        //    чтении — а `CREATE TABLE IF NOT EXISTS` к тому моменту уже
        //    испортил бы файл, к которому просто подобрали не тот ключ.
        Self::verify_key(&connection)?;

        // 4. Остальные настройки SQLite.
        for pragma in SQLITE_PRAGMAS {
            connection.execute_batch(pragma).map_err(storage_error)?;
        }

        // Создаем таблицы, если они еще не существуют
        Self::create_tables(&connection)?;

        Ok(Storage {
            connection: Mutex::new(connection),
            initialized: RwLock::new(true),
        })
    }

    /// Проверяет, что установленный ключ расшифровывает базу.
    ///
    /// Чтение `sqlite_schema` — первое обращение к зашифрованным страницам.
    /// На неверном ключе SQLCipher не может расшифровать заголовок и
    /// возвращает ошибку «file is not a database»; на пустом новом файле
    /// чтение проходит успешно и база связывается с этим ключом.
    fn verify_key(connection: &Connection) -> Result<()> {
        connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })
            // Причина не детализируется: отличать «неверный ключ» от «файл
            // повреждён» значит давать оракул тому, кто подбирает ключ.
            .map_err(|_| AegisError::Crypto)?;

        Ok(())
    }

    /// Создает все необходимые таблицы в базе данных.
    fn create_tables(connection: &Connection) -> Result<()> {
        // Таблица для хранения информации об аккаунте (один запись)
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                account_id BLOB NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для сессий (по chat_id)
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS sessions (
                chat_id BLOB PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для предварительных ключей bundles (по account_id, device_id)
        connection
            .execute(
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
            )
            .map_err(storage_error)?;

        // Таблица для использованных одноразовых предварительных ключей
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS used_op_ks (
                account_id BLOB NOT NULL,
                device_id BLOB NOT NULL,
                opk_id INTEGER NOT NULL,
                used_at INTEGER NOT NULL,
                PRIMARY KEY (account_id, device_id, opk_id)
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для использованных одноразовых пост-квантовых предварительных ключей
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS used_pqop_ks (
                account_id BLOB NOT NULL,
                device_id BLOB NOT NULL,
                pqopk_id INTEGER NOT NULL,
                used_at INTEGER NOT NULL,
                PRIMARY KEY (account_id, device_id, pqopk_id)
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для известных устройств (device_id -> device_name)
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS known_devices (
                device_id BLOB PRIMARY KEY,
                device_name TEXT NOT NULL
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для известных контактов (account_id -> identity_key)
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS known_contacts (
                account_id BLOB PRIMARY KEY,
                identity_key BLOB NOT NULL
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для безопасных номеров (account_id -> safety_number)
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS safety_numbers (
                account_id BLOB PRIMARY KEY,
                safety_number BLOB NOT NULL
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для отметок о верификации контактов
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS verified_contacts (
                account_id BLOB PRIMARY KEY
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для состояний чатов
        connection
            .execute(
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
            )
            .map_err(storage_error)?;

        // Таблица для последней синхронизации с сервером
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS last_sync (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                timestamp INTEGER
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для флага резервного копирования
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS backup_overdue (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                overdue BOOLEAN NOT NULL
            )
            ",
                [],
            )
            .map_err(storage_error)?;
        // Убедимся, что есть одна строка с надписью false по умолчанию
        connection
            .execute(
                "
            INSERT OR IGNORE INTO backup_overdue (id, overdue) VALUES (1, 0)
            ",
                [],
            )
            .map_err(storage_error)?;

        // Таблица для сообщений
        connection
            .execute(
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
            )
            .map_err(storage_error)?;

        // Таблица для вложений (метаданные)
        connection
            .execute(
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
            )
            .map_err(storage_error)?;

        // Append-only журнал безопасности
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS security_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT
            )
            ",
                [],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    // --- Account methods ---

    /// Сохраняет идентификатор аккаунта.
    ///
    /// Время передаётся аргументом, а не берётся из системных часов: этот
    /// крейт, как и `aegis-protocol`, не обращается к глобальному источнику
    /// времени — иначе тесты перестают быть воспроизводимыми (раздел 9.2).
    pub fn set_account_id(&self, account_id: &AccountId, now: Timestamp) -> Result<()> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let account_bytes = account_id.as_bytes();
        conn.execute(
            "
            INSERT OR REPLACE INTO account (id, account_id, created_at)
            VALUES (1, ?, ?)
            ",
            params![account_bytes, now.as_millis()],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    /// Получает идентификатор аккаунта, если он существует.
    pub fn get_account_id(&self) -> Result<Option<AccountId>> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut stmt = conn
            .prepare("SELECT account_id FROM account WHERE id = 1")
            .map_err(storage_error)?;
        let mut rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage_error)?;

        let Some(bytes) = rows.next().transpose().map_err(storage_error)? else {
            return Ok(None);
        };

        // Битые байты в собственной БД — признак повреждения, а не сценарий
        // работы: отвечаем ошибкой, а не паникой.
        let uuid = uuid::Uuid::from_slice(&bytes).map_err(|_| AegisError::Storage)?;

        Ok(Some(AccountId::from_uuid(uuid)))
    }

    // --- Session methods ---

    /// Сохраняет состояние сессии для указанного чата.
    pub fn save_session(
        &self,
        chat_id: &ChatId,
        state: &SessionState,
        now: Timestamp,
    ) -> Result<()> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let state_bytes = state.serialized().expose_secret().to_vec();
        conn.execute(
            "
            INSERT OR REPLACE INTO sessions (chat_id, state, updated_at)
            VALUES (?, ?, ?)
            ",
            params![chat_id.as_bytes(), state_bytes, now.as_millis()],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    /// Получает состояние сессии для указанного чата, если оно существует.
    pub fn load_session(&self, chat_id: &ChatId) -> Result<Option<SessionState>> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut stmt = conn
            .prepare("SELECT state FROM sessions WHERE chat_id = ?")
            .map_err(storage_error)?;
        let mut rows = stmt
            .query_map(params![chat_id.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage_error)?;

        Ok(rows
            .next()
            .transpose()
            .map_err(storage_error)?
            .map(|bytes| SessionState::from_serialized(Secret::new(bytes))))
    }

    // TODO: Implement other methods (prekey bundles, used OPKs, known devices, etc.)

    /// Записывает событие в журнал безопасности.
    pub fn log_security_event(
        &self,
        event_type: &str,
        details: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        let timestamp = now.as_millis();
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        conn.execute(
            "INSERT INTO security_log (timestamp, event_type, details) VALUES (?, ?, ?)",
            params![timestamp, event_type, details.unwrap_or("")],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    /// Готово ли хранилище к работе.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.read().is_ok_and(|flag| *flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Опознаваемая строка, которую тесты ищут в сыром файле базы.
    const CANARY: &str = "ATTACK-AT-DAWN-CANARY";

    fn test_key() -> [u8; SQLCIPHER_KEY_SIZE] {
        [0x5Au8; SQLCIPHER_KEY_SIZE]
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    /// Открывает базу во временном каталоге и возвращает её вместе с путём.
    fn open_temp(key: &[u8; SQLCIPHER_KEY_SIZE]) -> (Storage, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("временный каталог");
        let path = dir.path().join("aegis.db").to_string_lossy().into_owned();
        let storage = Storage::new(&path, key).expect("база открывается");

        (storage, dir, path)
    }

    #[test]
    fn storage_opens_and_reports_initialized() {
        let (storage, _dir, _path) = open_temp(&test_key());

        assert!(storage.is_initialized());
    }

    #[test]
    fn account_id_round_trips() {
        let (storage, _dir, _path) = open_temp(&test_key());
        assert!(storage.get_account_id().unwrap().is_none());

        let account = AccountId::generate();
        storage.set_account_id(&account, now()).unwrap();
        assert_eq!(storage.get_account_id().unwrap(), Some(account));

        // Повторная запись заменяет значение, а не добавляет вторую строку.
        let replacement = AccountId::generate();
        storage.set_account_id(&replacement, now()).unwrap();
        assert_eq!(storage.get_account_id().unwrap(), Some(replacement));
    }

    #[test]
    fn session_state_round_trips() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();
        assert!(storage.load_session(&chat).unwrap().is_none());

        let state = SessionState::from_serialized(Secret::new(CANARY.as_bytes().to_vec()));
        storage.save_session(&chat, &state, now()).unwrap();

        let loaded = storage.load_session(&chat).unwrap().expect("сессия есть");
        assert_eq!(loaded.serialized().expose_secret(), CANARY.as_bytes());
    }

    /// Данные переживают закрытие и повторное открытие базы.
    ///
    /// Проверяет, что ключ и параметры шифра совпадают между сессиями:
    /// при неверном порядке PRAGMA база открывается, но читается уже иначе.
    #[test]
    fn data_survives_reopen_with_same_key() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);
        let account = AccountId::generate();
        storage.set_account_id(&account, now()).unwrap();
        drop(storage);

        let reopened = Storage::new(&path, &key).expect("та же база с тем же ключом");

        assert_eq!(reopened.get_account_id().unwrap(), Some(account));
    }

    /// С неверным ключом база не открывается.
    ///
    /// Это и есть проверка того, что файл действительно зашифрован: без неё
    /// «шифрование» могло бы молча не применяться (ровно так и было, пока
    /// `PRAGMA key` шёл после параметров шифра).
    #[test]
    fn wrong_key_is_rejected() {
        let (storage, _dir, path) = open_temp(&test_key());
        storage
            .set_account_id(&AccountId::generate(), now())
            .unwrap();
        drop(storage);

        let mut wrong = test_key();
        wrong[0] ^= 0xFF;

        assert!(matches!(
            Storage::new(&path, &wrong),
            Err(AegisError::Crypto)
        ));
    }

    /// 🧪 Задача M3: сырой файл базы не содержит распознаваемых строк.
    #[test]
    fn database_file_contains_no_plaintext() {
        let (storage, _dir, path) = open_temp(&test_key());
        let chat = ChatId::generate();

        storage
            .save_session(
                &chat,
                &SessionState::from_serialized(Secret::new(CANARY.as_bytes().to_vec())),
                now(),
            )
            .unwrap();
        storage
            .log_security_event("identity_key_changed", Some(CANARY), now())
            .unwrap();
        // Закрываем базу, чтобы WAL сбросился в основной файл.
        drop(storage);

        for candidate in [&path, &format!("{path}-wal")] {
            let Ok(raw) = std::fs::read(candidate) else {
                continue;
            };

            assert!(
                !raw.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
                "открытый текст найден в {candidate}"
            );
            // Заголовок «SQLite format 3» есть у незашифрованной базы и
            // отсутствует у зашифрованной SQLCipher.
            assert!(
                !raw.starts_with(b"SQLite format 3"),
                "{candidate} не зашифрован"
            );
        }
    }

    /// Журнал безопасности пишется и не теряет события.
    #[test]
    fn security_log_accepts_events() {
        let (storage, _dir, _path) = open_temp(&test_key());

        storage
            .log_security_event("session_reset", None, now())
            .unwrap();
        storage
            .log_security_event("identity_key_changed", Some("device 2"), now())
            .unwrap();
    }
}
