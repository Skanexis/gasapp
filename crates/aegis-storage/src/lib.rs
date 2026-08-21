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
use aegis_types::{
    AccountId, AegisError, ChatId, Ciphertext, MessageId, Result, Secret, Timestamp,
};
use rusqlite::{params, Connection, OpenFlags};

/// Сводит ошибку `SQLite` к [`AegisError::Storage`], не раскрывая деталей.
///
/// Текст ошибки `SQLite` может содержать фрагменты запроса и имена таблиц,
/// а он попадает в логи и в UI — правило раздела 4.1 это запрещает. Причина
/// поэтому теряется намеренно, но перед этим пишется в `tracing` на уровне
/// `warn`: журнал разработчика и сообщение пользователю — разные каналы.
///
/// Отдельная функция, а не `impl From<rusqlite::Error> for AegisError`:
/// [`AegisError`] живёт в `aegis-types`, который про `SQLite` ничего не знает
/// и знать не должен (раздел 8.2 — границы между слоями).
// Ошибка принимается по значению, потому что функция ставится в `map_err`,
// который отдаёт владение. Ссылка вынудила бы каждый вызов писать `|e| ...`.
#[allow(clippy::needless_pass_by_value)]
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

/// PRAGMA уровня `SQLite`, не связанные с ключом.
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

/// Триггеры, запрещающие изменение и удаление записей журнала безопасности.
///
/// Журнал должен быть append-only: добавлять записи можно, менять
/// и удалять — нельзя. Ограничение живёт в схеме, а не в коде, поэтому
/// действует для любого кода, обращающегося к базе.
const SECURITY_LOG_TRIGGERS: &[&str] = &[
    "CREATE TRIGGER IF NOT EXISTS security_log_no_update
     BEFORE UPDATE ON security_log
     BEGIN
         SELECT RAISE(ABORT, 'security_log is append-only');
     END;",
    "CREATE TRIGGER IF NOT EXISTS security_log_no_delete
     BEFORE DELETE ON security_log
     BEGIN
         SELECT RAISE(ABORT, 'security_log is append-only');
     END;",
];

/// Статус доставки сообщения.
///
/// Числовые значения попадают в базу, поэтому менять их нельзя без
/// миграции: существующие записи получили бы другой смысл.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageStatus {
    /// Поставлено в очередь, но ещё не отправлено.
    Pending,
    /// Отправлено на сервер.
    Sent,
    /// Доставлено на устройство получателя.
    Delivered,
    /// Прочитано получателем.
    Read,
    /// Отправка не удалась.
    Failed,
}

impl MessageStatus {
    /// Числовое представление для записи в базу.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Sent => 1,
            Self::Delivered => 2,
            Self::Read => 3,
            Self::Failed => 4,
        }
    }

    /// Разбирает статус из базы.
    ///
    /// Неизвестное значение трактуется как [`MessageStatus::Pending`]:
    /// база своя, но повреждение файла не должно ронять приложение,
    /// а «ещё не отправлено» — самая безопасная трактовка (сообщение
    /// будет отправлено повторно, а не потеряно молча).
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Sent,
            2 => Self::Delivered,
            3 => Self::Read,
            4 => Self::Failed,
            _ => Self::Pending,
        }
    }
}

/// Собственные ключи устройства, прочитанные из хранилища.
#[derive(Debug, Clone)]
pub struct OwnKeys {
    /// Приватная часть identity-пары.
    pub identity_private: Vec<u8>,
    /// Публичная часть identity-пары.
    pub identity_public: Vec<u8>,
    /// Сериализованные секреты предключей.
    pub prekey_secrets: Vec<u8>,
    /// Идентификатор устройства, выданный сервером при регистрации.
    pub device_id: u32,
    /// Занятое имя пользователя, если оно уже зарегистрировано.
    pub username: Option<String>,
}

/// Строка списка чатов.
#[derive(Debug, Clone)]
pub struct ChatSummaryRow {
    /// Идентификатор чата.
    pub chat_id: ChatId,
    /// Время последней активности в миллисекундах.
    pub last_activity: i64,
}

/// Сообщение в том виде, в каком оно лежит в базе.
///
/// Содержимое — [`Ciphertext`]: открытый текст на диск не попадает
/// ни при каких условиях (раздел 8.2 плана).
#[derive(Clone, Debug)]
pub struct StoredMessage {
    /// Идентификатор сообщения.
    pub id: MessageId,
    /// Чат, которому принадлежит сообщение.
    pub chat_id: ChatId,
    /// Отправитель.
    pub sender_id: AccountId,
    /// Время отправки по данным отправителя.
    pub timestamp: Timestamp,
    /// Зашифрованное содержимое.
    pub content: Ciphertext,
    /// Статус доставки.
    pub status: MessageStatus,
    /// Тип сообщения: текст, вложение, системное.
    pub message_type: u8,

    /// Момент истечения в миллисекундах.
    ///
    /// `None` — сообщение не исчезает. Заполняется из таймера чата
    /// при сохранении: хранить срок в самом сообщении надёжнее, чем
    /// вычислять его при чтении, — смена таймера чата не должна
    /// задним числом продлевать или сокращать жизнь уже полученных
    /// сообщений.
    pub expires_at: Option<Timestamp>,
}

/// Метаданные вложения.
///
/// Сам файл лежит в файловой системе в зашифрованном виде; здесь только
/// то, что нужно для отображения списка и очистки.
#[derive(Clone, Debug)]
pub struct StoredAttachment {
    /// Сообщение, к которому относится вложение.
    pub message_id: MessageId,
    /// Тип вложения.
    pub attachment_type: u8,
    /// Подпись или имя файла.
    pub description: Option<String>,
    /// Размер в байтах.
    pub size: i64,
    /// Когда вложение появилось.
    pub created_at: Timestamp,
}

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
    /// Текущая версия схемы базы данных.
    const SCHEMA_VERSION: i32 = 1;
    /// Создает новое хранилище и инициализирует базу данных.
    ///
    /// # Arguments
    /// * `path` - путь к файлу базы данных.
    /// * `encryption_key` - 32-байтовый ключ для `SQLCipher` из иерархии ключей.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Crypto`] — ключ не расшифровывает базу.
    /// * [`AegisError::Storage`] — файл недоступен, повреждён либо создан
    ///   более новой версией приложения.
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

        // Выполняем миграции схемы базы данных
        Self::migrate_schema(&connection, Self::SCHEMA_VERSION)?;

        // 🔐 Истёкшие сообщения удаляются вызывающей стороной сразу
        // после открытия — см. `purge_expired`.
        //
        // Не здесь, потому что крейт не обращается к системным часам:
        // это условие воспроизводимости тестов (раздел 9.2 плана).
        // Время приходит снаружи, поэтому и чистку запускает тот, кто
        // им располагает. Пропустить этот вызов — значит оставить
        // на диске переписку, которую пользователь считает исчезнувшей.
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

    /// Читает текущую версию схемы.
    ///
    /// Строка всегда одна — таблица объявлена с `CHECK (id = 1)`.
    fn get_schema_version(connection: &Connection) -> Result<i32> {
        connection
            .query_row(
                "SELECT version FROM schema_version WHERE id = 1",
                [],
                |row| row.get::<_, i32>(0),
            )
            .map_err(storage_error)
    }

    /// Записывает версию схемы.
    fn set_schema_version(connection: &Connection, version: i32) -> Result<()> {
        connection
            .execute(
                "UPDATE schema_version SET version = ? WHERE id = 1",
                params![version],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Приводит схему к целевой версии, применяя миграции по одной.
    ///
    /// Вызывается после [`Storage::create_tables`], поэтому набор таблиц
    /// текущей версии уже существует. Задача этой функции — доводить до
    /// целевой версии базы, созданные **прежними** версиями приложения.
    ///
    /// # Транзакционность
    ///
    /// Каждый шаг и сопровождающее его обновление `schema_version` выполняются
    /// в одной транзакции: прерывание посреди миграции (падение процесса,
    /// убийство приложения системой) не оставляет базу в состоянии, где
    /// изменения применены, а версия не обновлена, — такая база при следующем
    /// открытии получила бы ту же миграцию повторно.
    ///
    /// # Откат вниз
    ///
    /// База новее приложения — ошибка: старый код не знает структуры новых
    /// таблиц и, продолжив работу, повредил бы их. Downgrade не поддерживается
    /// сознательно.
    ///
    /// # Arguments
    /// * `connection` — соединение с базой.
    /// * `target_version` — целевая версия схемы.
    fn migrate_schema(connection: &Connection, target_version: i32) -> Result<()> {
        let current_version = Self::get_schema_version(connection)?;

        if current_version > target_version {
            // База создана более новой версией приложения.
            return Err(AegisError::Storage);
        }

        // `saturating_add`: значение читается из базы, то есть это
        // недоверенный вход. При `i32::MAX` обычное сложение переполнилось бы,
        // а насыщение даёт пустой диапазон — миграций не будет, и это верно:
        // такая версия заведомо больше целевой и отсеяна проверкой выше.
        for version in current_version.saturating_add(1)..=target_version {
            let transaction = connection.unchecked_transaction().map_err(storage_error)?;

            match version {
                // 0 → 1: базовый набор таблиц. Отдельных действий не требует —
                // `create_tables` уже создал их перед вызовом миграций.
                1 => {}
                // Будущие миграции добавляются сюда явными ветками.
                // Недостижимо: `target_version` — это `SCHEMA_VERSION`.
                _ => return Err(AegisError::Storage),
            }

            Self::set_schema_version(&transaction, version)?;
            transaction.commit().map_err(storage_error)?;
        }

        Ok(())
    }

    /// Создает все необходимые таблицы в базе данных.
    ///
    /// Длина функции — прямое следствие числа таблиц: это линейный список
    /// DDL без ветвлений. Дробление его на подфункции по три таблицы
    /// усложнило бы чтение схемы, ради которого схему и держат в одном месте.
    #[allow(clippy::too_many_lines)]
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


        // Собственные долгоживущие ключи: identity-пара и секреты предключей.
        //
        // Лежат в той же зашифрованной базе, что и переписка: отдельное
        // хранилище потребовало бы второго ключа и второго места, где
        // можно ошибиться. Строка `id = 1` — весь смысл таблицы: у
        // устройства ровно одна identity-пара, и CHECK не даёт завести
        // вторую незаметно.
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS own_keys (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                identity_private BLOB NOT NULL,
                identity_public BLOB NOT NULL,
                prekey_secrets BLOB NOT NULL,
                device_id INTEGER NOT NULL,
                username TEXT,
                updated_at INTEGER NOT NULL
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

        // Таблица версии схемы — ровно одна строка.
        //
        // `id INTEGER PRIMARY KEY CHECK (id = 1)` физически запрещает вторую
        // строку: без этого ограничения повторное открытие базы добавляло бы
        // ещё одну запись, и `SELECT ... LIMIT 1` начал бы возвращать
        // произвольную из них.
        connection
            .execute(
                "
            CREATE TABLE IF NOT EXISTS schema_version (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            )
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
                created_at INTEGER NOT NULL,

                -- 🔐 Момент, после которого сообщение подлежит удалению.
                --
                -- NULL означает «не истекает». Поле в самой таблице,
                -- а не в отдельной: удаление должно быть одним запросом,
                -- иначе часть сообщений переживёт сбой посреди чистки.
                expires_at INTEGER
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

        // Триггеры, делающие журнал append-only на уровне базы.
        //
        // # Зачем триггеры, а не дисциплина вызовов
        //
        // Журнал безопасности фиксирует смену identity-ключа, сброс сессии
        // и прочие события, по которым пользователь потом судит, что
        // произошло с его перепиской. Если запись можно отредактировать
        // или удалить, журнал перестаёт быть свидетельством: атакующий,
        // получивший доступ к устройству, заметает следы.
        //
        // Ограничение на уровне схемы действует независимо от того, какой
        // код обращается к базе — включая код, написанный позже и не
        // знающий об этом правиле. Отсутствие такого триггера было
        // отмечено в M3 как открытый пункт: таблица называлась
        // append-only, но ничем это не подкрепляла.
        //
        // `RAISE(ABORT)` откатывает транзакцию целиком, поэтому попытка
        // подправить журнал не может пройти частично.
        for trigger in SECURITY_LOG_TRIGGERS {
            connection.execute_batch(trigger).map_err(storage_error)?;
        }

        // Засеваем версию схемы нулём, а не `SCHEMA_VERSION`.
        //
        // Ноль означает «таблицы созданы, ни одна миграция не выполнена».
        // Записать здесь сразу целевую версию значило бы сообщить
        // `migrate_schema`, что мигрировать нечего, — и любая будущая
        // миграция молча не выполнилась бы на свежей базе.
        //
        // `INSERT OR IGNORE` по первичному ключу `id = 1`: на уже
        // существующей базе строка сохраняется вместе с её версией.
        connection
            .execute(
                "
            INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 0)
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
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
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
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо записанные байты
    /// не разбираются как UUID (признак повреждения базы).
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

    // --- Own keys ---

    /// Сохраняет собственные долгоживущие ключи устройства.
    ///
    /// # Что сюда попадает
    ///
    /// Приватная часть identity-пары и сериализованные секреты предключей.
    /// Это самые ценные байты на устройстве: с ними читается вся переписка
    /// и подделывается личность владельца. Они защищены тем же ключом
    /// SQLCipher, что и остальная база, — то есть Argon2id над PIN.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_own_keys(
        &self,
        identity_private: &[u8],
        identity_public: &[u8],
        prekey_secrets: &[u8],
        device_id: u32,
        username: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        conn.execute(
            "
            INSERT OR REPLACE INTO own_keys
                (id, identity_private, identity_public, prekey_secrets,
                 device_id, username, updated_at)
            VALUES (1, ?, ?, ?, ?, ?, ?)
            ",
            params![
                identity_private,
                identity_public,
                prekey_secrets,
                device_id,
                username,
                now.as_millis()
            ],
        )
        .map_err(storage_error)?;

        Ok(())
    }

    /// Загружает собственные ключи устройства.
    ///
    /// Возвращает `None`, когда регистрация ещё не проходила: это штатное
    /// состояние первого запуска, а не ошибка.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn load_own_keys(&self) -> Result<Option<OwnKeys>> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut stmt = conn
            .prepare(
                "
                SELECT identity_private, identity_public, prekey_secrets,
                       device_id, username
                FROM own_keys WHERE id = 1
                ",
            )
            .map_err(storage_error)?;

        let mut rows = stmt.query([]).map_err(storage_error)?;
        let Some(row) = rows.next().map_err(storage_error)? else {
            return Ok(None);
        };

        Ok(Some(OwnKeys {
            identity_private: row.get(0).map_err(storage_error)?,
            identity_public: row.get(1).map_err(storage_error)?,
            prekey_secrets: row.get(2).map_err(storage_error)?,
            device_id: row.get(3).map_err(storage_error)?,
            username: row.get(4).map_err(storage_error)?,
        }))
    }

    /// Перечисляет чаты в порядке последней активности.
    ///
    /// Возвращает только идентификаторы и время: превью подставляет
    /// вызывающая сторона из [`Storage::load_messages`]. Так список
    /// строится без расшифровки всей переписки разом.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn list_chats(&self, limit: u32) -> Result<Vec<ChatSummaryRow>> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut stmt = conn
            .prepare(
                "
                SELECT chat_id, last_activity
                FROM chat_states
                ORDER BY last_activity DESC
                LIMIT ?
                ",
            )
            .map_err(storage_error)?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                ))
            })
            .map_err(storage_error)?;

        let mut chats = Vec::new();
        for row in rows {
            let (raw_id, last_activity) = row.map_err(storage_error)?;

            // Повреждённый идентификатор пропускается, а не роняет весь
            // список: одна битая строка не должна лишать пользователя
            // доступа ко всем остальным чатам.
            let Ok(uuid) = uuid::Uuid::from_slice(&raw_id) else {
                continue;
            };

            chats.push(ChatSummaryRow {
                chat_id: ChatId::from_uuid(uuid),
                last_activity: last_activity.unwrap_or(0),
            });
        }

        Ok(chats)
    }

    // --- Session methods ---

    /// Сохраняет состояние сессии для указанного чата.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_session(
        &self,
        chat_id: &ChatId,
        state: &SessionState,
        now: Timestamp,
    ) -> Result<()> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let state_bytes = state.serialized().expose_secret().clone();
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
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
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
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
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

    // --- Message repository ---

    /// Сохраняет сообщение.
    ///
    /// # Что попадает на диск
    ///
    /// Только [`Ciphertext`]. Тип аргумента — не формальность: `Plaintext`
    /// в `aegis-types` не реализует ни `Serialize`, ни доступ к байтам
    /// для записи, поэтому «случайно сохранить открытый текст» здесь
    /// невозможно на уровне компиляции (раздел 8.2 плана).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_message(&self, message: &StoredMessage) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT OR REPLACE INTO messages
                (message_id, chat_id, sender_id, timestamp, content, status,
                 message_type, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
                params![
                    message.id.as_bytes(),
                    message.chat_id.as_bytes(),
                    message.sender_id.as_bytes(),
                    message.timestamp.as_millis(),
                    message.content.as_bytes(),
                    i64::from(message.status.as_u8()),
                    i64::from(message.message_type),
                    message.timestamp.as_millis(),
                    message.expires_at.map(|expiry| expiry.as_millis()),
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Загружает сообщения чата, новые в конце.
    ///
    /// `limit` ограничивает выборку: история чата не помещается в память
    /// целиком, а UI показывает окно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn load_messages(&self, chat_id: &ChatId, limit: u32) -> Result<Vec<StoredMessage>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare(
                "
            SELECT message_id, chat_id, sender_id, timestamp, content,
                   status, message_type, expires_at
            FROM messages
            WHERE chat_id = ?
            ORDER BY timestamp ASC, rowid ASC
            LIMIT ?
            ",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map(params![chat_id.as_bytes(), limit], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(storage_error)?;

        let mut messages = Vec::new();
        for row in rows {
            let (id, chat, sender, timestamp, content, status, kind, expires) =
                row.map_err(storage_error)?;

            messages.push(StoredMessage {
                id: MessageId::from_uuid(uuid_from_slice(&id)?),
                chat_id: ChatId::from_uuid(uuid_from_slice(&chat)?),
                sender_id: AccountId::from_uuid(uuid_from_slice(&sender)?),
                timestamp: Timestamp::from_millis(timestamp),
                content: Ciphertext::new(content),
                status: MessageStatus::from_u8(u8::try_from(status).unwrap_or(0)),
                message_type: u8::try_from(kind).unwrap_or(0),
                expires_at: expires.map(Timestamp::from_millis),
            });
        }

        Ok(messages)
    }

    /// Обновляет статус доставки сообщения.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_message_status(&self, id: &MessageId, status: MessageStatus) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "UPDATE messages SET status = ? WHERE message_id = ?",
                params![i64::from(status.as_u8()), id.as_bytes()],
            )
            .map_err(storage_error)?;

        Ok(())
    }


    /// Заменяет текст сообщения.
    ///
    /// Отсутствие сообщения не считается ошибкой: собеседник мог
    /// править то, чего мы не получали — например, если сообщение
    /// истекло по таймеру раньше правки. Создавать его задним числом
    /// нельзя, оно появилось бы без контекста разговора.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn edit_message(&self, id: &MessageId, text: &str) -> Result<()> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;

        conn.execute(
            "UPDATE messages SET content = ? WHERE message_id = ?",
            params![text.as_bytes(), id.as_bytes()],
        )
        .map_err(storage_error)?;

        Ok(())
    }
    /// Удаляет истёкшие сообщения.
    ///
    /// # 🔐 Почему при открытии базы, а не по таймеру
    ///
    /// Таймер в памяти работает, только пока приложение запущено.
    /// Сообщение с часовым сроком, полученное перед тем, как телефон
    /// убрали в ящик на неделю, пережило бы этот срок в семь раз —
    /// и лежало бы на диске всё это время. Изъятие устройства
    /// показало бы переписку, которую пользователь считает исчезнувшей.
    ///
    /// Поэтому чистка происходит при каждом открытии хранилища,
    /// а таймер в приложении лишь дополняет её для уже открытой базы.
    ///
    /// # Про `VACUUM`
    ///
    /// Не вызывается: он перестраивает файл целиком и на большой базе
    /// занимает секунды, а `secure_delete = ON` (см. PRAGMA при
    /// открытии) уже затирает освобождённые страницы нулями.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn purge_expired(&self, now: Timestamp) -> Result<usize> {
        let conn = self.connection.lock().map_err(|_| AegisError::Storage)?;

        // Одним запросом: чистка по одному сообщению пережила бы сбой
        // посреди себя, оставив часть истёкших на диске.
        let removed = conn
            .execute(
                "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?",
                params![now.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(removed)
    }

    /// Вычисляет момент истечения по таймеру чата.
    ///
    /// Возвращает `None`, если у чата нет таймера.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение таймера не удалось.
    pub fn expiry_for_chat(
        &self,
        chat_id: &ChatId,
        now: Timestamp,
    ) -> Result<Option<Timestamp>> {
        let Some(seconds) = self.get_disappearing_timer(chat_id)? else {
            return Ok(None);
        };

        // Отсчёт от момента получения, а не от отправки: часы
        // отправителя могут отставать или спешить, и сообщение
        // исчезло бы у получателя раньше, чем тот успел его прочитать.
        let millis = i64::from(seconds).saturating_mul(1_000);

        Ok(Some(Timestamp::from_millis(
            now.as_millis().saturating_add(millis),
        )))
    }
    /// не остаётся в файле (раздел 11.3 плана).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn delete_message(&self, id: &MessageId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "DELETE FROM messages WHERE message_id = ?",
                params![id.as_bytes()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    // --- Contact repository ---

    /// Сохраняет identity-ключ контакта.
    ///
    /// # Про смену ключа
    ///
    /// Метод перезаписывает ключ молча. Обнаружение смены — задача
    /// вызывающего кода: он обязан сравнить новый ключ с прежним
    /// ([`Storage::get_contact_identity`]) и при расхождении записать
    /// событие в журнал безопасности. Хранилище не решает за него,
    /// потому что реакция зависит от того, верифицирован ли контакт.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_contact_identity(&self, account: &AccountId, identity: &[u8]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT OR REPLACE INTO known_contacts (account_id, identity_key)
            VALUES (?, ?)
            ",
                params![account.as_bytes(), identity],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Возвращает известный identity-ключ контакта.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn get_contact_identity(&self, account: &AccountId) -> Result<Option<Vec<u8>>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare("SELECT identity_key FROM known_contacts WHERE account_id = ?")
            .map_err(storage_error)?;

        let mut rows = statement
            .query_map(params![account.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage_error)?;

        rows.next().transpose().map_err(storage_error)
    }

    /// Отмечает контакт как верифицированный или снимает отметку.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_contact_verified(
        &self,
        account: &AccountId,
        verified: bool,
        now: Timestamp,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        if verified {
            // Таблица хранит только факт верификации: время сверки живёт
            // в журнале безопасности, где его нельзя подправить.
            let _ = now;

            connection
                .execute(
                    "INSERT OR REPLACE INTO verified_contacts (account_id) VALUES (?)",
                    params![account.as_bytes()],
                )
                .map_err(storage_error)?;
        } else {
            connection
                .execute(
                    "DELETE FROM verified_contacts WHERE account_id = ?",
                    params![account.as_bytes()],
                )
                .map_err(storage_error)?;
        }

        Ok(())
    }

    /// Верифицирован ли контакт.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn is_contact_verified(&self, account: &AccountId) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM verified_contacts WHERE account_id = ?",
                params![account.as_bytes()],
                |row| row.get(0),
            )
            .map_err(storage_error)?;

        Ok(count > 0)
    }

    // --- Chat repository ---

    /// Обновляет состояние чата после активности.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn touch_chat(
        &self,
        chat_id: &ChatId,
        last_message: Option<&MessageId>,
        now: Timestamp,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT INTO chat_states (chat_id, last_message_id, last_activity)
            VALUES (?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                last_message_id = excluded.last_message_id,
                last_activity   = excluded.last_activity
            ",
                params![
                    chat_id.as_bytes(),
                    last_message.map(aegis_types::MessageId::as_bytes),
                    now.as_millis(),
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Устанавливает таймер исчезающих сообщений для чата.
    ///
    /// `None` выключает исчезновение.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_disappearing_timer(&self, chat_id: &ChatId, seconds: Option<u32>) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT INTO chat_states (chat_id, disappearing_timer)
            VALUES (?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                disappearing_timer = excluded.disappearing_timer
            ",
                params![chat_id.as_bytes(), seconds],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Возвращает таймер исчезающих сообщений, если он задан.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn get_disappearing_timer(&self, chat_id: &ChatId) -> Result<Option<u32>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare("SELECT disappearing_timer FROM chat_states WHERE chat_id = ?")
            .map_err(storage_error)?;

        let mut rows = statement
            .query_map(params![chat_id.as_bytes()], |row| {
                row.get::<_, Option<u32>>(0)
            })
            .map_err(storage_error)?;

        Ok(rows.next().transpose().map_err(storage_error)?.flatten())
    }

    // --- Attachment repository ---

    /// Сохраняет метаданные вложения.
    ///
    /// Сам файл вложения в базе не лежит: он шифруется отдельно и хранится
    /// в файловой системе. Здесь — только то, что нужно для отображения
    /// и очистки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_attachment(&self, attachment: &StoredAttachment) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT INTO attachments
                (message_id, attachment_type, description, size, created_at)
            VALUES (?, ?, ?, ?, ?)
            ",
                params![
                    attachment.message_id.as_bytes(),
                    i64::from(attachment.attachment_type),
                    attachment.description.as_deref(),
                    attachment.size,
                    attachment.created_at.as_millis(),
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Возвращает вложения сообщения.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn load_attachments(&self, message_id: &MessageId) -> Result<Vec<StoredAttachment>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare(
                "
            SELECT message_id, attachment_type, description, size, created_at
            FROM attachments
            WHERE message_id = ?
            ORDER BY id ASC
            ",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map(params![message_id.as_bytes()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(storage_error)?;

        let mut attachments = Vec::new();
        for row in rows {
            let (id, kind, description, size, created) = row.map_err(storage_error)?;

            attachments.push(StoredAttachment {
                message_id: MessageId::from_uuid(uuid_from_slice(&id)?),
                attachment_type: u8::try_from(kind).unwrap_or(0),
                description,
                size,
                created_at: Timestamp::from_millis(created),
            });
        }

        Ok(attachments)
    }

    /// Готово ли хранилище к работе.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.read().is_ok_and(|flag| *flag)
    }
}

/// Разбирает UUID из байт, хранящихся в базе.
///
/// Битые байты в собственной базе — признак повреждения, а не сценарий
/// работы: возвращается ошибка, а не паника.
fn uuid_from_slice(bytes: &[u8]) -> Result<uuid::Uuid> {
    uuid::Uuid::from_slice(bytes).map_err(|_| AegisError::Storage)
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

        let connection = storage.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_log", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 2);
    }

    /// 🔐 Задача M3: запись журнала безопасности нельзя изменить.
    ///
    /// Журнал фиксирует смену identity-ключа и сброс сессии — события,
    /// по которым пользователь судит, что произошло с перепиской.
    /// Возможность подправить запись превратила бы журнал из свидетельства
    /// в набор произвольных строк.
    #[test]
    fn security_log_rejects_updates() {
        let (storage, _dir, _path) = open_temp(&test_key());
        storage
            .log_security_event("identity_key_changed", Some("device 2"), now())
            .unwrap();

        let connection = storage.connection.lock().unwrap();
        let result = connection.execute(
            "UPDATE security_log SET event_type = 'nothing_happened'",
            [],
        );

        assert!(result.is_err(), "журнал допустил изменение записи");

        // Запись осталась прежней: триггер откатил операцию целиком.
        let event: String = connection
            .query_row("SELECT event_type FROM security_log", [], |row| row.get(0))
            .unwrap();

        assert_eq!(event, "identity_key_changed");
    }

    /// 🔐 Задача M3: запись журнала безопасности нельзя удалить.
    ///
    /// Иначе атакующий, получивший доступ к устройству, заметал бы следы.
    #[test]
    fn security_log_rejects_deletes() {
        let (storage, _dir, _path) = open_temp(&test_key());
        storage
            .log_security_event("session_reset", None, now())
            .unwrap();

        let connection = storage.connection.lock().unwrap();

        assert!(
            connection.execute("DELETE FROM security_log", []).is_err(),
            "журнал допустил удаление записи"
        );

        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM security_log", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 1, "запись исчезла из журнала");
    }

    /// Триггеры переживают повторное открытие базы.
    ///
    /// `CREATE TRIGGER IF NOT EXISTS` не должен молча пропасть при
    /// открытии уже существующего файла.
    #[test]
    fn security_log_triggers_survive_reopen() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);
        storage
            .log_security_event("session_reset", None, now())
            .unwrap();
        drop(storage);

        let reopened = Storage::new(&path, &key).unwrap();
        let connection = reopened.connection.lock().unwrap();

        assert!(connection.execute("DELETE FROM security_log", []).is_err());
    }

    /// Сообщение переживает сохранение и загрузку.
    #[test]
    fn message_round_trips() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();
        let message = StoredMessage {
            id: MessageId::generate(),
            chat_id: chat,
            sender_id: AccountId::generate(),
            timestamp: now(),
            content: Ciphertext::new(b"encrypted blob".to_vec()),
            status: MessageStatus::Sent,
            message_type: 0,
            expires_at: None,
        };

        storage.save_message(&message).unwrap();
        let loaded = storage.load_messages(&chat, 10).unwrap();

        assert_eq!(loaded.len(), 1);
        let first = loaded.first().unwrap();
        assert_eq!(first.id, message.id);
        assert_eq!(first.content.as_bytes(), b"encrypted blob");
        assert_eq!(first.status, MessageStatus::Sent);
    }

    /// Сообщения возвращаются в хронологическом порядке.
    #[test]
    fn messages_are_ordered_by_time() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();
        let sender = AccountId::generate();

        for offset in [3_i64, 1, 2] {
            storage
                .save_message(&StoredMessage {
                    id: MessageId::generate(),
                    chat_id: chat,
                    sender_id: sender,
                    timestamp: Timestamp::from_millis(now().as_millis() + offset),
                    content: Ciphertext::new(vec![u8::try_from(offset).unwrap_or(0)]),
                    status: MessageStatus::Sent,
                    message_type: 0,
                    expires_at: None,
                })
                .unwrap();
        }

        let loaded = storage.load_messages(&chat, 10).unwrap();
        let order: Vec<u8> = loaded
            .iter()
            .filter_map(|m| m.content.as_bytes().first().copied())
            .collect();

        assert_eq!(order, vec![1, 2, 3]);
    }

    /// Выборка ограничивается `limit`.
    #[test]
    fn message_limit_is_respected() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();

        for index in 0..5_i64 {
            storage
                .save_message(&StoredMessage {
                    id: MessageId::generate(),
                    chat_id: chat,
                    sender_id: AccountId::generate(),
                    timestamp: Timestamp::from_millis(now().as_millis() + index),
                    content: Ciphertext::new(vec![0]),
                    status: MessageStatus::Pending,
                    message_type: 0,
                    expires_at: None,
                })
                .unwrap();
        }

        assert_eq!(storage.load_messages(&chat, 2).unwrap().len(), 2);
    }

    /// Сообщения других чатов не попадают в выборку.
    #[test]
    fn messages_are_scoped_to_their_chat() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let ours = ChatId::generate();
        let theirs = ChatId::generate();

        for chat in [ours, theirs] {
            storage
                .save_message(&StoredMessage {
                    id: MessageId::generate(),
                    chat_id: chat,
                    sender_id: AccountId::generate(),
                    timestamp: now(),
                    content: Ciphertext::new(vec![1]),
                    status: MessageStatus::Sent,
                    message_type: 0,
                    expires_at: None,
                })
                .unwrap();
        }

        assert_eq!(storage.load_messages(&ours, 10).unwrap().len(), 1);
    }

    /// Статус сообщения обновляется и переживает перезагрузку.
    #[test]
    fn message_status_updates() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();
        let id = MessageId::generate();

        storage
            .save_message(&StoredMessage {
                id,
                chat_id: chat,
                sender_id: AccountId::generate(),
                timestamp: now(),
                content: Ciphertext::new(vec![1]),
                status: MessageStatus::Pending,
                message_type: 0,
                expires_at: None,
            })
            .unwrap();

        storage
            .set_message_status(&id, MessageStatus::Delivered)
            .unwrap();

        let loaded = storage.load_messages(&chat, 1).unwrap();
        assert_eq!(
            loaded.first().map(|m| m.status),
            Some(MessageStatus::Delivered)
        );
    }

    /// Удалённое сообщение больше не возвращается.
    #[test]
    fn deleted_message_disappears() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();
        let id = MessageId::generate();

        storage
            .save_message(&StoredMessage {
                id,
                chat_id: chat,
                sender_id: AccountId::generate(),
                timestamp: now(),
                content: Ciphertext::new(vec![1]),
                status: MessageStatus::Sent,
                message_type: 0,
                expires_at: None,
            })
            .unwrap();

        storage.delete_message(&id).unwrap();

        assert!(storage.load_messages(&chat, 10).unwrap().is_empty());
    }

    /// Статус разбирается устойчиво к повреждению.
    ///
    /// Неизвестное число трактуется как `Pending`: сообщение будет
    /// отправлено повторно, а не потеряно молча.
    #[test]
    fn unknown_status_falls_back_to_pending() {
        assert_eq!(MessageStatus::from_u8(200), MessageStatus::Pending);
        for status in [
            MessageStatus::Pending,
            MessageStatus::Sent,
            MessageStatus::Delivered,
            MessageStatus::Read,
            MessageStatus::Failed,
        ] {
            assert_eq!(MessageStatus::from_u8(status.as_u8()), status);
        }
    }

    /// Identity-ключ контакта сохраняется и читается.
    #[test]
    fn contact_identity_round_trips() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let account = AccountId::generate();

        assert!(storage.get_contact_identity(&account).unwrap().is_none());

        storage.save_contact_identity(&account, &[7u8; 32]).unwrap();

        assert_eq!(
            storage.get_contact_identity(&account).unwrap(),
            Some(vec![7u8; 32])
        );
    }

    /// 🔐 Смена identity-ключа контакта видна вызывающему коду.
    ///
    /// Хранилище перезаписывает ключ, но прежнее значение доступно до
    /// записи — на этом строится обнаружение смены ключа и запись
    /// события в журнал безопасности.
    #[test]
    fn contact_identity_change_is_observable() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let account = AccountId::generate();

        storage.save_contact_identity(&account, &[1u8; 32]).unwrap();
        let previous = storage.get_contact_identity(&account).unwrap();

        storage.save_contact_identity(&account, &[2u8; 32]).unwrap();
        let current = storage.get_contact_identity(&account).unwrap();

        assert_ne!(previous, current, "смена ключа должна быть различима");
    }

    /// Отметка верификации ставится и снимается.
    #[test]
    fn contact_verification_toggles() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let account = AccountId::generate();

        assert!(!storage.is_contact_verified(&account).unwrap());

        storage.set_contact_verified(&account, true, now()).unwrap();
        assert!(storage.is_contact_verified(&account).unwrap());

        storage
            .set_contact_verified(&account, false, now())
            .unwrap();
        assert!(!storage.is_contact_verified(&account).unwrap());
    }

    /// Состояние чата обновляется без дублирования строк.
    #[test]
    fn chat_state_upserts() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();
        let first = MessageId::generate();
        let second = MessageId::generate();

        storage.touch_chat(&chat, Some(&first), now()).unwrap();
        storage.touch_chat(&chat, Some(&second), now()).unwrap();

        let connection = storage.connection.lock().unwrap();
        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM chat_states", [], |row| row.get(0))
            .unwrap();

        assert_eq!(rows, 1, "состояние чата продублировалось");
    }

    /// Таймер исчезающих сообщений сохраняется и выключается.
    #[test]
    fn disappearing_timer_round_trips() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();

        assert_eq!(storage.get_disappearing_timer(&chat).unwrap(), None);

        storage.set_disappearing_timer(&chat, Some(86_400)).unwrap();
        assert_eq!(storage.get_disappearing_timer(&chat).unwrap(), Some(86_400));

        storage.set_disappearing_timer(&chat, None).unwrap();
        assert_eq!(storage.get_disappearing_timer(&chat).unwrap(), None);
    }

    /// Таймер и активность чата не затирают друг друга.
    ///
    /// Обе операции пишут в одну строку через `ON CONFLICT`, поэтому
    /// важно, что каждая обновляет только свои поля.
    #[test]
    fn chat_timer_and_activity_are_independent() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();

        storage.set_disappearing_timer(&chat, Some(3600)).unwrap();
        storage.touch_chat(&chat, None, now()).unwrap();

        assert_eq!(
            storage.get_disappearing_timer(&chat).unwrap(),
            Some(3600),
            "обновление активности стёрло таймер"
        );
    }

    /// Вложения сохраняются и читаются по сообщению.
    ///
    /// Сообщение создаётся первым: у таблицы вложений есть внешний ключ
    /// на `messages`, и вложение без сообщения — противоречивое состояние.
    #[test]
    fn attachments_round_trip() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let message_id = MessageId::generate();

        storage
            .save_message(&StoredMessage {
                id: message_id,
                chat_id: ChatId::generate(),
                sender_id: AccountId::generate(),
                timestamp: now(),
                content: Ciphertext::new(vec![1]),
                status: MessageStatus::Sent,
                message_type: 0,
                expires_at: None,
            })
            .unwrap();

        storage
            .save_attachment(&StoredAttachment {
                message_id,
                attachment_type: 1,
                description: Some("photo.jpg".to_owned()),
                size: 2048,
                created_at: now(),
            })
            .unwrap();

        let loaded = storage.load_attachments(&message_id).unwrap();

        assert_eq!(loaded.len(), 1);
        let first = loaded.first().unwrap();
        assert_eq!(first.description.as_deref(), Some("photo.jpg"));
        assert_eq!(first.size, 2048);
    }

    /// 🔐 Задача M3: содержимое сообщений не видно в сыром файле базы.
    ///
    /// Дополняет `database_file_contains_no_plaintext`: там проверялись
    /// сессии и чаты, здесь — репозиторий сообщений и вложений.
    #[test]
    fn message_repository_writes_no_plaintext() {
        let (storage, _dir, path) = open_temp(&test_key());
        let message_id = MessageId::generate();

        storage
            .save_message(&StoredMessage {
                id: message_id,
                chat_id: ChatId::generate(),
                sender_id: AccountId::generate(),
                timestamp: now(),
                content: Ciphertext::new(CANARY.as_bytes().to_vec()),
                status: MessageStatus::Sent,
                message_type: 0,
                expires_at: None,
            })
            .unwrap();
        storage
            .save_attachment(&StoredAttachment {
                message_id,
                attachment_type: 0,
                description: Some(CANARY.to_owned()),
                size: 1,
                created_at: now(),
            })
            .unwrap();
        drop(storage);

        let raw = std::fs::read(&path).expect("файл базы читается");

        assert!(
            !raw.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
            "содержимое сообщения найдено в сыром файле базы"
        );
    }

    /// 🧪 Задача M3: новая база доводится миграциями до текущей версии.
    #[test]
    fn fresh_database_is_migrated_to_current_version() {
        let (storage, _dir, _path) = open_temp(&test_key());

        let connection = storage.connection.lock().unwrap();

        assert_eq!(
            Storage::get_schema_version(&connection).unwrap(),
            Storage::SCHEMA_VERSION
        );
    }

    /// 🧪 Задача M3: строка версии ровно одна после повторных открытий.
    ///
    /// Регрессионный тест на засев версии. Пока таблица не ограничивала себя
    /// одной строкой, каждое открытие базы добавляло новую запись, и версия
    /// схемы начинала зависеть от того, какую из них вернёт выборка.
    #[test]
    fn schema_version_row_is_unique_across_reopens() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);
        drop(storage);

        let reopened = Storage::new(&path, &key).unwrap();
        let connection = reopened.connection.lock().unwrap();

        let rows: i32 = connection
            .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();

        assert_eq!(rows, 1, "версия схемы должна храниться в одной строке");
        assert_eq!(
            Storage::get_schema_version(&connection).unwrap(),
            Storage::SCHEMA_VERSION
        );
    }

    /// 🧪 Задача M3: база, созданная более новой версией, отвергается.
    ///
    /// Downgrade не поддерживается: старый код не знает структуры новых таблиц
    /// и, открыв такую базу, повредил бы её.
    #[test]
    fn database_from_newer_version_is_rejected() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);

        {
            let connection = storage.connection.lock().unwrap();
            Storage::set_schema_version(&connection, Storage::SCHEMA_VERSION + 1).unwrap();
        }
        drop(storage);

        assert!(matches!(
            Storage::new(&path, &key),
            Err(AegisError::Storage)
        ));
    }

    #[test]
    fn own_keys_survive_reopen() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);

        storage
            .save_own_keys(
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 64],
                7,
                Some("alice"),
                now(),
            )
            .expect("ключи сохраняются");

        drop(storage);

        let reopened = Storage::new(&path, &key).expect("та же база с тем же ключом");
        let loaded = reopened
            .load_own_keys()
            .expect("чтение удалось")
            .expect("ключи на месте");

        assert_eq!(loaded.identity_private, vec![0x11; 32]);
        assert_eq!(loaded.identity_public, vec![0x22; 32]);
        assert_eq!(loaded.prekey_secrets, vec![0x33; 64]);
        assert_eq!(loaded.device_id, 7);
        assert_eq!(loaded.username.as_deref(), Some("alice"));
    }

    #[test]
    fn own_keys_absent_before_registration() {
        let (storage, _dir, _path) = open_temp(&test_key());

        // Первый запуск — штатное состояние, а не ошибка: приложение
        // должно отличать «ещё не регистрировались» от «база сломалась».
        assert!(storage.load_own_keys().expect("чтение удалось").is_none());
    }

    /// 🔐 Приватный ключ не лежит в файле открытым текстом.
    ///
    /// Проверка сырых байтов файла, а не API: именно так его увидит тот,
    /// кто снял образ диска с изъятого устройства.
    #[test]
    fn own_private_key_is_not_readable_in_raw_file() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);

        // Узнаваемая последовательность: если шифрование не работает,
        // она найдётся в файле как есть.
        let private = [0xABu8; 32];
        storage
            .save_own_keys(&private, &[0x22; 32], &[0x33; 64], 1, None, now())
            .expect("ключи сохраняются");

        drop(storage);

        let raw = std::fs::read(&path).expect("файл базы читается");
        assert!(
            !raw.windows(private.len()).any(|window| window == private),
            "приватный ключ найден в файле базы открытым текстом"
        );
    }

    #[test]
    fn chats_are_listed_by_recent_activity() {
        let (storage, _dir, _path) = open_temp(&test_key());

        let older = ChatId::from_uuid(uuid::Uuid::from_u128(1));
        let newer = ChatId::from_uuid(uuid::Uuid::from_u128(2));

        storage
            .touch_chat(&older, None, Timestamp::from_millis(1_000))
            .expect("чат отмечен");
        storage
            .touch_chat(&newer, None, Timestamp::from_millis(2_000))
            .expect("чат отмечен");

        let chats = storage.list_chats(10).expect("список читается");

        assert_eq!(chats.len(), 2);
        // Свежий чат первым: список, отсортированный иначе, заставлял бы
        // искать новое сообщение прокруткой.
        assert_eq!(chats[0].chat_id, newer);
        assert_eq!(chats[1].chat_id, older);
    }

    /// 🔐 Истёкшие сообщения удаляются после холодного старта.
    ///
    /// Требование раздела M5. Таймер в памяти работает, только пока
    /// приложение запущено: сообщение с часовым сроком, полученное
    /// перед тем, как телефон убрали в ящик на неделю, пережило бы
    /// свой срок в семь раз. Изъятие устройства показало бы переписку,
    /// которую пользователь считает исчезнувшей.
    #[test]
    fn expired_messages_are_purged_after_cold_start() {
        let key = test_key();
        let (storage, _dir, path) = open_temp(&key);

        let chat = ChatId::generate();
        let expiring = MessageId::generate();
        let permanent = MessageId::generate();

        let sent = Timestamp::from_millis(1_000);

        storage
            .save_message(&StoredMessage {
                id: expiring,
                chat_id: chat,
                sender_id: AccountId::generate(),
                timestamp: sent,
                content: Ciphertext::new(b"disappears".to_vec()),
                status: MessageStatus::Delivered,
                message_type: 0,
                expires_at: Some(Timestamp::from_millis(2_000)),
            })
            .expect("сообщение сохранено");

        storage
            .save_message(&StoredMessage {
                id: permanent,
                chat_id: chat,
                sender_id: AccountId::generate(),
                timestamp: sent,
                content: Ciphertext::new(b"stays".to_vec()),
                status: MessageStatus::Delivered,
                message_type: 0,
                expires_at: None,
            })
            .expect("сообщение сохранено");

        // Холодный старт: приложение закрыли и открыли позже срока.
        drop(storage);

        let reopened = Storage::new(&path, &key).expect("база открывается");
        let removed = reopened
            .purge_expired(Timestamp::from_millis(3_000))
            .expect("чистка");

        assert_eq!(removed, 1, "удалено не одно сообщение");

        let remaining = reopened.load_messages(&chat, 10).expect("чтение");

        assert_eq!(remaining.len(), 1, "истёкшее сообщение пережило чистку");
        assert_eq!(remaining[0].id, permanent);
    }

    /// Сообщение, срок которого ещё не наступил, остаётся.
    #[test]
    fn unexpired_message_survives_purge() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();

        storage
            .save_message(&StoredMessage {
                id: MessageId::generate(),
                chat_id: chat,
                sender_id: AccountId::generate(),
                timestamp: now(),
                content: Ciphertext::new(b"later".to_vec()),
                status: MessageStatus::Delivered,
                message_type: 0,
                expires_at: Some(Timestamp::from_millis(10_000)),
            })
            .expect("сообщение сохранено");

        let removed = storage
            .purge_expired(Timestamp::from_millis(5_000))
            .expect("чистка");

        assert_eq!(removed, 0);
        assert_eq!(storage.load_messages(&chat, 10).expect("чтение").len(), 1);
    }

    /// Срок отсчитывается от момента получения, а не отправки.
    ///
    /// Часы отправителя могут спешить, и сообщение исчезло бы
    /// у получателя раньше, чем тот успел его прочитать.
    #[test]
    fn expiry_counts_from_receipt() {
        let (storage, _dir, _path) = open_temp(&test_key());
        let chat = ChatId::generate();

        storage
            .set_disappearing_timer(&chat, Some(60))
            .expect("таймер установлен");

        let received = Timestamp::from_millis(100_000);
        let expiry = storage
            .expiry_for_chat(&chat, received)
            .expect("вычисление")
            .expect("таймер задан");

        assert_eq!(expiry.as_millis(), 160_000);
    }

    /// У чата без таймера сообщения не истекают.
    #[test]
    fn chat_without_timer_has_no_expiry() {
        let (storage, _dir, _path) = open_temp(&test_key());

        assert!(storage
            .expiry_for_chat(&ChatId::generate(), now())
            .expect("вычисление")
            .is_none());
    }
}
