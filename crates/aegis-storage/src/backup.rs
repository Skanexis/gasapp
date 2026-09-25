// SPDX-License-Identifier: Apache-2.0

//! Выгрузка и загрузка данных для резервной копии, обслуживание базы.
//!
//! # Что здесь есть и чего нет
//!
//! Здесь — чтение и запись строк. Шифрования нет: им занимается
//! `aegis-backup`, а порядок вызовов задаёт `aegis-core`. Разделение
//! не формальное — оно означает, что этот модуль **не знает
//! recovery key** и не может его случайно записать на диск.
//!
//! # 🔐 Что не выгружается
//!
//! [`Storage::export_for_backup`] не читает таблиц `sessions`,
//! `own_keys`, `prekey_bundles`, `used_op_ks` и `used_pqop_ks`.
//! Это решение раздела 12.5: состояние храповика в копии означало бы
//! возврат к уже использованным message key после восстановления,
//! то есть повторное использование ключа в AEAD. Приватный
//! identity-ключ не выгружается по правилу раздела 13.1: у каждого
//! устройства своя identity, и восстановление заводит новую.
//!
//! Проверяет это не комментарий, а тест
//! `export_contains_no_session_or_identity_material`.

use aegis_types::{AccountId, AegisError, ChatId, Ciphertext, MessageId, Result, Timestamp};
use rusqlite::{params, Connection};

use crate::{
    storage_error, uuid_from_slice, ContactRow, MessageStatus, Storage, StoredAttachment,
    StoredMessage,
};

/// Состояние чата, попадающее в копию.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatBackupRow {
    /// Идентификатор чата.
    pub chat_id: ChatId,
    /// Время последней активности в миллисекундах.
    pub last_activity_millis: Option<i64>,
    /// Таймер исчезающих сообщений в секундах.
    pub disappearing_timer_seconds: Option<u32>,
}

/// Состояние цепочки резервных копий.
///
/// 🔐 Секретов здесь нет: соль и параметры растягивания лежат
/// и в открытом заголовке файла копии. Без recovery key они
/// не дают ничего.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupChainState {
    /// Соль растягивания.
    pub salt: Vec<u8>,
    /// Память Argon2id в килобайтах.
    pub memory_kib: u32,
    /// Число проходов.
    pub iterations: u32,
    /// Степень параллелизма.
    pub parallelism: u32,
    /// Номер последнего записанного поколения.
    pub generation: u32,
    /// SHA-256 последнего файла цепочки.
    pub last_digest: Vec<u8>,
    /// Отметка, до которой данные уже попали в копию.
    ///
    /// Следующий инкремент берёт строки, изменённые **после** неё.
    pub watermark: Timestamp,
    /// Когда копия делалась в последний раз.
    pub last_backup_at: Option<Timestamp>,
}

/// Всё, что выгружено для копии.
///
/// `Default` не выводится намеренно: у структуры есть поле
/// `watermark`, и «отметка по умолчанию» — это либо начало эпохи,
/// либо текущий момент, а разница между ними означает разницу между
/// «выгрузить всё» и «не выгружать ничего». Значение обязано
/// приходить от вызывающего явно.
#[derive(Debug, Clone)]
pub struct BackupExport {
    /// Идентификатор аккаунта.
    pub account_id: Option<AccountId>,
    /// Имя пользователя.
    pub username: Option<String>,
    /// Сообщения.
    pub messages: Vec<StoredMessage>,
    /// Контакты.
    pub contacts: Vec<ContactRow>,
    /// Состояния чатов.
    pub chats: Vec<ChatBackupRow>,
    /// Метаданные вложений.
    pub attachments: Vec<StoredAttachment>,
    /// Настройки.
    pub settings: Vec<(String, i64)>,
    /// Надгробия удалённых сообщений.
    pub tombstones: Vec<MessageId>,
    /// 🔐 Секрет ключа восстановления аккаунта: им новая установка
    /// возвращает себе имя. Не identity-ключ — тот в копию не входит.
    pub account_recovery: Option<[u8; crate::pq::ACCOUNT_RECOVERY_LEN]>,
    /// Хеши пост-квантовых половин контактов.
    pub contact_pq_hashes: Vec<(AccountId, [u8; crate::pq::PQ_HASH_LEN])>,
    /// Отметка, которую нужно запомнить после успешной выгрузки.
    pub watermark: Timestamp,
}

impl BackupExport {
    /// Сколько всего строк выгружено.
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

    /// Есть ли что выгружать.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.record_count() == 0
    }
}

/// Файл в хранилище под вторым фактором.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFileRow {
    /// Идентификатор файла.
    pub file_id: MessageId,
    /// Имя, показываемое пользователю.
    pub name: String,
    /// Размер открытого файла в байтах.
    pub size: i64,
    /// Когда файл добавлен.
    pub created_at: Timestamp,
    /// Путь к шифроблобу на диске.
    pub location: String,
    /// Ключ файла, завёрнутый `K_vault`.
    ///
    /// 🔐 Лежит в базе завёрнутым: расшифрованная база сама по себе
    /// содержимого vault не выдаёт, для этого нужен ещё и `K_vault`,
    /// который появляется только после повторной аутентификации.
    pub wrapped_key: Vec<u8>,
}

impl Storage {
    /// Выгружает данные для резервной копии.
    ///
    /// `since` задаёт инкрементальность: `None` — полный снимок,
    /// `Some(отметка)` — только изменения после неё.
    ///
    /// # Что попадает в инкремент
    ///
    /// Сообщения и вложения — по времени изменения. Контакты, чаты
    /// и настройки — целиком всегда: их единицы, и отслеживать
    /// изменения по каждому обошлось бы дороже, чем выгрузить.
    /// Надгробия — поставленные после отметки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись
    /// в базе повреждена.
    pub fn export_for_backup(
        &self,
        since: Option<Timestamp>,
        now: Timestamp,
    ) -> Result<BackupExport> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        // Отсутствие отметки — полный снимок: берём всё, начиная
        // с самого раннего возможного момента.
        let threshold = since.map_or(i64::MIN, |mark| mark.as_millis());

        let (account_id, username) = read_account(&connection)?;

        Ok(BackupExport {
            account_id,
            username,
            messages: read_messages(&connection, threshold)?,
            contacts: read_contacts(&connection)?,
            chats: read_chats(&connection)?,
            attachments: read_attachments(&connection, threshold)?,
            settings: read_settings(&connection)?,
            tombstones: read_tombstones(&connection, threshold)?,
            account_recovery: read_account_recovery(&connection)?,
            contact_pq_hashes: read_contact_pq_hashes(&connection)?,
            watermark: now,
        })
    }

    /// Записывает восстановленные данные в базу.
    ///
    /// Возвращает число применённых строк.
    ///
    /// # Порядок
    ///
    /// Всё одной транзакцией. Восстановление наполовину хуже, чем
    /// его отсутствие: пользователь увидел бы часть переписки
    /// и решил, что копия цела.
    ///
    /// # 🔐 Чего этот метод не делает
    ///
    /// Не трогает `own_keys` и `sessions`. Восстановление не даёт
    /// устройству чужую identity и не воскрешает сессии — они
    /// устанавливаются заново при первом сообщении (раздел 12.5).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    ///
    // Длина функции — прямое следствие числа таблиц: это линейный
    // список вставок без ветвлений, и он обязан идти одной
    // транзакцией. Дробление на подфункции по таблице потребовало бы
    // протаскивать транзакцию через каждую и разнесло бы порядок
    // применения — а порядок здесь значим: надгробия идут последними.
    #[allow(clippy::too_many_lines)]
    pub fn import_from_backup(&self, data: &BackupExport) -> Result<usize> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let transaction = connection.unchecked_transaction().map_err(storage_error)?;

        let mut applied = 0usize;

        // Секрет восстановления аккаунта — если копия его несёт.
        if let Some(secret) = &data.account_recovery {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO own_account_recovery (id, secret) VALUES (1, ?)",
                    params![secret.as_slice()],
                )
                .map_err(storage_error)?;
        }

        for message in &data.messages {
            transaction
                .execute(
                    "
                INSERT OR REPLACE INTO messages
                    (message_id, chat_id, sender_id, timestamp, content, status,
                     message_type, created_at, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        message.timestamp.as_millis(),
                    ],
                )
                .map_err(storage_error)?;
            applied = applied.saturating_add(1);
        }

        for contact in &data.contacts {
            transaction
                .execute(
                    "
                INSERT OR REPLACE INTO known_contacts
                    (account_id, identity_key, username, chat_id, added_at)
                VALUES (?, ?, ?, ?, ?)
                ",
                    params![
                        contact.account_id.as_bytes(),
                        contact.identity_key,
                        contact.username,
                        contact.chat_id.as_ref().map(ChatId::as_bytes),
                        contact.added_at,
                    ],
                )
                .map_err(storage_error)?;

            // 🔐 Отметка личной верификации восстанавливается вместе
            // с контактом. Потерять её означало бы, что человек,
            // однажды сверивший safety number лично, после
            // восстановления видит контакт непроверенным и сверяет
            // заново — или, что хуже, перестаёт сверять вообще.
            if contact.verified {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO verified_contacts (account_id) VALUES (?)",
                        params![contact.account_id.as_bytes()],
                    )
                    .map_err(storage_error)?;
            }

            applied = applied.saturating_add(1);
        }

        for chat in &data.chats {
            transaction
                .execute(
                    "
                INSERT OR REPLACE INTO chat_states
                    (chat_id, last_activity, disappearing_timer)
                VALUES (?, ?, ?)
                ",
                    params![
                        chat.chat_id.as_bytes(),
                        chat.last_activity_millis,
                        chat.disappearing_timer_seconds,
                    ],
                )
                .map_err(storage_error)?;
            applied = applied.saturating_add(1);
        }

        for attachment in &data.attachments {
            // Идентификатор строки вложения — автоинкремент, поэтому
            // повторный импорт задвоил бы записи. Прежние строки
            // того же сообщения и типа убираются перед вставкой.
            transaction
                .execute(
                    "DELETE FROM attachments WHERE message_id = ? AND attachment_type = ?",
                    params![
                        attachment.message_id.as_bytes(),
                        i64::from(attachment.attachment_type)
                    ],
                )
                .map_err(storage_error)?;

            transaction
                .execute(
                    "
                INSERT INTO attachments
                    (message_id, attachment_type, description, size, created_at, descriptor)
                VALUES (?, ?, ?, ?, ?, ?)
                ",
                    params![
                        attachment.message_id.as_bytes(),
                        i64::from(attachment.attachment_type),
                        attachment.description,
                        attachment.size,
                        attachment.created_at.as_millis(),
                        attachment.descriptor,
                    ],
                )
                .map_err(storage_error)?;
            applied = applied.saturating_add(1);
        }

        // Хеши пост-квантовых половин — после контактов: строка контакта
        // уже есть.
        for (account, hash) in &data.contact_pq_hashes {
            transaction
                .execute(
                    "UPDATE known_contacts SET pq_identity_hash = ? WHERE account_id = ?",
                    params![hash.as_slice(), account.as_bytes()],
                )
                .map_err(storage_error)?;
        }

        for (key, value) in &data.settings {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    params![key, value],
                )
                .map_err(storage_error)?;
            applied = applied.saturating_add(1);
        }

        // 🔐 Надгробия применяются последними: сообщение, удалённое
        // позже, чем оно попало в копию, обязано остаться удалённым.
        for tombstone in &data.tombstones {
            // Описания вложений — раньше сообщения: внешний ключ
            // `attachments → messages` проверяется, и при обратном
            // порядке надгробие сообщения с файлом роняло импорт копии.
            transaction
                .execute(
                    "DELETE FROM attachments WHERE message_id = ?",
                    params![tombstone.as_bytes()],
                )
                .map_err(storage_error)?;
            transaction
                .execute(
                    "DELETE FROM messages WHERE message_id = ?",
                    params![tombstone.as_bytes()],
                )
                .map_err(storage_error)?;
            transaction
                .execute(
                    "
                INSERT OR REPLACE INTO backup_tombstones (message_id, deleted_at)
                VALUES (?, ?)
                ",
                    params![tombstone.as_bytes(), data.watermark.as_millis()],
                )
                .map_err(storage_error)?;
            applied = applied.saturating_add(1);
        }

        transaction.commit().map_err(storage_error)?;

        // 🔐 Надгробия удаляют сообщения внутри той же транзакции, что
        // их вставила; страницы, вытесненные в журнал до фиксации,
        // могли унести текст с собой. Точка обнуляет журнал.
        if !data.tombstones.is_empty() {
            crate::checkpoint_truncate(&connection)?;
        }

        Ok(applied)
    }

    /// Читает состояние цепочки копий.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn backup_chain_state(&self) -> Result<Option<BackupChainState>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection
            .query_row(
                "
            SELECT salt, memory_kib, iterations, parallelism,
                   generation, last_digest, watermark, last_backup_at
            FROM backup_chain WHERE id = 1
            ",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                    ))
                },
            )
            .ok();

        let Some((
            salt,
            memory_kib,
            iterations,
            parallelism,
            generation,
            last_digest,
            watermark,
            last_backup_at,
        )) = row
        else {
            return Ok(None);
        };

        Ok(Some(BackupChainState {
            salt,
            // Значения писало это же приложение, но база могла быть
            // повреждена: отрицательное или непомерное число здесь
            // означает порчу, и обращаться с ним как с параметром
            // Argon2id нельзя.
            memory_kib: u32::try_from(memory_kib).map_err(|_| AegisError::Storage)?,
            iterations: u32::try_from(iterations).map_err(|_| AegisError::Storage)?,
            parallelism: u32::try_from(parallelism).map_err(|_| AegisError::Storage)?,
            generation: u32::try_from(generation).map_err(|_| AegisError::Storage)?,
            last_digest,
            watermark: Timestamp::from_millis(watermark),
            last_backup_at: last_backup_at.map(Timestamp::from_millis),
        }))
    }

    /// Сохраняет состояние цепочки копий.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_backup_chain_state(&self, state: &BackupChainState) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT OR REPLACE INTO backup_chain
                (id, salt, memory_kib, iterations, parallelism,
                 generation, last_digest, watermark, last_backup_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
                params![
                    state.salt,
                    i64::from(state.memory_kib),
                    i64::from(state.iterations),
                    i64::from(state.parallelism),
                    i64::from(state.generation),
                    state.last_digest,
                    state.watermark.as_millis(),
                    state.last_backup_at.map(|moment| moment.as_millis()),
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Забывает цепочку копий.
    ///
    /// Вызывается, когда пользователь создаёт новый recovery key:
    /// прежняя цепочка выведена прежним ключом и продолжению
    /// не подлежит.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn clear_backup_chain_state(&self) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute("DELETE FROM backup_chain WHERE id = 1", [])
            .map_err(storage_error)?;

        Ok(())
    }

    /// Убирает надгробия, уже уехавшие в копию.
    ///
    /// Без этого таблица росла бы вечно: надгробие нужно ровно
    /// до момента, когда оно попало в очередной инкремент.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn prune_tombstones(&self, up_to: Timestamp) -> Result<usize> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let removed = connection
            .execute(
                "DELETE FROM backup_tombstones WHERE deleted_at <= ?",
                params![up_to.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(removed)
    }

    /// Уплотняет базу.
    ///
    /// # 🔐 Зачем это здесь, а не в списке украшений
    ///
    /// `PRAGMA secure_delete = ON` перезаписывает освобождённые
    /// страницы нулями, но сам файл не сжимается: страницы остаются
    /// в нём свободными. `VACUUM` пересобирает файл целиком, и после
    /// него следов удалённых сообщений в нём не остаётся даже
    /// в виде занятого места. Для мессенджера с исчезающими
    /// сообщениями это часть обещания, а не обслуживание.
    ///
    /// # Про стоимость
    ///
    /// `VACUUM` переписывает файл целиком, поэтому запускается
    /// не при каждом старте — см. [`Storage::vacuum_if_due`].
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — уплотнение не удалось.
    pub fn vacuum(&self, now: Timestamp) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        // `execute_batch`, а не `execute`: VACUUM не возвращает числа
        // изменённых строк. Внутри транзакции он тоже невозможен,
        // поэтому отметка ставится отдельным запросом после него.
        connection.execute_batch("VACUUM;").map_err(storage_error)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO maintenance (id, last_vacuum_at) VALUES (1, ?)",
                params![now.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Уплотняет базу, если с прошлого раза прошло довольно времени.
    ///
    /// Возвращает `true`, если уплотнение выполнено.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение отметки или уплотнение
    /// не удалось.
    pub fn vacuum_if_due(&self, now: Timestamp, interval_millis: i64) -> Result<bool> {
        let last = {
            let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

            connection
                .query_row(
                    "SELECT last_vacuum_at FROM maintenance WHERE id = 1",
                    [],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .ok()
                .flatten()
        };

        let due = match last {
            // Никогда не уплотнялась: первый запуск ставит отметку,
            // но саму работу не делает — свежей базе уплотнять нечего,
            // а лишний проход по файлу при первом старте заметен.
            None => {
                let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
                connection
                    .execute(
                        "INSERT OR REPLACE INTO maintenance (id, last_vacuum_at) VALUES (1, ?)",
                        params![now.as_millis()],
                    )
                    .map_err(storage_error)?;

                return Ok(false);
            }
            Some(moment) => now.as_millis().saturating_sub(moment) >= interval_millis,
        };

        if !due {
            return Ok(false);
        }

        self.vacuum(now)?;

        Ok(true)
    }

    // --- File Vault ---

    /// Добавляет файл в хранилище под вторым фактором.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_vault_file(&self, file: &VaultFileRow) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT OR REPLACE INTO vault_files
                (file_id, name, size, created_at, location, wrapped_key)
            VALUES (?, ?, ?, ?, ?, ?)
            ",
                params![
                    file.file_id.as_bytes(),
                    file.name,
                    file.size,
                    file.created_at.as_millis(),
                    file.location,
                    file.wrapped_key,
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Перечисляет файлы vault.
    ///
    /// # 🔐 Про метаданные
    ///
    /// Метод отдаёт имена и размеры — то есть содержимое списка,
    /// который видит пользователь. Вызывать его до повторной
    /// аутентификации нельзя: список имён файлов сам по себе
    /// говорит достаточно. Проверку делает `aegis-core`, у которого
    /// есть состояние блокировки; хранилище состояния не знает
    /// и знать не должно.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn list_vault_files(&self, limit: u32) -> Result<Vec<VaultFileRow>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare(
                "
            SELECT file_id, name, size, created_at, location, wrapped_key
            FROM vault_files
            ORDER BY created_at DESC
            LIMIT ?
            ",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map(params![limit], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .map_err(storage_error)?;

        let mut files = Vec::new();
        for row in rows {
            let (file_id, name, size, created_at, location, wrapped_key) =
                row.map_err(storage_error)?;

            files.push(VaultFileRow {
                file_id: MessageId::from_uuid(uuid_from_slice(&file_id)?),
                name,
                size,
                created_at: Timestamp::from_millis(created_at),
                location,
                wrapped_key,
            });
        }

        Ok(files)
    }

    /// Читает один файл vault по идентификатору.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn vault_file(&self, file_id: &MessageId) -> Result<Option<VaultFileRow>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection
            .query_row(
                "
            SELECT name, size, created_at, location, wrapped_key
            FROM vault_files WHERE file_id = ?
            ",
                params![file_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .ok();

        Ok(row.map(
            |(name, size, created_at, location, wrapped_key)| VaultFileRow {
                file_id: *file_id,
                name,
                size,
                created_at: Timestamp::from_millis(created_at),
                location,
                wrapped_key,
            },
        ))
    }

    /// Убирает файл из vault.
    ///
    /// Возвращает путь к удалённому шифроблобу: сам файл с диска
    /// стирает вызывающий код, потому что файловой системы этот
    /// крейт не касается.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn delete_vault_file(&self, file_id: &MessageId) -> Result<Option<String>> {
        let Some(existing) = self.vault_file(file_id)? else {
            return Ok(None);
        };

        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        connection
            .execute(
                "DELETE FROM vault_files WHERE file_id = ?",
                params![file_id.as_bytes()],
            )
            .map_err(storage_error)?;

        // 🔐 Описание файла — имя и ключ шифроблоба — не должно
        // пережить удаление в основном файле базы (см. `checkpoint_truncate`).
        crate::checkpoint_truncate(&connection)?;

        Ok(Some(existing.location))
    }

    /// Читает последние события журнала безопасности.
    ///
    /// Возвращает тройки «тип события, подробности, время», новые
    /// первыми.
    ///
    /// # Зачем читать журнал
    ///
    /// Журнал append-only и до сих пор только пополнялся. Читать
    /// его нужно двум экранам: Security Center показывает, что
    /// происходило с устройством, а Recovery Center — когда
    /// восстанавливались из копии. Журнал, который никто не читает,
    /// не свидетельство, а мусор.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn recent_security_events(&self, limit: u32) -> Result<Vec<(String, String, Timestamp)>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare(
                "
            SELECT event_type, details, timestamp
            FROM security_log
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            ",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map(params![limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(storage_error)?;

        let mut events = Vec::new();
        for row in rows {
            let (event_type, details, timestamp) = row.map_err(storage_error)?;
            events.push((event_type, details, Timestamp::from_millis(timestamp)));
        }

        Ok(events)
    }

    /// Сколько файлов лежит в vault.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn vault_file_count(&self) -> Result<u32> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let count = connection
            .query_row("SELECT count(*) FROM vault_files", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(storage_error)?;

        u32::try_from(count).map_err(|_| AegisError::Storage)
    }
}

/// Читает идентификатор аккаунта и имя пользователя.
fn read_contact_pq_hashes(
    connection: &Connection,
) -> Result<Vec<(AccountId, [u8; crate::pq::PQ_HASH_LEN])>> {
    let mut statement = connection
        .prepare("SELECT account_id, pq_identity_hash FROM known_contacts WHERE pq_identity_hash IS NOT NULL")
        .map_err(storage_error)?;

    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(storage_error)?;

    let mut out = Vec::new();

    for row in rows {
        let (account, hash) = row.map_err(storage_error)?;
        out.push((
            AccountId::from_uuid(uuid_from_slice(&account)?),
            hash.as_slice()
                .try_into()
                .map_err(|_| AegisError::Storage)?,
        ));
    }

    Ok(out)
}

fn read_account_recovery(
    connection: &Connection,
) -> Result<Option<[u8; crate::pq::ACCOUNT_RECOVERY_LEN]>> {
    let row = connection.query_row(
        "SELECT secret FROM own_account_recovery WHERE id = 1",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    );

    match row {
        Ok(secret) => Ok(Some(
            secret
                .as_slice()
                .try_into()
                .map_err(|_| AegisError::Storage)?,
        )),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(storage_error(error)),
    }
}

fn read_account(connection: &Connection) -> Result<(Option<AccountId>, Option<String>)> {
    let account = connection
        .query_row("SELECT account_id FROM account WHERE id = 1", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .ok();

    let account_id = match account {
        None => None,
        Some(bytes) => Some(AccountId::from_uuid(uuid_from_slice(&bytes)?)),
    };

    let username = connection
        .query_row("SELECT username FROM own_keys WHERE id = 1", [], |row| {
            row.get::<_, Option<String>>(0)
        })
        .ok()
        .flatten();

    Ok((account_id, username))
}

/// Читает сообщения, изменённые после отметки.
fn read_messages(connection: &Connection, threshold: i64) -> Result<Vec<StoredMessage>> {
    let mut statement = connection
        .prepare(
            "
        SELECT message_id, chat_id, sender_id, timestamp, content,
               status, message_type, expires_at
        FROM messages
        -- 🔐 Исчезающие сообщения в копию не попадают. Выгруженная копия
        -- живёт у того, кто её хранит, и стереть из неё по таймеру нечем:
        -- снимок, сделанный до истечения, держал бы текст всегда. Прежде
        -- они попадали в копию вместе со сроком, и срок действовал только
        -- на устройстве.
        WHERE COALESCE(updated_at, created_at) > ?
          AND expires_at IS NULL
        ORDER BY timestamp ASC, rowid ASC
        ",
        )
        .map_err(storage_error)?;

    let rows = statement
        .query_map(params![threshold], |row| {
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

/// Читает контакты вместе с отметками верификации.
fn read_contacts(connection: &Connection) -> Result<Vec<ContactRow>> {
    let mut statement = connection
        .prepare(
            "
        SELECT c.account_id, c.identity_key, c.username, c.chat_id, c.added_at,
               v.account_id IS NOT NULL
        FROM known_contacts AS c
        LEFT JOIN verified_contacts AS v ON v.account_id = c.account_id
        ORDER BY c.added_at ASC
        ",
        )
        .map_err(storage_error)?;

    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })
        .map_err(storage_error)?;

    let mut contacts = Vec::new();
    for row in rows {
        let (account, identity, username, chat, added_at, verified) = row.map_err(storage_error)?;

        let chat_id = match chat {
            None => None,
            Some(bytes) => Some(ChatId::from_uuid(uuid_from_slice(&bytes)?)),
        };

        contacts.push(ContactRow {
            account_id: AccountId::from_uuid(uuid_from_slice(&account)?),
            identity_key: identity,
            username,
            chat_id,
            verified,
            added_at,
            replaced: false,
            confirmed_by_link: false,
            // Подтверждение журналом не переносится: его проще и
            // надёжнее получить заново, чем доверять копии.
            confirmed_by_kt: false,
        });
    }

    Ok(contacts)
}

/// Читает состояния чатов.
fn read_chats(connection: &Connection) -> Result<Vec<ChatBackupRow>> {
    let mut statement = connection
        .prepare(
            "
        SELECT chat_id, last_activity, disappearing_timer
        FROM chat_states
        ORDER BY last_activity ASC
        ",
        )
        .map_err(storage_error)?;

    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })
        .map_err(storage_error)?;

    let mut chats = Vec::new();
    for row in rows {
        let (chat, last_activity, timer) = row.map_err(storage_error)?;

        chats.push(ChatBackupRow {
            chat_id: ChatId::from_uuid(uuid_from_slice(&chat)?),
            last_activity_millis: last_activity,
            disappearing_timer_seconds: timer.and_then(|value| u32::try_from(value).ok()),
        });
    }

    Ok(chats)
}

/// Читает метаданные вложений, появившиеся после отметки.
fn read_attachments(connection: &Connection, threshold: i64) -> Result<Vec<StoredAttachment>> {
    let mut statement = connection
        .prepare(
            "
        SELECT message_id, attachment_type, description, size, created_at, descriptor
        FROM attachments
        -- Описания вложений исчезающих сообщений — тоже: в них ключи
        -- файлов, и по ним файл скачивается с сервера, пока он там лежит.
        WHERE created_at > ?
          AND message_id NOT IN (
              SELECT message_id FROM messages WHERE expires_at IS NOT NULL
          )
        ORDER BY created_at ASC
        ",
        )
        .map_err(storage_error)?;

    let rows = statement
        .query_map(params![threshold], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })
        .map_err(storage_error)?;

    let mut attachments = Vec::new();
    for row in rows {
        let (message, kind, description, size, created_at, descriptor) =
            row.map_err(storage_error)?;

        attachments.push(StoredAttachment {
            message_id: MessageId::from_uuid(uuid_from_slice(&message)?),
            attachment_type: u8::try_from(kind).unwrap_or(0),
            description,
            size,
            created_at: Timestamp::from_millis(created_at),
            descriptor,
        });
    }

    Ok(attachments)
}

/// Читает настройки.
fn read_settings(connection: &Connection) -> Result<Vec<(String, i64)>> {
    let mut statement = connection
        .prepare("SELECT key, value FROM settings ORDER BY key ASC")
        .map_err(storage_error)?;

    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(storage_error)?;

    let mut settings = Vec::new();
    for row in rows {
        settings.push(row.map_err(storage_error)?);
    }

    Ok(settings)
}

/// Читает надгробия, поставленные после отметки.
fn read_tombstones(connection: &Connection, threshold: i64) -> Result<Vec<MessageId>> {
    let mut statement = connection
        .prepare(
            "
        SELECT message_id FROM backup_tombstones
        WHERE deleted_at > ?
        ORDER BY deleted_at ASC
        ",
        )
        .map_err(storage_error)?;

    let rows = statement
        .query_map(params![threshold], |row| row.get::<_, Vec<u8>>(0))
        .map_err(storage_error)?;

    let mut tombstones = Vec::new();
    for row in rows {
        let bytes = row.map_err(storage_error)?;
        tombstones.push(MessageId::from_uuid(uuid_from_slice(&bytes)?));
    }

    Ok(tombstones)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_protocol::keys::SessionState;
    use aegis_types::Secret;

    /// Опознавательная строка состояния храповика.
    const SESSION_CANARY: &str = "RATCHET-STATE-MUST-NEVER-BE-BACKED-UP";

    /// Опознавательная строка приватного identity-ключа.
    const IDENTITY_CANARY: &str = "PRIVATE-IDENTITY-MUST-NEVER-BE-BACKED-UP";

    fn test_key() -> [u8; 32] {
        [0x5Au8; 32]
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn later(offset: i64) -> Timestamp {
        Timestamp::from_millis(now().as_millis().saturating_add(offset))
    }

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("временный каталог");
        let path = directory
            .path()
            .join("aegis.db")
            .to_string_lossy()
            .into_owned();
        let storage = Storage::new(&path, &test_key()).expect("база открывается");

        (storage, directory)
    }

    fn message(chat: ChatId, at: Timestamp) -> StoredMessage {
        StoredMessage {
            id: MessageId::generate(),
            chat_id: chat,
            sender_id: AccountId::generate(),
            timestamp: at,
            content: Ciphertext::new(b"ciphertext".to_vec()),
            status: MessageStatus::Sent,
            message_type: 0,
            expires_at: None,
        }
    }

    /// Полная выгрузка забирает всё, что нужно восстановлению.
    #[test]
    fn full_export_collects_everything() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let contact = AccountId::generate();

        storage
            .set_account_id(&AccountId::generate(), now())
            .unwrap();
        storage.save_message(&message(chat, now())).unwrap();
        storage
            .save_contact(&contact, &[0x11; 32], Some("bob"), Some(&chat), now())
            .unwrap();
        storage.set_contact_verified(&contact, true, now()).unwrap();
        storage.set_disappearing_timer(&chat, Some(3600)).unwrap();
        storage.set_setting_bool("presence_sharing", true).unwrap();

        let export = storage.export_for_backup(None, now()).expect("выгрузка");

        assert_eq!(export.messages.len(), 1);
        assert_eq!(export.contacts.len(), 1);
        assert!(export.account_id.is_some());
        assert!(
            export.contacts.first().is_some_and(|row| row.verified),
            "отметка личной верификации потеряна"
        );
        assert!(
            export
                .chats
                .iter()
                .any(|row| row.disappearing_timer_seconds == Some(3600)),
            "таймер исчезающих сообщений не выгружен"
        );
        assert!(export
            .settings
            .iter()
            .any(|(key, _)| key == "presence_sharing"));
    }

    /// 🔐 Решение раздела 12.5: в выгрузке нет ни состояния храповика,
    /// ни приватного identity-ключа.
    ///
    /// Проверяются байты, а не структура: канарейки записаны
    /// в `sessions` и `own_keys`, и ни одна не должна встретиться
    /// нигде в выгруженных данных. Тест сломается, если кто-нибудь
    /// добавит эти таблицы в выгрузку «для удобства восстановления».
    #[test]
    fn export_contains_no_session_or_identity_material() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();

        storage
            .save_session(
                &chat,
                &SessionState::from_serialized(Secret::new(SESSION_CANARY.as_bytes().to_vec())),
                now(),
            )
            .unwrap();
        storage
            .save_own_keys(
                IDENTITY_CANARY.as_bytes(),
                &[0x22; 32],
                &[0x33; 64],
                Some("device"),
                Some("alice"),
                now(),
            )
            .unwrap();
        storage.save_message(&message(chat, now())).unwrap();

        let export = storage.export_for_backup(None, now()).expect("выгрузка");

        // Всё, что вообще выгружено, сводится в один буфер байт.
        let mut everything: Vec<u8> = Vec::new();
        for row in &export.messages {
            everything.extend_from_slice(row.content.as_bytes());
            everything.extend_from_slice(row.id.as_bytes());
        }
        for row in &export.contacts {
            everything.extend_from_slice(&row.identity_key);
        }
        for row in &export.attachments {
            if let Some(descriptor) = &row.descriptor {
                everything.extend_from_slice(descriptor);
            }
        }
        for (key, value) in &export.settings {
            everything.extend_from_slice(key.as_bytes());
            everything.extend_from_slice(&value.to_be_bytes());
        }
        if let Some(name) = &export.username {
            everything.extend_from_slice(name.as_bytes());
        }

        for canary in [SESSION_CANARY, IDENTITY_CANARY] {
            assert!(
                !everything
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "в резервную копию попало то, чего там быть не должно: {canary}"
            );
        }
    }

    /// Инкремент забирает только изменённое.
    #[test]
    fn increment_takes_only_changed_rows() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();

        storage.save_message(&message(chat, now())).unwrap();
        let mark = later(1_000);
        storage.save_message(&message(chat, later(2_000))).unwrap();

        let increment = storage
            .export_for_backup(Some(mark), later(3_000))
            .expect("выгрузка");

        assert_eq!(
            increment.messages.len(),
            1,
            "инкремент забрал старые сообщения"
        );
    }

    /// 🔐 Смена статуса попадает в инкремент.
    ///
    /// Без столбца `updated_at` она терялась бы: `created_at`
    /// при смене статуса не меняется, и восстановленная переписка
    /// показывала бы «отправляется» на давно доставленном.
    #[test]
    fn status_change_lands_in_the_increment() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let stored = message(chat, now());

        storage.save_message(&stored).unwrap();
        let mark = later(1_000);
        storage
            .set_message_status(&stored.id, MessageStatus::Delivered, later(2_000))
            .unwrap();

        let increment = storage
            .export_for_backup(Some(mark), later(3_000))
            .expect("выгрузка");

        assert_eq!(increment.messages.len(), 1, "смена статуса потерялась");
        assert!(increment
            .messages
            .first()
            .is_some_and(|row| row.status == MessageStatus::Delivered));
    }

    /// 🔐 Удаление сообщения оставляет надгробие.
    #[test]
    fn deleting_a_message_leaves_a_tombstone() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let stored = message(chat, now());

        storage.save_message(&stored).unwrap();
        storage.delete_message(&stored.id, later(1_000)).unwrap();

        let export = storage
            .export_for_backup(None, later(2_000))
            .expect("выгрузка");

        assert!(export.messages.is_empty());
        assert_eq!(export.tombstones, vec![stored.id]);
    }

    /// 🔐 Истечение по таймеру тоже оставляет надгробие.
    ///
    /// Это и есть механизм, из-за которого исчезнувшее сообщение
    /// не возвращается при восстановлении из копии.
    #[test]
    fn expiring_a_message_leaves_a_tombstone() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let mut stored = message(chat, now());
        stored.expires_at = Some(later(1_000));

        storage.save_message(&stored).unwrap();
        let removed = storage.purge_expired(later(2_000)).unwrap();

        assert_eq!(removed, 1);

        let export = storage
            .export_for_backup(None, later(3_000))
            .expect("выгрузка");

        assert_eq!(export.tombstones, vec![stored.id]);
    }

    /// Импорт возвращает данные в базу.
    #[test]
    fn import_restores_rows() {
        let (source, _source_dir) = open_temp();
        let chat = ChatId::generate();
        let contact = AccountId::generate();

        source.save_message(&message(chat, now())).unwrap();
        source
            .save_contact(&contact, &[0x11; 32], Some("bob"), Some(&chat), now())
            .unwrap();
        source.set_contact_verified(&contact, true, now()).unwrap();
        source.set_disappearing_timer(&chat, Some(600)).unwrap();

        let export = source.export_for_backup(None, now()).expect("выгрузка");

        let (target, _target_dir) = open_temp();
        let applied = target.import_from_backup(&export).expect("импорт");

        assert!(applied >= 3);
        assert_eq!(target.load_messages(&chat, 10).unwrap().len(), 1);
        assert_eq!(target.list_contacts(10).unwrap().len(), 1);
        assert!(
            target.is_contact_verified(&contact).unwrap(),
            "отметка верификации не восстановлена"
        );
        assert_eq!(target.get_disappearing_timer(&chat).unwrap(), Some(600));
    }

    /// 🔐 Надгробие в копии убирает сообщение и при импорте.
    #[test]
    fn import_applies_tombstones() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let stored = message(chat, now());

        storage.save_message(&stored).unwrap();
        assert_eq!(storage.load_messages(&chat, 10).unwrap().len(), 1);

        let data = BackupExport {
            account_id: None,
            username: None,
            messages: Vec::new(),
            contacts: Vec::new(),
            chats: Vec::new(),
            attachments: Vec::new(),
            settings: Vec::new(),
            tombstones: vec![stored.id],
            account_recovery: None,
            contact_pq_hashes: Vec::new(),
            watermark: later(1_000),
        };

        storage.import_from_backup(&data).expect("импорт");

        assert!(storage.load_messages(&chat, 10).unwrap().is_empty());
    }

    /// 🔐 Исчезающее сообщение и его вложение в копию не попадают.
    ///
    /// Срок действовал только на устройстве: в копии сообщение лежало
    /// вместе со сроком, и снимок, сделанный до истечения, держал текст
    /// всегда — у того, кто хранит файлы копии.
    #[test]
    fn disappearing_messages_are_not_exported() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();

        let lasting = message(chat, now());
        let vanishing = StoredMessage {
            id: MessageId::generate(),
            expires_at: Some(later(60_000)),
            ..message(chat, now())
        };

        storage.save_message(&lasting).unwrap();
        storage.save_message(&vanishing).unwrap();
        storage
            .save_attachment(&StoredAttachment {
                message_id: vanishing.id,
                attachment_type: 1,
                description: Some("фото".to_owned()),
                size: 1024,
                created_at: now(),
                descriptor: Some(vec![0x77; 32]),
            })
            .unwrap();

        let export = storage
            .export_for_backup(None, later(1_000))
            .expect("выгрузка");

        let exported: Vec<MessageId> = export.messages.iter().map(|row| row.id).collect();
        assert_eq!(
            exported,
            vec![lasting.id],
            "исчезающее сообщение попало в копию"
        );
        assert!(
            export.attachments.is_empty(),
            "описание вложения исчезающего сообщения попало в копию"
        );
    }

    /// 🔐 Надгробие убирает при импорте и сообщение с вложением.
    ///
    /// Прежде сообщение удалялось раньше описаний вложений, и внешний
    /// ключ `attachments → messages` ронял импорт копии целиком.
    #[test]
    fn import_applies_a_tombstone_to_a_message_with_an_attachment() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let stored = message(chat, now());

        storage.save_message(&stored).unwrap();
        storage
            .save_attachment(&StoredAttachment {
                message_id: stored.id,
                attachment_type: 1,
                description: Some("фото".to_owned()),
                size: 1024,
                created_at: now(),
                descriptor: Some(vec![0x77; 32]),
            })
            .unwrap();

        let data = BackupExport {
            account_id: None,
            username: None,
            messages: Vec::new(),
            contacts: Vec::new(),
            chats: Vec::new(),
            attachments: Vec::new(),
            settings: Vec::new(),
            tombstones: vec![stored.id],
            account_recovery: None,
            contact_pq_hashes: Vec::new(),
            watermark: later(1_000),
        };

        storage.import_from_backup(&data).expect("импорт");

        assert!(storage.load_messages(&chat, 10).unwrap().is_empty());
        assert!(storage.load_attachments(&stored.id).unwrap().is_empty());
    }

    /// Повторный импорт не задваивает вложения.
    #[test]
    fn repeated_import_does_not_duplicate_attachments() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let stored = message(chat, now());

        storage.save_message(&stored).unwrap();
        storage
            .save_attachment(&StoredAttachment {
                message_id: stored.id,
                attachment_type: 1,
                description: Some("фото".to_owned()),
                size: 1024,
                created_at: now(),
                descriptor: Some(vec![0x77; 32]),
            })
            .unwrap();

        let export = storage.export_for_backup(None, now()).expect("выгрузка");

        storage.import_from_backup(&export).expect("импорт");
        storage
            .import_from_backup(&export)
            .expect("повторный импорт");

        assert_eq!(storage.load_attachments(&stored.id).unwrap().len(), 1);
    }

    /// Состояние цепочки переживает перезапись и очистку.
    #[test]
    fn chain_state_round_trips() {
        let (storage, _dir) = open_temp();

        assert!(storage.backup_chain_state().unwrap().is_none());

        let state = BackupChainState {
            salt: vec![0x11; 16],
            memory_kib: 262_144,
            iterations: 4,
            parallelism: 4,
            generation: 3,
            last_digest: vec![0x22; 32],
            watermark: now(),
            last_backup_at: Some(later(1_000)),
        };

        storage.save_backup_chain_state(&state).unwrap();

        assert_eq!(storage.backup_chain_state().unwrap(), Some(state));

        storage.clear_backup_chain_state().unwrap();

        assert!(storage.backup_chain_state().unwrap().is_none());
    }

    /// Надгробия убираются после того, как уехали в копию.
    #[test]
    fn tombstones_are_pruned_after_backup() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        let stored = message(chat, now());

        storage.save_message(&stored).unwrap();
        storage.delete_message(&stored.id, later(1_000)).unwrap();

        assert_eq!(storage.prune_tombstones(later(2_000)).unwrap(), 1);
        assert!(storage
            .export_for_backup(None, later(3_000))
            .unwrap()
            .tombstones
            .is_empty());
    }

    /// 🧪 Задача M6: периодический VACUUM.
    ///
    /// Первый запуск только ставит отметку, следующий до срока
    /// ничего не делает, а после срока — уплотняет.
    #[test]
    fn vacuum_runs_on_schedule() {
        let (storage, _dir) = open_temp();
        let day = 24 * 60 * 60 * 1000;
        // Половина срока записана произведением, а не делением:
        // деление целых запрещено правилами проекта.
        let day_half = 12 * 60 * 60 * 1000;

        assert!(
            !storage.vacuum_if_due(now(), day).unwrap(),
            "первый запуск не должен уплотнять — свежей базе нечего уплотнять"
        );
        assert!(
            !storage.vacuum_if_due(later(day_half), day).unwrap(),
            "уплотнение сработало раньше срока"
        );
        assert!(
            storage.vacuum_if_due(later(day + 1), day).unwrap(),
            "уплотнение не сработало по сроку"
        );
        assert!(
            !storage.vacuum_if_due(later(day + 2), day).unwrap(),
            "отметка не обновилась после уплотнения"
        );
    }

    /// База переживает уплотнение и открывается дальше.
    ///
    /// 🔐 Проверка не декоративная: `VACUUM` пересобирает файл
    /// целиком, и ошибка в порядке PRAGMA сделала бы базу
    /// неоткрываемой — то есть уничтожила бы переписку при попытке
    /// её защитить.
    #[test]
    fn database_survives_vacuum() {
        let directory = tempfile::tempdir().expect("каталог");
        let path = directory
            .path()
            .join("vacuum.db")
            .to_string_lossy()
            .into_owned();
        let storage = Storage::new(&path, &test_key()).expect("база");

        let chat = ChatId::generate();
        let kept = message(chat, now());
        let removed = message(chat, now());

        storage.save_message(&kept).unwrap();
        storage.save_message(&removed).unwrap();
        storage.delete_message(&removed.id, later(1_000)).unwrap();
        storage.vacuum(later(2_000)).unwrap();
        drop(storage);

        let reopened = Storage::new(&path, &test_key()).expect("база после VACUUM");
        let messages = reopened.load_messages(&chat, 10).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages.first().map(|row| row.id), Some(kept.id));
    }

    /// Файлы vault сохраняются, перечисляются и удаляются.
    #[test]
    fn vault_files_round_trip() {
        let (storage, _dir) = open_temp();
        let file = VaultFileRow {
            file_id: MessageId::generate(),
            name: "паспорт.pdf".to_owned(),
            size: 4096,
            created_at: now(),
            location: "vault/abc.enc".to_owned(),
            wrapped_key: vec![0x99; 48],
        };

        storage.save_vault_file(&file).unwrap();

        assert_eq!(storage.vault_file_count().unwrap(), 1);
        assert_eq!(storage.list_vault_files(10).unwrap(), vec![file.clone()]);
        assert_eq!(
            storage.vault_file(&file.file_id).unwrap(),
            Some(file.clone())
        );

        assert_eq!(
            storage.delete_vault_file(&file.file_id).unwrap(),
            Some("vault/abc.enc".to_owned()),
            "путь к блобу нужен вызывающему, чтобы стереть файл с диска"
        );
        assert_eq!(storage.vault_file_count().unwrap(), 0);
    }

    /// Удаление несуществующего файла vault — не ошибка.
    #[test]
    fn deleting_absent_vault_file_is_not_an_error() {
        let (storage, _dir) = open_temp();

        assert_eq!(
            storage.delete_vault_file(&MessageId::generate()).unwrap(),
            None
        );
    }
}
