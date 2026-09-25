// SPDX-License-Identifier: Apache-2.0

//! Журнал ключей на устройстве (схема 14, спецификация §9.7).
//!
//! * проверенная цепочка вершин эпох — корни, против которых
//!   проверяются доказательства;
//! * состояние проверки своего имени: до какой эпохи проверено
//!   и какая версия ключа своя;
//! * отметка контакта «ключ подтверждён журналом».
//!
//! Секретов здесь нет: корни и вершины публичны. Всё равно в
//! зашифрованной базе — чтобы не выдавать, с кем идёт переписка.

use aegis_types::{AccountId, AegisError, Result};
use rusqlite::{params, OptionalExtension as _};

use crate::{storage_error, Storage};

/// Эпоха цепочки: номер, корень, вершина.
pub type KtHead = (u64, [u8; 32], [u8; 32]);

fn to32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| AegisError::Storage)
}

fn epoch_sql(epoch: u64) -> Result<i64> {
    i64::try_from(epoch).map_err(|_| AegisError::Storage)
}

fn epoch_from_sql(epoch: i64) -> Result<u64> {
    u64::try_from(epoch).map_err(|_| AegisError::Storage)
}

impl Storage {
    /// Последняя проверенная эпоха.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn kt_latest_head(&self) -> Result<Option<KtHead>> {
        self.kt_head_query(
            "SELECT epoch, root, head FROM kt_heads ORDER BY epoch DESC LIMIT 1",
            None,
        )
    }

    /// Последняя проверенная эпоха не позже `epoch`.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn kt_head_at_or_before(&self, epoch: u64) -> Result<Option<KtHead>> {
        self.kt_head_query(
            "SELECT epoch, root, head FROM kt_heads WHERE epoch <= ?1 ORDER BY epoch DESC LIMIT 1",
            Some(epoch_sql(epoch)?),
        )
    }

    /// Проверенная эпоха ровно `epoch`.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn kt_head_exact(&self, epoch: u64) -> Result<Option<KtHead>> {
        self.kt_head_query(
            "SELECT epoch, root, head FROM kt_heads WHERE epoch = ?1",
            Some(epoch_sql(epoch)?),
        )
    }

    fn kt_head_query(&self, sql: &str, epoch: Option<i64>) -> Result<Option<KtHead>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let map = |row: &rusqlite::Row<'_>| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        };
        let row = match epoch {
            Some(epoch) => connection.query_row(sql, params![epoch], map),
            None => connection.query_row(sql, [], map),
        }
        .optional()
        .map_err(storage_error)?;

        row.map(|(epoch, root, head)| Ok((epoch_from_sql(epoch)?, to32(&root)?, to32(&head)?)))
            .transpose()
    }

    /// Номера проверенных эпох в диапазоне `[from, to]` по возрастанию.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn kt_epochs_between(&self, from: u64, to: u64) -> Result<Vec<u64>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let mut statement = connection
            .prepare("SELECT epoch FROM kt_heads WHERE epoch BETWEEN ?1 AND ?2 ORDER BY epoch")
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![epoch_sql(from)?, epoch_sql(to)?], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(storage_error)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(epoch_from_sql(row.map_err(storage_error)?)?);
        }

        Ok(out)
    }

    /// Дописывает проверенные эпохи и забывает эпохи раньше `keep_from`.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn kt_store_heads(&self, heads: &[KtHead], keep_from: u64) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        for (epoch, root, head) in heads {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO kt_heads (epoch, root, head) VALUES (?1, ?2, ?3)",
                    params![epoch_sql(*epoch)?, root.as_slice(), head.as_slice()],
                )
                .map_err(storage_error)?;
        }

        transaction
            .execute(
                "DELETE FROM kt_heads WHERE epoch < ?1",
                params![epoch_sql(keep_from)?],
            )
            .map_err(storage_error)?;

        transaction.commit().map_err(storage_error)
    }

    /// Забывает цепочку целиком — начать её заново (после долгого
    /// отсутствия, когда сервер уже не хранит эпоху, на которой
    /// остановились).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn kt_forget_heads(&self) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute("DELETE FROM kt_heads", [])
            .map(|_| ())
            .map_err(storage_error)
    }

    /// Состояние проверки своего имени: до какой эпохи проверено
    /// и какая версия ключа своя (0 — своего листа ещё не видели).
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn kt_self(&self) -> Result<Option<(u64, u64)>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection
            .query_row(
                "SELECT checked_epoch, version FROM kt_self WHERE id = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(storage_error)?;

        row.map(|(checked, version)| Ok((epoch_from_sql(checked)?, epoch_from_sql(version)?)))
            .transpose()
    }

    /// Записывает состояние проверки своего имени.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_kt_self(&self, checked_epoch: u64, version: u64) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO kt_self (id, checked_epoch, version) VALUES (1, ?1, ?2)",
                params![epoch_sql(checked_epoch)?, epoch_sql(version)?],
            )
            .map(|_| ())
            .map_err(storage_error)
    }

    /// Отмечает ключ контакта подтверждённым журналом ключей.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn mark_contact_confirmed_by_kt(&self, account: &AccountId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "UPDATE known_contacts SET confirmed_by_kt = 1 WHERE account_id = ?",
                params![account.as_bytes()],
            )
            .map(|_| ())
            .map_err(storage_error)
    }
}

#[cfg(test)]
mod tests {
    use crate::Storage;

    fn open() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("kt.db").to_string_lossy().into_owned();

        (Storage::new(&path, &[0x33; 32]).expect("база"), dir)
    }

    #[test]
    fn heads_are_stored_queried_and_pruned() {
        let (storage, _dir) = open();
        assert!(storage.kt_latest_head().expect("пусто").is_none());

        storage
            .kt_store_heads(
                &[
                    (10, [1; 32], [2; 32]),
                    (11, [3; 32], [4; 32]),
                    (13, [5; 32], [6; 32]),
                ],
                0,
            )
            .expect("запись");

        assert_eq!(
            storage.kt_latest_head().expect("последняя"),
            Some((13, [5; 32], [6; 32]))
        );
        assert_eq!(
            storage
                .kt_head_at_or_before(12)
                .expect("до 12")
                .map(|h| h.0),
            Some(11)
        );
        assert_eq!(storage.kt_head_exact(12).expect("12"), None);
        assert_eq!(
            storage.kt_epochs_between(10, 12).expect("диапазон"),
            vec![10, 11]
        );

        storage
            .kt_store_heads(&[(14, [7; 32], [8; 32])], 12)
            .expect("обрезка");
        assert_eq!(
            storage.kt_epochs_between(0, 20).expect("после"),
            vec![13, 14]
        );

        storage.kt_forget_heads().expect("сброс");
        assert!(storage.kt_latest_head().expect("пусто").is_none());
    }

    #[test]
    fn self_state_round_trips() {
        let (storage, _dir) = open();

        assert_eq!(storage.kt_self().expect("нет"), None);
        storage.set_kt_self(40, 2).expect("запись");
        assert_eq!(storage.kt_self().expect("есть"), Some((40, 2)));
    }
}
