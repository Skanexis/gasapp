// SPDX-License-Identifier: Apache-2.0

//! Запас пропусков — анонимных одноразовых прав на подписку.
//!
//! Пропуск — это зерно и секрет (`gasapp_protocol::pass`). Сервер выдал
//! его вслепую и не знает, кому какой достался; приложение держит
//! небольшой запас, чтобы выдача и трата не стояли рядом по времени.
//!
//! 🔐 В резервную копию пропуска не входят: это расходный материал,
//! и новый запас берётся у сервера за минуту.

use gasapp_types::{GasAppError, Result};
use rusqlite::{params, OptionalExtension as _};

use crate::{storage_error, Storage};

/// Пропуск в базе: зерно и секрет.
pub type StoredPass = ([u8; 32], [u8; 32]);

impl Storage {
    /// Кладёт пропуска в запас.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn store_passes(&self, passes: &[StoredPass]) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        for (seed, secret) in passes {
            transaction
                .execute(
                    "INSERT OR IGNORE INTO passes (seed, secret) VALUES (?, ?)",
                    params![seed.as_slice(), secret.as_slice()],
                )
                .map_err(storage_error)?;
        }

        transaction.commit().map_err(storage_error)
    }

    /// Забирает один пропуск из запаса — он удаляется сразу: потраченный
    /// или потерянный, второй раз он не годится.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы либо испорченная строка.
    pub fn take_pass(&self) -> Result<Option<StoredPass>> {
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        let found: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row("SELECT seed, secret FROM passes LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(storage_error)?;

        let Some((seed, secret)) = found else {
            return Ok(None);
        };

        transaction
            .execute("DELETE FROM passes WHERE seed = ?", params![seed])
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;

        Ok(Some((
            seed.try_into().map_err(|_| GasAppError::Storage)?,
            secret.try_into().map_err(|_| GasAppError::Storage)?,
        )))
    }

    /// Сколько пропусков в запасе.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn count_passes(&self) -> Result<u32> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let count: i64 = connection
            .query_row("SELECT count(*) FROM passes", [], |row| row.get(0))
            .map_err(storage_error)?;

        u32::try_from(count).map_err(|_| GasAppError::Storage)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_is_taken_once() {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("passes.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");

        assert_eq!(storage.take_pass().unwrap(), None);

        storage
            .store_passes(&[([1; 32], [2; 32]), ([3; 32], [4; 32])])
            .unwrap();
        // Повтор того же зерна второй пропуск не заводит.
        storage.store_passes(&[([1; 32], [9; 32])]).unwrap();
        assert_eq!(storage.count_passes().unwrap(), 2);

        let first = storage.take_pass().unwrap().unwrap();
        let second = storage.take_pass().unwrap().unwrap();
        assert_ne!(first.0, second.0);
        assert_eq!(storage.take_pass().unwrap(), None);
        assert_eq!(storage.count_passes().unwrap(), 0);
    }
}
