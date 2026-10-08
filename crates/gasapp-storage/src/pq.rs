// SPDX-License-Identifier: Apache-2.0

//! Пост-квантовая половина identity (схема 12).
//!
//! * собственный seed ML-DSA-65 и отметка его публикации на сервере;
//! * хеш пост-квантовой половины каждого контакта — для сверки
//!   и обнаружения подмены так же, как классического ключа.
//!
//! 🔐 Seed — закрытый ключ, наравне с identity-ключом: живёт
//! в зашифрованной базе и уходит в резервную копию.

use gasapp_types::{AccountId, GasAppError, Result, Timestamp};
use rusqlite::params;

use crate::{storage_error, Storage};

/// Длина seed пост-квантовой половины.
pub const PQ_SEED_LEN: usize = 32;

/// Длина хеша пост-квантовой половины.
pub const PQ_HASH_LEN: usize = 32;

/// Длина секрета ключа восстановления аккаунта.
pub const ACCOUNT_RECOVERY_LEN: usize = 64;

impl Storage {
    /// Seed собственной пост-квантовой половины и момент публикации.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn own_pq_identity(&self) -> Result<Option<([u8; PQ_SEED_LEN], Option<Timestamp>)>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let row = connection.query_row(
            "SELECT seed, published_at FROM own_pq_identity WHERE id = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?)),
        );

        let (seed, published_at) = match row {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(error) => return Err(storage_error(error)),
        };

        Ok(Some((
            seed.as_slice()
                .try_into()
                .map_err(|_| GasAppError::Storage)?,
            published_at.map(Timestamp::from_millis),
        )))
    }

    /// Заводит seed пост-квантовой половины, если его ещё нет.
    ///
    /// Существующий не перезаписывается: его открытая часть уже могла
    /// уйти на сервер и собеседникам, и тихая замена выглядела бы
    /// у них подменой ключа.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn init_own_pq_identity(&self, seed: &[u8; PQ_SEED_LEN]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "INSERT OR IGNORE INTO own_pq_identity (id, seed) VALUES (1, ?)",
                params![seed.as_slice()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Отмечает, что пост-квантовая половина опубликована на сервере.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Uninitialized`] — половины ещё нет;
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn mark_own_pq_identity_published(&self, now: Timestamp) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let changed = connection
            .execute(
                "UPDATE own_pq_identity SET published_at = ? WHERE id = 1",
                params![now.as_millis()],
            )
            .map_err(storage_error)?;

        if changed == 0 {
            return Err(GasAppError::Uninitialized);
        }

        Ok(())
    }

    /// Секрет ключа восстановления аккаунта; `None` — не заведён
    /// (аккаунт зарегистрирован до появления ключа).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn own_account_recovery(&self) -> Result<Option<[u8; ACCOUNT_RECOVERY_LEN]>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

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
                    .map_err(|_| GasAppError::Storage)?,
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Записывает секрет ключа восстановления аккаунта, заменяя прежний.
    ///
    /// Замена — не ошибка: восстановление из копии приносит секрет,
    /// которым аккаунт и вернули.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_own_account_recovery(&self, secret: &[u8; ACCOUNT_RECOVERY_LEN]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO own_account_recovery (id, secret) VALUES (1, ?)",
                params![secret.as_slice()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Хеш пост-квантовой половины контакта; `None` — ещё не известен.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn contact_pq_hash(&self, account: &AccountId) -> Result<Option<[u8; PQ_HASH_LEN]>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let row = connection.query_row(
            "SELECT pq_identity_hash FROM known_contacts WHERE account_id = ?",
            params![account.as_bytes()],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        );

        match row {
            Ok(Some(hash)) => Ok(Some(
                hash.as_slice()
                    .try_into()
                    .map_err(|_| GasAppError::Storage)?,
            )),
            Ok(None) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Записывает хеш пост-квантовой половины контакта.
    ///
    /// Контакт обязан уже существовать: хеш — свойство известного
    /// ключа, а не самостоятельная запись.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_contact_pq_hash(&self, account: &AccountId, hash: &[u8; PQ_HASH_LEN]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "UPDATE known_contacts SET pq_identity_hash = ? WHERE account_id = ?",
                params![hash.as_slice(), account.as_bytes()],
            )
            .map_err(storage_error)?;

        Ok(())
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

        (Storage::new(&path, &[0x5Au8; 32]).expect("база"), directory)
    }

    #[test]
    fn own_pq_identity_is_created_once() {
        let (storage, _dir) = open_temp();

        assert!(storage.own_pq_identity().expect("чтение").is_none());
        storage.init_own_pq_identity(&[1; 32]).expect("запись");
        storage.init_own_pq_identity(&[2; 32]).expect("повтор");

        let (seed, published) = storage.own_pq_identity().expect("чтение").expect("есть");
        assert_eq!(seed, [1; 32], "seed перезаписан");
        assert!(published.is_none());

        storage
            .mark_own_pq_identity_published(Timestamp::from_millis(5))
            .expect("отметка");
        assert_eq!(
            storage.own_pq_identity().expect("чтение").expect("есть").1,
            Some(Timestamp::from_millis(5))
        );
    }

    #[test]
    fn account_recovery_is_stored_and_replaced() {
        let (storage, _dir) = open_temp();

        assert!(storage.own_account_recovery().expect("чтение").is_none());
        storage.set_own_account_recovery(&[1; 64]).expect("запись");
        storage.set_own_account_recovery(&[2; 64]).expect("замена");
        assert_eq!(
            storage.own_account_recovery().expect("чтение"),
            Some([2; 64])
        );
    }

    #[test]
    fn contact_pq_hash_round_trips() {
        let (storage, _dir) = open_temp();
        let account = AccountId::generate();

        storage
            .save_contact_identity(&account, &[3; 32])
            .expect("контакт");
        assert_eq!(storage.contact_pq_hash(&account).expect("чтение"), None);

        storage
            .set_contact_pq_hash(&account, &[4; 32])
            .expect("запись");
        assert_eq!(
            storage.contact_pq_hash(&account).expect("чтение"),
            Some([4; 32])
        );
    }
}
