// SPDX-License-Identifier: Apache-2.0

//! Устройства аккаунтов (`docs/protocol/MULTI-DEVICE.md`).
//!
//! * **Списки устройств собеседников** — последний проверенный подписанный
//!   список (SDL) каждого аккаунта: версия и отпечаток для правила версий,
//!   сами байты и ключи устройств для отправки.
//! * **Справочник устройств** — какому аккаунту принадлежит ключ
//!   устройства. Конверт и сертификат называют устройство, а чат и
//!   контакт живут по ключу аккаунта.
//! * **Ключ своего аккаунта** — у основного устройства он совпадает с
//!   ключом устройства (и не записывается), у подключённого — другой.
//!
//! 🔐 Сюда попадает только список, подпись которого уже проверена ключом
//! аккаунта (это делает ядро): справочник — не слова сервера.

use gasapp_types::{GasAppError, PublicKeyBytes, Result, Timestamp};
use rusqlite::{params, OptionalExtension as _};

use crate::{storage_error, Storage};

/// Устройство из проверенного списка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDevice {
    /// Идентификатор устройства (UUID) — им адресуется доставка.
    pub device_id: [u8; 16],
    /// Identity-ключ устройства.
    pub identity: PublicKeyBytes,
    /// Пост-квантовая половина его identity.
    pub pq_identity: Vec<u8>,
}

/// Запомненный список устройств аккаунта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeviceList {
    /// Версия.
    pub version: u64,
    /// Отпечаток подписанных байтов.
    pub digest: [u8; 32],
    /// Подписанный список целиком (список ‖ подпись).
    pub signed: Vec<u8>,
}

fn key(bytes: Vec<u8>) -> Result<PublicKeyBytes> {
    Ok(PublicKeyBytes::new(bytes.try_into().map_err(|_| GasAppError::Storage)?))
}

impl Storage {
    /// Запоминает проверенный список устройств аккаунта: прежние
    /// устройства аккаунта забываются, новые записываются.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn save_device_list(
        &self,
        account: &PublicKeyBytes,
        list: &StoredDeviceList,
        devices: &[KnownDevice],
        now: Timestamp,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;
        let version = i64::try_from(list.version).map_err(|_| GasAppError::Storage)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO device_lists (account_identity, version, digest, signed, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![account.as_bytes(), version, list.digest, list.signed, now.as_millis()],
            )
            .map_err(storage_error)?;
        transaction
            .execute("DELETE FROM device_keys WHERE account_identity = ?1", params![account.as_bytes()])
            .map_err(storage_error)?;
        for device in devices {
            transaction
                .execute(
                    "INSERT OR REPLACE INTO device_keys (device_identity, account_identity, device_id, pq_identity)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![device.identity.as_bytes(), account.as_bytes(), device.device_id, device.pq_identity],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)
    }

    /// Запомненный список устройств аккаунта.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn device_list(&self, account: &PublicKeyBytes) -> Result<Option<StoredDeviceList>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let row: Option<(i64, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT version, digest, signed FROM device_lists WHERE account_identity = ?1",
                params![account.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage_error)?;
        row.map(|(version, digest, signed)| {
            Ok(StoredDeviceList {
                version: u64::try_from(version).map_err(|_| GasAppError::Storage)?,
                digest: digest.try_into().map_err(|_| GasAppError::Storage)?,
                signed,
            })
        })
        .transpose()
    }

    /// Устройства аккаунта из запомненного списка.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn known_devices(&self, account: &PublicKeyBytes) -> Result<Vec<KnownDevice>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare_cached(
                "SELECT device_id, device_identity, pq_identity FROM device_keys
                  WHERE account_identity = ?1 ORDER BY device_id",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(params![account.as_bytes()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
            })
            .map_err(storage_error)?;
        rows.map(|row| {
            let (device_id, identity, pq_identity) = row.map_err(storage_error)?;
            Ok(KnownDevice {
                device_id: device_id.try_into().map_err(|_| GasAppError::Storage)?,
                identity: key(identity)?,
                pq_identity,
            })
        })
        .collect()
    }

    /// Аккаунт, которому принадлежит ключ устройства, — по проверенным
    /// спискам. `None` — устройства нет ни в одном списке (у аккаунта с
    /// одним устройством ключ устройства и есть ключ аккаунта).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn account_of_device(&self, device: &PublicKeyBytes) -> Result<Option<PublicKeyBytes>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let account: Option<Vec<u8>> = connection
            .query_row(
                "SELECT account_identity FROM device_keys WHERE device_identity = ?1",
                params![device.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        account.map(key).transpose()
    }

    /// Запоминает ключ своего аккаунта — на подключённом устройстве, где
    /// он не совпадает с ключом устройства.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_own_account_identity(&self, identity: &PublicKeyBytes, pq: &[u8]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO own_account (id, identity, pq_identity) VALUES (1, ?1, ?2)",
                params![identity.as_bytes(), pq],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    /// Ключ своего аккаунта и его пост-квантовая половина; `None` — это
    /// основное устройство (ключ аккаунта — ключ устройства).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn own_account_identity(&self) -> Result<Option<(PublicKeyBytes, Vec<u8>)>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let row: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row("SELECT identity, pq_identity FROM own_account WHERE id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(storage_error)?;
        row.map(|(identity, pq)| Ok((key(identity)?, pq))).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("devices.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");
        (storage, dir)
    }

    fn device(byte: u8) -> KnownDevice {
        KnownDevice {
            device_id: [byte; 16],
            identity: PublicKeyBytes::new([byte; 32]),
            pq_identity: vec![byte; 8],
        }
    }

    #[test]
    fn device_lists_replace_the_previous_devices() {
        let (storage, _dir) = open_temp();
        let account = PublicKeyBytes::new([1; 32]);
        let now = Timestamp::from_millis(1);

        assert!(storage.device_list(&account).unwrap().is_none());
        assert!(storage.account_of_device(&PublicKeyBytes::new([2; 32])).unwrap().is_none());

        let first = StoredDeviceList { version: 2, digest: [9; 32], signed: vec![1, 2, 3] };
        storage.save_device_list(&account, &first, &[device(1), device(2)], now).unwrap();
        assert_eq!(storage.device_list(&account).unwrap(), Some(first));
        assert_eq!(storage.known_devices(&account).unwrap(), vec![device(1), device(2)]);
        assert_eq!(storage.account_of_device(&PublicKeyBytes::new([2; 32])).unwrap(), Some(account));

        // Устройство отключено — забыто.
        let second = StoredDeviceList { version: 3, digest: [8; 32], signed: vec![4] };
        storage.save_device_list(&account, &second, &[device(1)], now).unwrap();
        assert_eq!(storage.known_devices(&account).unwrap(), vec![device(1)]);
        assert!(storage.account_of_device(&PublicKeyBytes::new([2; 32])).unwrap().is_none());
    }

    #[test]
    fn own_account_identity_is_absent_on_a_primary_device() {
        let (storage, _dir) = open_temp();
        assert!(storage.own_account_identity().unwrap().is_none());
        storage.set_own_account_identity(&PublicKeyBytes::new([5; 32]), &[6, 6]).unwrap();
        assert_eq!(
            storage.own_account_identity().unwrap(),
            Some((PublicKeyBytes::new([5; 32]), vec![6, 6]))
        );
    }
}
