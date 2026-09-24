// SPDX-License-Identifier: Apache-2.0

//! Состояние sealed sender и текстовые настройки (M7).
//!
//! # Что здесь хранится
//!
//! * собственный ключ доступа и отметка о его публикации на сервере;
//! * последний сертификат отправителя и ключ сервера, которым он
//!   подписан;
//! * ключи доступа собеседников — они приходят внутри переписки;
//! * отметки «свой ключ этому собеседнику уже передан»;
//! * текстовые настройки — адрес прокси (ADR-024).
//!
//! # 🔐 Почему всё это в зашифрованной базе
//!
//! Ни ключ доступа, ни сертификат не являются секретами в
//! криптографическом смысле: первый ничего не шифрует, второй видит
//! каждый собеседник. Но их **наличие** рядом с базой открытым текстом
//! сообщало бы наблюдателю, что владелец пользуется sealed sender,
//! а адрес прокси — что он ходит через Tor. Факт использования защиты
//! сам по себе метаданные, и хранится он там же, где переписка.

use aegis_types::{AccountId, AegisError, Result, Timestamp};
use rusqlite::params;

use crate::{storage_error, Storage};

/// Длина ключа доступа sealed sender.
pub const ACCESS_KEY_LEN: usize = 32;

/// Длина публичного ключа сервера.
pub const SERVER_KEY_LEN: usize = 32;

/// Собственный ключ доступа.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnAccessKey {
    /// Сам ключ.
    pub key: [u8; ACCESS_KEY_LEN],
    /// Когда хеш ключа опубликован на сервере; `None` — ещё нет.
    pub published_at: Option<Timestamp>,
}

// Ключ доступа не шифрует переписку, но его утечка позволяет писать
// владельцу анонимно. Печатать его в лог незачем (Правило 4), поэтому
// `Debug` показывает только отметку публикации.
impl core::fmt::Debug for OwnAccessKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OwnAccessKey")
            .field("published_at", &self.published_at)
            .finish_non_exhaustive()
    }
}

/// Сертификат отправителя, сохранённый до истечения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCertificate {
    /// Сертификат целиком — в том виде, в каком его выдал сервер.
    pub certificate: Vec<u8>,
    /// Момент истечения.
    pub expires_at: Timestamp,
    /// Публичный ключ сервера, которым сертификат подписан.
    pub server_key: [u8; SERVER_KEY_LEN],
}

/// Длина seed ключа ML-KEM-1024 sealed sender.
pub const SEALED_KEM_SEED_LEN: usize = 64;

impl Storage {
    /// Читает собственный ключ доступа.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn own_access_key(&self) -> Result<Option<OwnAccessKey>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection.query_row(
            "SELECT access_key, published_at FROM own_access_key WHERE id = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?)),
        );

        // Отсутствие строки — нормальное состояние («ключ ещё не заведён»),
        // а сбой чтения — нет. Сводить второе к первому значило бы молча
        // завести новый ключ поверх недоступного старого.
        let (key, published_at) = match row {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(error) => return Err(storage_error(error)),
        };

        Ok(Some(OwnAccessKey {
            key: to_array(&key)?,
            published_at: published_at.map(Timestamp::from_millis),
        }))
    }

    /// Заводит собственный ключ доступа, если его ещё нет.
    ///
    /// Существующий ключ не перезаписывается: его хеш уже мог уйти
    /// на сервер, а сам ключ — собеседникам, и тихая замена сломала бы
    /// им анонимную отправку.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn init_own_access_key(&self, key: &[u8; ACCESS_KEY_LEN]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR IGNORE INTO own_access_key (id, access_key) VALUES (1, ?)",
                params![key.as_slice()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Отмечает, что хеш ключа доступа опубликован на сервере.
    ///
    /// # Errors
    ///
    /// [`AegisError::Uninitialized`] — ключ ещё не заведён;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn mark_own_access_key_published(&self, now: Timestamp) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let changed = connection
            .execute(
                "UPDATE own_access_key SET published_at = ? WHERE id = 1",
                params![now.as_millis()],
            )
            .map_err(storage_error)?;

        if changed == 0 {
            return Err(AegisError::Uninitialized);
        }

        Ok(())
    }

    /// Seed собственного ключа ML-KEM sealed sender и момент публикации.
    ///
    /// 🔐 Seed — закрытый ключ: им разворачивается пост-квантовая половина
    /// внешнего слоя каждого входящего сообщения. Живёт в зашифрованной
    /// базе, как и identity-ключ.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn own_sealed_kem(&self) -> Result<Option<([u8; SEALED_KEM_SEED_LEN], Option<Timestamp>)>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection.query_row(
            "SELECT seed, published_at FROM own_sealed_kem WHERE id = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?)),
        );

        let (seed, published_at) = match row {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(error) => return Err(storage_error(error)),
        };

        Ok(Some((
            to_array(&seed)?,
            published_at.map(Timestamp::from_millis),
        )))
    }

    /// Заводит seed ключа ML-KEM sealed sender, если его ещё нет.
    ///
    /// Существующий не перезаписывается: собеседники запечатывают
    /// на опубликованный ключ, и тихая замена сделала бы их конверты
    /// нечитаемыми.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn init_own_sealed_kem(&self, seed: &[u8; SEALED_KEM_SEED_LEN]) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR IGNORE INTO own_sealed_kem (id, seed) VALUES (1, ?)",
                params![seed.as_slice()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Сменяет ключ ML-KEM sealed sender: прежний уходит в выведенные.
    ///
    /// Новый ключ ещё не опубликован (`published_at` сбрасывается), и
    /// до публикации собеседники запечатывают на прежний — он остаётся
    /// среди выведенных и конверты открывает.
    ///
    /// Одна транзакция: прерванная смена не должна ни потерять прежний
    /// ключ, ни оставить два действующих.
    ///
    /// # Errors
    ///
    /// [`AegisError::Uninitialized`] — ключа ещё нет;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn rotate_own_sealed_kem(
        &self,
        seed: &[u8; SEALED_KEM_SEED_LEN],
        now: Timestamp,
    ) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        let retired = transaction
            .execute(
                "INSERT INTO retired_sealed_kem (seed, retired_at)
                 SELECT seed, ? FROM own_sealed_kem WHERE id = 1",
                params![now.as_millis()],
            )
            .map_err(storage_error)?;

        if retired == 0 {
            return Err(AegisError::Uninitialized);
        }

        transaction
            .execute(
                "UPDATE own_sealed_kem SET seed = ?, published_at = NULL WHERE id = 1",
                params![seed.as_slice()],
            )
            .map_err(storage_error)?;

        transaction.commit().map_err(storage_error)?;

        Ok(())
    }

    /// Выведенные ключи ML-KEM sealed sender, от новых к старым.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn retired_sealed_kems(&self) -> Result<Vec<[u8; SEALED_KEM_SEED_LEN]>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let mut statement = connection
            .prepare("SELECT seed FROM retired_sealed_kem ORDER BY retired_at DESC, id DESC")
            .map_err(storage_error)?;

        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage_error)?;

        let mut seeds = Vec::new();

        for row in rows {
            seeds.push(to_array(&row.map_err(storage_error)?)?);
        }

        Ok(seeds)
    }

    /// Стирает выведенные ключи ML-KEM, выведенные раньше `retired_before`,
    /// и все сверх `keep` самых новых.
    ///
    /// 🔐 Каждый лишний ключ — это прошлое: отняв устройство, им можно
    /// открыть внешний слой записанных конвертов и узнать отправителя.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn prune_retired_sealed_kems(&self, retired_before: Timestamp, keep: usize) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;
        let keep = i64::try_from(keep).unwrap_or(i64::MAX);

        connection
            .execute(
                "DELETE FROM retired_sealed_kem
                 WHERE retired_at < ?
                    OR id NOT IN (
                        SELECT id FROM retired_sealed_kem
                        ORDER BY retired_at DESC, id DESC
                        LIMIT ?
                    )",
                params![retired_before.as_millis(), keep],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Отмечает, что ключ ML-KEM sealed sender опубликован на сервере.
    ///
    /// # Errors
    ///
    /// [`AegisError::Uninitialized`] — ключ ещё не заведён;
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn mark_own_sealed_kem_published(&self, now: Timestamp) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let changed = connection
            .execute(
                "UPDATE own_sealed_kem SET published_at = ? WHERE id = 1",
                params![now.as_millis()],
            )
            .map_err(storage_error)?;

        if changed == 0 {
            return Err(AegisError::Uninitialized);
        }

        Ok(())
    }

    /// Читает сохранённый сертификат отправителя.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn sender_certificate(&self) -> Result<Option<StoredCertificate>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection.query_row(
            "SELECT certificate, expires_at, server_key FROM sender_certificate WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        );

        let (certificate, expires_at, server_key) = match row {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(error) => return Err(storage_error(error)),
        };

        Ok(Some(StoredCertificate {
            certificate,
            expires_at: Timestamp::from_millis(expires_at),
            server_key: to_array(&server_key)?,
        }))
    }

    /// Сохраняет сертификат отправителя, заменяя прежний.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_sender_certificate(&self, stored: &StoredCertificate) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT OR REPLACE INTO sender_certificate (id, certificate, expires_at, server_key)
            VALUES (1, ?, ?, ?)
            ",
                params![
                    stored.certificate,
                    stored.expires_at.as_millis(),
                    stored.server_key.as_slice(),
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Читает ключ доступа собеседника.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось либо запись повреждена.
    pub fn contact_access_key(&self, account: &AccountId) -> Result<Option<[u8; ACCESS_KEY_LEN]>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection.query_row(
            "SELECT access_key FROM contact_access_keys WHERE account_id = ?",
            params![account.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match row {
            Ok(key) => Ok(Some(to_array(&key)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Сохраняет ключ доступа собеседника, заменяя прежний.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn save_contact_access_key(
        &self,
        account: &AccountId,
        key: &[u8; ACCESS_KEY_LEN],
        now: Timestamp,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "
            INSERT OR REPLACE INTO contact_access_keys (account_id, access_key, updated_at)
            VALUES (?, ?, ?)
            ",
                params![account.as_bytes(), key.as_slice(), now.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Забывает ключ доступа собеседника.
    ///
    /// Вызывается, когда сервер отверг ключ: он устарел — собеседник
    /// переустановил приложение или сменил ключ. Держать заведомо
    /// негодный ключ значило бы проваливать каждую отправку.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn forget_contact_access_key(&self, account: &AccountId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "DELETE FROM contact_access_keys WHERE account_id = ?",
                params![account.as_bytes()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Передан ли собеседнику собственный ключ доступа.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn access_key_shared_with(&self, account: &AccountId) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection.query_row(
            "SELECT 1 FROM access_key_shares WHERE account_id = ?",
            params![account.as_bytes()],
            |row| row.get::<_, i64>(0),
        );

        match row {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Отмечает, что собственный ключ доступа передан собеседнику.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn mark_access_key_shared(&self, account: &AccountId, now: Timestamp) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO access_key_shares (account_id, shared_at) VALUES (?, ?)",
                params![account.as_bytes(), now.as_millis()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Снимает отметку о передаче ключа доступа собеседнику.
    ///
    /// Вызывается, когда собеседник начал новую сессию: у него, возможно,
    /// новое устройство или восстановленная копия, и нашего ключа там нет.
    /// Отметка, пережившая это, навсегда оставила бы его сообщения к нам
    /// незапечатанными.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — удаление не удалось.
    pub fn forget_access_key_share(&self, account: &AccountId) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "DELETE FROM access_key_shares WHERE account_id = ?",
                params![account.as_bytes()],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Читает текстовую настройку.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn setting_text(&self, key: &str) -> Result<Option<String>> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        let row = connection.query_row(
            "SELECT value FROM settings_text WHERE key = ?",
            params![key],
            |row| row.get::<_, String>(0),
        );

        match row {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }

    /// Записывает текстовую настройку.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn set_setting_text(&self, key: &str, value: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| AegisError::Storage)?;

        connection
            .execute(
                "INSERT OR REPLACE INTO settings_text (key, value) VALUES (?, ?)",
                params![key, value],
            )
            .map_err(storage_error)?;

        Ok(())
    }
}

/// Переводит байты из базы в массив нужной длины.
///
/// Неверная длина в собственной базе — признак повреждения, а не
/// сценарий работы: ошибка, а не обрезка или дополнение.
fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| AegisError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_760_000_000_000)
    }

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("временный каталог");
        let path = directory
            .path()
            .join("aegis.db")
            .to_string_lossy()
            .into_owned();
        let storage = Storage::new(&path, &[0x5Au8; 32]).expect("база открывается");

        (storage, directory)
    }

    /// Ключ доступа заводится один раз и не перезаписывается.
    ///
    /// Его хеш уже мог уйти на сервер, а сам ключ — собеседникам:
    /// тихая замена сломала бы им анонимную отправку.
    #[test]
    fn own_access_key_is_created_once() {
        let (storage, _dir) = open_temp();

        assert!(storage.own_access_key().expect("чтение").is_none());

        storage.init_own_access_key(&[1u8; 32]).expect("запись");
        storage
            .init_own_access_key(&[2u8; 32])
            .expect("повторная запись");

        let own = storage
            .own_access_key()
            .expect("чтение")
            .expect("ключ есть");

        assert_eq!(own.key, [1u8; 32], "ключ доступа перезаписан");
        assert!(own.published_at.is_none());
    }

    /// Отметка публикации сохраняется.
    #[test]
    fn publication_is_recorded() {
        let (storage, _dir) = open_temp();
        storage.init_own_access_key(&[1u8; 32]).expect("запись");

        storage
            .mark_own_access_key_published(now())
            .expect("отметка");

        assert_eq!(
            storage
                .own_access_key()
                .expect("чтение")
                .expect("ключ есть")
                .published_at,
            Some(now())
        );
    }

    /// Нельзя отметить опубликованным ключ, которого нет.
    #[test]
    fn publishing_without_a_key_is_an_error() {
        let (storage, _dir) = open_temp();

        assert!(matches!(
            storage.mark_own_access_key_published(now()),
            Err(AegisError::Uninitialized)
        ));
    }

    /// 🔐 Debug не раскрывает ключ доступа.
    #[test]
    fn debug_does_not_print_the_access_key() {
        let own = OwnAccessKey {
            key: [0xABu8; 32],
            published_at: None,
        };

        let text = format!("{own:?}");

        assert!(!text.contains("171"), "ключ попал в Debug: {text}");
        assert!(!text.contains("key:"), "ключ попал в Debug: {text}");
    }

    /// Сертификат сохраняется и заменяется целиком.
    #[test]
    fn certificate_round_trips_and_is_replaced() {
        let (storage, _dir) = open_temp();

        assert!(storage.sender_certificate().expect("чтение").is_none());

        let first = StoredCertificate {
            certificate: vec![1u8; 130],
            expires_at: now(),
            server_key: [3u8; 32],
        };
        let second = StoredCertificate {
            certificate: vec![2u8; 130],
            expires_at: Timestamp::from_millis(now().as_millis() + 1),
            server_key: [4u8; 32],
        };

        storage.save_sender_certificate(&first).expect("запись");
        assert_eq!(storage.sender_certificate().expect("чтение"), Some(first));

        storage.save_sender_certificate(&second).expect("замена");
        assert_eq!(storage.sender_certificate().expect("чтение"), Some(second));
    }

    /// Ключ доступа собеседника сохраняется, заменяется и забывается.
    #[test]
    fn contact_access_key_lifecycle() {
        let (storage, _dir) = open_temp();
        let contact = AccountId::generate();

        assert_eq!(storage.contact_access_key(&contact).expect("чтение"), None);

        storage
            .save_contact_access_key(&contact, &[5u8; 32], now())
            .expect("запись");
        storage
            .save_contact_access_key(&contact, &[6u8; 32], now())
            .expect("замена");

        assert_eq!(
            storage.contact_access_key(&contact).expect("чтение"),
            Some([6u8; 32])
        );

        storage
            .forget_contact_access_key(&contact)
            .expect("удаление");

        assert_eq!(storage.contact_access_key(&contact).expect("чтение"), None);
    }

    /// Ключи разных собеседников не смешиваются.
    #[test]
    fn contact_access_keys_are_per_contact() {
        let (storage, _dir) = open_temp();
        let first = AccountId::generate();
        let second = AccountId::generate();

        storage
            .save_contact_access_key(&first, &[1u8; 32], now())
            .expect("запись");

        assert_eq!(storage.contact_access_key(&second).expect("чтение"), None);
    }

    /// Отметка передачи ключа ставится и снимается.
    #[test]
    fn share_marks_are_set_and_cleared() {
        let (storage, _dir) = open_temp();
        let contact = AccountId::generate();

        assert!(!storage.access_key_shared_with(&contact).expect("чтение"));

        storage
            .mark_access_key_shared(&contact, now())
            .expect("отметка");
        assert!(storage.access_key_shared_with(&contact).expect("чтение"));

        storage.forget_access_key_share(&contact).expect("снятие");
        assert!(!storage.access_key_shared_with(&contact).expect("чтение"));
    }

    /// Текстовая настройка записывается и заменяется.
    #[test]
    fn text_setting_round_trips() {
        let (storage, _dir) = open_temp();

        assert_eq!(storage.setting_text("network_proxy").expect("чтение"), None);

        storage
            .set_setting_text("network_proxy", "orbot")
            .expect("запись");
        storage
            .set_setting_text("network_proxy", "socks5:proxy.example.org:1080")
            .expect("замена");

        assert_eq!(
            storage
                .setting_text("network_proxy")
                .expect("чтение")
                .as_deref(),
            Some("socks5:proxy.example.org:1080")
        );
    }

    /// 🔐 Смена ключа ML-KEM: прежний уходит в выведенные, новый
    /// не опубликован.
    #[test]
    fn rotating_the_sealed_kem_retires_the_previous_key() {
        let (storage, _dir) = open_temp();

        assert!(
            matches!(
                storage.rotate_own_sealed_kem(&[2u8; 64], now()),
                Err(AegisError::Uninitialized)
            ),
            "сменён ключ, которого не было"
        );

        storage.init_own_sealed_kem(&[1u8; 64]).expect("запись");
        storage
            .mark_own_sealed_kem_published(now())
            .expect("публикация");
        storage
            .rotate_own_sealed_kem(&[2u8; 64], now())
            .expect("смена");

        let (seed, published) = storage
            .own_sealed_kem()
            .expect("чтение")
            .expect("ключ есть");
        assert_eq!(seed, [2u8; 64]);
        assert!(published.is_none(), "новый ключ считается опубликованным");
        assert_eq!(
            storage.retired_sealed_kems().expect("чтение"),
            vec![[1u8; 64]],
            "прежний ключ потерян"
        );
    }

    /// 🔐 Выведенные ключи стираются по сроку и сверх предела, новые —
    /// первыми в списке.
    #[test]
    fn retired_sealed_kems_are_pruned_by_age_and_count() {
        let (storage, _dir) = open_temp();
        storage.init_own_sealed_kem(&[0u8; 64]).expect("запись");

        for day in 1..=4u8 {
            let at = Timestamp::from_millis(now().as_millis() + i64::from(day) * 86_400_000);
            storage
                .rotate_own_sealed_kem(&[day; 64], at)
                .expect("смена");
        }

        // Выведены ключи 0, 1, 2, 3 — в дни 1, 2, 3, 4.
        assert_eq!(
            storage.retired_sealed_kems().expect("чтение"),
            vec![[3u8; 64], [2u8; 64], [1u8; 64], [0u8; 64]]
        );

        // Старше третьего дня — прочь.
        let cutoff = Timestamp::from_millis(now().as_millis() + 3 * 86_400_000);
        storage
            .prune_retired_sealed_kems(cutoff, 8)
            .expect("чистка");
        assert_eq!(
            storage.retired_sealed_kems().expect("чтение"),
            vec![[3u8; 64], [2u8; 64]]
        );

        // Сверх предела — тоже.
        storage.prune_retired_sealed_kems(now(), 1).expect("чистка");
        assert_eq!(
            storage.retired_sealed_kems().expect("чтение"),
            vec![[3u8; 64]]
        );
    }
}
