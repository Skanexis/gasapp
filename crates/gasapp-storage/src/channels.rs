// SPDX-License-Identifier: Apache-2.0

//! Каналы: подписки и прочитанные записи.
//!
//! # Что здесь лежит
//!
//! * `channels` — каналы, которые человек читает или ведёт: секрет
//!   чтения и публичный ключ подписи из ссылки-приглашения, название
//!   и описание, а у своих каналов — ещё и приватный ключ подписи.
//! * `channel_posts` — расшифрованные записи.
//!
//! 🔐 Список каналов существует только здесь. Сервер подписчиков не
//! знает: подписка — это строка в этой таблице, и ничего больше.
//! База зашифрована (`SQLCipher`), ключ подписи лежит под тем же
//! ключом, что и остальные секреты.

use gasapp_types::{GasAppError, Result, Timestamp};
use rusqlite::{params, OptionalExtension as _};

use crate::{storage_error, Storage};

/// Канал в локальной базе.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredChannel {
    /// Идентификатор канала.
    pub channel_id: [u8; 16],
    /// Секрет чтения из ссылки.
    pub secret: [u8; 32],
    /// Публичный ключ подписи автора.
    pub verify_key: [u8; 32],
    /// Приватный ключ подписи — только у своего канала.
    pub signing_key: Option<[u8; 32]>,
    /// Название.
    pub title: String,
    /// Описание.
    pub description: String,
    /// Время описания по часам автора: более старое не принимается.
    pub meta_updated_at: i64,
    /// Номер последней записи, сохранённой локально.
    pub last_seq: u64,
    /// Номер последней записи, которую человек видел.
    pub last_read_seq: u64,
    /// Когда канал добавлен на это устройство.
    pub joined_at: Timestamp,
}

impl core::fmt::Debug for StoredChannel {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Секрет и ключ подписи в отладочный вывод не попадают.
        formatter
            .debug_struct("StoredChannel")
            .field("channel_id", &self.channel_id)
            .field("owned", &self.signing_key.is_some())
            .field("last_seq", &self.last_seq)
            .finish_non_exhaustive()
    }
}

/// Запись канала в локальной базе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPost {
    /// Номер записи в канале.
    pub seq: u64,
    /// Текст.
    pub text: String,
    /// Время публикации по часам автора.
    pub created_at: Timestamp,
}

const CHANNEL_COLUMNS: &str = "channel_id, secret, verify_key, signing_key, title, description,
     meta_updated_at, last_seq, last_read_seq, joined_at";

type ChannelRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
);

fn read_channel_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChannelRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn channel_from_row(row: ChannelRow) -> Result<StoredChannel> {
    let (id, secret, verify, signing, title, description, meta_at, last, read, joined) = row;

    Ok(StoredChannel {
        channel_id: id.try_into().map_err(|_| GasAppError::Storage)?,
        secret: secret.try_into().map_err(|_| GasAppError::Storage)?,
        verify_key: verify.try_into().map_err(|_| GasAppError::Storage)?,
        signing_key: signing
            .map(|key| <[u8; 32]>::try_from(key).map_err(|_| GasAppError::Storage))
            .transpose()?,
        title,
        description,
        meta_updated_at: meta_at,
        last_seq: u64::try_from(last).map_err(|_| GasAppError::Storage)?,
        last_read_seq: u64::try_from(read).map_err(|_| GasAppError::Storage)?,
        joined_at: Timestamp::from_millis(joined),
    })
}

fn seq_to_sql(seq: u64) -> Result<i64> {
    i64::try_from(seq).map_err(|_| GasAppError::Storage)
}

impl Storage {
    /// Сохраняет канал: новый — добавляет, известный — не трогает.
    ///
    /// Повторный переход по той же ссылке не сбрасывает прочитанное
    /// и не затирает ключ подписи своего канала.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn insert_channel(&self, channel: &StoredChannel) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO channels
                     (channel_id, secret, verify_key, signing_key, title, description,
                      meta_updated_at, last_seq, last_read_seq, joined_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    channel.channel_id.as_slice(),
                    channel.secret.as_slice(),
                    channel.verify_key.as_slice(),
                    channel.signing_key.as_ref().map(<[u8; 32]>::as_slice),
                    channel.title,
                    channel.description,
                    channel.meta_updated_at,
                    seq_to_sql(channel.last_seq)?,
                    seq_to_sql(channel.last_read_seq)?,
                    channel.joined_at.as_millis(),
                ],
            )
            .map_err(storage_error)?;

        Ok(inserted > 0)
    }

    /// Канал по идентификатору.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы либо испорченная строка.
    pub fn channel(&self, channel_id: &[u8; 16]) -> Result<Option<StoredChannel>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .query_row(
                &format!("SELECT {CHANNEL_COLUMNS} FROM channels WHERE channel_id = ?"),
                params![channel_id.as_slice()],
                read_channel_row,
            )
            .optional()
            .map_err(storage_error)?
            .map(channel_from_row)
            .transpose()
    }

    /// Все каналы: сначала те, где самая свежая запись.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы либо испорченная строка.
    pub fn channels(&self) -> Result<Vec<StoredChannel>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {CHANNEL_COLUMNS} FROM channels
                  ORDER BY COALESCE(
                      (SELECT max(created_at) FROM channel_posts p
                        WHERE p.channel_id = channels.channel_id),
                      joined_at) DESC"
            ))
            .map_err(storage_error)?;

        let rows = statement
            .query_map([], read_channel_row)
            .map_err(storage_error)?;

        rows.map(|row| channel_from_row(row.map_err(storage_error)?))
            .collect()
    }

    /// Обновляет название и описание — только если они новее известных.
    ///
    /// 🔐 Сервер не подсунет прежнее название: описание старше уже
    /// принятого молча отбрасывается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn update_channel_meta(
        &self,
        channel_id: &[u8; 16],
        title: &str,
        description: &str,
        updated_at: i64,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "UPDATE channels SET title = ?, description = ?, meta_updated_at = ?
                  WHERE channel_id = ? AND meta_updated_at < ?",
                params![
                    title,
                    description,
                    updated_at,
                    channel_id.as_slice(),
                    updated_at
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Сохраняет запись и сдвигает `last_seq` канала.
    ///
    /// Повтор той же записи ничего не меняет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn insert_channel_post(&self, channel_id: &[u8; 16], post: &StoredPost) -> Result<()> {
        let seq = seq_to_sql(post.seq)?;
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        transaction
            .execute(
                "INSERT OR IGNORE INTO channel_posts (channel_id, seq, text, created_at)
                 VALUES (?, ?, ?, ?)",
                params![
                    channel_id.as_slice(),
                    seq,
                    post.text,
                    post.created_at.as_millis()
                ],
            )
            .map_err(storage_error)?;

        transaction
            .execute(
                "UPDATE channels SET last_seq = ? WHERE channel_id = ? AND last_seq < ?",
                params![seq, channel_id.as_slice(), seq],
            )
            .map_err(storage_error)?;

        transaction.commit().map_err(storage_error)
    }

    /// Сдвигает `last_seq` без сохранения записи — когда запись не
    /// прошла проверку и её нужно пропустить, а не запрашивать вечно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn skip_channel_seq(&self, channel_id: &[u8; 16], seq: u64) -> Result<()> {
        let seq = seq_to_sql(seq)?;
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "UPDATE channels SET last_seq = ? WHERE channel_id = ? AND last_seq < ?",
                params![seq, channel_id.as_slice(), seq],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Последние записи канала — не больше `limit`, от старых к новым.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_posts(&self, channel_id: &[u8; 16], limit: u32) -> Result<Vec<StoredPost>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare(
                "SELECT seq, text, created_at FROM channel_posts
                  WHERE channel_id = ?
                  ORDER BY seq DESC
                  LIMIT ?",
            )
            .map_err(storage_error)?;

        let rows = statement
            .query_map(params![channel_id.as_slice(), limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(storage_error)?;

        let mut posts = rows
            .map(|row| {
                let (seq, text, created_at) = row.map_err(storage_error)?;

                Ok(StoredPost {
                    seq: u64::try_from(seq).map_err(|_| GasAppError::Storage)?,
                    text,
                    created_at: Timestamp::from_millis(created_at),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        posts.reverse();

        Ok(posts)
    }

    /// Сколько сохранённых записей канала идёт после номера `seq`.
    ///
    /// Счёт по записям, а не по разности номеров: запись, не прошедшая
    /// проверку, номер занимает, но человеку не показывается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn count_channel_posts_after(&self, channel_id: &[u8; 16], seq: u64) -> Result<u64> {
        let seq = seq_to_sql(seq)?;
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM channel_posts WHERE channel_id = ? AND seq > ?",
                params![channel_id.as_slice(), seq],
                |row| row.get(0),
            )
            .map_err(storage_error)?;

        u64::try_from(count).map_err(|_| GasAppError::Storage)
    }

    /// Отмечает записи канала прочитанными до `seq` включительно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn mark_channel_read(&self, channel_id: &[u8; 16], seq: u64) -> Result<()> {
        let seq = seq_to_sql(seq)?;
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "UPDATE channels SET last_read_seq = ? WHERE channel_id = ? AND last_read_seq < ?",
                params![seq, channel_id.as_slice(), seq],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Удаляет канал с устройства вместе с записями.
    ///
    /// ⚠️ У своего канала вместе с ним исчезает ключ подписи: писать
    /// в канал после этого нельзя ни с какого устройства.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn delete_channel(&self, channel_id: &[u8; 16]) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        transaction
            .execute(
                "DELETE FROM channel_posts WHERE channel_id = ?",
                params![channel_id.as_slice()],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM channels WHERE channel_id = ?",
                params![channel_id.as_slice()],
            )
            .map_err(storage_error)?;

        transaction.commit().map_err(storage_error)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Хранилище во временном каталоге; каталог живёт, пока жив тест.
    fn open_temp() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("channels.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");

        (storage, dir)
    }

    fn channel(id: u8, owned: bool) -> StoredChannel {
        StoredChannel {
            channel_id: [id; 16],
            secret: [0x11; 32],
            verify_key: [0x22; 32],
            signing_key: owned.then_some([0x33; 32]),
            title: format!("Канал {id}"),
            description: String::new(),
            meta_updated_at: 100,
            last_seq: 0,
            last_read_seq: 0,
            joined_at: Timestamp::from_millis(1_000),
        }
    }

    fn post(seq: u64, text: &str) -> StoredPost {
        StoredPost {
            seq,
            text: text.to_owned(),
            created_at: Timestamp::from_millis(i64::try_from(seq).unwrap().saturating_add(2_000)),
        }
    }

    #[test]
    fn a_channel_round_trips() {
        let (storage, _dir) = open_temp();

        assert!(storage.insert_channel(&channel(1, true)).unwrap());
        assert_eq!(storage.channel(&[1; 16]).unwrap(), Some(channel(1, true)));
        assert_eq!(storage.channel(&[9; 16]).unwrap(), None);
    }

    /// Повторный переход по ссылке не затирает ключ подписи своего канала.
    #[test]
    fn joining_again_keeps_the_signing_key() {
        let (storage, _dir) = open_temp();

        storage.insert_channel(&channel(1, true)).unwrap();
        assert!(!storage.insert_channel(&channel(1, false)).unwrap());

        assert!(storage
            .channel(&[1; 16])
            .unwrap()
            .unwrap()
            .signing_key
            .is_some());
    }

    #[test]
    fn posts_are_kept_in_order_and_move_last_seq() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();

        for seq in [2, 1, 3] {
            storage
                .insert_channel_post(&[1; 16], &post(seq, &format!("запись {seq}")))
                .unwrap();
        }
        // Повтор ничего не меняет.
        storage
            .insert_channel_post(&[1; 16], &post(2, "другая"))
            .unwrap();

        let posts = storage.channel_posts(&[1; 16], 10).unwrap();
        assert_eq!(
            posts.iter().map(|post| post.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(posts.get(1).unwrap().text, "запись 2");
        assert_eq!(storage.channel(&[1; 16]).unwrap().unwrap().last_seq, 3);

        let tail = storage.channel_posts(&[1; 16], 2).unwrap();
        assert_eq!(
            tail.iter().map(|post| post.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    /// 🔐 Описание старше известного не принимается.
    #[test]
    fn stale_meta_is_ignored() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();

        storage
            .update_channel_meta(&[1; 16], "Новое", "описание", 200)
            .unwrap();
        storage
            .update_channel_meta(&[1; 16], "Прежнее", "", 150)
            .unwrap();

        let stored = storage.channel(&[1; 16]).unwrap().unwrap();
        assert_eq!(stored.title, "Новое");
        assert_eq!(stored.meta_updated_at, 200);
    }

    #[test]
    fn read_marks_only_move_forward() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();

        storage.mark_channel_read(&[1; 16], 5).unwrap();
        storage.mark_channel_read(&[1; 16], 3).unwrap();

        assert_eq!(storage.channel(&[1; 16]).unwrap().unwrap().last_read_seq, 5);
    }

    #[test]
    fn deleting_a_channel_removes_its_posts() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();
        storage.insert_channel(&channel(2, false)).unwrap();
        storage
            .insert_channel_post(&[1; 16], &post(1, "a"))
            .unwrap();
        storage
            .insert_channel_post(&[2; 16], &post(1, "b"))
            .unwrap();

        storage.delete_channel(&[1; 16]).unwrap();

        assert_eq!(storage.channel(&[1; 16]).unwrap(), None);
        assert!(storage.channel_posts(&[1; 16], 10).unwrap().is_empty());
        assert_eq!(storage.channel_posts(&[2; 16], 10).unwrap().len(), 1);
        assert_eq!(storage.channels().unwrap().len(), 1);
    }
}
