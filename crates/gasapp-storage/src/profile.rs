// SPDX-License-Identifier: Apache-2.0

//! Картинки и доставка: расшифрованные аватары каналов, фото профиля
//! (своё и собеседников) и отметка «доставлено» у своих сообщений.
//!
//! 🔐 Всё — в зашифрованной базе (SQLCipher), а не в файлах кеша:
//! аватар закрытого канала и фото собеседника — не для чужих глаз.

use gasapp_types::{AccountId, ChatId, GasAppError, MessageId, Result, Timestamp};
use rusqlite::{params, OptionalExtension as _};

use crate::{storage_error, uuid_from_slice, MessageStatus, Storage};

/// Предел картинки, которую хранит база: фото профиля и аватар канала —
/// маленькие квадраты, а не исходные снимки.
pub const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;

impl Storage {
    /// Расшифрованный аватар канала — если он для этого описания файла.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn cached_channel_avatar(
        &self,
        channel_id: &[u8; 16],
        descriptor: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .query_row(
                "SELECT image FROM channel_avatars WHERE channel_id = ? AND descriptor = ?",
                params![channel_id.as_slice(), descriptor],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(storage_error)
    }

    /// Запоминает расшифрованный аватар канала (прежний заменяется).
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — картинка больше предела;
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn cache_channel_avatar(
        &self,
        channel_id: &[u8; 16],
        descriptor: &[u8],
        image: &[u8],
    ) -> Result<()> {
        if image.len() > MAX_IMAGE_BYTES {
            return Err(GasAppError::Malformed);
        }
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO channel_avatars (channel_id, descriptor, image) VALUES (?, ?, ?)",
                params![channel_id.as_slice(), descriptor, image],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    /// Фото профиля по чату (своё — под чатом с собой) и его версия.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn profile_photo(&self, chat_id: &ChatId) -> Result<Option<(Vec<u8>, i64)>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .query_row(
                "SELECT image, version FROM profile_photos WHERE chat_id = ?",
                params![chat_id.as_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(storage_error)
    }

    /// Ставит фото профиля; `None` — убирает. Версия — время смены: более
    /// старая версия не заменяет более новую (письма приходят не по порядку).
    /// Возвращает, изменилось ли что-то.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — картинка больше предела;
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn set_profile_photo(
        &self,
        chat_id: &ChatId,
        image: Option<&[u8]>,
        version: i64,
    ) -> Result<bool> {
        if image.is_some_and(|bytes| bytes.len() > MAX_IMAGE_BYTES) {
            return Err(GasAppError::Malformed);
        }
        let current = self.profile_photo(chat_id)?.map(|(_, version)| version);
        if current.is_some_and(|known| known >= version) {
            return Ok(false);
        }
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        // Снятое фото — пустая картинка с версией: иначе старое письмо с
        // фото вернуло бы его после снятия.
        connection
            .execute(
                "INSERT OR REPLACE INTO profile_photos (chat_id, image, version) VALUES (?, ?, ?)",
                params![chat_id.as_bytes(), image.unwrap_or_default(), version],
            )
            .map_err(storage_error)?;
        Ok(true)
    }

    /// Все непустые фото профиля — для списка чатов одним запросом.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn profile_photos(&self) -> Result<Vec<(ChatId, Vec<u8>)>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection
            .prepare_cached("SELECT chat_id, image FROM profile_photos WHERE length(image) > 0")
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(storage_error)?;
        let mut photos = Vec::new();
        for row in rows {
            let (chat, image) = row.map_err(storage_error)?;
            photos.push((ChatId::from_uuid(uuid_from_slice(&chat)?), image));
        }
        Ok(photos)
    }

    /// Свои сообщения чата до названного включительно — «доставлено»
    /// (квитанция доставки). Только «отправлено» → «доставлено»:
    /// прочитанное назад не откатывается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn mark_delivered_until(
        &self,
        chat_id: &ChatId,
        own: &AccountId,
        until: &MessageId,
        now: Timestamp,
    ) -> Result<usize> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        connection
            .execute(
                "UPDATE messages SET status = ?, updated_at = ?
                  WHERE chat_id = ? AND sender_id = ? AND status = ?
                    AND timestamp <= (
                        SELECT timestamp FROM messages
                         WHERE message_id = ? AND chat_id = ? AND sender_id = ?
                    )",
                params![
                    i64::from(MessageStatus::Delivered.as_u8()),
                    now.as_millis(),
                    chat_id.as_bytes(),
                    own.as_bytes(),
                    i64::from(MessageStatus::Sent.as_u8()),
                    until.as_bytes(),
                    chat_id.as_bytes(),
                    own.as_bytes(),
                ],
            )
            .map_err(storage_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("каталог");
        let path = dir.path().join("profile.db");
        let storage = Storage::new(path.to_str().expect("путь"), &[7u8; 32]).expect("база");
        (storage, dir)
    }

    #[test]
    fn an_older_photo_never_replaces_a_newer_one() {
        let (storage, _dir) = open_temp();
        let chat = ChatId::generate();
        assert!(storage.set_profile_photo(&chat, Some(&[1, 2]), 10).unwrap());
        assert!(!storage.set_profile_photo(&chat, Some(&[9]), 5).unwrap());
        assert_eq!(
            storage.profile_photo(&chat).unwrap(),
            Some((vec![1, 2], 10))
        );
        assert_eq!(storage.profile_photos().unwrap().len(), 1);

        // Снятое — пустое, в список не попадает и старым не возвращается.
        assert!(storage.set_profile_photo(&chat, None, 20).unwrap());
        assert!(storage.profile_photos().unwrap().is_empty());
        assert!(!storage.set_profile_photo(&chat, Some(&[1, 2]), 10).unwrap());
    }

    #[test]
    fn a_channel_avatar_is_cached_per_descriptor() {
        let (storage, _dir) = open_temp();
        let channel = [3u8; 16];
        storage.cache_channel_avatar(&channel, &[1], &[42]).unwrap();
        assert_eq!(
            storage.cached_channel_avatar(&channel, &[1]).unwrap(),
            Some(vec![42])
        );
        // Новый аватар — новое описание: старая картинка не подходит.
        assert_eq!(storage.cached_channel_avatar(&channel, &[2]).unwrap(), None);
        assert!(storage
            .cache_channel_avatar(&channel, &[2], &vec![0; MAX_IMAGE_BYTES + 1])
            .is_err());
    }
}
