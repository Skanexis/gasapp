// SPDX-License-Identifier: Apache-2.0

//! Каналы: подписки и прочитанные записи.
//!
//! # Что здесь лежит
//!
//! * `channels` — каналы, которые человек читает или ведёт: секрет
//!   чтения и публичный ключ подписи из ссылки-приглашения, название,
//!   описание, закреп и аватар, а у своих каналов — ещё и приватный
//!   ключ подписи.
//! * `channel_posts` — расшифрованные записи: текст, описания
//!   вложений, номер редакции, счётчики сервера и своя реакция.
//!
//! 🔐 Список каналов существует только здесь. Сервер знает подписчика
//! как случайный жетон (`sub_token`), отдельный для каждого канала:
//! по нему считаются подписчики, просмотры и реакции, а чей он —
//! в базе сервера не записано. База зашифрована (`SQLCipher`), ключ
//! подписи и жетоны лежат под тем же ключом, что и остальные секреты.
//!
//! # Удалённые записи
//!
//! Удалённая запись не стирается, а остаётся пустой строкой с пометкой
//! и номером редакции. Иначе сервер вернул бы её прежний шифротекст —
//! и запись, удалённая автором, появилась бы снова.

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
    /// Номер закреплённой записи; `0` — закрепа нет.
    pub pinned_seq: u64,
    /// Описание вложения с аватаром канала.
    pub avatar: Option<Vec<u8>>,
    /// Публичное имя — со слов сервера.
    pub handle: Option<String>,
    /// Число подписчиков — со слов сервера.
    pub subscribers: u64,
    /// Не считать непрочитанное этого канала в общем счётчике.
    pub muted: bool,
    /// Номер последней записи, сохранённой локально.
    pub last_seq: u64,
    /// Номер последнего изменения канала, известного локально.
    pub last_rev: u64,
    /// Номер последней записи, которую человек видел.
    pub last_read_seq: u64,
    /// До какой записи серверу отправлена отметка о прочтении.
    pub seen_sent_seq: u64,
    /// Жетон подписчика; `None` — подписка на сервере не оформлена.
    pub sub_token: Option<[u8; 32]>,
    /// Когда канал добавлен на это устройство.
    pub joined_at: Timestamp,
}

impl core::fmt::Debug for StoredChannel {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Секрет, ключ подписи и жетон в отладочный вывод не попадают.
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
    /// Номер редакции: растёт с каждой правкой.
    pub revision: u32,
    /// Текст.
    pub text: String,
    /// Время публикации по часам автора.
    pub created_at: Timestamp,
    /// Время последней правки, миллисекунды; `0` — не правили.
    pub edited_at: i64,
    /// Удалена ли запись автором.
    pub deleted: bool,
    /// Просмотры — со слов сервера.
    pub views: u64,
    /// Реакции `эмодзи:число,…` — со слов сервера.
    pub reactions: String,
    /// Своя реакция; пусто — нет.
    pub my_reaction: String,
    /// Описания вложений, как они пришли в записи.
    pub attachments: Vec<Vec<u8>>,
}

/// Что изменила попытка сохранить запись.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostChange {
    /// Записи не было — добавлена.
    Inserted,
    /// Запись была — заменена более новой редакцией.
    Updated,
    /// Ничего: редакция не новее известной либо запись удалена.
    Unchanged,
}

const CHANNEL_COLUMNS: &str = "channel_id, secret, verify_key, signing_key, title, description,
     meta_updated_at, pinned_seq, avatar, handle, subscribers, muted, last_seq, last_rev,
     last_read_seq, seen_sent_seq, sub_token, joined_at";

const POST_COLUMNS: &str = "seq, revision, text, created_at, edited_at, deleted, views,
     reactions, my_reaction, attachments";

fn channel_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<StoredChannel>> {
    let id: Vec<u8> = row.get(0)?;
    let secret: Vec<u8> = row.get(1)?;
    let verify: Vec<u8> = row.get(2)?;
    let signing: Option<Vec<u8>> = row.get(3)?;
    let title: String = row.get(4)?;
    let description: String = row.get(5)?;
    let meta_updated_at: i64 = row.get(6)?;
    let pinned: i64 = row.get(7)?;
    let avatar: Option<Vec<u8>> = row.get(8)?;
    let handle: Option<String> = row.get(9)?;
    let subscribers: i64 = row.get(10)?;
    let muted: bool = row.get(11)?;
    let last_seq: i64 = row.get(12)?;
    let last_rev: i64 = row.get(13)?;
    let last_read: i64 = row.get(14)?;
    let seen_sent: i64 = row.get(15)?;
    let token: Option<Vec<u8>> = row.get(16)?;
    let joined: i64 = row.get(17)?;

    Ok((|| {
        Ok(StoredChannel {
            channel_id: id.try_into().map_err(|_| GasAppError::Storage)?,
            secret: secret.try_into().map_err(|_| GasAppError::Storage)?,
            verify_key: verify.try_into().map_err(|_| GasAppError::Storage)?,
            signing_key: signing.map(key_from_blob).transpose()?,
            title,
            description,
            meta_updated_at,
            pinned_seq: from_sql(pinned)?,
            avatar,
            handle,
            subscribers: from_sql(subscribers)?,
            muted,
            last_seq: from_sql(last_seq)?,
            last_rev: from_sql(last_rev)?,
            last_read_seq: from_sql(last_read)?,
            seen_sent_seq: from_sql(seen_sent)?,
            sub_token: token.map(key_from_blob).transpose()?,
            joined_at: Timestamp::from_millis(joined),
        })
    })())
}

fn post_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<StoredPost>> {
    let seq: i64 = row.get(0)?;
    let revision: i64 = row.get(1)?;
    let text: String = row.get(2)?;
    let created_at: i64 = row.get(3)?;
    let edited_at: i64 = row.get(4)?;
    let deleted: bool = row.get(5)?;
    let views: i64 = row.get(6)?;
    let reactions: String = row.get(7)?;
    let my_reaction: String = row.get(8)?;
    let attachments: Option<Vec<u8>> = row.get(9)?;

    Ok((|| {
        Ok(StoredPost {
            seq: from_sql(seq)?,
            revision: u32::try_from(revision).map_err(|_| GasAppError::Storage)?,
            text,
            created_at: Timestamp::from_millis(created_at),
            edited_at,
            deleted,
            views: from_sql(views)?,
            reactions,
            my_reaction,
            attachments: attachments
                .as_deref()
                .map(decode_attachments)
                .transpose()?
                .unwrap_or_default(),
        })
    })())
}

fn key_from_blob(blob: Vec<u8>) -> Result<[u8; 32]> {
    blob.try_into().map_err(|_| GasAppError::Storage)
}

fn to_sql(number: u64) -> Result<i64> {
    i64::try_from(number).map_err(|_| GasAppError::Storage)
}

fn from_sql(number: i64) -> Result<u64> {
    u64::try_from(number).map_err(|_| GasAppError::Storage)
}

/// Список описаний вложений одним блобом: число, затем длина и байты
/// каждого.
fn encode_attachments(attachments: &[Vec<u8>]) -> Result<Option<Vec<u8>>> {
    if attachments.is_empty() {
        return Ok(None);
    }

    let mut out = vec![u8::try_from(attachments.len()).map_err(|_| GasAppError::Storage)?];

    for descriptor in attachments {
        out.extend_from_slice(
            &u16::try_from(descriptor.len())
                .map_err(|_| GasAppError::Storage)?
                .to_be_bytes(),
        );
        out.extend_from_slice(descriptor);
    }

    Ok(Some(out))
}

fn decode_attachments(blob: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (count, mut rest) = blob.split_first().ok_or(GasAppError::Storage)?;
    let mut attachments = Vec::with_capacity(usize::from(*count));

    for _ in 0..*count {
        if rest.len() < 2 {
            return Err(GasAppError::Storage);
        }
        let (len, tail) = rest.split_at(2);
        let len = usize::from(u16::from_be_bytes(
            len.try_into().map_err(|_| GasAppError::Storage)?,
        ));

        if tail.len() < len {
            return Err(GasAppError::Storage);
        }
        let (descriptor, tail) = tail.split_at(len);

        attachments.push(descriptor.to_vec());
        rest = tail;
    }

    Ok(attachments)
}

/// Шаблон `LIKE` для поиска подстроки: знаки шаблона экранируются `@`
/// (см. `Storage::search_messages`).
fn like_pattern(query: &str) -> String {
    let escaped = query
        .replace('@', "@@")
        .replace('%', "@%")
        .replace('_', "@_");

    format!("%{escaped}%")
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
                &format!(
                    "INSERT OR IGNORE INTO channels ({CHANNEL_COLUMNS})
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                ),
                params![
                    channel.channel_id.as_slice(),
                    channel.secret.as_slice(),
                    channel.verify_key.as_slice(),
                    channel.signing_key.as_ref().map(<[u8; 32]>::as_slice),
                    channel.title,
                    channel.description,
                    channel.meta_updated_at,
                    to_sql(channel.pinned_seq)?,
                    channel.avatar,
                    channel.handle,
                    to_sql(channel.subscribers)?,
                    channel.muted,
                    to_sql(channel.last_seq)?,
                    to_sql(channel.last_rev)?,
                    to_sql(channel.last_read_seq)?,
                    to_sql(channel.seen_sent_seq)?,
                    channel.sub_token.as_ref().map(<[u8; 32]>::as_slice),
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
                channel_from_row,
            )
            .optional()
            .map_err(storage_error)?
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
                        WHERE p.channel_id = channels.channel_id AND p.deleted = 0),
                      joined_at) DESC"
            ))
            .map_err(storage_error)?;

        let rows = statement
            .query_map([], channel_from_row)
            .map_err(storage_error)?;

        rows.map(|row| row.map_err(storage_error)?).collect()
    }

    /// Обновляет описание канала — только если оно новее известного.
    ///
    /// 🔐 Сервер не подсунет прежнее название, закреп или аватар:
    /// описание старше уже принятого молча отбрасывается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn update_channel_meta(
        &self,
        channel_id: &[u8; 16],
        title: &str,
        description: &str,
        pinned_seq: u64,
        avatar: Option<&[u8]>,
        updated_at: i64,
    ) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection
            .execute(
                "UPDATE channels
                    SET title = ?, description = ?, pinned_seq = ?, avatar = ?,
                        meta_updated_at = ?
                  WHERE channel_id = ? AND meta_updated_at < ?",
                params![
                    title,
                    description,
                    to_sql(pinned_seq)?,
                    avatar,
                    updated_at,
                    channel_id.as_slice(),
                    updated_at
                ],
            )
            .map_err(storage_error)?;

        Ok(())
    }

    /// Запоминает то, что о канале говорит сервер: публичное имя
    /// и число подписчиков.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_server_info(
        &self,
        channel_id: &[u8; 16],
        handle: Option<&str>,
        subscribers: u64,
    ) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET handle = ?2, subscribers = ?3 WHERE channel_id = ?1",
            params![channel_id.as_slice(), handle, to_sql(subscribers)?],
        )
    }

    /// Сдвигает номер последнего известного изменения — только вперёд.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_last_rev(&self, channel_id: &[u8; 16], rev: u64) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET last_rev = ?2 WHERE channel_id = ?1 AND last_rev < ?2",
            params![channel_id.as_slice(), to_sql(rev)?],
        )
    }

    /// Запоминает либо стирает жетон подписчика.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_sub_token(
        &self,
        channel_id: &[u8; 16],
        token: Option<&[u8; 32]>,
    ) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET sub_token = ?2 WHERE channel_id = ?1",
            params![channel_id.as_slice(), token.map(<[u8; 32]>::as_slice)],
        )
    }

    /// Включает либо выключает «без звука».
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_muted(&self, channel_id: &[u8; 16], muted: bool) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET muted = ?2 WHERE channel_id = ?1",
            params![channel_id.as_slice(), muted],
        )
    }

    /// Запоминает, до какой записи серверу отправлена отметка о
    /// прочтении.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_seen_sent(&self, channel_id: &[u8; 16], seq: u64) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET seen_sent_seq = ?2 WHERE channel_id = ?1 AND seen_sent_seq < ?2",
            params![channel_id.as_slice(), to_sql(seq)?],
        )
    }

    fn channel_update(&self, sql: &str, params: impl rusqlite::Params) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        connection.execute(sql, params).map_err(storage_error)?;

        Ok(())
    }

    /// Сохраняет запись либо её более новую редакцию и сдвигает
    /// `last_seq` канала.
    ///
    /// 🔐 Редакция не новее известной не принимается, удалённая запись
    /// не возвращается: сервер не откатит правку и не отменит удаление.
    /// Счётчики и своя реакция при правке сохраняются.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn upsert_channel_post(
        &self,
        channel_id: &[u8; 16],
        post: &StoredPost,
    ) -> Result<PostChange> {
        let seq = to_sql(post.seq)?;
        let attachments = encode_attachments(&post.attachments)?;
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        let known: Option<(i64, bool)> = transaction
            .query_row(
                "SELECT revision, deleted FROM channel_posts WHERE channel_id = ? AND seq = ?",
                params![channel_id.as_slice(), seq],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?;

        let change = match known {
            None => {
                transaction
                    .execute(
                        "INSERT INTO channel_posts
                             (channel_id, seq, revision, text, created_at, edited_at, deleted,
                              views, reactions, my_reaction, attachments)
                         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
                        params![
                            channel_id.as_slice(),
                            seq,
                            post.revision,
                            post.text,
                            post.created_at.as_millis(),
                            post.edited_at,
                            to_sql(post.views)?,
                            post.reactions,
                            post.my_reaction,
                            attachments,
                        ],
                    )
                    .map_err(storage_error)?;

                PostChange::Inserted
            }
            Some((revision, deleted)) if !deleted && i64::from(post.revision) > revision => {
                transaction
                    .execute(
                        "UPDATE channel_posts
                            SET revision = ?, text = ?, created_at = ?, edited_at = ?,
                                attachments = ?
                          WHERE channel_id = ? AND seq = ?",
                        params![
                            post.revision,
                            post.text,
                            post.created_at.as_millis(),
                            post.edited_at,
                            attachments,
                            channel_id.as_slice(),
                            seq,
                        ],
                    )
                    .map_err(storage_error)?;

                PostChange::Updated
            }
            Some(_) => PostChange::Unchanged,
        };

        transaction
            .execute(
                "UPDATE channels SET last_seq = ? WHERE channel_id = ? AND last_seq < ?",
                params![seq, channel_id.as_slice(), seq],
            )
            .map_err(storage_error)?;

        transaction.commit().map_err(storage_error)?;

        Ok(change)
    }

    /// Помечает запись удалённой: текст и вложения стираются, строка
    /// остаётся. Возвращает, изменилось ли что-то.
    ///
    /// Отметка для записи, которой здесь не было, тоже сохраняется —
    /// чтобы запись не появилась позже из прежнего шифротекста.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn tombstone_channel_post(
        &self,
        channel_id: &[u8; 16],
        seq: u64,
        revision: u32,
    ) -> Result<bool> {
        let seq = to_sql(seq)?;
        let mut connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let transaction = connection.transaction().map_err(storage_error)?;

        let changed = transaction
            .execute(
                "INSERT INTO channel_posts
                     (channel_id, seq, revision, text, created_at, edited_at, deleted,
                      views, reactions, my_reaction, attachments)
                 VALUES (?1, ?2, ?3, '', 0, 0, 1, 0, '', '', NULL)
                 ON CONFLICT (channel_id, seq) DO UPDATE
                    SET deleted = 1, text = '', attachments = NULL, reactions = '',
                        my_reaction = '', revision = max(revision, excluded.revision)
                  WHERE deleted = 0",
                params![channel_id.as_slice(), seq, revision],
            )
            .map_err(storage_error)?;

        transaction
            .execute(
                "UPDATE channels SET last_seq = ? WHERE channel_id = ? AND last_seq < ?",
                params![seq, channel_id.as_slice(), seq],
            )
            .map_err(storage_error)?;

        transaction.commit().map_err(storage_error)?;

        Ok(changed > 0)
    }

    /// Обновляет счётчики записи — просмотры и реакции со слов сервера.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_post_counters(
        &self,
        channel_id: &[u8; 16],
        seq: u64,
        views: u64,
        reactions: &str,
    ) -> Result<()> {
        self.channel_update(
            "UPDATE channel_posts SET views = ?3, reactions = ?4
              WHERE channel_id = ?1 AND seq = ?2 AND deleted = 0",
            params![
                channel_id.as_slice(),
                to_sql(seq)?,
                to_sql(views)?,
                reactions
            ],
        )
    }

    /// Запоминает свою реакцию на запись; пустая строка — реакции нет.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn set_channel_post_reaction(
        &self,
        channel_id: &[u8; 16],
        seq: u64,
        emoji: &str,
    ) -> Result<()> {
        self.channel_update(
            "UPDATE channel_posts SET my_reaction = ?3
              WHERE channel_id = ?1 AND seq = ?2 AND deleted = 0",
            params![channel_id.as_slice(), to_sql(seq)?, emoji],
        )
    }

    /// Сдвигает `last_seq` без сохранения записи — когда запись не
    /// прошла проверку и её нужно пропустить, а не запрашивать вечно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn skip_channel_seq(&self, channel_id: &[u8; 16], seq: u64) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET last_seq = ?2 WHERE channel_id = ?1 AND last_seq < ?2",
            params![channel_id.as_slice(), to_sql(seq)?],
        )
    }

    /// Последние записи канала — не больше `limit`, от старых к новым.
    /// Удалённые не отдаются.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_posts(&self, channel_id: &[u8; 16], limit: u32) -> Result<Vec<StoredPost>> {
        self.channel_posts_before(channel_id, u64::MAX, limit)
    }

    /// Записи канала с номером меньше `before_seq` — не больше `limit`,
    /// от старых к новым. Удалённые не отдаются.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_posts_before(
        &self,
        channel_id: &[u8; 16],
        before_seq: u64,
        limit: u32,
    ) -> Result<Vec<StoredPost>> {
        // Номера в базе — `i64`: всё, что больше, значит «без границы».
        let before = i64::try_from(before_seq).unwrap_or(i64::MAX);

        let mut posts = self.query_posts(
            &format!(
                "SELECT {POST_COLUMNS} FROM channel_posts
                  WHERE channel_id = ?1 AND deleted = 0 AND seq < ?2
                  ORDER BY seq DESC
                  LIMIT ?3"
            ),
            params![channel_id.as_slice(), before, limit],
        )?;

        posts.reverse();

        Ok(posts)
    }

    /// Запись по номеру — в том числе удалённая.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn channel_post(&self, channel_id: &[u8; 16], seq: u64) -> Result<Option<StoredPost>> {
        Ok(self
            .query_posts(
                &format!(
                    "SELECT {POST_COLUMNS} FROM channel_posts WHERE channel_id = ?1 AND seq = ?2"
                ),
                params![channel_id.as_slice(), to_sql(seq)?],
            )?
            .pop())
    }

    /// Наименьший номер записи канала, известный локально, — от него
    /// догружается история.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn min_channel_seq(&self, channel_id: &[u8; 16]) -> Result<Option<u64>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let min: Option<i64> = connection
            .query_row(
                "SELECT min(seq) FROM channel_posts WHERE channel_id = ?",
                params![channel_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage_error)?;

        min.map(from_sql).transpose()
    }

    /// Ищет подстроку в записях канала: свежие — первыми.
    ///
    /// Сравнение регистронезависимое только для латиницы — как и
    /// в поиске по переписке.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn search_channel_posts(
        &self,
        channel_id: &[u8; 16],
        query: &str,
        limit: u32,
    ) -> Result<Vec<StoredPost>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }

        self.query_posts(
            &format!(
                "SELECT {POST_COLUMNS} FROM channel_posts
                  WHERE channel_id = ?1 AND deleted = 0 AND text LIKE ?2 ESCAPE '@'
                  ORDER BY seq DESC
                  LIMIT ?3"
            ),
            params![channel_id.as_slice(), like_pattern(query), limit],
        )
    }

    fn query_posts(&self, sql: &str, params: impl rusqlite::Params) -> Result<Vec<StoredPost>> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;
        let mut statement = connection.prepare(sql).map_err(storage_error)?;

        let rows = statement
            .query_map(params, post_from_row)
            .map_err(storage_error)?;

        rows.map(|row| row.map_err(storage_error)?).collect()
    }

    /// Сколько сохранённых записей канала идёт после номера `seq`.
    ///
    /// Счёт по записям, а не по разности номеров: запись, не прошедшая
    /// проверку либо удалённая, номер занимает, но не показывается.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn count_channel_posts_after(&self, channel_id: &[u8; 16], seq: u64) -> Result<u64> {
        let seq = to_sql(seq)?;
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM channel_posts
                  WHERE channel_id = ? AND seq > ? AND deleted = 0",
                params![channel_id.as_slice(), seq],
                |row| row.get(0),
            )
            .map_err(storage_error)?;

        from_sql(count)
    }

    /// Сколько непрочитанных записей во всех каналах, кроме тех, что
    /// «без звука», — для счётчика на вкладке.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn count_unread_channel_posts(&self) -> Result<u64> {
        let connection = self.connection.lock().map_err(|_| GasAppError::Storage)?;

        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM channel_posts p
                   JOIN channels c ON c.channel_id = p.channel_id
                  WHERE c.muted = 0 AND p.deleted = 0 AND p.seq > c.last_read_seq",
                [],
                |row| row.get(0),
            )
            .map_err(storage_error)?;

        from_sql(count)
    }

    /// Отмечает записи канала прочитанными до `seq` включительно.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn mark_channel_read(&self, channel_id: &[u8; 16], seq: u64) -> Result<()> {
        self.channel_update(
            "UPDATE channels SET last_read_seq = ?2 WHERE channel_id = ?1 AND last_read_seq < ?2",
            params![channel_id.as_slice(), to_sql(seq)?],
        )
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
            pinned_seq: 0,
            avatar: None,
            handle: None,
            subscribers: 0,
            muted: false,
            last_seq: 0,
            last_rev: 0,
            last_read_seq: 0,
            seen_sent_seq: 0,
            sub_token: None,
            joined_at: Timestamp::from_millis(1_000),
        }
    }

    fn post(seq: u64, text: &str) -> StoredPost {
        StoredPost {
            seq,
            revision: 0,
            text: text.to_owned(),
            created_at: Timestamp::from_millis(i64::try_from(seq).unwrap().saturating_add(2_000)),
            edited_at: 0,
            deleted: false,
            views: 0,
            reactions: String::new(),
            my_reaction: String::new(),
            attachments: Vec::new(),
        }
    }

    #[test]
    fn a_channel_round_trips() {
        let (storage, _dir) = open_temp();
        let full = StoredChannel {
            pinned_seq: 4,
            avatar: Some(vec![1, 2, 3]),
            handle: Some("gas_news".to_owned()),
            subscribers: 12,
            muted: true,
            sub_token: Some([0x44; 32]),
            ..channel(1, true)
        };

        assert!(storage.insert_channel(&full).unwrap());
        assert_eq!(storage.channel(&[1; 16]).unwrap(), Some(full));
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
            assert_eq!(
                storage
                    .upsert_channel_post(&[1; 16], &post(seq, &format!("запись {seq}")))
                    .unwrap(),
                PostChange::Inserted
            );
        }
        // Повтор той же редакции ничего не меняет.
        assert_eq!(
            storage
                .upsert_channel_post(&[1; 16], &post(2, "другая"))
                .unwrap(),
            PostChange::Unchanged
        );

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

        let older = storage.channel_posts_before(&[1; 16], 3, 10).unwrap();
        assert_eq!(
            older.iter().map(|post| post.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(storage.min_channel_seq(&[1; 16]).unwrap(), Some(1));
    }

    /// 🔐 Правка принимается только с большей редакцией; счётчики
    /// и своя реакция её переживают.
    #[test]
    fn an_edit_needs_a_newer_revision() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();
        storage
            .upsert_channel_post(&[1; 16], &post(1, "первая редакция"))
            .unwrap();
        storage
            .set_channel_post_counters(&[1; 16], 1, 9, "🔥:2")
            .unwrap();
        storage
            .set_channel_post_reaction(&[1; 16], 1, "🔥")
            .unwrap();

        let edited = StoredPost {
            revision: 2,
            edited_at: 5_000,
            attachments: vec![vec![1, 2], vec![3]],
            ..post(1, "вторая редакция")
        };
        assert_eq!(
            storage.upsert_channel_post(&[1; 16], &edited).unwrap(),
            PostChange::Updated
        );

        // Сервер отдаёт прежнюю редакцию — она не возвращается.
        let stale = StoredPost {
            revision: 1,
            ..post(1, "откат")
        };
        assert_eq!(
            storage.upsert_channel_post(&[1; 16], &stale).unwrap(),
            PostChange::Unchanged
        );

        let stored = storage.channel_post(&[1; 16], 1).unwrap().unwrap();
        assert_eq!(stored.text, "вторая редакция");
        assert_eq!(stored.attachments, vec![vec![1, 2], vec![3]]);
        assert_eq!(stored.views, 9);
        assert_eq!(stored.my_reaction, "🔥");
    }

    /// 🔐 Удалённая запись не возвращается из прежнего шифротекста.
    #[test]
    fn a_deleted_post_stays_deleted() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();
        storage
            .upsert_channel_post(&[1; 16], &post(1, "секрет"))
            .unwrap();
        storage
            .upsert_channel_post(&[1; 16], &post(2, "остаётся"))
            .unwrap();

        assert!(storage.tombstone_channel_post(&[1; 16], 1, 1).unwrap());
        assert!(!storage.tombstone_channel_post(&[1; 16], 1, 1).unwrap());

        let revived = StoredPost {
            revision: 7,
            ..post(1, "секрет")
        };
        assert_eq!(
            storage.upsert_channel_post(&[1; 16], &revived).unwrap(),
            PostChange::Unchanged
        );

        let posts = storage.channel_posts(&[1; 16], 10).unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(storage.count_channel_posts_after(&[1; 16], 0).unwrap(), 1);

        let gone = storage.channel_post(&[1; 16], 1).unwrap().unwrap();
        assert!(gone.deleted);
        assert!(gone.text.is_empty());

        // Отметка для записи, которой не было, тоже держится.
        assert!(storage.tombstone_channel_post(&[1; 16], 5, 3).unwrap());
        assert_eq!(
            storage
                .upsert_channel_post(&[1; 16], &post(5, "призрак"))
                .unwrap(),
            PostChange::Unchanged
        );
    }

    /// 🔐 Описание старше известного не принимается.
    #[test]
    fn stale_meta_is_ignored() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();

        storage
            .update_channel_meta(&[1; 16], "Новое", "описание", 3, Some(&[9]), 200)
            .unwrap();
        storage
            .update_channel_meta(&[1; 16], "Прежнее", "", 0, None, 150)
            .unwrap();

        let stored = storage.channel(&[1; 16]).unwrap().unwrap();
        assert_eq!(stored.title, "Новое");
        assert_eq!(stored.pinned_seq, 3);
        assert_eq!(stored.avatar, Some(vec![9]));
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

    /// Общий счётчик непрочитанного не считает каналы «без звука».
    #[test]
    fn muted_channels_stay_out_of_the_total() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();
        storage.insert_channel(&channel(2, false)).unwrap();
        for seq in 1..=3 {
            storage
                .upsert_channel_post(&[1; 16], &post(seq, "a"))
                .unwrap();
        }
        storage
            .upsert_channel_post(&[2; 16], &post(1, "b"))
            .unwrap();

        assert_eq!(storage.count_unread_channel_posts().unwrap(), 4);

        storage.set_channel_muted(&[1; 16], true).unwrap();
        assert_eq!(storage.count_unread_channel_posts().unwrap(), 1);

        storage.mark_channel_read(&[2; 16], 1).unwrap();
        assert_eq!(storage.count_unread_channel_posts().unwrap(), 0);
    }

    #[test]
    fn search_finds_text_and_escapes_wildcards() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();
        storage
            .upsert_channel_post(&[1; 16], &post(1, "скидка 50% на всё"))
            .unwrap();
        storage
            .upsert_channel_post(&[1; 16], &post(2, "новости недели"))
            .unwrap();

        let found = storage.search_channel_posts(&[1; 16], "недел", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found.first().unwrap().seq, 2);

        assert_eq!(
            storage
                .search_channel_posts(&[1; 16], "%", 10)
                .unwrap()
                .len(),
            1
        );
        assert!(storage
            .search_channel_posts(&[1; 16], "", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn deleting_a_channel_removes_its_posts() {
        let (storage, _dir) = open_temp();
        storage.insert_channel(&channel(1, false)).unwrap();
        storage.insert_channel(&channel(2, false)).unwrap();
        storage
            .upsert_channel_post(&[1; 16], &post(1, "a"))
            .unwrap();
        storage
            .upsert_channel_post(&[2; 16], &post(1, "b"))
            .unwrap();

        storage.delete_channel(&[1; 16]).unwrap();

        assert_eq!(storage.channel(&[1; 16]).unwrap(), None);
        assert!(storage.channel_posts(&[1; 16], 10).unwrap().is_empty());
        assert_eq!(storage.channel_posts(&[2; 16], 10).unwrap().len(), 1);
        assert_eq!(storage.channels().unwrap().len(), 1);
    }
}
