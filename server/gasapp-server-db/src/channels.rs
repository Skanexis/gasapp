// SPDX-License-Identifier: AGPL-3.0-only

//! Премиум и каналы (миграция 0018).
//!
//! # 🔐 Что сервер знает о канале
//!
//! Владельца, число записей, их размер и час публикации. Название,
//! описание и текст записей — шифротекст: ключ канала живёт в
//! ссылке-приглашении и сюда не попадает. Подписчиков сервер не знает
//! вовсе — таблицы подписок нет.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repo::RepoError;

/// Предел шифротекста записи.
pub const MAX_POST_BYTES: usize = 65_536;

/// Предел шифротекста описания канала.
pub const MAX_META_BYTES: usize = 8_192;

/// Сколько каналов может держать один аккаунт.
pub const MAX_CHANNELS_PER_ACCOUNT: i64 = 10;

/// Сколько записей отдаётся за один запрос.
pub const MAX_POSTS_PER_PAGE: i64 = 100;

/// Канал в том виде, в каком его получает читатель.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Идентификатор.
    pub channel_id: Uuid,
    /// Публичный ключ подписи записей.
    pub verify_key: Vec<u8>,
    /// Зашифрованное описание.
    pub meta: Vec<u8>,
    /// Номер последней записи.
    pub last_seq: i64,
}

/// Запись канала.
#[derive(Debug, Clone)]
pub struct Post {
    /// Порядковый номер в канале, с единицы.
    pub seq: i64,
    /// Шифротекст.
    pub body: Vec<u8>,
    /// Час публикации, миллисекунды эпохи.
    pub posted_at_millis: i64,
}

/// Аккаунт устройства и его премиум.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — устройства нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn account_status(pool: &PgPool, device_id: Uuid) -> Result<(Uuid, bool), RepoError> {
    Ok(sqlx::query_as(
        "SELECT a.account_id, a.premium
           FROM accounts a JOIN devices d ON d.account_id = a.account_id
          WHERE d.device_id = $1",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await?)
}

/// Выдаёт или снимает премиум по точному имени.
///
/// Возвращает `false`, если аккаунта нет.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn set_premium(pool: &PgPool, username: &str, premium: bool) -> Result<bool, RepoError> {
    let changed = sqlx::query("UPDATE accounts SET premium = $2 WHERE username = $1")
        .bind(username)
        .bind(premium)
        .execute(pool)
        .await?
        .rows_affected();

    Ok(changed > 0)
}

/// Выдаёт или снимает премиум по идентификатору аккаунта.
///
/// Возвращает `false`, если аккаунта нет.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn set_premium_by_id(
    pool: &PgPool,
    account_id: Uuid,
    premium: bool,
) -> Result<bool, RepoError> {
    let changed = sqlx::query("UPDATE accounts SET premium = $2 WHERE account_id = $1")
        .bind(account_id)
        .bind(premium)
        .execute(pool)
        .await?
        .rows_affected();

    Ok(changed > 0)
}

/// Создаёт канал. Право (премиум) проверяет вызывающий — здесь только
/// предел числа каналов.
///
/// # Errors
///
/// * [`RepoError::QuotaExceeded`] — у аккаунта уже предел каналов.
/// * [`RepoError::Conflict`] — идентификатор занят.
/// * [`RepoError::Database`] — сбой базы.
pub async fn create_channel(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    verify_key: &[u8],
    meta: &[u8],
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки аккаунта: два одновременных создания не
    // перешагнут предел.
    sqlx::query("SELECT 1 FROM accounts WHERE account_id = $1 FOR UPDATE")
        .bind(owner_account)
        .fetch_one(&mut *tx)
        .await?;

    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM channels WHERE owner_account = $1")
        .bind(owner_account)
        .fetch_one(&mut *tx)
        .await?;

    if owned >= MAX_CHANNELS_PER_ACCOUNT {
        return Err(RepoError::QuotaExceeded);
    }

    let inserted = sqlx::query(
        "INSERT INTO channels (channel_id, owner_account, verify_key, meta)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (channel_id) DO NOTHING",
    )
    .bind(channel_id)
    .bind(owner_account)
    .bind(verify_key)
    .bind(meta)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 0 {
        return Err(RepoError::Conflict);
    }

    tx.commit().await?;

    Ok(())
}

/// Заменяет зашифрованное описание канала.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой (не различается).
/// * [`RepoError::Database`] — сбой базы.
pub async fn update_meta(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    meta: &[u8],
) -> Result<(), RepoError> {
    let changed =
        sqlx::query("UPDATE channels SET meta = $3 WHERE channel_id = $1 AND owner_account = $2")
            .bind(channel_id)
            .bind(owner_account)
            .bind(meta)
            .execute(pool)
            .await?
            .rows_affected();

    if changed == 0 {
        return Err(RepoError::NotFound);
    }

    Ok(())
}

/// Удаляет канал вместе с записями.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::Database`] — сбой базы.
pub async fn delete_channel(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
) -> Result<(), RepoError> {
    let removed = sqlx::query("DELETE FROM channels WHERE channel_id = $1 AND owner_account = $2")
        .bind(channel_id)
        .bind(owner_account)
        .execute(pool)
        .await?
        .rows_affected();

    if removed == 0 {
        return Err(RepoError::NotFound);
    }

    Ok(())
}

/// Публикует запись и возвращает её номер.
///
/// Номер выдаёт сервер: `UPDATE … RETURNING` берёт блокировку строки
/// канала, и две одновременные записи получают разные номера.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::Database`] — сбой базы.
pub async fn publish_post(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    body: &[u8],
) -> Result<i64, RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let seq: Option<i64> = sqlx::query_scalar(
        "UPDATE channels SET last_seq = last_seq + 1
          WHERE channel_id = $1 AND owner_account = $2
      RETURNING last_seq",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(seq) = seq else {
        return Err(RepoError::NotFound);
    };

    sqlx::query("INSERT INTO channel_posts (channel_id, seq, body) VALUES ($1, $2, $3)")
        .bind(channel_id)
        .bind(seq)
        .bind(body)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(seq)
}

/// Канал по идентификатору — для читателя.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn find_channel(pool: &PgPool, channel_id: Uuid) -> Result<Channel, RepoError> {
    let (verify_key, meta, last_seq): (Vec<u8>, Vec<u8>, i64) =
        sqlx::query_as("SELECT verify_key, meta, last_seq FROM channels WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_one(pool)
            .await?;

    Ok(Channel {
        channel_id,
        verify_key,
        meta,
        last_seq,
    })
}

/// Записи канала с номером больше `after`, по возрастанию.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn list_posts(
    pool: &PgPool,
    channel_id: Uuid,
    after: i64,
    limit: i64,
) -> Result<Vec<Post>, RepoError> {
    let rows: Vec<(i64, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT seq, body, (extract(epoch FROM posted_at) * 1000)::bigint
           FROM channel_posts
          WHERE channel_id = $1 AND seq > $2
          ORDER BY seq
          LIMIT $3",
    )
    .bind(channel_id)
    .bind(after)
    .bind(limit.clamp(1, MAX_POSTS_PER_PAGE))
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(seq, body, posted_at_millis)| Post {
            seq,
            body,
            posted_at_millis,
        })
        .collect())
}
