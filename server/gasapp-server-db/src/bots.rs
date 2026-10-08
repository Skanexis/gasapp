// SPDX-License-Identifier: AGPL-3.0-only

//! Боты: аккаунты, которые ведёт программа владельца (миграция 0022).
//!
//! Владелец с премиумом берёт одноразовый токен под имя, программа
//! бота по токену регистрируется со своими ключами. Дальше бот —
//! обычный аккаунт; сервер за него ничего не делает.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repo::RepoError;

/// Сколько ботов (вместе с невыкупленными токенами) у одного владельца.
pub const MAX_BOTS_PER_OWNER: i64 = 20;

/// Сколько живёт токен, секунды.
pub const BOT_TOKEN_TTL_SECS: i64 = 3600;

/// Чем обязано кончаться имя бота — и чем не может кончаться имя
/// обычного аккаунта.
pub const BOT_SUFFIX: &str = "bot";

/// Бот глазами владельца.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bot {
    /// Аккаунт бота.
    pub account_id: Uuid,
    /// Имя бота.
    pub username: String,
}

/// Имя бота: каноничное и на `bot`.
#[must_use]
pub fn is_bot_username(username: &str) -> bool {
    crate::is_canonical_username(username)
        && username.len() > BOT_SUFFIX.len()
        && username.ends_with(BOT_SUFFIX)
}

/// Выдаёт владельцу токен под имя будущего бота: запоминает его хеш.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунта владельца нет.
/// * [`RepoError::Conflict`] — у владельца нет премиума.
/// * [`RepoError::UsernameTaken`] — имя занято аккаунтом либо другим
///   токеном.
/// * [`RepoError::QuotaExceeded`] — у владельца предел ботов.
/// * [`RepoError::Database`] — сбой базы.
pub async fn issue_token(
    pool: &PgPool,
    owner_id: Uuid,
    username: &str,
    token_hash: &[u8; 32],
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки владельца: предел считается и токен добавляется
    // вместе, два одновременных запроса его не обойдут.
    let premium: Option<bool> =
        sqlx::query_scalar("SELECT premium FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(owner_id)
            .fetch_optional(&mut *tx)
            .await?;

    match premium {
        None => return Err(RepoError::NotFound),
        Some(false) => return Err(RepoError::Conflict),
        Some(true) => {}
    }

    // Истёкшие токены — чьи угодно — имён и мест не занимают.
    sqlx::query("DELETE FROM bot_tokens WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await?;

    let held: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM bots WHERE owner_id = $1)
              + (SELECT count(*) FROM bot_tokens WHERE owner_id = $1)",
    )
    .bind(owner_id)
    .fetch_one(&mut *tx)
    .await?;

    if held >= MAX_BOTS_PER_OWNER {
        return Err(RepoError::QuotaExceeded);
    }

    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE username = $1)")
            .bind(username)
            .fetch_one(&mut *tx)
            .await?;

    if taken {
        return Err(RepoError::UsernameTaken);
    }

    let inserted = sqlx::query(
        "INSERT INTO bot_tokens (token_hash, owner_id, username, expires_at)
         VALUES ($1, $2, $3, now() + $4 * interval '1 second')
         ON CONFLICT DO NOTHING",
    )
    .bind(token_hash.as_slice())
    .bind(owner_id)
    .bind(username)
    .bind(BOT_TOKEN_TTL_SECS)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 0 {
        return Err(RepoError::UsernameTaken);
    }

    tx.commit().await?;

    Ok(())
}

/// Регистрирует бота по токену, выданному под имя `username`: аккаунт
/// без почты, первое устройство и связь с владельцем. Возвращает
/// аккаунт и устройство.
///
/// Токен расходуется только вместе с успешной регистрацией: сбой
/// откатывает всё, и программа бота может повторить запрос.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — токена нет, он истёк либо выдан под
///   другое имя.
/// * [`RepoError::IdentityInUse`] — ключ identity уже чей-то.
/// * [`RepoError::UsernameTaken`] — имя успели занять.
/// * [`RepoError::Database`] — сбой базы.
pub async fn register_bot(
    pool: &PgPool,
    token_hash: &[u8; 32],
    username: &str,
    identity_key: &[u8],
    device_identity: &[u8],
    pq_identity: &[u8],
    identity_binding: &[u8],
) -> Result<(Uuid, Uuid), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let owner_id: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM bot_tokens
          WHERE token_hash = $1 AND username = $2 AND expires_at > now()
      RETURNING owner_id",
    )
    .bind(token_hash.as_slice())
    .bind(username)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(owner_id) = owner_id else {
        return Err(RepoError::NotFound);
    };

    let identity_taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE identity_key = $1)")
            .bind(identity_key)
            .fetch_one(&mut *tx)
            .await?;

    if identity_taken {
        return Err(RepoError::IdentityInUse);
    }

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // Занятое имя — ноль строк, а не ошибка базы (см. `register_account`).
    let inserted = sqlx::query(
        "INSERT INTO accounts (account_id, username, identity_key, pq_identity_key, identity_binding)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(username)
    .bind(identity_key)
    .bind(pq_identity)
    .bind(identity_binding)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 0 {
        return Err(RepoError::UsernameTaken);
    }

    sqlx::query("INSERT INTO devices (device_id, account_id, identity_key) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(account_id)
        .bind(device_identity)
        .execute(&mut *tx)
        .await?;

    sqlx::query("INSERT INTO bots (account_id, owner_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok((account_id, device_id))
}

/// Боты владельца, по имени.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn list_bots(pool: &PgPool, owner_id: Uuid) -> Result<Vec<Bot>, RepoError> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT a.account_id, a.username
           FROM bots b JOIN accounts a ON a.account_id = b.account_id
          WHERE b.owner_id = $1
          ORDER BY a.username",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(account_id, username)| Bot {
            account_id,
            username,
        })
        .collect())
}

/// Удаляет бота владельца вместе с его аккаунтом — либо невыкупленный
/// токен под это имя.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — такого бота у владельца нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn delete_bot(pool: &PgPool, owner_id: Uuid, username: &str) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let token = sqlx::query("DELETE FROM bot_tokens WHERE owner_id = $1 AND username = $2")
        .bind(owner_id)
        .bind(username)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    // Одна строка аккаунта; остальное уносят каскады схемы.
    let account = sqlx::query(
        "DELETE FROM accounts a
          USING bots b
          WHERE b.account_id = a.account_id AND b.owner_id = $1 AND a.username = $2",
    )
    .bind(owner_id)
    .bind(username)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if token == 0 && account == 0 {
        return Err(RepoError::NotFound);
    }

    tx.commit().await?;

    Ok(())
}
