// SPDX-License-Identifier: AGPL-3.0-only

//! Токены уведомлений (миграция 0028).
//!
//! Устройство в фоне не может подписать запрос: его ключ лежит в базе,
//! запертой PIN. Отдельный токен отвечает на один вопрос — непуста ли
//! очередь устройства. Сервер хранит хеш токена и ничего о том, когда
//! по нему спрашивали.

use sqlx::PgPool;
use uuid::Uuid;

use crate::repo::RepoError;

/// Запоминает хеш токена уведомлений устройства; прежний заменяется.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы (в том числе устройства нет).
pub async fn set_token(
    pool: &PgPool,
    device_id: Uuid,
    token_hash: &[u8; 32],
) -> Result<(), RepoError> {
    sqlx::query(
        "INSERT INTO notify_tokens (device_id, token_hash) VALUES ($1, $2)
         ON CONFLICT (device_id) DO UPDATE SET token_hash = EXCLUDED.token_hash",
    )
    .bind(device_id)
    .bind(token_hash.as_slice())
    .execute(pool)
    .await?;

    Ok(())
}

/// Забывает токен уведомлений устройства.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn delete_token(pool: &PgPool, device_id: Uuid) -> Result<(), RepoError> {
    sqlx::query("DELETE FROM notify_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Непуста ли очередь устройства — для предъявившего токен с этим хешем.
///
/// `None` — устройства нет либо токен не тот: вызывающий отвечает на оба
/// случая одинаково.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn pending(
    pool: &PgPool,
    device_id: Uuid,
    token_hash: &[u8; 32],
) -> Result<Option<bool>, RepoError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM envelopes e
                         WHERE e.destination_device_id = t.device_id
                           AND e.expires_at > now())
           FROM notify_tokens t
          WHERE t.device_id = $1 AND t.token_hash = $2",
    )
    .bind(device_id)
    .bind(token_hash.as_slice())
    .fetch_optional(pool)
    .await?)
}
