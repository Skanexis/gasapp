// SPDX-License-Identifier: AGPL-3.0-only

//! Токены уведомлений (миграция 0028).
//!
//! Устройство в фоне не может подписать запрос: его ключ лежит в базе,
//! запертой PIN. Отдельный токен отвечает на один вопрос — непуста ли
//! очередь устройства. Сервер хранит хеш токена и ничего о том, когда
//! по нему спрашивали.

use sqlx::PgPool;
use subtle::ConstantTimeEq as _;
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
/// Хеш берётся по ключу устройства и сравнивается за постоянное время
/// (аудит 2026-11-28): проверка идёт раньше ограничителя, и время ответа
/// не должно подсказывать, сколько байт хеша совпало. Очередь смотрится
/// только для верного токена.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn pending(
    pool: &PgPool,
    device_id: Uuid,
    token_hash: &[u8; 32],
) -> Result<Option<bool>, RepoError> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT token_hash FROM notify_tokens WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(pool)
            .await?;

    let Some(stored) = stored else {
        return Ok(None);
    };

    if !bool::from(stored.as_slice().ct_eq(token_hash.as_slice())) {
        return Ok(None);
    }

    Ok(Some(
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM envelopes
                             WHERE destination_device_id = $1 AND expires_at > now())",
        )
        .bind(device_id)
        .fetch_one(pool)
        .await?,
    ))
}
