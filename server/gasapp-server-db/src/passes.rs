// SPDX-License-Identifier: AGPL-3.0-only

//! Пропуска: сколько выдано аккаунту и какие уже потрачены
//! (миграция 0021).
//!
//! # 🔐 Что здесь хранится и чего нет
//!
//! * `pass_quota` — сколько пропусков аккаунт взял за сутки. Число,
//!   без каналов: на что пропуск пойдёт, при выдаче неизвестно.
//! * `spent_passes` — хеши зёрен потраченных пропусков и день траты.
//!   Без аккаунтов: при трате сервер не знает, чей это пропуск.
//!
//! Связать строку одной таблицы со строкой другой по базе нельзя —
//! в этом и состоит слепая выдача (см. `gasapp-server-api::pass`).

use sqlx::PgPool;
use uuid::Uuid;

use crate::repo::RepoError;

/// Сколько пропусков аккаунт может взять за сутки.
///
/// Пропуск тратится на подписку на канал. Сорок в сутки — заведомо
/// больше, чем подписывается человек, и это же верхняя граница того,
/// сколько «подписчиков» в сутки может дать один аккаунт.
pub const PASSES_PER_DAY: i32 = 40;

/// Сколько пропусков выдаётся одним запросом.
pub const MAX_PASSES_PER_REQUEST: usize = 16;

/// Сколько суток хранится счёт выданного.
const QUOTA_DAYS_KEPT: i32 = 2;

/// Записывает, что аккаунту выдаётся `wanted` пропусков, если суточный
/// предел это позволяет. Всё или ничего: частичной выдачи нет.
///
/// # Errors
///
/// * [`RepoError::QuotaExceeded`] — суточный предел был бы превышен.
/// * [`RepoError::Database`] — сбой базы.
pub async fn reserve(pool: &PgPool, account_id: Uuid, wanted: i32) -> Result<(), RepoError> {
    if wanted <= 0 || wanted > PASSES_PER_DAY {
        return Err(RepoError::QuotaExceeded);
    }

    // Одним запросом: проверка отдельным `SELECT` оставила бы окно,
    // в котором два параллельных запроса оба уложились бы в предел.
    let granted = sqlx::query(
        "INSERT INTO pass_quota (account_id, day, issued)
         VALUES ($1, current_date, $2)
         ON CONFLICT (account_id, day) DO UPDATE
            SET issued = pass_quota.issued + EXCLUDED.issued
          WHERE pass_quota.issued + EXCLUDED.issued <= $3",
    )
    .bind(account_id)
    .bind(wanted)
    .bind(PASSES_PER_DAY)
    .execute(pool)
    .await?
    .rows_affected();

    if granted == 0 {
        return Err(RepoError::QuotaExceeded);
    }

    Ok(())
}

/// Помечает пропуск потраченным. `false` — он уже был потрачен.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn spend(pool: &PgPool, seed_hash: &[u8; 32]) -> Result<bool, RepoError> {
    let fresh =
        sqlx::query("INSERT INTO spent_passes (seed_hash) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(seed_hash.as_slice())
            .execute(pool)
            .await?
            .rows_affected();

    Ok(fresh > 0)
}

/// Удаляет счёт выданного за прошедшие сутки. Вызывается по расписанию.
///
/// Потраченные пропуска не удаляются: ключ пропусков не меняется,
/// и забытый потраченный пропуск стал бы снова годным.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_old_quota(pool: &PgPool) -> Result<u64, RepoError> {
    Ok(
        sqlx::query("DELETE FROM pass_quota WHERE day < current_date - $1::int")
            .bind(QUOTA_DAYS_KEPT)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
