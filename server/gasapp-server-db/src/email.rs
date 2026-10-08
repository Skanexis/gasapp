// SPDX-License-Identifier: AGPL-3.0-only

//! Коды подтверждения адреса почты (миграция 0017).
//!
//! # 🔐 Что здесь хранится
//!
//! Только хеши: `email_hash` — HMAC адреса на ключе узла, `code_hash` —
//! хеш кода. Ни адрес, ни код сюда не попадают: их считает слой API
//! и передаёт уже хешами.
//!
//! # Что защищает код
//!
//! Не хеш — шесть цифр перебираются мгновенно, — а счётчик попыток
//! ([`MAX_ATTEMPTS`]) и срок ([`CODE_TTL_MINUTES`]).

use sqlx::PgPool;
use subtle::ConstantTimeEq;

use crate::repo::RepoError;

/// Сколько живёт код.
pub const CODE_TTL_MINUTES: i32 = 15;

/// Сколько неверных вводов выдерживает один код.
pub const MAX_ATTEMPTS: i32 = 5;

/// Сколько писем уходит на один адрес за час.
pub const MAX_SENDS_PER_HOUR: i32 = 5;

/// Пауза между письмами на один адрес, секунды.
pub const RESEND_PAUSE_SECONDS: i32 = 60;

/// Что вышло из запроса кода.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeIssue {
    /// Код записан — письмо можно отправлять.
    Stored,
    /// Слишком часто: письмо не отправляется.
    Throttled,
}

/// Записывает новый код для адреса, заменяя прежний.
///
/// Ограничение частоты — здесь же, одним запросом: проверка отдельным
/// `SELECT` оставила бы окно, в котором два узла отправят по письму.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn store_code(
    pool: &PgPool,
    email_hash: &[u8; 32],
    code_hash: &[u8; 32],
) -> Result<CodeIssue, RepoError> {
    // Вставка либо обновление — только если пауза выдержана и окно
    // не исчерпано. Истёкшее часовое окно начинается заново.
    let stored = sqlx::query(
        "INSERT INTO email_codes (email_hash, code_hash, expires_at)
         VALUES ($1, $2, now() + make_interval(mins => $3))
         ON CONFLICT (email_hash) DO UPDATE
            SET code_hash    = EXCLUDED.code_hash,
                expires_at   = EXCLUDED.expires_at,
                attempts     = 0,
                last_sent_at = now(),
                sends        = CASE WHEN email_codes.window_start <= now() - interval '1 hour'
                                    THEN 1 ELSE email_codes.sends + 1 END,
                window_start = CASE WHEN email_codes.window_start <= now() - interval '1 hour'
                                    THEN now() ELSE email_codes.window_start END
          WHERE email_codes.last_sent_at <= now() - make_interval(secs => $4)
            AND (email_codes.window_start <= now() - interval '1 hour'
                 OR email_codes.sends < $5)",
    )
    .bind(email_hash.as_slice())
    .bind(code_hash.as_slice())
    .bind(CODE_TTL_MINUTES)
    .bind(f64::from(RESEND_PAUSE_SECONDS))
    .bind(MAX_SENDS_PER_HOUR)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(if stored == 0 {
        CodeIssue::Throttled
    } else {
        CodeIssue::Stored
    })
}

/// Сверяет код, не расходуя его.
///
/// Верный код остаётся в базе до [`consume_code`]: регистрация может
/// не пройти по другой причине (занято имя), и человеку не нужно
/// второе письмо, чтобы попробовать другое имя.
///
/// Неверный ввод увеличивает счётчик; после [`MAX_ATTEMPTS`] код
/// перестаёт приниматься, даже верный.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — кода нет, он истёк, сгорел или не совпал.
///   Причины не различаются намеренно.
/// * [`RepoError::Database`] — сбой базы.
pub async fn check_code(
    pool: &PgPool,
    email_hash: &[u8; 32],
    code_hash: &[u8; 32],
) -> Result<(), RepoError> {
    // Попытка засчитывается до сравнения: параллельные запросы не
    // получают больше попыток, чем положено.
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "UPDATE email_codes
            SET attempts = attempts + 1
          WHERE email_hash = $1 AND expires_at > now() AND attempts < $2
      RETURNING code_hash",
    )
    .bind(email_hash.as_slice())
    .bind(MAX_ATTEMPTS)
    .fetch_optional(pool)
    .await?;

    let Some(stored) = stored else {
        return Err(RepoError::NotFound);
    };

    if !bool::from(stored.as_slice().ct_eq(code_hash.as_slice())) {
        return Err(RepoError::NotFound);
    }

    // Верный ввод попыткой не считается: иначе пять неудачных имён
    // подряд сожгли бы честный код.
    sqlx::query(
        "UPDATE email_codes SET attempts = attempts - 1 WHERE email_hash = $1 AND attempts > 0",
    )
    .bind(email_hash.as_slice())
    .execute(pool)
    .await?;

    Ok(())
}

/// Удаляет код после состоявшейся регистрации.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn consume_code(pool: &PgPool, email_hash: &[u8; 32]) -> Result<(), RepoError> {
    sqlx::query("DELETE FROM email_codes WHERE email_hash = $1")
        .bind(email_hash.as_slice())
        .execute(pool)
        .await?;

    Ok(())
}

/// Удаляет истёкшие коды. Вызывается по расписанию (`retention`).
///
/// Строка держится час после истечения кода: в ней живёт окно
/// ограничения отправки, и удаление вместе с кодом обнулило бы его.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_expired_codes(pool: &PgPool) -> Result<u64, RepoError> {
    Ok(
        sqlx::query("DELETE FROM email_codes WHERE expires_at <= now() - interval '1 hour'")
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
