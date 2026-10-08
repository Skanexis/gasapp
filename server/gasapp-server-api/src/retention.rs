// SPDX-License-Identifier: Apache-2.0

//! Исполнение сроков хранения.
//!
//! # Что здесь чинится
//!
//! Документ о сроках хранения обещал, что недоставленные конверты
//! и вложения живут тридцать суток. `repo::purge_expired` и
//! `repo::purge_expired_attachments` существовали, их комментарии
//! говорили «вызывается по расписанию» — а расписания не было.
//! Их вызывал только тест.
//!
//! `fetch_*` просто переставали отдавать истёкшее, и снаружи всё
//! выглядело исполненным. Строки при этом оставались в базе навсегда —
//! вместе с `uploader_device_id` вложений.
//!
//! # Почему в каждом узле
//!
//! Узлов API три, и очистку запускает каждый. `DELETE … WHERE
//! expires_at <= now()` идемпотентен: второй узел находит пустоту.
//! Выделенный «главный» узел означал бы, что с его падением сроки
//! перестают исполняться, и этого снова никто бы не заметил.

use std::time::Duration;

use gasapp_server_db::repo::{self, RepoError};
use sqlx::PgPool;

/// Как часто удаляется истёкшее.
///
/// Время в базе огрублено до часа (миграция 0005), так что конверт
/// переживает свой срок не больше чем на этот интервал.
pub const PURGE_INTERVAL: Duration = Duration::from_mins(10);

/// Сколько удалено за один проход.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Purged {
    /// Недоставленных конвертов.
    pub envelopes: u64,
    /// Вложений.
    pub attachments: u64,
    /// Аккаунтов, не появлявшихся год (миграция 0011).
    pub accounts: u64,
    /// Истёкших кодов подтверждения почты (миграция 0017).
    pub email_codes: u64,
}

/// Удаляет истёкшие конверты и вложения — один раз.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_once(pool: &PgPool) -> Result<Purged, RepoError> {
    Ok(Purged {
        envelopes: repo::purge_expired(pool).await?,
        attachments: repo::purge_expired_attachments(pool).await?,
        accounts: repo::purge_inactive_accounts(pool).await?,
        email_codes: gasapp_server_db::email::purge_expired_codes(pool).await?,
    })
}

/// Удаляет истёкшее по расписанию — всё время работы процесса.
///
/// Сбой базы не останавливает цикл: следующий проход повторит
/// попытку. Остановиться насовсем значило бы тихо перестать
/// исполнять сроки — ровно то, что здесь и чинится.
pub async fn run(pool: PgPool) {
    let mut ticks = tokio::time::interval(PURGE_INTERVAL);

    loop {
        ticks.tick().await;

        match purge_once(&pool).await {
            // Только числа: ни идентификаторов, ни устройств.
            Ok(purged) if purged.envelopes > 0 || purged.attachments > 0 || purged.accounts > 0 => {
                tracing::info!(
                    envelopes = purged.envelopes,
                    attachments = purged.attachments,
                    accounts = purged.accounts,
                    "удалено истёкшее"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "очистка истёкшего не удалась"),
        }
    }
}
