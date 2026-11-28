// SPDX-License-Identifier: AGPL-3.0-only

//! Схема базы при запуске службы: применить миграции или только сверить.
//!
//! 🔐 Аудит 2026-11-28, S-10: службы работают под своими ролями без права
//! менять схему (`deploy/postgres/roles.sql`). Миграции применяет
//! владелец схемы отдельным шагом (`gasapp-server-admin migrate`), а
//! служба лишь проверяет, что все миграции её сборки уже в базе, — и
//! внятно отказывается стартовать, если нет.
//!
//! `GASAPP_DB_MIGRATIONS`:
//!
//! * не задана — по правам роли: может менять схему (владелец: разработка,
//!   тесты, развёртывание до разделения ролей) — применить, как прежде;
//!   не может (`gasapp_api`, `gasapp_admin`) — только сверить;
//! * `apply` — применить;
//! * `check` — только сверить.

use std::collections::HashSet;

use sqlx::migrate::Migrator;
use sqlx::PgPool;

/// Права ролей: выполняет владелец после миграций.
const ROLE_GRANTS: &str = include_str!("../../deploy/postgres/roles.sql");

/// Роли, которым раздаются права.
const ROLES: [&str; 3] = ["gasapp_api", "gasapp_admin", "gasapp_push"];

/// Почему схема не готова.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// Сбой базы или миграции.
    #[error("база: {0}")]
    Database(#[from] sqlx::Error),
    /// Сбой применения миграции.
    #[error("миграция: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// В базе нет миграций этой сборки.
    #[error(
        "схема базы старше программы (нет миграции {0}): выполните \
         `gasapp-server-admin migrate` на машине базы (docs/ops/db-roles.md)"
    )]
    Behind(i64),
    /// Неизвестное значение `GASAPP_DB_MIGRATIONS`.
    #[error("GASAPP_DB_MIGRATIONS={0}: допустимо apply или check")]
    Mode(String),
}

/// Применяет миграции либо сверяет схему — по `GASAPP_DB_MIGRATIONS`.
///
/// # Errors
///
/// [`SchemaError`] — схема не готова; служба не должна стартовать.
pub async fn prepare(pool: &PgPool, migrator: &Migrator) -> Result<(), SchemaError> {
    let apply = match std::env::var("GASAPP_DB_MIGRATIONS").as_deref() {
        Err(_) | Ok("") => may_change_schema(pool).await?,
        Ok("apply") => true,
        Ok("check") => false,
        Ok(other) => return Err(SchemaError::Mode(other.to_owned())),
    };
    if apply {
        Ok(migrator.run(pool).await?)
    } else {
        check(pool, migrator).await
    }
}

/// Может ли роль менять схему: владелец — да, роли служб — нет.
async fn may_change_schema(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
        .fetch_one(pool)
        .await
}

/// Все ли миграции сборки уже в базе.
///
/// # Errors
///
/// [`SchemaError::Behind`] — какой-то нет.
pub async fn check(pool: &PgPool, migrator: &Migrator) -> Result<(), SchemaError> {
    let applied: HashSet<i64> =
        sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations WHERE success")
            .fetch_all(pool)
            .await?
            .into_iter()
            .collect();
    match migrator
        .iter()
        .map(|migration| migration.version)
        .find(|version| !applied.contains(version))
    {
        Some(missing) => Err(SchemaError::Behind(missing)),
        None => Ok(()),
    }
}

/// Раздаёт права ролям ([`ROLE_GRANTS`]) — если роли заведены.
/// Возвращает, раздал ли. Выполняет владелец схемы.
///
/// # Errors
///
/// Сбой базы.
pub async fn apply_role_grants(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let present: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname = ANY($1)")
        .bind(&ROLES[..])
        .fetch_one(pool)
        .await?;
    if usize::try_from(present).ok() != Some(ROLES.len()) {
        return Ok(false);
    }
    sqlx::raw_sql(ROLE_GRANTS).execute(pool).await?;
    Ok(true)
}
