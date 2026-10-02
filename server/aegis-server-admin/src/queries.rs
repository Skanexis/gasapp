// SPDX-License-Identifier: AGPL-3.0-only

//! Запросы админ-центра к базе.
//!
//! 🔐 Граница — в том, каких запросов **здесь нет**: перечня всех
//! имён, истории входов, времени сообщений, связей «кто кому пишет».
//! Этих данных нет и в базе, но и то, что есть, отдаётся только в том
//! виде, который нужен решению: число жалобщиков, а не их список; месяц
//! активности, а не день.

use sqlx::PgPool;
use uuid::Uuid;

/// Причина действия оператора — ровно те, что допускает схема
/// (`admin_actions.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Спам.
    Spam,
    /// Травля, угрозы.
    Harassment,
    /// Сексуальное насилие над детьми и эксплуатация.
    Csae,
    /// Выдаёт себя за другого.
    Impersonation,
    /// Иное незаконное.
    Illegal,
    /// Прочее.
    Other,
    /// Жалобы необоснованны (только для отклонения).
    Unfounded,
}

impl Reason {
    /// Все причины удаления — для выбора в форме.
    pub const FOR_DELETION: [Self; 6] = [
        Self::Spam,
        Self::Harassment,
        Self::Csae,
        Self::Impersonation,
        Self::Illegal,
        Self::Other,
    ];

    /// Значение в базе и в форме.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Harassment => "harassment",
            Self::Csae => "csae",
            Self::Impersonation => "impersonation",
            Self::Illegal => "illegal",
            Self::Other => "other",
            Self::Unfounded => "unfounded",
        }
    }

    /// Подпись для оператора.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Spam => "Спам",
            Self::Harassment => "Травля, угрозы",
            Self::Csae => "Насилие над детьми (CSAE)",
            Self::Impersonation => "Выдаёт себя за другого",
            Self::Illegal => "Иное незаконное",
            Self::Other => "Прочее",
            Self::Unfounded => "Жалобы необоснованны",
        }
    }

    /// Разбирает значение из формы.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        [
            Self::Spam,
            Self::Harassment,
            Self::Csae,
            Self::Impersonation,
            Self::Illegal,
            Self::Other,
            Self::Unfounded,
        ]
        .into_iter()
        .find(|reason| reason.code() == code)
    }
}

/// Счётчики для сводки. Только числа — ни одного имени.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub accounts: i64,
    pub devices: i64,
    pub envelopes: i64,
    pub attachments: i64,
    pub attachments_bytes: i64,
    pub database_bytes: i64,
    pub reported_accounts: i64,
    pub kt_epoch: Option<i64>,
}

/// Аккаунт, на который пожаловались.
#[derive(Debug, Clone)]
pub struct ReportedAccount {
    pub account_id: Uuid,
    pub username: String,
    /// Месяц последней активности — `ГГГГ-ММ`. Дня создания у сервера
    /// нет: он хранит только месяц активности (миграция 0011).
    pub active_month: String,
    /// Сколько **разных** людей пожаловались.
    pub reporters: i64,
    /// Сколькими **разными** сертификатами отправителя доказаны жалобы.
    ///
    /// 🔐 Сертификат предъявительский: десяток жалоб одним сертификатом —
    /// скорее один человек с десятком аккаунтов (аудит 2026-10-02, S-4).
    pub certificates: i64,
    /// Первая и последняя жалоба — с точностью до часа.
    pub first_report: String,
    pub last_report: String,
}

/// Найденный по точному имени аккаунт.
#[derive(Debug, Clone)]
pub struct AccountCard {
    pub account_id: Uuid,
    pub username: String,
    /// Месяц последней активности.
    pub active_month: String,
    pub devices: i64,
    pub reporters: i64,
    /// Разных сертификатов в жалобах — см. [`ReportedAccount::certificates`].
    pub certificates: i64,
}

/// Строка отчёта о прозрачности: месяц, действие, причина, сколько.
#[derive(Debug, Clone)]
pub struct TransparencyRow {
    pub month: String,
    pub action: String,
    pub reason: String,
    pub count: i64,
    pub reporters: i64,
}

/// Счётчики для сводки.
///
/// # Errors
///
/// Ошибка базы.
pub async fn summary(pool: &PgPool) -> Result<Summary, sqlx::Error> {
    let count = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql).fetch_one(pool);

    Ok(Summary {
        accounts: count("SELECT count(*) FROM accounts").await?,
        devices: count("SELECT count(*) FROM devices").await?,
        envelopes: count("SELECT count(*) FROM envelopes").await?,
        attachments: count("SELECT count(*) FROM attachments").await?,
        attachments_bytes: count("SELECT pg_total_relation_size('attachments')").await?,
        database_bytes: count("SELECT pg_database_size(current_database())").await?,
        reported_accounts: count(
            "SELECT count(DISTINCT reported_account) FROM sealed_sender_reports",
        )
        .await?,
        kt_epoch: sqlx::query_scalar("SELECT max(epoch) FROM kt_epochs")
            .fetch_one(pool)
            .await?,
    })
}

/// Аккаунты с жалобами — у кого больше жалобщиков, выше.
///
/// # Errors
///
/// Ошибка базы.
pub async fn reported_accounts(pool: &PgPool) -> Result<Vec<ReportedAccount>, sqlx::Error> {
    // Выше — у кого больше разных сертификатов: их не накрутить
    // одним полученным сообщением, в отличие от числа жалобщиков.
    let rows: Vec<(Uuid, String, String, i64, i64, String, String)> = sqlx::query_as(
        "SELECT a.account_id,
                a.username,
                to_char(a.active_month, 'YYYY-MM'),
                count(DISTINCT r.complainant_device),
                count(DISTINCT r.certificate_hash),
                to_char(min(r.created_at), 'YYYY-MM-DD HH24:00'),
                to_char(max(r.created_at), 'YYYY-MM-DD HH24:00')
           FROM sealed_sender_reports r
           JOIN accounts a ON a.account_id = r.reported_account
          GROUP BY a.account_id, a.username, a.active_month
          ORDER BY count(DISTINCT r.certificate_hash) DESC,
                   count(DISTINCT r.complainant_device) DESC,
                   max(r.created_at) DESC
          LIMIT 200",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                account_id,
                username,
                active_month,
                reporters,
                certificates,
                first_report,
                last_report,
            )| {
                ReportedAccount {
                    account_id,
                    username,
                    active_month,
                    reporters,
                    certificates,
                    first_report,
                    last_report,
                }
            },
        )
        .collect())
}

/// Аккаунт по **точному** имени. Перечня имён нет намеренно: он был бы
/// каталогом пользователей, который сервер не должен уметь выдать.
///
/// # Errors
///
/// Ошибка базы.
pub async fn account_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<AccountCard>, sqlx::Error> {
    let row: Option<(Uuid, String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT a.account_id,
                a.username,
                to_char(a.active_month, 'YYYY-MM'),
                (SELECT count(*) FROM devices d WHERE d.account_id = a.account_id),
                (SELECT count(DISTINCT r.complainant_device)
                   FROM sealed_sender_reports r
                  WHERE r.reported_account = a.account_id),
                (SELECT count(DISTINCT r.certificate_hash)
                   FROM sealed_sender_reports r
                  WHERE r.reported_account = a.account_id)
           FROM accounts a
          WHERE a.username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(account_id, username, active_month, devices, reporters, certificates)| AccountCard {
            account_id,
            username,
            active_month,
            devices,
            reporters,
            certificates,
        },
    ))
}

/// Удаляет аккаунт по решению оператора — так же, как при удалении
/// владельцем: одна строка, остальное уносят каскады схемы.
///
/// Возвращает число жалобщиков, если аккаунт был; `None` — уже удалён.
///
/// # Errors
///
/// Ошибка базы.
pub async fn delete_account(
    pool: &PgPool,
    account_id: Uuid,
    reason: Reason,
) -> Result<Option<i64>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let reporters: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT complainant_device)
           FROM sealed_sender_reports WHERE reported_account = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

    let removed = sqlx::query("DELETE FROM accounts WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if removed == 0 {
        return Ok(None);
    }

    // Журнал — без имени и без идентификатора аккаунта (см. миграцию 0015).
    sqlx::query(
        "INSERT INTO admin_actions (action, reason, reporters)
         VALUES ('account_deleted', $1, $2)",
    )
    .bind(reason.code())
    .bind(i32::try_from(reporters).unwrap_or(i32::MAX))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(reporters))
}

/// Отклоняет жалобы на аккаунт: они удаляются, аккаунт остаётся.
///
/// # Errors
///
/// Ошибка базы.
pub async fn dismiss_reports(pool: &PgPool, account_id: Uuid) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let reporters: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT complainant_device)
           FROM sealed_sender_reports WHERE reported_account = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM sealed_sender_reports WHERE reported_account = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    if reporters > 0 {
        sqlx::query(
            "INSERT INTO admin_actions (action, reason, reporters)
             VALUES ('reports_dismissed', 'unfounded', $1)",
        )
        .bind(i32::try_from(reporters).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(reporters)
}

/// Отчёт о прозрачности: действия оператора по месяцам.
///
/// # Errors
///
/// Ошибка базы.
pub async fn transparency(pool: &PgPool) -> Result<Vec<TransparencyRow>, sqlx::Error> {
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT to_char(date_trunc('month', created_at), 'YYYY-MM'),
                action,
                reason,
                count(*),
                coalesce(sum(reporters), 0)::BIGINT
           FROM admin_actions
          GROUP BY 1, 2, 3
          ORDER BY 1 DESC, 2, 3",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(month, action, reason, count, reporters)| TransparencyRow {
                month,
                action,
                reason,
                count,
                reporters,
            },
        )
        .collect())
}

/// Сколько жалоб пришло после последнего уведомления; отмечает их
/// увиденными.
///
/// # Errors
///
/// Ошибка базы.
pub async fn take_new_reports(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let last_seen: i64 =
        sqlx::query_scalar("SELECT last_report_seq FROM admin_state WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;

    let (fresh, newest): (i64, Option<i64>) = sqlx::query_as(
        "SELECT count(*), max(report_seq) FROM sealed_sender_reports WHERE report_seq > $1",
    )
    .bind(last_seen)
    .fetch_one(&mut *tx)
    .await?;

    if let Some(newest) = newest {
        sqlx::query("UPDATE admin_state SET last_report_seq = $1 WHERE id = 1")
            .bind(newest)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    Ok(fresh)
}
