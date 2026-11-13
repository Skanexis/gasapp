// SPDX-License-Identifier: AGPL-3.0-only

//! Обзор сервиса, списки, журнал действий и здоровье базы — для оператора.
//!
//! 🔐 Только то, что сервер и так хранит: имена, месяц последней
//! активности, флаги премиума и бота, счётчики. Адресов, почты, времени
//! входа и переписки здесь нет — их нет и в базе (миграции 0011, 0017).
//! Активность — по месяцам, как её хранит сервер: дневной истории
//! регистраций нет, и эта страница её не выдумывает.

use std::fmt::Write as _;

use sqlx::PgPool;
use uuid::Uuid;

use crate::escape;

/// Строк на странице списка.
pub const PAGE: i64 = 50;

/// Месяцев в графике активности.
const ACTIVITY_MONTHS: i64 = 6;

// ---------------------------------------------------------------------
// Обзор

/// Счётчики обзора. Только числа.
#[derive(Debug, Clone, Default)]
pub struct Dashboard {
    pub accounts: i64,
    pub bots: i64,
    pub premium: i64,
    pub active_this_month: i64,
    pub active_last_month: i64,
    pub dormant: i64,
    pub channels: i64,
    pub public_channels: i64,
    pub closed_channels: i64,
    pub posts: i64,
    pub subscriptions: i64,
    pub reported_accounts: i64,
    pub reported_channels: i64,
    pub devices: i64,
    pub envelopes: i64,
    /// Возраст самого старого недоставленного конверта, часов.
    pub oldest_envelope_hours: Option<i64>,
    pub attachments: i64,
    pub attachments_bytes: i64,
    pub database_bytes: i64,
    pub kt_epoch: Option<i64>,
    /// Аккаунтов по месяцу последней активности: `ГГГГ-ММ`, число.
    pub activity: Vec<(String, i64)>,
}

/// Собирает обзор.
///
/// # Errors
///
/// Ошибка базы.
pub async fn dashboard(pool: &PgPool) -> Result<Dashboard, sqlx::Error> {
    let count = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql).fetch_one(pool);

    let activity: Vec<(String, i64)> = sqlx::query_as(
        "SELECT to_char(active_month, 'YYYY-MM'), count(*)
           FROM accounts
          WHERE active_month >= (date_trunc('month', now()) - make_interval(months => $1::int))::date
          GROUP BY active_month
          ORDER BY active_month",
    )
    .bind(i32::try_from(ACTIVITY_MONTHS.saturating_sub(1)).unwrap_or(5))
    .fetch_all(pool)
    .await?;

    Ok(Dashboard {
        accounts: count("SELECT count(*) FROM accounts").await?,
        bots: count("SELECT count(*) FROM bots").await?,
        premium: count("SELECT count(*) FROM accounts WHERE premium").await?,
        active_this_month: count(
            "SELECT count(*) FROM accounts WHERE active_month = date_trunc('month', now())::date",
        )
        .await?,
        active_last_month: count(
            "SELECT count(*) FROM accounts
              WHERE active_month = (date_trunc('month', now()) - interval '1 month')::date",
        )
        .await?,
        dormant: count(
            "SELECT count(*) FROM accounts
              WHERE active_month < (date_trunc('month', now()) - interval '1 month')::date",
        )
        .await?,
        channels: count("SELECT count(*) FROM channels").await?,
        public_channels: count("SELECT count(*) FROM channels WHERE handle IS NOT NULL").await?,
        closed_channels: count("SELECT count(*) FROM channels WHERE closed").await?,
        posts: count("SELECT count(*) FROM channel_posts").await?,
        subscriptions: count("SELECT count(*) FROM channel_subscribers").await?,
        reported_accounts: count("SELECT count(DISTINCT reported_account) FROM sealed_sender_reports")
            .await?,
        reported_channels: count("SELECT count(DISTINCT channel_id) FROM channel_reports").await?,
        devices: count("SELECT count(*) FROM devices").await?,
        envelopes: count("SELECT count(*) FROM envelopes").await?,
        oldest_envelope_hours: sqlx::query_scalar(
            "SELECT (extract(epoch FROM now() - min(queued_at)) / 3600)::bigint FROM envelopes",
        )
        .fetch_one(pool)
        .await?,
        attachments: count("SELECT count(*) FROM attachments").await?,
        attachments_bytes: count("SELECT pg_total_relation_size('attachments')").await?,
        database_bytes: count("SELECT pg_database_size(current_database())").await?,
        kt_epoch: sqlx::query_scalar("SELECT max(epoch) FROM kt_epochs")
            .fetch_one(pool)
            .await?,
        activity,
    })
}

// ---------------------------------------------------------------------
// Списки

/// Строка выборки аккаунтов: id, имя, месяц, премиум, бот, устройства, каналы, жалобщики.
type AccountTuple = (Uuid, String, String, bool, bool, i64, i64, i64);

/// Строка выборки каналов: id, @имя, владелец, закрыт, создан, подписчики, записи, жалобы.
type ChannelTuple = (Uuid, Option<String>, String, bool, String, i64, i64, i64);

/// Какие аккаунты показать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountView {
    All,
    Premium,
    Bots,
    Reported,
    Dormant,
}

impl AccountView {
    pub const ALL: [Self; 5] = [Self::All, Self::Premium, Self::Bots, Self::Reported, Self::Dormant];

    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        Self::ALL
            .into_iter()
            .find(|view| Some(view.code()) == raw)
            .unwrap_or(Self::All)
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Premium => "premium",
            Self::Bots => "bots",
            Self::Reported => "reported",
            Self::Dormant => "dormant",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Premium => "Premium",
            Self::Bots => "Bots",
            Self::Reported => "Reported",
            Self::Dormant => "Inactive 2+ months",
        }
    }
}

/// Строка списка аккаунтов.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub account_id: Uuid,
    pub username: String,
    pub active_month: String,
    pub premium: bool,
    pub bot: bool,
    pub devices: i64,
    pub channels: i64,
    pub reporters: i64,
}

/// `LIKE` по началу имени: служебные знаки шаблона — буквально.
fn prefix_pattern(query: &str) -> String {
    let cleaned = query.trim().trim_start_matches('@').to_lowercase();
    let mut pattern = String::with_capacity(cleaned.len().saturating_add(1));
    for ch in cleaned.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

/// Страница аккаунтов. Второе значение — есть ли следующая страница.
///
/// # Errors
///
/// Ошибка базы.
pub async fn accounts(
    pool: &PgPool,
    view: AccountView,
    query: &str,
    page: i64,
) -> Result<(Vec<AccountRow>, bool), sqlx::Error> {
    let rows: Vec<AccountTuple> = sqlx::query_as(
        "SELECT a.account_id,
                a.username,
                to_char(a.active_month, 'YYYY-MM'),
                a.premium,
                b.account_id IS NOT NULL,
                (SELECT count(*) FROM devices d WHERE d.account_id = a.account_id),
                (SELECT count(*) FROM channels c WHERE c.owner_account = a.account_id),
                (SELECT count(DISTINCT r.complainant_device) FROM sealed_sender_reports r
                  WHERE r.reported_account = a.account_id)
           FROM accounts a
           LEFT JOIN bots b ON b.account_id = a.account_id
          WHERE a.username LIKE $1 ESCAPE '\\'
            AND ($2 = 'all'
                 OR ($2 = 'premium' AND a.premium)
                 OR ($2 = 'bots' AND b.account_id IS NOT NULL)
                 OR ($2 = 'reported' AND EXISTS (SELECT 1 FROM sealed_sender_reports r
                                                  WHERE r.reported_account = a.account_id))
                 OR ($2 = 'dormant' AND a.active_month < (date_trunc('month', now()) - interval '1 month')::date))
          ORDER BY a.username
          LIMIT $3 OFFSET $4",
    )
    .bind(prefix_pattern(query))
    .bind(view.code())
    .bind(PAGE.saturating_add(1))
    .bind(page.max(0).saturating_mul(PAGE))
    .fetch_all(pool)
    .await?;

    let more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > PAGE;
    let rows = rows
        .into_iter()
        .take(usize::try_from(PAGE).unwrap_or(50))
        .map(|(account_id, username, active_month, premium, bot, devices, channels, reporters)| AccountRow {
            account_id,
            username,
            active_month,
            premium,
            bot,
            devices,
            channels,
            reporters,
        })
        .collect();

    Ok((rows, more))
}

/// Какие каналы показать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelView {
    All,
    Public,
    Closed,
    Reported,
}

impl ChannelView {
    pub const ALL: [Self; 4] = [Self::All, Self::Public, Self::Closed, Self::Reported];

    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        Self::ALL
            .into_iter()
            .find(|view| Some(view.code()) == raw)
            .unwrap_or(Self::All)
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Public => "public",
            Self::Closed => "closed",
            Self::Reported => "reported",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Public => "Public",
            Self::Closed => "Closed",
            Self::Reported => "Reported",
        }
    }
}

/// Строка списка каналов.
///
/// 🔐 Название и описание канала — шифротекст: сервер их не знает.
/// Видны только публичное `@имя` (его владелец отдал серверу сам),
/// владелец и счётчики.
#[derive(Debug, Clone)]
pub struct ChannelRow {
    pub channel_id: Uuid,
    pub handle: Option<String>,
    pub owner: String,
    pub closed: bool,
    pub created: String,
    pub subscribers: i64,
    pub posts: i64,
    pub reports: i64,
}

/// Страница каналов: поиск по `@имени` канала или имени владельца.
///
/// # Errors
///
/// Ошибка базы.
pub async fn channels(
    pool: &PgPool,
    view: ChannelView,
    query: &str,
    page: i64,
) -> Result<(Vec<ChannelRow>, bool), sqlx::Error> {
    let rows: Vec<ChannelTuple> = sqlx::query_as(
        "SELECT c.channel_id,
                c.handle,
                o.username,
                c.closed,
                to_char(c.created_at, 'YYYY-MM-DD'),
                (SELECT count(*) FROM channel_subscribers s WHERE s.channel_id = c.channel_id),
                c.last_seq,
                (SELECT count(*) FROM channel_reports r WHERE r.channel_id = c.channel_id)
           FROM channels c
           JOIN accounts o ON o.account_id = c.owner_account
          WHERE (coalesce(c.handle, '') LIKE $1 ESCAPE '\\' OR o.username LIKE $1 ESCAPE '\\')
            AND ($2 = 'all'
                 OR ($2 = 'public' AND c.handle IS NOT NULL)
                 OR ($2 = 'closed' AND c.closed)
                 OR ($2 = 'reported' AND EXISTS (SELECT 1 FROM channel_reports r
                                                  WHERE r.channel_id = c.channel_id)))
          ORDER BY 6 DESC, c.created_at DESC
          LIMIT $3 OFFSET $4",
    )
    .bind(prefix_pattern(query))
    .bind(view.code())
    .bind(PAGE.saturating_add(1))
    .bind(page.max(0).saturating_mul(PAGE))
    .fetch_all(pool)
    .await?;

    let more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > PAGE;
    let rows = rows
        .into_iter()
        .take(usize::try_from(PAGE).unwrap_or(50))
        .map(|(channel_id, handle, owner, closed, created, subscribers, posts, reports)| ChannelRow {
            channel_id,
            handle,
            owner,
            closed,
            created,
            subscribers,
            posts,
            reports,
        })
        .collect();

    Ok((rows, more))
}

// ---------------------------------------------------------------------
// Журнал и здоровье

/// Запись журнала действий оператора — без имён (как отчёт о прозрачности).
#[derive(Debug, Clone)]
pub struct JournalRow {
    pub hour: String,
    pub action: String,
    pub reason: String,
    pub reporters: i32,
}

/// Последние действия оператора.
///
/// # Errors
///
/// Ошибка базы.
pub async fn journal(pool: &PgPool) -> Result<Vec<JournalRow>, sqlx::Error> {
    let rows: Vec<(String, String, String, i32)> = sqlx::query_as(
        "SELECT to_char(created_at, 'YYYY-MM-DD HH24:00'), action, reason, reporters
           FROM admin_actions
          ORDER BY action_id DESC
          LIMIT 200",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(hour, action, reason, reporters)| JournalRow { hour, action, reason, reporters })
        .collect())
}

/// Здоровье базы.
#[derive(Debug, Clone, Default)]
pub struct Health {
    pub version: String,
    pub uptime: String,
    pub connections: i64,
    pub database_bytes: i64,
    pub envelopes: i64,
    pub oldest_envelope_hours: Option<i64>,
    pub tables: Vec<(String, i64)>,
}

/// Состояние базы — тем, что видит сама база.
///
/// # Errors
///
/// Ошибка базы.
pub async fn health(pool: &PgPool) -> Result<Health, sqlx::Error> {
    let version: String = sqlx::query_scalar("SELECT split_part(version(), ' ', 2)").fetch_one(pool).await?;
    let uptime: String = sqlx::query_scalar(
        "SELECT CASE WHEN now() - pg_postmaster_start_time() >= interval '1 day'
                     THEN extract(day FROM now() - pg_postmaster_start_time())::int || ' d '
                          || extract(hour FROM now() - pg_postmaster_start_time())::int || ' h'
                     ELSE extract(hour FROM now() - pg_postmaster_start_time())::int || ' h '
                          || extract(minute FROM now() - pg_postmaster_start_time())::int || ' min' END",
    )
    .fetch_one(pool)
    .await?;
    let tables: Vec<(String, i64)> = sqlx::query_as(
        "SELECT relname::text, pg_total_relation_size(relid)
           FROM pg_stat_user_tables
          ORDER BY 2 DESC
          LIMIT 8",
    )
    .fetch_all(pool)
    .await?;

    Ok(Health {
        version,
        uptime,
        connections: sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()",
        )
        .fetch_one(pool)
        .await?,
        database_bytes: sqlx::query_scalar("SELECT pg_database_size(current_database())")
            .fetch_one(pool)
            .await?,
        envelopes: sqlx::query_scalar("SELECT count(*) FROM envelopes").fetch_one(pool).await?,
        oldest_envelope_hours: sqlx::query_scalar(
            "SELECT (extract(epoch FROM now() - min(queued_at)) / 3600)::bigint FROM envelopes",
        )
        .fetch_one(pool)
        .await?,
        tables,
    })
}

// ---------------------------------------------------------------------
// HTML — компоненты Tabler (assets/tabler.min.css), тема Night Camp.

use crate::icon;

/// Число с разделением разрядов узким пробелом: «1 284», а не «1284».
fn grouped(number: i64) -> String {
    let digits = number.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len().saturating_mul(4));
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && digits.len().saturating_sub(index) % 3 == 0 {
            out.push('\u{202F}');
        }
        out.push(ch);
    }
    if number < 0 {
        out.insert(0, '\u{2212}');
    }
    out
}

fn percent_of(part: i64, whole: i64) -> i64 {
    if whole <= 0 {
        return 0;
    }
    part.saturating_mul(100).checked_div(whole).unwrap_or(0).clamp(0, 100)
}

/// Карточка показателя: иконка, подпись, число, пояснение.
fn stat(glyph: &str, tone: &str, label: &str, value: &str, hint: &str) -> String {
    format!(
        "<div class=\"col-sm-6 col-xl-3\"><div class=\"card card-sm h-100\"><div class=\"card-body\">\
         <div class=\"row align-items-center\"><div class=\"col-auto\"><span class=\"stat-tile tone-{tone}\">{}</span></div>\
         <div class=\"col\"><div class=\"text-secondary fw-medium\">{}</div><div class=\"stat-value num\">{}</div>\
         <div class=\"text-secondary small\">{}</div></div></div></div></div></div>",
        icon(glyph),
        escape(label),
        escape(value),
        escape(hint),
    )
}

/// Аватар-инициалы: цвет по имени, как в приложении (шесть тонов).
fn avatar(name: &str) -> String {
    const INKS: [&str; 6] = ["#ffcb2e", "#5ed3c9", "#f59ab8", "#f5b08a", "#c4a9ff", "#7fc4f5"];
    let mut hash: i32 = 0;
    for unit in name.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    let index = usize::try_from(hash.rem_euclid(6)).unwrap_or(0);
    let ink = INKS.get(index).copied().unwrap_or("#ffcb2e");
    let initials: String = name
        .split(['_', ' '])
        .filter(|part| !part.is_empty())
        .take(2)
        .filter_map(|part| part.chars().next())
        .collect::<String>()
        .to_uppercase();
    let initials = if initials.chars().count() == 1 {
        name.chars().take(2).collect::<String>().to_uppercase()
    } else {
        initials
    };
    format!(
        "<span class=\"ava\" style=\"background:{ink}29;color:{ink}\" aria-hidden=\"true\">{}</span>",
        escape(&initials)
    )
}

/// Страница обзора.
#[must_use]
pub fn dashboard_html(d: &Dashboard, bytes: fn(i64) -> String) -> String {
    let queue = d.reported_accounts.saturating_add(d.reported_channels);
    let (hero_class, glyph, title, lead) = if queue == 0 {
        (
            "hero calm",
            "circle-check",
            "Nothing waits for review".to_owned(),
            "No open reports on accounts or channels.".to_owned(),
        )
    } else {
        (
            "hero",
            "alert-triangle",
            format!("{queue} case{} waiting for review", if queue == 1 { "" } else { "s" }),
            format!(
                "{} reported account{} and {} reported channel{}. Review within 24 hours.",
                d.reported_accounts,
                if d.reported_accounts == 1 { "" } else { "s" },
                d.reported_channels,
                if d.reported_channels == 1 { "" } else { "s" },
            ),
        )
    };
    let hero_tone = if queue == 0 { "ok" } else { "warn" };

    let mut html = format!(
        "<div class=\"card {hero_class} mb-4\"><div class=\"card-body\"><div class=\"row g-3 align-items-center\">\
         <div class=\"col-auto\"><span class=\"stat-tile tone-{hero_tone}\" style=\"width:3.2rem;height:3.2rem\">{}</span></div>\
         <div class=\"col\"><h3 class=\"m-0\">{}</h3><div class=\"text-secondary mt-1\">{}</div></div>\
         <div class=\"col-12 col-md-auto d-flex gap-2 flex-wrap\">\
         <a class=\"btn btn-primary\" href=\"/reports\">{} Open the report queue</a>\
         <a class=\"btn\" href=\"/accounts?view=premium\">{} Premium</a>\
         <a class=\"btn\" href=\"/health\">{} Health</a></div></div></div></div>",
        icon(glyph),
        escape(&title),
        escape(&lead),
        icon("flag"),
        icon("crown"),
        icon("heart-rate-monitor"),
    );

    html.push_str("<div class=\"row row-cards mb-4\">");
    html.push_str(&stat("users", "info", "Accounts", &grouped(d.accounts), &format!("{} are bots", grouped(d.bots))));
    html.push_str(&stat(
        "activity",
        "ok",
        "Active this month",
        &grouped(d.active_this_month),
        &format!("{}% of all accounts", percent_of(d.active_this_month, d.accounts)),
    ));
    html.push_str(&stat("crown", "gold", "Premium", &grouped(d.premium), "can create channels and bots"));
    html.push_str(&stat(
        "broadcast",
        "pink",
        "Channels",
        &grouped(d.channels),
        &format!("{} posts · {} subscriptions", grouped(d.posts), grouped(d.subscriptions)),
    ));
    html.push_str("</div>");

    // Графики: активность по месяцам и доли.
    html.push_str("<div class=\"row row-cards mb-4\">");
    html.push_str(&activity_chart(&d.activity));
    html.push_str(&activity_split(d));
    html.push_str("</div>");

    html.push_str("<div class=\"row row-cards mb-4 align-items-start\">");
    html.push_str(&channel_access(d));
    let backlog_tone = match d.oldest_envelope_hours {
        Some(hours) if hours >= 72 => "warn",
        _ => "info",
    };
    html.push_str(&stat(
        "send",
        backlog_tone,
        "Queued envelopes",
        &grouped(d.envelopes),
        &d.oldest_envelope_hours
            .map_or_else(|| "queue is empty".to_owned(), |hours| format!("oldest waits {hours} h")),
    ));
    html.push_str(&stat("paperclip", "info", "Attachments", &grouped(d.attachments), &bytes(d.attachments_bytes)));
    html.push_str("</div><div class=\"row row-cards mb-3\">");
    html.push_str(&stat("database", "info", "Database size", &bytes(d.database_bytes), "including indexes"));
    html.push_str(&stat("device-mobile", "info", "Devices", &grouped(d.devices), "one per account today"));
    html.push_str(&stat(
        "key",
        "gold",
        "Key log epoch",
        &d.kt_epoch.map_or_else(|| "—".to_owned(), grouped),
        "public key transparency log",
    ));
    html.push_str(&stat(
        "flag",
        if queue > 0 { "warn" } else { "ok" },
        "Open reports",
        &grouped(queue),
        &format!("{} accounts · {} channels", d.reported_accounts, d.reported_channels),
    ));
    html.push_str(
        "</div><p class=\"text-secondary small\">Operational totals only. The server does not retain readable conversations, \
         email addresses, IP addresses, login history or a social graph, so this view cannot show them.</p>",
    );

    html
}

/// Столбцы: аккаунты по месяцу последней активности. Один ряд — без
/// легенды; подписаны пик и последний месяц, остальное — по наведению.
fn activity_chart(activity: &[(String, i64)]) -> String {
    let mut html = String::from(
        "<div class=\"col-lg-7\"><div class=\"card h-100\"><div class=\"card-header\"><div>\
         <h3 class=\"card-title\">Accounts by month of last activity</h3>\
         <div class=\"card-subtitle text-secondary\">The server keeps only the month — no days, times or logins.</div></div></div>\
         <div class=\"card-body\">",
    );
    if activity.is_empty() {
        html.push_str("<div class=\"empty\"><p class=\"empty-title\">No accounts yet</p></div></div></div></div>");
        return html;
    }
    let peak = activity.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);
    let last = activity.len().saturating_sub(1);
    html.push_str("<div class=\"bars mt-4\" role=\"img\" aria-label=\"Accounts by month of last activity\">");
    for (index, (month, number)) in activity.iter().enumerate() {
        let height = percent_of(*number, peak).max(3);
        let latest = if index == last { " latest" } else { "" };
        let label = if index == last || *number == peak {
            format!("<span class=\"v num\">{}</span>", grouped(*number))
        } else {
            String::new()
        };
        let _ = write!(
            html,
            "<div class=\"bar{latest}\" data-tip=\"{}: {} accounts\">{label}<i style=\"height:{height}%\"></i></div>",
            escape(month),
            grouped(*number),
        );
    }
    html.push_str("</div><div class=\"axis\">");
    for (month, _) in activity {
        let _ = write!(html, "<span>{}</span>", escape(month));
    }
    html.push_str("</div><details class=\"mt-3\"><summary class=\"text-secondary small\">Show as table</summary>\
                   <table class=\"table table-sm mt-2\"><thead><tr><th>Month</th><th class=\"text-end\">Accounts</th></tr></thead><tbody>");
    for (month, number) in activity {
        let _ = write!(html, "<tr><td>{}</td><td class=\"text-end num\">{}</td></tr>", escape(month), grouped(*number));
    }
    html.push_str("</tbody></table></details></div></div></div>");
    html
}

/// Кольцо: доли активности. Три ряда — легенда с числами (цвет не один).
fn activity_split(d: &Dashboard) -> String {
    let total = d.active_this_month.saturating_add(d.active_last_month).saturating_add(d.dormant).max(1);
    let a = percent_of(d.active_this_month, total);
    let b = percent_of(d.active_last_month, total).saturating_add(a).min(100);
    format!(
        "<div class=\"col-lg-5\"><div class=\"card h-100\"><div class=\"card-header\"><h3 class=\"card-title\">Activity split</h3></div>\
         <div class=\"card-body d-flex align-items-center gap-4 flex-wrap\">\
         <div class=\"donut\" role=\"img\" aria-label=\"Active this month {a}%, last month {lm}%, inactive {ia}%\" \
         style=\"background:conic-gradient(var(--s1) 0 {a}%,#141a4a {a}% calc({a}% + .6%),var(--s2) calc({a}% + .6%) {b}%,#141a4a {b}% calc({b}% + .6%),var(--s3) calc({b}% + .6%) 100%)\">\
         <div class=\"mid\"><b class=\"num\">{a}%</b><small>active now</small></div></div>\
         <div class=\"flex-fill\"><div class=\"mb-2\"><span class=\"legend-dot c1\"></span>This month <b class=\"float-end num\">{n1}</b></div>\
         <div class=\"mb-2\"><span class=\"legend-dot c2\"></span>Last month <b class=\"float-end num\">{n2}</b></div>\
         <div><span class=\"legend-dot c3\"></span>Inactive 2+ months <b class=\"float-end num\">{n3}</b></div>\
         <div class=\"text-secondary small mt-3\">Inactive accounts are deleted after 12 months.</div></div></div></div></div>",
        lm = percent_of(d.active_last_month, total),
        ia = percent_of(d.dormant, total),
        n1 = grouped(d.active_this_month),
        n2 = grouped(d.active_last_month),
        n3 = grouped(d.dormant),
    )
}

/// Полоса: доступ к каналам — по @имени, по заявке, по ссылке.
fn channel_access(d: &Dashboard) -> String {
    let link_only = d
        .channels
        .saturating_sub(d.public_channels)
        .saturating_sub(d.closed_channels)
        .max(0);
    let total = d.channels.max(1);
    format!(
        "<div class=\"col-xl-6\"><div class=\"card\"><div class=\"card-header\"><h3 class=\"card-title\">Channel access</h3></div>\
         <div class=\"card-body\"><div class=\"stack mb-3\" role=\"img\" aria-label=\"Public {p}, by request {c}, by link {l}\">\
         <i class=\"c1\" style=\"flex:{p}\"></i><i class=\"c2\" style=\"flex:{c}\"></i><i class=\"c3\" style=\"flex:{l}\"></i></div>\
         <div class=\"row\"><div class=\"col\"><span class=\"legend-dot c1\"></span>Public @name<div class=\"h3 m-0 num\">{pg}</div><div class=\"text-secondary small\">{pp}% · server can read</div></div>\
         <div class=\"col\"><span class=\"legend-dot c2\"></span>By request<div class=\"h3 m-0 num\">{cg}</div><div class=\"text-secondary small\">{cp}% · members only</div></div>\
         <div class=\"col\"><span class=\"legend-dot c3\"></span>By link<div class=\"h3 m-0 num\">{lg}</div><div class=\"text-secondary small\">{lp}% · encrypted</div></div></div></div></div></div>",
        p = d.public_channels.max(0),
        c = d.closed_channels.max(0),
        l = link_only,
        pg = grouped(d.public_channels),
        cg = grouped(d.closed_channels),
        lg = grouped(link_only),
        pp = percent_of(d.public_channels, total),
        cp = percent_of(d.closed_channels, total),
        lp = percent_of(link_only, total),
    )
}

fn tabs<T: Copy + PartialEq>(
    base: &str,
    current: T,
    all: &[T],
    code: fn(T) -> &'static str,
    label: fn(T) -> &'static str,
    query: &str,
) -> String {
    let mut html = String::from("<nav class=\"tabs\" aria-label=\"Filter\">");
    for view in all {
        let selected = if *view == current { " aria-current=\"page\"" } else { "" };
        let _ = write!(
            html,
            "<a href=\"{base}?view={}&amp;q={}\"{selected}>{}</a>",
            code(*view),
            escape(&url_part(query)),
            escape(label(*view)),
        );
    }
    html.push_str("</nav>");
    html
}

/// Поиск — только буквы, цифры и `_` (так выглядят имена): в адрес без
/// кодирования.
fn url_part(query: &str) -> String {
    query
        .trim()
        .trim_start_matches('@')
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .take(32)
        .collect()
}

fn search_form(base: &str, view: &str, query: &str, placeholder: &str) -> String {
    format!(
        "<form method=\"get\" action=\"{base}\" class=\"ms-auto\"><input type=\"hidden\" name=\"view\" value=\"{view}\">\
         <div class=\"input-icon\"><span class=\"input-icon-addon\">{}</span>\
         <input class=\"form-control\" name=\"q\" value=\"{}\" placeholder=\"{}\" aria-label=\"Search\" autocomplete=\"off\" spellcheck=\"false\"></div></form>",
        icon("search"),
        escape(&url_part(query)),
        escape(placeholder),
    )
}

fn pager(base: &str, view: &str, query: &str, page: i64, more: bool) -> String {
    if page == 0 && !more {
        return String::new();
    }
    let q = escape(&url_part(query));
    let prev = if page > 0 {
        format!(
            "<li class=\"page-item\"><a class=\"page-link\" href=\"{base}?view={view}&amp;q={q}&amp;page={}\">{} Previous</a></li>",
            page.saturating_sub(1),
            icon("chevron-left")
        )
    } else {
        String::new()
    };
    let next = if more {
        format!(
            "<li class=\"page-item\"><a class=\"page-link\" href=\"{base}?view={view}&amp;q={q}&amp;page={}\">Next {}</a></li>",
            page.saturating_add(1),
            icon("chevron-right")
        )
    } else {
        String::new()
    };
    format!(
        "<div class=\"card-footer d-flex align-items-center\"><p class=\"m-0 text-secondary\">Page {}</p>\
         <ul class=\"pagination m-0 ms-auto\">{prev}{next}</ul></div>",
        page.saturating_add(1)
    )
}

/// Страница аккаунтов.
#[must_use]
pub fn accounts_html(rows: &[AccountRow], view: AccountView, query: &str, page: i64, more: bool, csrf: &str) -> String {
    let mut html = format!(
        "<div class=\"card\"><div class=\"card-header d-flex flex-wrap gap-2\">{}{}</div>",
        tabs("/accounts", view, &AccountView::ALL, AccountView::code, AccountView::label, query),
        search_form("/accounts", view.code(), query, "Username starts with…"),
    );

    if rows.is_empty() {
        html.push_str("<div class=\"empty\"><p class=\"empty-title\">No accounts match</p>\
                       <p class=\"empty-subtitle text-secondary\">Try another filter or a shorter name.</p></div></div>");
        return html;
    }

    html.push_str(
        "<div class=\"table-responsive\"><table class=\"table table-vcenter card-table\"><thead><tr><th>Account</th><th>Last active</th>\
         <th class=\"text-end\">Devices</th><th class=\"text-end\">Channels</th><th class=\"text-end\">Reporters</th>\
         <th>Premium</th><th class=\"w-1\"></th></tr></thead><tbody>",
    );
    for row in rows {
        let mut badges = String::new();
        if row.bot {
            badges.push_str(" <span class=\"badge bg-info-lt ms-1\">bot</span>");
        }
        if row.premium {
            badges.push_str(" <span class=\"badge bg-primary-lt ms-1\">premium</span>");
        }
        let (value, label, class) = if row.premium {
            ("off", "Revoke", "btn btn-sm")
        } else {
            ("on", "Grant", "btn btn-sm btn-primary")
        };
        let reporters = if row.reporters > 0 {
            format!("<span class=\"badge bg-danger-lt\">{}</span>", row.reporters)
        } else {
            "<span class=\"text-secondary\">0</span>".to_owned()
        };
        let _ = write!(
            html,
            "<tr><td><div class=\"d-flex align-items-center gap-2\">{ava}<span class=\"fw-medium\">@{name}</span>{badges}</div></td>\
             <td class=\"text-secondary\">{active}</td><td class=\"text-end num\">{devices}</td><td class=\"text-end num\">{channels}</td>\
             <td class=\"text-end\">{reporters}</td>\
             <td><form method=\"post\" action=\"/accounts/{id}/premium\" class=\"m-0\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"username\" value=\"{name}\">\
             <input type=\"hidden\" name=\"premium\" value=\"{value}\"><input type=\"hidden\" name=\"back\" value=\"{view}\">\
             <button class=\"{class}\">{crown} {label}</button></form></td>\
             <td><a class=\"btn btn-sm btn-ghost-secondary\" href=\"/account?username={name}\">Open {go}</a></td></tr>",
            ava = avatar(&row.username),
            name = escape(&row.username),
            active = escape(&row.active_month),
            devices = row.devices,
            channels = row.channels,
            id = row.account_id,
            csrf = escape(csrf),
            view = view.code(),
            crown = icon("crown"),
            go = icon("arrow-up-right"),
        );
    }
    html.push_str("</tbody></table></div>");
    html.push_str(&pager("/accounts", view.code(), query, page, more));
    html.push_str("</div><p class=\"text-secondary small mt-3\">Revoking premium also removes the account's bots. \
                   Deleting an account is done from its card or from the report queue.</p>");
    html
}

/// Страница каналов.
#[must_use]
pub fn channels_html(rows: &[ChannelRow], view: ChannelView, query: &str, page: i64, more: bool) -> String {
    let mut html = format!(
        "<div class=\"card\"><div class=\"card-header d-flex flex-wrap gap-2\">{}{}</div>",
        tabs("/channels", view, &ChannelView::ALL, ChannelView::code, ChannelView::label, query),
        search_form("/channels", view.code(), query, "@name or owner starts with…"),
    );

    if rows.is_empty() {
        html.push_str("<div class=\"empty\"><p class=\"empty-title\">No channels match</p></div></div>");
        return html;
    }

    html.push_str(
        "<div class=\"table-responsive\"><table class=\"table table-vcenter card-table\"><thead><tr><th>Channel</th><th>Owner</th><th>Access</th>\
         <th class=\"text-end\">Subscribers</th><th class=\"text-end\">Posts</th><th class=\"text-end\">Reports</th><th>Created</th></tr></thead><tbody>",
    );
    for row in rows {
        let name = row.handle.as_ref().map_or_else(
            || format!("<span class=\"text-secondary\">private · {}</span>", row.channel_id.to_string().get(..8).unwrap_or("")),
            |handle| format!("<span class=\"fw-medium\">@{}</span>", escape(handle)),
        );
        let access = if row.handle.is_some() {
            format!("<span class=\"badge bg-info-lt\">{} public</span>", icon("world"))
        } else if row.closed {
            format!("<span class=\"badge bg-success-lt\">{} by request</span>", icon("lock"))
        } else {
            format!("<span class=\"badge\">{} by link</span>", icon("link"))
        };
        let reports = if row.reports > 0 {
            format!("<a class=\"badge bg-danger-lt\" href=\"/reports\">{}</a>", row.reports)
        } else {
            "<span class=\"text-secondary\">0</span>".to_owned()
        };
        let _ = write!(
            html,
            "<tr><td><div class=\"d-flex align-items-center gap-2\">{ava}{name}</div></td>\
             <td><a href=\"/account?username={owner}\">@{owner}</a></td><td>{access}</td>\
             <td class=\"text-end num\">{subs}</td><td class=\"text-end num\">{posts}</td><td class=\"text-end\">{reports}</td>\
             <td class=\"text-secondary\">{created}</td></tr>",
            ava = avatar(row.handle.as_deref().unwrap_or(&row.owner)),
            owner = escape(&row.owner),
            subs = grouped(row.subscribers),
            posts = grouped(row.posts),
            created = escape(&row.created),
        );
    }
    html.push_str("</tbody></table></div>");
    html.push_str(&pager("/channels", view.code(), query, page, more));
    html.push_str("</div><p class=\"text-secondary small mt-3\">Titles and posts of channels without a public @name are \
                   end-to-end encrypted: the server — and this view — cannot read them.</p>");
    html
}

/// Страница журнала.
#[must_use]
pub fn journal_html(rows: &[JournalRow], reason_label: fn(&str) -> String) -> String {
    let mut html = String::from(
        "<div class=\"card\"><div class=\"card-header\"><div><h3 class=\"card-title\">Moderation decisions</h3>\
         <div class=\"card-subtitle text-secondary\">Recorded without the account name, to the hour — the records the transparency report is built from.</div></div></div>",
    );
    if rows.is_empty() {
        html.push_str("<div class=\"empty\"><p class=\"empty-title\">No moderation actions yet</p></div></div>");
        return html;
    }
    html.push_str("<div class=\"list-group list-group-flush\">");
    for row in rows {
        let (glyph, tone, action) = match row.action.as_str() {
            "account_deleted" => ("trash", "warn", "Account deleted"),
            "reports_dismissed" => ("check", "ok", "Reports dismissed"),
            other => ("list-details", "info", other),
        };
        let _ = write!(
            html,
            "<div class=\"list-group-item\"><div class=\"row align-items-center\">\
             <div class=\"col-auto\"><span class=\"stat-tile tone-{tone}\">{}</span></div>\
             <div class=\"col\"><div class=\"fw-medium\">{}</div><div class=\"text-secondary small\">Reason: {} · {} reporter{}</div></div>\
             <div class=\"col-auto text-secondary small num\">{} UTC</div></div></div>",
            icon(glyph),
            escape(action),
            escape(&reason_label(&row.reason)),
            row.reporters,
            if row.reporters == 1 { "" } else { "s" },
            escape(&row.hour),
        );
    }
    html.push_str("</div></div>");
    html
}

/// Страница здоровья базы.
#[must_use]
pub fn health_html(h: &Health, bytes: fn(i64) -> String) -> String {
    let backlog_tone = match h.oldest_envelope_hours {
        Some(hours) if hours >= 72 => "warn",
        _ => "ok",
    };
    let mut html = String::from("<div class=\"row row-cards mb-4\">");
    html.push_str(&stat("database", "ok", "PostgreSQL", &h.version, &format!("up {}", h.uptime)));
    html.push_str(&stat("server", "info", "Connections", &grouped(h.connections), "to this database"));
    html.push_str(&stat("stack-2", "info", "Database size", &bytes(h.database_bytes), "including indexes"));
    html.push_str(&stat(
        "send",
        backlog_tone,
        "Delivery backlog",
        &grouped(h.envelopes),
        &h.oldest_envelope_hours
            .map_or_else(|| "queue is empty".to_owned(), |hours| format!("oldest waits {hours} h")),
    ));
    html.push_str(
        "</div><div class=\"card\"><div class=\"card-header\"><h3 class=\"card-title\">Largest tables</h3></div>\
         <div class=\"table-responsive\"><table class=\"table table-vcenter card-table\"><thead><tr><th>Table</th>\
         <th class=\"w-50\">Share of the largest</th><th class=\"text-end\">Size</th></tr></thead><tbody>",
    );
    let largest = h.tables.first().map_or(1, |(_, size)| (*size).max(1));
    for (table, size) in &h.tables {
        let _ = write!(
            html,
            "<tr><td><code>{}</code></td><td><div class=\"progress progress-sm\"><div class=\"progress-bar bg-primary\" style=\"width:{}%\"></div></div></td>\
             <td class=\"text-end num\">{}</td></tr>",
            escape(table),
            percent_of(*size, largest).max(1),
            escape(&bytes(*size)),
        );
    }
    html.push_str(
        "</tbody></table></div></div><p class=\"text-secondary small mt-3\">Machines, disks, certificates and backups are watched by \
         the monitor on every server; problems arrive in Telegram. Undelivered envelopes expire after 30 days.</p>",
    );
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_wildcards_are_literal() {
        assert_eq!(prefix_pattern("@Bob_1"), "bob\\_1%");
        assert_eq!(prefix_pattern("50%"), "50\\%%");
        assert_eq!(prefix_pattern(""), "%");
    }

    #[test]
    fn search_in_links_is_plain() {
        assert_eq!(url_part("@a&b<c>d_1"), "abcd_1");
    }

    #[test]
    fn views_parse_with_fallback() {
        assert_eq!(AccountView::parse(Some("premium")), AccountView::Premium);
        assert_eq!(AccountView::parse(Some("<x>")), AccountView::All);
        assert_eq!(ChannelView::parse(None), ChannelView::All);
    }

    #[test]
    fn numbers_are_grouped() {
        assert_eq!(grouped(7), "7");
        assert_eq!(grouped(1284), "1\u{202F}284");
        assert_eq!(grouped(1_000_000), "1\u{202F}000\u{202F}000");
    }

    #[test]
    fn percent_is_bounded() {
        assert_eq!(percent_of(5, 0), 0);
        assert_eq!(percent_of(50, 100), 50);
        assert_eq!(percent_of(500, 100), 100);
    }

    #[test]
    fn avatar_escapes_and_has_initials() {
        let html = avatar("anna_k");
        assert!(html.contains(">AK<"));
        assert!(!avatar("<script>").contains("<script>"));
    }
}
