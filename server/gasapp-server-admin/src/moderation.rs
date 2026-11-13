// SPDX-License-Identifier: AGPL-3.0-only

//! Решения оператора по аккаунту: заморозка, блокировка, удаление
//! (миграция 0031).
//!
//! * **Заморозка** — на 1, 7 или 30 дней: аккаунт и переписка целы, но
//!   сервер отвергает его запросы (`423`), кроме вопроса о статусе.
//!   Срок вышел — снимается сама.
//! * **Блокировка** — до снятия оператором. Имя и адрес почты остаются
//!   занятыми, по имени аккаунт не находится.
//! * **Удаление** — необратимо (см. `queries::delete_account`).
//!
//! Ограничение владельца действует и на его ботов. Заморозка и
//! блокировка закрывают дело: жалобы и улики удаляются, в журнал
//! попадает решение — без имени, как и прежде.
//!
//! ⚠️ Чего мера не даёт: сертификат отправителя, выданный до решения,
//! живёт до суток, и запечатанные (sealed sender) сообщения по нему
//! сервер отличить не может.

use std::fmt::Write as _;

use sqlx::PgPool;
use uuid::Uuid;

use crate::icon;
use crate::queries::Reason;
use crate::escape;

/// На сколько дней можно заморозить.
pub const FREEZE_DAYS: [i32; 3] = [1, 7, 30];

/// Действующее ограничение аккаунта.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restricted {
    /// Блокировка до снятия; иначе — заморозка до [`Self::until`].
    pub blocked: bool,
    /// Конец заморозки, `ГГГГ-ММ-ДД ЧЧ:ММ UTC`.
    pub until: Option<String>,
    /// Причина (код).
    pub reason: Option<String>,
}

/// Мера мягче удаления.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    /// Заморозка на столько дней.
    Freeze(i32),
    /// Блокировка до снятия.
    Block,
}

impl Measure {
    /// Из формы: `freeze` с днями из [`FREEZE_DAYS`] либо `block`.
    #[must_use]
    pub fn parse(measure: &str, days: Option<i32>) -> Option<Self> {
        match measure {
            "block" => Some(Self::Block),
            "freeze" => days.filter(|days| FREEZE_DAYS.contains(days)).map(Self::Freeze),
            _ => None,
        }
    }

    const fn action(self) -> &'static str {
        match self {
            Self::Freeze(_) => "account_frozen",
            Self::Block => "account_blocked",
        }
    }
}

/// Ограничение аккаунта, если действует.
///
/// # Errors
///
/// Ошибка базы.
pub async fn restriction(pool: &PgPool, account_id: Uuid) -> Result<Option<Restricted>, sqlx::Error> {
    let row: Option<(Option<bool>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT restricted_until = 'infinity'::timestamptz,
                CASE WHEN restricted_until <> 'infinity'::timestamptz
                     THEN to_char(restricted_until AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') END,
                restriction_reason
           FROM accounts
          WHERE account_id = $1 AND restricted_until > now()",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(blocked, until, reason)| Restricted {
        blocked: blocked.unwrap_or(false),
        until,
        reason,
    }))
}

/// Замораживает либо блокирует аккаунт и закрывает дело по нему.
/// Повторная мера заменяет прежнюю (например, заморозку — блокировкой).
///
/// `false` — аккаунта нет.
///
/// # Errors
///
/// Ошибка базы.
pub async fn restrict(
    pool: &PgPool,
    account_id: Uuid,
    measure: Measure,
    reason: Reason,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let days = match measure {
        Measure::Freeze(days) => Some(days),
        Measure::Block => None,
    };
    let updated = sqlx::query(
        "UPDATE accounts
            SET restricted_until = CASE WHEN $2::int IS NULL THEN 'infinity'::timestamptz
                                        ELSE date_trunc('hour', now()) + $2::int * interval '1 day' END,
                restriction_reason = $3
          WHERE account_id = $1",
    )
    .bind(account_id)
    .bind(days)
    .bind(reason.code())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Ok(false);
    }

    let reporters: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT complainant_device) FROM sealed_sender_reports WHERE reported_account = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sealed_sender_reports WHERE reported_account = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM report_evidence WHERE reported_account = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO admin_actions (action, reason, reporters) VALUES ($1, $2, $3)")
        .bind(measure.action())
        .bind(reason.code())
        .bind(i32::try_from(reporters).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(true)
}

/// Снимает заморозку либо блокировку. `false` — снимать было нечего.
///
/// # Errors
///
/// Ошибка базы.
pub async fn lift(pool: &PgPool, account_id: Uuid) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let lifted = sqlx::query(
        "UPDATE accounts SET restricted_until = NULL, restriction_reason = NULL
          WHERE account_id = $1 AND restricted_until > now()",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if lifted > 0 {
        sqlx::query(
            "INSERT INTO admin_actions (action, reason, reporters) VALUES ('restriction_lifted', 'other', 0)",
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(lifted > 0)
}

/// Значок состояния: «Frozen until …» либо «Blocked».
#[must_use]
pub fn status_badge(restricted: Option<&Restricted>) -> String {
    match restricted {
        Some(Restricted { blocked: true, .. }) => {
            format!("<span class=\"badge badge-blocked\">{} Blocked</span>", icon("ban"))
        }
        Some(Restricted { until, .. }) => format!(
            "<span class=\"badge badge-frozen\">{} Frozen until {}</span>",
            icon("snowflake"),
            escape(until.as_deref().unwrap_or("—"))
        ),
        None => String::new(),
    }
}

fn reason_options(suggested: Reason) -> String {
    Reason::FOR_DELETION.iter().fold(String::new(), |mut out, reason| {
        let selected = if *reason == suggested { " selected" } else { "" };
        let _ = write!(
            out,
            "<option value=\"{}\"{selected}>{}</option>",
            reason.code(),
            escape(reason.label())
        );
        out
    })
}

fn reason_label(code: Option<&str>) -> &'static str {
    code.and_then(Reason::parse).map_or("not recorded", Reason::label)
}

/// Где оператор принимает решение: дело (`dismiss` — есть кнопка
/// «отклонить жалобы») либо карточка аккаунта.
pub struct Decision<'a> {
    pub account_id: Uuid,
    pub username: &'a str,
    pub restricted: Option<&'a Restricted>,
    pub suggested: Reason,
    pub csrf: &'a str,
    pub dismiss: bool,
}

/// Блок «Decision»: отклонить, заморозить, заблокировать, удалить.
#[must_use]
pub fn decision_html(decision: &Decision<'_>) -> String {
    let mut html = String::from(
        "<div class=\"card mb-4 decision\"><div class=\"card-header\"><h3 class=\"card-title\">Decision</h3>\
         <div class=\"card-actions text-secondary small\">From mildest to final</div></div><div class=\"card-body\">",
    );
    if let Some(restricted) = decision.restricted {
        html.push_str(&current_html(decision, restricted));
    }
    html.push_str("<div class=\"decision-grid\">");
    if decision.dismiss {
        html.push_str(&dismiss_tile(decision));
    }
    html.push_str(&freeze_tile(decision));
    if !decision.restricted.is_some_and(|r| r.blocked) {
        html.push_str(&block_tile(decision));
    }
    html.push_str(&delete_tile(decision));
    let _ = write!(
        html,
        "</div></div></div><p class=\"text-secondary small\">{} Reporter identities are never shown. \
         Decisions go to the journal without names. A freeze or block also covers the account's bots.</p>",
        icon("lock")
    );
    html
}

fn hidden(decision: &Decision<'_>) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"username\" value=\"{}\">\
         <input type=\"hidden\" name=\"back\" value=\"{}\">",
        escape(decision.csrf),
        escape(decision.username),
        if decision.dismiss { "case" } else { "account" }
    )
}

fn current_html(decision: &Decision<'_>, restricted: &Restricted) -> String {
    let what = if restricted.blocked {
        "This account is <b>blocked</b> until you lift it.".to_owned()
    } else {
        format!(
            "This account is <b>frozen until {} UTC</b>; it unfreezes by itself.",
            escape(restricted.until.as_deref().unwrap_or("—"))
        )
    };
    format!(
        "<div class=\"restriction-now\"><div>{badge}<p class=\"m-0 mt-2\">{what} Reason: {reason}.</p></div>\
         <form method=\"post\" action=\"/accounts/{id}/lift\">{hidden}\
         <button class=\"btn\">{undo} Lift restriction</button></form></div>",
        badge = status_badge(Some(restricted)),
        reason = escape(reason_label(restricted.reason.as_deref())),
        id = decision.account_id,
        hidden = hidden(decision),
        undo = icon("arrow-back-up"),
    )
}

fn dismiss_tile(decision: &Decision<'_>) -> String {
    format!(
        "<form class=\"decision-tile\" method=\"post\" action=\"/accounts/{id}/dismiss\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <h4>{check} No violation</h4><p>The reports and their evidence are deleted; the account stays as it is.</p>\
         <button class=\"btn w-100\">Dismiss reports</button></form>",
        id = decision.account_id,
        csrf = escape(decision.csrf),
        check = icon("circle-check"),
    )
}

fn freeze_tile(decision: &Decision<'_>) -> String {
    let days = FREEZE_DAYS.iter().fold(String::new(), |mut out, days| {
        let selected = if *days == 7 { " selected" } else { "" };
        let label = if *days == 1 { "1 day".to_owned() } else { format!("{days} days") };
        let _ = write!(out, "<option value=\"{days}\"{selected}>{label}</option>");
        out
    });
    format!(
        "<form class=\"decision-tile tile-freeze\" method=\"post\" action=\"/accounts/{id}/restrict\">{hidden}\
         <input type=\"hidden\" name=\"measure\" value=\"freeze\">\
         <h4>{snow} Freeze</h4><p>Nothing can be sent or received until the date; messages and channels are kept. Lifts itself.</p>\
         <div class=\"d-flex gap-2 mb-2\"><select class=\"form-select\" name=\"days\" aria-label=\"Freeze for\">{days}</select>\
         <select class=\"form-select\" name=\"reason\" aria-label=\"Reason for freezing\">{options}</select></div>\
         <button class=\"btn btn-freeze w-100\">{verb}</button></form>",
        id = decision.account_id,
        hidden = hidden(decision),
        snow = icon("snowflake"),
        options = reason_options(decision.suggested),
        verb = if decision.restricted.is_some() { "Freeze instead" } else { "Freeze account" },
    )
}

fn block_tile(decision: &Decision<'_>) -> String {
    format!(
        "<form class=\"decision-tile tile-block\" method=\"post\" action=\"/accounts/{id}/restrict\">{hidden}\
         <input type=\"hidden\" name=\"measure\" value=\"block\">\
         <h4>{ban} Block</h4><p>Until you lift it. The name and email stay taken, so the person cannot sign up again; the account cannot be found by name.</p>\
         <select class=\"form-select mb-2\" name=\"reason\" aria-label=\"Reason for blocking\">{options}</select>\
         <label class=\"form-check mb-2\"><input class=\"form-check-input\" type=\"checkbox\" name=\"confirm\" value=\"yes\" required> \
         <span class=\"form-check-label\">Block this account</span></label>\
         <button class=\"btn btn-block w-100\">Block account</button></form>",
        id = decision.account_id,
        hidden = hidden(decision),
        ban = icon("ban"),
        options = reason_options(decision.suggested),
    )
}

fn delete_tile(decision: &Decision<'_>) -> String {
    format!(
        "<form class=\"decision-tile tile-delete\" method=\"post\" action=\"/accounts/{id}/delete\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <h4>{trash} Delete</h4><p>The account, devices, keys, queue and evidence go at once. The name is freed. Cannot be undone.</p>\
         <select class=\"form-select mb-2\" name=\"reason\" aria-label=\"Reason for deletion\">{options}</select>\
         <label class=\"form-check mb-2\"><input class=\"form-check-input\" type=\"checkbox\" name=\"confirm\" value=\"yes\" required> \
         <span class=\"form-check-label\">I understand this cannot be undone</span></label>\
         <button class=\"btn btn-danger w-100\">Delete account</button></form>",
        id = decision.account_id,
        csrf = escape(decision.csrf),
        trash = icon("trash"),
        options = reason_options(decision.suggested),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_measures_parse() {
        assert_eq!(Measure::parse("block", None), Some(Measure::Block));
        assert_eq!(Measure::parse("freeze", Some(7)), Some(Measure::Freeze(7)));
        assert_eq!(Measure::parse("freeze", Some(365)), None);
        assert_eq!(Measure::parse("freeze", None), None);
        assert_eq!(Measure::parse("delete", Some(1)), None);
    }

    #[test]
    fn decision_shows_lift_only_when_restricted() {
        let frozen = Restricted { blocked: false, until: Some("2026-11-20 14:00".into()), reason: Some("spam".into()) };
        let mut decision = Decision {
            account_id: Uuid::nil(),
            username: "spammer42",
            restricted: None,
            suggested: Reason::Spam,
            csrf: "c",
            dismiss: true,
        };
        let open = decision_html(&decision);
        assert!(!open.contains("Lift restriction"));
        assert!(open.contains("Freeze account") && open.contains("Block account") && open.contains("Dismiss reports"));

        decision.restricted = Some(&frozen);
        let html = decision_html(&decision);
        assert!(html.contains("Lift restriction") && html.contains("frozen until 2026-11-20 14:00"));
        assert!(html.contains("Freeze instead") && html.contains("Block account"));

        let blocked = Restricted { blocked: true, ..Restricted::default() };
        decision.restricted = Some(&blocked);
        assert!(!decision_html(&decision).contains("Block account"));
    }
}
