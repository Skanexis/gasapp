// SPDX-License-Identifier: AGPL-3.0-only

//! Админ-центр оператора GasApp.
//!
//! # Что это
//!
//! Отдельная программа рядом с сервером: жалобы и действия по ним,
//! счётчики состояния, отчёт о прозрачности. В публичном API админских
//! путей нет вовсе — атаковать через интернет нечего.
//!
//! # 🔐 Граница приватности
//!
//! Админ-центр показывает только то, что у сервера и так есть, и в том
//! виде, которого хватает решению:
//!
//! * **сводка** — числа, ни одного имени;
//! * **жалобы** — имя аккаунта, на который пожаловались, число **разных**
//!   жалобщиков (не они сами), время жалоб с точностью до часа, месяц
//!   создания аккаунта;
//! * **аккаунт** — поиск только по точному имени: перечня пользователей
//!   нет и не будет;
//! * **прозрачность** — сколько действий, за что, по месяцам, без имён.
//!
//! Переписки, адресов, истории входов, графа «кто кому пишет» здесь нет:
//! их нет в базе, и админ-центр их не добавляет.
//!
//! # Доступ
//!
//! Слушает только петлю (`127.0.0.1`/`::1`); снаружи — через SSH-туннель
//! или onion-сервис. Вход — токеном оператора (`auth`).

pub mod auth;
pub mod push;
pub mod queries;

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{Form, Path, Query, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, COOKIE, REFERRER_POLICY, SET_COOKIE,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use auth::{session_from_cookies, Auth, LoginError, SESSION_COOKIE};
use queries::Reason;

/// Состояние админ-центра.
#[derive(Debug)]
pub struct AdminState {
    /// База сервера.
    pub pool: PgPool,
    /// Вход и сессии.
    pub auth: Auth,
}

/// Маршруты админ-центра.
pub fn router(state: Arc<AdminState>) -> Router {
    let protected = Router::new()
        .route("/", get(summary_page))
        .route("/reports", get(reports_page))
        .route("/account", get(account_page))
        .route("/transparency", get(transparency_page))
        .route("/accounts/:id/delete", post(delete_account))
        .route("/accounts/:id/dismiss", post(dismiss_reports))
        .route("/channels/:id/delete", post(delete_channel))
        .route("/channels/:id/dismiss", post(dismiss_channel_reports))
        .route("/accounts/:id/premium", post(set_premium))
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_session,
        ));

    Router::new()
        .route("/login", get(login_page).post(login_submit))
        .merge(protected)
        .layer(middleware::from_fn(same_origin))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// 🔐 Запросы — только к своему имени и только со своих страниц
/// (аудит 2026-10-02, S-5).
///
/// * `Host` — петля или `.onion`. Админ-центр слушает петлю, но браузер
///   оператора ходит туда со всех открытых вкладок: чужой сайт, чьё имя
///   переназначено на 127.0.0.1 (DNS rebinding), иначе говорил бы
///   с админ-центром как со своим.
/// * `Origin` у POST — тот же хост. Прежде чужая страница отправляла
///   форму входа с пятью неверными токенами и закрывала вход оператору
///   на десять минут — сколько угодно раз. Cookie с `SameSite=Strict`
///   от этого не защищает: вход происходит без сессии.
async fn same_origin(request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    // Без `Host` браузер не ходит (HTTP/1.1 его требует), а переназначение
    // имени — атака именно через браузер.
    if !host.is_empty() && !host_allowed(&host) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }

    if request.method() == axum::http::Method::POST {
        if let Some(origin) = request
            .headers()
            .get(axum::http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            let origin = origin.to_ascii_lowercase();
            let same = origin == format!("http://{host}") || origin == format!("https://{host}");
            if !same {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }

    next.run(request).await
}

/// Петля (`127.0.0.1`, `localhost`, `[::1]`) или onion-адрес, с портом или без.
#[must_use]
pub fn host_allowed(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };

    matches!(name, "127.0.0.1" | "localhost" | "::1")
        || name
            .strip_suffix(".onion")
            .is_some_and(|label| !label.is_empty())
}

/// 🔐 Заголовки на каждый ответ: без скриптов, без встраивания, без
/// кеша и без утечки адреса в Referer.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // `no-referrer` makes browsers send `Origin: null` on HTML form POSTs;
    // our same-origin guard would then reject the admin's own login form.
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    response
}

/// Сессия из запроса: идентификатор и токен CSRF.
fn session(state: &AdminState, headers: &HeaderMap) -> Option<(String, String)> {
    let cookies = headers.get(COOKIE)?.to_str().ok()?;
    let id = session_from_cookies(cookies)?.to_owned();
    let csrf = state.auth.touch(&id)?;

    Some((id, csrf))
}

/// Без сессии — на страницу входа.
async fn require_session(
    State(state): State<Arc<AdminState>>,
    request: Request,
    next: Next,
) -> Response {
    if session(&state, request.headers()).is_none() {
        return Redirect::to("/login").into_response();
    }

    next.run(request).await
}

// ---------------------------------------------------------------------
// Вход и выход

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_page() -> Html<String> {
    Html(login_html(None))
}

async fn login_submit(
    State(state): State<Arc<AdminState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    match state.auth.login(&form.token) {
        Ok(id) => {
            let cookie = format!("{SESSION_COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/");
            ([(SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Err(LoginError::Wrong) => (
            StatusCode::UNAUTHORIZED,
            Html(login_html(Some("Invalid operator token."))),
        )
            .into_response(),
        Err(LoginError::Locked) => (
            StatusCode::TOO_MANY_REQUESTS,
            Html(login_html(Some(
                "Too many attempts. Try again in 10 minutes.",
            ))),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some((id, _)) = session(&state, &headers) {
        if state.auth.csrf_matches(&id, &form.csrf) {
            state.auth.logout(&id);
        }
    }

    let cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    ([(SET_COOKIE, cookie)], Redirect::to("/login")).into_response()
}

// ---------------------------------------------------------------------
// Страницы

async fn summary_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };

    match queries::summary(&state.pool).await {
        Ok(summary) => Html(layout("Overview", &csrf, &summary_html(&summary))).into_response(),
        Err(error) => database_error(&error),
    }
}

#[derive(Deserialize)]
struct Flash {
    done: Option<String>,
}

async fn reports_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(flash): Query<Flash>,
) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let rows = match queries::reported_accounts(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => return database_error(&error),
    };
    let channels = match queries::reported_channels(&state.pool).await {
        Ok(channels) => channels,
        Err(error) => return database_error(&error),
    };

    let mut body = format!(
        "<div class=\"queue-summary\" aria-label=\"Current report queue\">\
         <div><span>ACCOUNT CASES</span><b class=\"num\">{}</b><small>Accounts awaiting review</small></div>\
         <div><span>CHANNEL CASES</span><b class=\"num\">{}</b><small>Channels awaiting review</small></div>\
         <div class=\"queue-message\"><span>REVIEW STANDARD</span><strong>Evidence before action.</strong>\
         <small>Compare reports and certificates before making a decision.</small></div></div>",
        rows.len(),
        channels.len()
    );
    body.push_str(&reports_html(&rows, &csrf, flash.done.as_deref()));
    body.push_str(&channel_reports_html(&channels, &csrf));

    Html(layout("Reports", &csrf, &body)).into_response()
}

/// Удаляет канал, на который жаловались.
async fn delete_channel(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(channel_id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match queries::delete_reported_channel(&state.pool, channel_id).await {
        Ok(()) => {
            tracing::info!("админ-центр: канал удалён по жалобам");
            Redirect::to("/reports?done=channel_deleted").into_response()
        }
        Err(error) => database_error(&error),
    }
}

/// Отклоняет жалобы на канал.
async fn dismiss_channel_reports(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(channel_id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match queries::dismiss_channel_reports(&state.pool, channel_id).await {
        Ok(()) => Redirect::to("/reports?done=dismissed").into_response(),
        Err(error) => database_error(&error),
    }
}

#[derive(Deserialize)]
struct Lookup {
    username: Option<String>,
}

async fn account_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(lookup): Query<Lookup>,
) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };

    let wanted = lookup
        .username
        .as_deref()
        .map(canonical_username)
        .filter(|name| !name.is_empty());

    let card = match &wanted {
        Some(name) => match queries::account_by_username(&state.pool, name).await {
            Ok(card) => Some(card),
            Err(error) => return database_error(&error),
        },
        None => None,
    };

    Html(layout(
        "Account",
        &csrf,
        &account_html(
            wanted.as_deref(),
            card.as_ref().and_then(Option::as_ref),
            &csrf,
        ),
    ))
    .into_response()
}

async fn transparency_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };

    match queries::transparency(&state.pool).await {
        Ok(rows) => Html(layout("Transparency", &csrf, &transparency_html(&rows))).into_response(),
        Err(error) => database_error(&error),
    }
}

// ---------------------------------------------------------------------
// Действия

#[derive(Deserialize)]
struct DeleteForm {
    csrf: String,
    reason: String,
    confirm: Option<String>,
}

async fn delete_account(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Подтверждение проверяется и здесь, а не только галочкой в форме:
    // удаление необратимо.
    let Some(reason) = Reason::parse(&form.reason).filter(|reason| *reason != Reason::Unfounded)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if form.confirm.as_deref() != Some("yes") {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match queries::delete_account(&state.pool, account_id, reason).await {
        Ok(_) => {
            tracing::info!(reason = reason.code(), "админ-центр: аккаунт удалён");
            Redirect::to("/reports?done=deleted").into_response()
        }
        Err(error) => database_error(&error),
    }
}

async fn dismiss_reports(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match queries::dismiss_reports(&state.pool, account_id).await {
        Ok(_) => Redirect::to("/reports?done=dismissed").into_response(),
        Err(error) => database_error(&error),
    }
}

#[derive(Deserialize)]
struct PremiumForm {
    csrf: String,
    /// Имя аккаунта — только чтобы вернуться на его карточку.
    username: String,
    /// `on` — выдать, иначе снять.
    premium: String,
}

/// Выдаёт или снимает премиум — право создавать каналы.
///
/// Премиум выдаётся вручную: оплаты в приложении нет, и решение о том,
/// кому можно вести каналы, принимает оператор.
async fn set_premium(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    Form(form): Form<PremiumForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let premium = form.premium == "on";

    match gasapp_server_db::channels::set_premium_by_id(&state.pool, account_id, premium).await {
        Ok(_) => {
            tracing::info!(premium, "админ-центр: премиум изменён");
            // Имя — только из букв, цифр и «_» (каноничное): в адрес
            // подставляется без кодирования.
            let name = canonical_username(&form.username);
            let safe = name
                .chars()
                .all(|symbol| symbol.is_ascii_alphanumeric() || symbol == '_');

            if safe {
                Redirect::to(&format!("/account?username={name}")).into_response()
            } else {
                Redirect::to("/account").into_response()
            }
        }
        Err(error) => {
            tracing::error!(%error, "админ-центр: ошибка базы");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<p>Database error. See the control center logs.</p>".to_owned()),
            )
                .into_response()
        }
    }
}

/// Ошибка базы — без подробностей на странице, с ними в журнале.
fn database_error(error: &sqlx::Error) -> Response {
    tracing::error!(%error, "админ-центр: ошибка базы");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html("<p>Database error. See the control center logs.</p>".to_owned()),
    )
        .into_response()
}

/// Имя в том виде, в каком его хранит сервер: без «@», строчными.
fn canonical_username(raw: &str) -> String {
    raw.trim().trim_start_matches('@').to_lowercase()
}

// ---------------------------------------------------------------------
// HTML

/// Экранирует текст для HTML. 🔐 Имена выбирают пользователи.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const STYLE: &str = include_str!("style.css");

fn layout(title: &str, csrf: &str, body: &str) -> String {
    let mut nav = String::new();
    for (label, href, number) in [
        ("Overview", "/", "01"),
        ("Reports", "/reports", "02"),
        ("Account", "/account", "03"),
        ("Transparency", "/transparency", "04"),
    ] {
        let current = if label == title {
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = write!(
            nav,
            "<a href=\"{href}\"{current}><span class=\"nav-number\">{number}</span>{label}</a>"
        );
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"theme-color\" content=\"#0c1027\">\
         <title>{title} · GasApp Control</title><style>{STYLE}</style></head><body>\
         <a class=\"skip-link\" href=\"#content\">Skip to content</a>\
         <div class=\"app-shell\"><header class=\"sidebar\">\
         <a class=\"brand\" href=\"/\"><span class=\"brand-mark\">✦</span><span>GasApp<small>CONTROL CENTER</small></span></a>\
         <p class=\"sidebar-label\">WORKSPACE</p><nav aria-label=\"Main navigation\">{nav}</nav>\
         <div class=\"sidebar-foot\"><span class=\"private-pill\">● Private operator access</span>\
         <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <button class=\"sign-out\">Sign out →</button></form></div></header>\
         <main id=\"content\" class=\"workspace\"><div class=\"page-head\"><div>\
         <span class=\"eyebrow\">OPERATIONS / {title}</span><h1>{title}</h1></div>\
         <span class=\"access-badge\">● OPERATOR SESSION</span></div>{body}</main></div></body></html>",
        title = escape(title),
        csrf = escape(csrf),
    )
}

fn login_html(error: Option<&str>) -> String {
    let error = error
        .map(|text| {
            format!(
                "<p class=\"flash error\" role=\"alert\">{}</p>",
                escape(text)
            )
        })
        .unwrap_or_default();

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"theme-color\" content=\"#0c1027\">\
         <title>Sign in · GasApp Control</title><style>{STYLE}</style></head><body><main class=\"login\">\
         <section class=\"login-panel\"><div class=\"login-brand\"><span class=\"brand-mark\">✦</span>GasApp <span>CONTROL</span></div>\
         <div class=\"eyebrow\">PRIVATE OPERATOR ACCESS</div>\
         <h1>Welcome back.</h1><p>Sign in to review reports and manage your service.</p>{error}\
         <form method=\"post\" action=\"/login\">\
         <label for=\"token\">Operator token</label>\
         <input id=\"token\" type=\"password\" name=\"token\" autocomplete=\"off\" required>\
         <button>Sign in securely →</button></form>\
         <p class=\"note\">Access this page through your SSH tunnel or private onion service.</p>\
         </section></main></body></html>"
    )
}

/// Размер в МБ или ГБ с одним знаком после запятой — целочисленно.
fn bytes(size: i64) -> String {
    const MIB: i64 = 1024 * 1024;
    const GIB: i64 = 1024 * MIB;

    let (unit, name) = if size >= GIB {
        (GIB, "GB")
    } else {
        (MIB, "MB")
    };
    let tenths = size.saturating_mul(10).checked_div(unit).unwrap_or(0);
    let whole = tenths.checked_div(10).unwrap_or(0);
    let fraction = tenths.checked_rem(10).unwrap_or(0);

    format!("{whole}.{fraction} {name}")
}

fn summary_html(summary: &queries::Summary) -> String {
    let cards = [
        ("Accounts", summary.accounts.to_string()),
        ("Devices", summary.devices.to_string()),
        ("Queued envelopes", summary.envelopes.to_string()),
        ("Attachments", summary.attachments.to_string()),
        ("Attachment storage", bytes(summary.attachments_bytes)),
        ("Database size", bytes(summary.database_bytes)),
        ("Reported accounts", summary.reported_accounts.to_string()),
        (
            "Key log epoch",
            summary
                .kt_epoch
                .map_or_else(|| "—".to_owned(), |epoch| epoch.to_string()),
        ),
    ];

    let queue_title = if summary.reported_accounts == 0 {
        "No account reports waiting".to_owned()
    } else if summary.reported_accounts == 1 {
        "1 reported account to review".to_owned()
    } else {
        format!("{} reported accounts to review", summary.reported_accounts)
    };
    let mut html = format!(
        "<section class=\"overview-showcase\"><div class=\"overview-copy\">\
         <span class=\"eyebrow\">YOUR NEXT ACTION</span><h2>{queue_title}</h2>\
         <p>Open the report queue to review account and channel cases. Channel reports are tracked separately.</p>\
         <a class=\"action-link\" href=\"/reports\">Review reports <span aria-hidden=\"true\">↗</span></a>\
         </div><div class=\"overview-actions\"><span>QUICK ACCESS</span>\
         <a href=\"/account\">Find an account <span aria-hidden=\"true\">↗</span></a>\
         <a href=\"/transparency\">View transparency <span aria-hidden=\"true\">↗</span></a>\
         </div></section><div class=\"section-title\"><h2>Service snapshot</h2><span>LIVE DATABASE TOTALS</span></div><div class=\"grid\">"
    );
    for (label, value) in cards {
        let _ = write!(
            html,
            "<div class=\"card\"><span>{}</span><b class=\"num\">{}</b></div>",
            escape(label),
            escape(&value)
        );
    }
    html.push_str(
        "</div><p class=\"note\">Operational totals only. The server does not retain readable conversations, email addresses, login history or a social graph, so this view cannot show them.</p>",
    );

    html
}

fn reason_options(selected: Option<Reason>) -> String {
    Reason::FOR_DELETION
        .iter()
        .fold(String::new(), |mut html, reason| {
            let _ = write!(
                html,
                "<option value=\"{}\"{}>{}</option>",
                reason.code(),
                if Some(*reason) == selected {
                    " selected"
                } else {
                    ""
                },
                escape(reason.label())
            );
            html
        })
}

fn delete_form(account_id: Uuid, csrf: &str) -> String {
    format!(
        "<form class=\"inline\" method=\"post\" action=\"/accounts/{account_id}/delete\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <select name=\"reason\" aria-label=\"Reason for deletion\">{options}</select>\
         <label><input type=\"checkbox\" name=\"confirm\" value=\"yes\" required> I understand this cannot be undone</label>\
         <button class=\"danger\">Confirm deletion</button></form>",
        csrf = escape(csrf),
        options = reason_options(Some(Reason::Spam)),
    )
}

fn reports_html(rows: &[queries::ReportedAccount], csrf: &str, done: Option<&str>) -> String {
    let mut html = String::new();

    match done {
        Some("deleted") => html.push_str("<p class=\"flash\" role=\"status\">Account deleted.</p>"),
        Some("dismissed") => {
            html.push_str("<p class=\"flash\" role=\"status\">Reports dismissed.</p>");
        }
        Some("channel_deleted") => {
            html.push_str("<p class=\"flash\" role=\"status\">Channel deleted.</p>");
        }
        _ => {}
    }

    html.push_str(
        "<div class=\"guidance\"><p>Each account report includes a server-signed sender certificate. It proves that the reported account sent a message, without exposing the conversation. Review within 24 hours; escalate child safety reports immediately under the operator policy.</p>\
         <p><strong>Review carefully.</strong> A bearer certificate can be reused by multiple accounts. Compare distinct certificates and reporting dates before taking action; reporter count alone is not evidence of widespread abuse.</p></div>\
         <h2>Reported accounts</h2>",
    );

    if rows.is_empty() {
        html.push_str("<p class=\"empty-state\">No account reports are waiting for review.</p>");
        return html;
    }

    html.push_str(
        "<div class=\"table-scroll reports-table\"><table><thead><tr><th>Account</th><th class=\"num\">Reporters</th>\
         <th class=\"num\">Certificates</th>\
         <th>First / latest report</th><th>Last active</th><th>Actions</th></tr></thead><tbody>",
    );
    for row in rows {
        let _ = write!(
            html,
            "<tr><td data-label=\"Account\">@{name}</td><td data-label=\"Reporters\" class=\"num\">{reporters}</td>\
             <td data-label=\"Certificates\" class=\"num\">{certificates}</td><td data-label=\"First / latest\">{first}<br>{last}</td><td data-label=\"Last active\">{active}</td><td data-label=\"Actions\"><div class=\"row-actions\">\
             <form class=\"inline\" method=\"post\" action=\"/accounts/{id}/dismiss\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button>Dismiss reports</button></form><details class=\"destructive-action\"><summary>Delete account</summary>{delete}</details></div></td></tr>",
            name = escape(&row.username),
            reporters = row.reporters,
            certificates = row.certificates,
            first = escape(&row.first_report),
            last = escape(&row.last_report),
            active = escape(&row.active_month),
            delete = delete_form(row.account_id, csrf),
            id = row.account_id,
            csrf = escape(csrf),
        );
    }
    html.push_str("</tbody></table></div>");

    html
}

/// Жалобы на каналы.
///
/// 🔐 Записи канала без публичного имени сервер не читает. Ссылка в
/// строке — та, что приложил жалобщик: с ней канал открывается в
/// приложении, и видно, на что жалуются.
fn channel_reports_html(rows: &[queries::ReportedChannel], csrf: &str) -> String {
    let mut html = String::from(
        "<h2>Reported channels</h2>\
         <p class=\"note\">Any account can report a channel; these reports do not include sender proof. Review linked posts in the app where a reporter supplied a link. Escalate child safety reports immediately. Deleting a channel cannot be undone and does not delete its owner.</p>",
    );

    if rows.is_empty() {
        html.push_str("<p class=\"empty-state\">No channel reports are waiting for review.</p>");
        return html;
    }

    html.push_str(
        "<div class=\"table-scroll reports-table\"><table><thead><tr><th>Channel</th><th>Owner</th><th class=\"num\">Reporters</th>\
         <th class=\"num\">Child safety</th><th>Latest report</th><th>Link</th>\
         <th>Actions</th></tr></thead><tbody>",
    );
    for row in rows {
        let name = row
            .handle
            .as_deref()
            .map_or_else(|| row.channel_id.to_string(), |handle| format!("@{handle}"));

        let _ = write!(
            html,
            "<tr><td data-label=\"Channel\">{name}</td><td data-label=\"Owner\">@{owner}</td><td data-label=\"Reporters\" class=\"num\">{reporters}</td>\
             <td data-label=\"Child safety\" class=\"num\">{child}</td><td data-label=\"Latest report\">{last}</td><td data-label=\"Link\"><code>{link}</code></td><td data-label=\"Actions\"><div class=\"row-actions\">\
             <form class=\"inline\" method=\"post\" action=\"/channels/{id}/dismiss\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button>Dismiss reports</button></form><details class=\"destructive-action\"><summary>Delete channel</summary>\
             <form class=\"inline\" method=\"post\" action=\"/channels/{id}/delete\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label><input type=\"checkbox\" name=\"confirm\" value=\"yes\" required> I understand this cannot be undone</label>\
             <button class=\"danger\">Confirm deletion</button></form></details></div></td></tr>",
            name = escape(&name),
            owner = escape(&row.owner),
            reporters = row.reporters,
            child = row.child_safety,
            last = escape(&row.last_report),
            link = escape(row.link.as_deref().unwrap_or("—")),
            id = row.channel_id,
            csrf = escape(csrf),
        );
    }
    html.push_str("</tbody></table></div>");

    html
}

fn premium_form(card: &queries::AccountCard, csrf: &str) -> String {
    let (state, value, action) = if card.premium {
        ("Enabled", "off", "Revoke premium and remove bots")
    } else {
        ("Not enabled", "on", "Grant premium")
    };

    format!(
        "{state} <form class=\"inline\" method=\"post\" action=\"/accounts/{id}/premium\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"username\" value=\"{name}\">\
         <input type=\"hidden\" name=\"premium\" value=\"{value}\">\
         <button>{action}</button></form>",
        id = card.account_id,
        csrf = escape(csrf),
        name = escape(&card.username),
    )
}

fn account_html(wanted: Option<&str>, card: Option<&queries::AccountCard>, csrf: &str) -> String {
    let mut html = format!(
        "<form class=\"lookup\" method=\"get\" action=\"/account\">\
         <input name=\"username\" aria-label=\"Exact username\" placeholder=\"Exact username\" value=\"{}\" required>\
         <button>Find account</button></form>\
         <p class=\"note\">Search by exact username only. There is no browsable directory of accounts.</p>",
        escape(wanted.unwrap_or_default())
    );

    match (wanted, card) {
        (Some(name), None) => {
            let _ = write!(
                html,
                "<p class=\"empty-state\">No account found for @{}.</p>",
                escape(name)
            );
        }
        (Some(_), Some(card)) => {
            let _ = write!(
                html,
                "<div class=\"table-scroll detail-table\"><table><tbody><tr><th>Account</th><td>@{name}</td></tr>\
                 <tr><th>Last active</th><td>{active}</td></tr>\
                 <tr><th>Devices</th><td class=\"num\">{devices}</td></tr>\
                 <tr><th>Reporters</th><td class=\"num\">{reporters}</td></tr>\
                 <tr><th>Certificates</th><td class=\"num\">{certificates}</td></tr>\
                 <tr><th>Premium</th><td>{premium}</td></tr>\
                 <tr><th>Channels</th><td class=\"num\">{channels}</td></tr>\
                 <tr><th>Bots</th><td class=\"num\">{bots}</td></tr>\
                 <tr><th>Bot owner</th><td>{owner}</td></tr>\
                 <tr><th>Actions</th><td>{delete}</td></tr></tbody></table></div>",
                name = escape(&card.username),
                active = escape(&card.active_month),
                devices = card.devices,
                reporters = card.reporters,
                certificates = card.certificates,
                premium = premium_form(card, csrf),
                channels = card.channels,
                bots = card.bots,
                owner = card.bot_owner.as_deref().map_or_else(
                    || "—".to_owned(),
                    |name| {
                        format!(
                            "<a href=\"/account?username={name}\">@{name}</a>",
                            name = escape(name)
                        )
                    }
                ),
                delete = delete_form(card.account_id, csrf),
            );
        }
        (None, _) => {}
    }

    html
}

fn transparency_html(rows: &[queries::TransparencyRow]) -> String {
    let mut html = String::from(
        "<p class=\"note\">Operator actions are grouped without names. These totals can be published in a transparency report.</p>",
    );

    if rows.is_empty() {
        html.push_str("<p class=\"empty-state\">No moderation actions have been recorded yet.</p>");
        return html;
    }

    html.push_str(
        "<div class=\"table-scroll\"><table><thead><tr><th>Month</th><th>Action</th><th>Reason</th>\
         <th class=\"num\">Count</th><th class=\"num\">Reporters</th></tr></thead><tbody>",
    );
    for row in rows {
        let action = match row.action.as_str() {
            "account_deleted" => "Account deleted",
            "reports_dismissed" => "Reports dismissed",
            other => other,
        };
        let reason: &str = match Reason::parse(&row.reason) {
            Some(reason) => reason.label(),
            None => &row.reason,
        };
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
            escape(&row.month),
            escape(action),
            escape(reason),
            row.count,
            row.reporters,
        );
    }
    html.push_str("</tbody></table></div>");

    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    /// В браузере `no-referrer` превращает Origin формы POST в `null`.
    /// Вход должен сохранить свой Origin, не передавая Referer чужим сайтам.
    #[tokio::test]
    async fn login_form_uses_same_origin_referrer_policy() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gasapp")
            .expect("URL базы");
        let auth = Auth::from_hash_hex(&auth::token_hash_hex("a long test token for admin login"))
            .expect("хеш токена");
        let app = router(Arc::new(AdminState { pool, auth }));

        let response = app
            .clone()
            .oneshot(
                Request::get("/login")
                    .header(header::HOST, "127.0.0.1:8480")
                    .body(Body::empty())
                    .expect("запрос"),
            )
            .await
            .expect("ответ");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[REFERRER_POLICY], "same-origin");

        // Чужой (или непрозрачный) Origin всё ещё отвергается до разбора формы.
        let response = app
            .oneshot(
                Request::post("/login")
                    .header(header::HOST, "127.0.0.1:8480")
                    .header(header::ORIGIN, "null")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("diagnostic=1"))
                    .expect("запрос"),
            )
            .await
            .expect("ответ");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// 🔐 Только петля и onion: имя чужого сайта, переназначенное
    /// на 127.0.0.1, не проходит (аудит 2026-10-02, S-5).
    #[test]
    fn only_loopback_and_onion_hosts_are_allowed() {
        for allowed in [
            "127.0.0.1:8480",
            "localhost:8480",
            "localhost",
            "[::1]:8480",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        ] {
            assert!(host_allowed(allowed), "{allowed} отвергнут");
        }

        for refused in [
            "evil.example:8480",
            "127.0.0.1.evil.example",
            "localhost.evil.example:8480",
            "onion.evil.example",
            "[::2]:8480",
        ] {
            assert!(!host_allowed(refused), "{refused} принят");
        }
    }

    /// 🔐 Имя выбирает пользователь — в HTML оно попадает только экранированным.
    #[test]
    fn user_chosen_text_is_escaped() {
        assert_eq!(
            escape("<script>alert('x')</script>&\""),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;"
        );
    }

    #[test]
    fn a_lookup_name_is_canonical() {
        assert_eq!(canonical_username("  @Alice "), "alice");
    }

    #[test]
    fn reasons_round_trip() {
        for reason in Reason::FOR_DELETION {
            assert_eq!(Reason::parse(reason.code()), Some(reason));
        }
        assert_eq!(Reason::parse("drop table"), None);
    }

    #[test]
    fn operator_pages_use_english_labels_and_page_navigation() {
        let login = login_html(None);
        assert!(login.contains("<html lang=\"en\">"));
        assert!(login.contains("Operator token"));

        let overview = layout("Overview", "test-csrf", "<p>Body</p>");
        assert!(overview.contains("<html lang=\"en\">"));
        assert!(overview.contains("aria-current=\"page\""));
        assert!(overview.contains("Skip to content"));
        assert!(overview.contains("name=\"csrf\" value=\"test-csrf\""));

        let reports = reports_html(&[], "test-csrf", None);
        assert!(reports.contains("No account reports"));
        let channels = channel_reports_html(&[], "test-csrf");
        assert!(channels.contains("No channel reports"));
        let overview = summary_html(&queries::Summary {
            reported_accounts: 3,
            ..queries::Summary::default()
        });
        assert!(overview.contains("3 reported accounts to review"));
        assert!(overview.contains("href=\"/reports\""));
        for reason in Reason::FOR_DELETION {
            assert!(reason.label().is_ascii());
        }
    }

    #[test]
    fn operator_content_has_no_untranslated_cyrillic() {
        let account = queries::AccountCard {
            account_id: Uuid::nil(),
            username: "alice".to_owned(),
            active_month: "2026-10".to_owned(),
            devices: 2,
            reporters: 1,
            certificates: 1,
            premium: false,
            channels: 0,
            bots: 0,
            bot_owner: None,
        };
        let report = queries::ReportedAccount {
            account_id: Uuid::nil(),
            username: "alice".to_owned(),
            active_month: "2026-10".to_owned(),
            reporters: 1,
            certificates: 1,
            first_report: "2026-10-01".to_owned(),
            last_report: "2026-10-02".to_owned(),
        };
        let channel = queries::ReportedChannel {
            channel_id: Uuid::nil(),
            handle: Some("updates".to_owned()),
            owner: "alice".to_owned(),
            reporters: 1,
            child_safety: 0,
            link: None,
            last_report: "2026-10-02".to_owned(),
        };
        let action = queries::TransparencyRow {
            month: "2026-10".to_owned(),
            action: "account_deleted".to_owned(),
            reason: "spam".to_owned(),
            count: 1,
            reporters: 1,
        };
        let pages = [
            login_html(Some("Invalid operator token.")),
            summary_html(&queries::Summary::default()),
            reports_html(&[report], "csrf", Some("deleted")),
            channel_reports_html(&[channel], "csrf"),
            account_html(Some("alice"), Some(&account), "csrf"),
            transparency_html(&[action]),
        ];
        assert!(pages[2].contains("<details class=\"destructive-action\">"));
        assert!(pages[2].contains("name=\"confirm\" value=\"yes\" required"));
        assert!(pages[2].contains("class=\"table-scroll reports-table\""));
        assert!(pages[2].contains("data-label=\"Account\""));
        assert!(pages[3].contains("<details class=\"destructive-action\">"));
        assert!(pages[3].contains("data-label=\"Channel\""));
        for page in pages {
            assert!(
                page.chars()
                    .all(|ch| !('\u{0400}'..='\u{04ff}').contains(&ch)),
                "operator page contains untranslated Cyrillic"
            );
        }
    }
}
