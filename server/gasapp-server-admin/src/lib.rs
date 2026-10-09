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
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
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
            Html(login_html(Some("Неверный токен."))),
        )
            .into_response(),
        Err(LoginError::Locked) => (
            StatusCode::TOO_MANY_REQUESTS,
            Html(login_html(Some(
                "Вход закрыт на 10 минут после серии неверных токенов.",
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
        Ok(summary) => Html(layout("Сводка", &csrf, &summary_html(&summary))).into_response(),
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

    let mut body = reports_html(&rows, &csrf, flash.done.as_deref());
    body.push_str(&channel_reports_html(&channels, &csrf));

    Html(layout("Жалобы", &csrf, &body)).into_response()
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
        "Аккаунт",
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
        Ok(rows) => Html(layout("Прозрачность", &csrf, &transparency_html(&rows))).into_response(),
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
                Html("<p>Ошибка базы — подробности в журнале админ-центра.</p>".to_owned()),
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
        Html("<p>Ошибка базы — подробности в журнале админ-центра.</p>".to_owned()),
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

const STYLE: &str = "
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e8eb}
header{display:flex;gap:18px;align-items:center;padding:12px 24px;background:#171a21;border-bottom:1px solid #262b35}
header b{margin-right:12px}header a{color:#9fb3c8;text-decoration:none}header a:hover{color:#fff}
header form{margin-left:auto}main{max-width:1000px;margin:24px auto;padding:0 24px}
h1{font-size:22px}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #262b35;vertical-align:top}
th{color:#9aa4b2;font-weight:500}.num{font-variant-numeric:tabular-nums}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.card{background:#171a21;border:1px solid #262b35;border-radius:10px;padding:14px}
.card span{display:block;color:#9aa4b2;font-size:13px}.card b{font-size:22px}
.note{color:#9aa4b2;font-size:13px}.flash{background:#15321f;border:1px solid #2f6b43;padding:8px 12px;border-radius:8px}
button{background:#2b3240;color:#e6e8eb;border:1px solid #3a4352;border-radius:8px;padding:6px 12px;cursor:pointer}
button.danger{background:#5a1f24;border-color:#8a2f37}input,select{background:#0f1115;color:#e6e8eb;border:1px solid #3a4352;border-radius:8px;padding:6px 8px}
form.inline{display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap;margin:2px 0}
";

fn layout(title: &str, csrf: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title} · GasApp</title><style>{STYLE}</style></head><body>\
         <header><b>GasApp · админ-центр</b>\
         <a href=\"/\">Сводка</a><a href=\"/reports\">Жалобы</a>\
         <a href=\"/account\">Аккаунт</a><a href=\"/transparency\">Прозрачность</a>\
         <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <button>Выйти</button></form></header><main><h1>{title}</h1>{body}</main></body></html>",
        title = escape(title),
        csrf = escape(csrf),
    )
}

fn login_html(error: Option<&str>) -> String {
    let error = error
        .map(|text| format!("<p class=\"flash\">{}</p>", escape(text)))
        .unwrap_or_default();

    format!(
        "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Вход · GasApp</title><style>{STYLE}</style></head><body><main>\
         <h1>GasApp · админ-центр</h1>{error}\
         <form method=\"post\" action=\"/login\" class=\"inline\">\
         <input type=\"password\" name=\"token\" placeholder=\"Токен оператора\" autocomplete=\"off\" required>\
         <button>Войти</button></form>\
         <p class=\"note\">Доступ только с этой машины — через SSH-туннель или onion.</p>\
         </main></body></html>"
    )
}

/// Размер в МБ или ГБ с одним знаком после запятой — целочисленно.
fn bytes(size: i64) -> String {
    const MIB: i64 = 1024 * 1024;
    const GIB: i64 = 1024 * MIB;

    let (unit, name) = if size >= GIB {
        (GIB, "ГБ")
    } else {
        (MIB, "МБ")
    };
    let tenths = size.saturating_mul(10).checked_div(unit).unwrap_or(0);
    let whole = tenths.checked_div(10).unwrap_or(0);
    let fraction = tenths.checked_rem(10).unwrap_or(0);

    format!("{whole},{fraction} {name}")
}

fn summary_html(summary: &queries::Summary) -> String {
    let cards = [
        ("Аккаунтов", summary.accounts.to_string()),
        ("Устройств", summary.devices.to_string()),
        ("Конвертов в очереди", summary.envelopes.to_string()),
        ("Вложений", summary.attachments.to_string()),
        ("Место вложений", bytes(summary.attachments_bytes)),
        ("Размер базы", bytes(summary.database_bytes)),
        (
            "Аккаунтов с жалобами",
            summary.reported_accounts.to_string(),
        ),
        (
            "Эпоха журнала ключей",
            summary
                .kt_epoch
                .map_or_else(|| "—".to_owned(), |epoch| epoch.to_string()),
        ),
    ];

    let mut html = String::from("<div class=\"grid\">");
    for (label, value) in cards {
        let _ = write!(
            html,
            "<div class=\"card\"><span>{}</span><b class=\"num\">{}</b></div>",
            escape(label),
            escape(&value)
        );
    }
    html.push_str(
        "</div><p class=\"note\">Здесь только числа. Переписки, адресов, истории \
         входов и связей «кто кому пишет» у сервера нет — и админ-центр их не видит.</p>",
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
         <select name=\"reason\">{options}</select>\
         <label><input type=\"checkbox\" name=\"confirm\" value=\"yes\" required> необратимо</label>\
         <button class=\"danger\">Удалить аккаунт</button></form>",
        csrf = escape(csrf),
        options = reason_options(Some(Reason::Spam)),
    )
}

fn reports_html(rows: &[queries::ReportedAccount], csrf: &str, done: Option<&str>) -> String {
    let mut html = String::new();

    match done {
        Some("deleted") => html.push_str("<p class=\"flash\">Аккаунт удалён.</p>"),
        Some("dismissed") => html.push_str("<p class=\"flash\">Жалобы отклонены.</p>"),
        Some("channel_deleted") => html.push_str("<p class=\"flash\">Канал удалён.</p>"),
        _ => {}
    }

    html.push_str(
        "<p class=\"note\">Каждая жалоба доказана сертификатом отправителя, подписанным \
         сервером: пожаловаться можно только на того, кто действительно писал. \
         Переписки в жалобе нет. Срок реакции — 24 часа; CSAE — сразу и с сообщением в \
         компетентные органы (docs/ops/admin-center.md).</p>\
         <p class=\"note\">⚠️ Сертификат предъявительский: получивший одно сообщение \
         может пожаловаться с десятка своих аккаунтов. Смотрите на число <b>разных \
         сертификатов</b>: настоящий спам приходит многим и в разные сутки, накрутка \
         одним сообщением — одним сертификатом. Удалять только по числу жалобщиков \
         нельзя.</p>",
    );

    if rows.is_empty() {
        html.push_str("<p>Жалоб нет.</p>");
        return html;
    }

    html.push_str(
        "<table><tr><th>Аккаунт</th><th class=\"num\">Жалобщиков</th>\
         <th class=\"num\">Сертификатов</th>\
         <th>Первая / последняя</th><th>Активен</th><th>Решение</th></tr>",
    );
    for row in rows {
        let _ = write!(
            html,
            "<tr><td>@{name}</td><td class=\"num\">{reporters}</td>\
             <td class=\"num\">{certificates}</td><td>{first}<br>{last}</td><td>{active}</td><td>{delete}\
             <form class=\"inline\" method=\"post\" action=\"/accounts/{id}/dismiss\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button>Отклонить жалобы</button></form></td></tr>",
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
    html.push_str("</table>");

    html
}

/// Жалобы на каналы.
///
/// 🔐 Записи канала без публичного имени сервер не читает. Ссылка в
/// строке — та, что приложил жалобщик: с ней канал открывается в
/// приложении, и видно, на что жалуются.
fn channel_reports_html(rows: &[queries::ReportedChannel], csrf: &str) -> String {
    let mut html = String::from(
        "<h2>Каналы</h2>\
         <p class=\"note\">На канал жалуется любой аккаунт; доказательства отправителя, \
         как у переписки, здесь нет. Канал с публичным именем сервер читает сам; у \
         остальных записи видны только по ссылке, если её приложил жалобщик, — \
         откройте её в приложении. Жалобы на безопасность детей — сразу и с сообщением \
         в компетентные органы (docs/ops/admin-center.md). Удаление канала необратимо; \
         аккаунт владельца удаляется отдельно.</p>",
    );

    if rows.is_empty() {
        html.push_str("<p>Жалоб на каналы нет.</p>");
        return html;
    }

    html.push_str(
        "<table><tr><th>Канал</th><th>Владелец</th><th class=\"num\">Жалобщиков</th>\
         <th class=\"num\">Безопасность детей</th><th>Последняя</th><th>Ссылка</th>\
         <th>Решение</th></tr>",
    );
    for row in rows {
        let name = row
            .handle
            .as_deref()
            .map_or_else(|| row.channel_id.to_string(), |handle| format!("@{handle}"));

        let _ = write!(
            html,
            "<tr><td>{name}</td><td>@{owner}</td><td class=\"num\">{reporters}</td>\
             <td class=\"num\">{child}</td><td>{last}</td><td><code>{link}</code></td><td>\
             <form class=\"inline\" method=\"post\" action=\"/channels/{id}/delete\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <label><input type=\"checkbox\" name=\"confirm\" value=\"yes\" required> необратимо</label>\
             <button class=\"danger\">Удалить канал</button></form>\
             <form class=\"inline\" method=\"post\" action=\"/channels/{id}/dismiss\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button>Отклонить жалобы</button></form></td></tr>",
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
    html.push_str("</table>");

    html
}

fn premium_form(card: &queries::AccountCard, csrf: &str) -> String {
    let (state, value, action) = if card.premium {
        ("есть", "off", "Снять премиум")
    } else {
        ("нет", "on", "Выдать премиум")
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
        "<form class=\"inline\" method=\"get\" action=\"/account\">\
         <input name=\"username\" placeholder=\"точное имя\" value=\"{}\" required>\
         <button>Найти</button></form>\
         <p class=\"note\">Только по точному имени: перечня пользователей здесь нет — \
         это был бы каталог людей, которого сервер выдавать не должен.</p>",
        escape(wanted.unwrap_or_default())
    );

    match (wanted, card) {
        (Some(name), None) => {
            let _ = write!(html, "<p>Аккаунта @{} нет.</p>", escape(name));
        }
        (Some(_), Some(card)) => {
            let _ = write!(
                html,
                "<table><tr><th>Аккаунт</th><td>@{name}</td></tr>\
                 <tr><th>Активен</th><td>{active}</td></tr>\
                 <tr><th>Устройств</th><td class=\"num\">{devices}</td></tr>\
                 <tr><th>Жалобщиков</th><td class=\"num\">{reporters}</td></tr>\
                 <tr><th>Сертификатов</th><td class=\"num\">{certificates}</td></tr>\
                 <tr><th>Премиум</th><td>{premium}</td></tr>\
                 <tr><th>Каналов</th><td class=\"num\">{channels}</td></tr>\
                 <tr><th>Решение</th><td>{delete}</td></tr></table>",
                name = escape(&card.username),
                active = escape(&card.active_month),
                devices = card.devices,
                reporters = card.reporters,
                certificates = card.certificates,
                premium = premium_form(card, csrf),
                channels = card.channels,
                delete = delete_form(card.account_id, csrf),
            );
        }
        (None, _) => {}
    }

    html
}

fn transparency_html(rows: &[queries::TransparencyRow]) -> String {
    let mut html = String::from(
        "<p class=\"note\">Все действия оператора — без имён. Эти числа можно \
         публиковать как отчёт о прозрачности.</p>",
    );

    if rows.is_empty() {
        html.push_str("<p>Действий ещё не было.</p>");
        return html;
    }

    html.push_str(
        "<table><tr><th>Месяц</th><th>Действие</th><th>Причина</th>\
         <th class=\"num\">Сколько</th><th class=\"num\">Жалобщиков</th></tr>",
    );
    for row in rows {
        let action = match row.action.as_str() {
            "account_deleted" => "Аккаунт удалён",
            "reports_dismissed" => "Жалобы отклонены",
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
    html.push_str("</table>");

    html
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
