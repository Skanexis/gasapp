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
//!   создания аккаунта, причины и улики, которые жалобщики сами решили
//!   показать (зашифрованы ключом админ-центра, `cases`);
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
pub mod cases;
mod icons;
pub mod insights;
pub mod moderation;
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
    /// Ключ улик к жалобам; `None` — улики не принимаются и не читаются.
    pub evidence: Option<cases::EvidenceKey>,
}

/// Маршруты админ-центра.
pub fn router(state: Arc<AdminState>) -> Router {
    let protected = Router::new()
        .route("/", get(summary_page))
        .route("/reports", get(reports_page))
        .route("/reports/account/:id", get(case_page))
        .route("/accounts", get(accounts_page))
        .route("/channels", get(channels_page))
        .route("/account", get(account_page))
        .route("/journal", get(journal_page))
        .route("/health", get(health_page))
        .route("/transparency", get(transparency_page))
        .route("/accounts/:id/delete", post(delete_account))
        .route("/accounts/:id/dismiss", post(dismiss_reports))
        .route("/channels/:id/delete", post(delete_channel))
        .route("/channels/:id/dismiss", post(dismiss_channel_reports))
        .route("/accounts/:id/premium", post(set_premium))
        .route("/accounts/:id/restrict", post(restrict_account))
        .route("/accounts/:id/lift", post(lift_restriction))
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_session,
        ));

    Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/assets/tabler.min.css", get(tabler_css))
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
/// Tabler 1.7.1 (MIT) — в самой программе: админ-центр не ходит в
/// интернет и не грузит чужого (assets/README.md).
const TABLER_CSS: &str = include_str!("../assets/tabler.min.css");

async fn tabler_css() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        TABLER_CSS,
    )
        .into_response()
}

/// Иконка Tabler Icons (MIT) — встроенный SVG, без загрузки.
#[must_use]
pub fn icon(name: &str) -> String {
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" class=\"icon\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" \
         fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" \
         aria-hidden=\"true\">{}</svg>",
        icons::inner(name)
    )
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src data:; form-action 'self'; \
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

    match insights::dashboard(&state.pool).await {
        Ok(dashboard) => {
            Html(layout("Overview", &csrf, &insights::dashboard_html(&dashboard, bytes))).into_response()
        }
        Err(error) => database_error(&error),
    }
}

#[derive(Deserialize)]
struct ListQuery {
    view: Option<String>,
    q: Option<String>,
    page: Option<i64>,
}

async fn accounts_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(list): Query<ListQuery>,
) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let view = insights::AccountView::parse(list.view.as_deref());
    let query = list.q.unwrap_or_default();
    let page = list.page.unwrap_or(0).clamp(0, 10_000);

    match insights::accounts(&state.pool, view, &query, page).await {
        Ok((rows, more)) => Html(layout(
            "Accounts",
            &csrf,
            &insights::accounts_html(&rows, view, &query, page, more, &csrf),
        ))
        .into_response(),
        Err(error) => database_error(&error),
    }
}

async fn channels_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(list): Query<ListQuery>,
) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let view = insights::ChannelView::parse(list.view.as_deref());
    let query = list.q.unwrap_or_default();
    let page = list.page.unwrap_or(0).clamp(0, 10_000);

    match insights::channels(&state.pool, view, &query, page).await {
        Ok((rows, more)) => Html(layout(
            "Channels",
            &csrf,
            &insights::channels_html(&rows, view, &query, page, more),
        ))
        .into_response(),
        Err(error) => database_error(&error),
    }
}

fn reason_label(code: &str) -> String {
    Reason::parse(code).map_or_else(|| code.to_owned(), |reason| reason.label().to_owned())
}

async fn journal_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    match insights::journal(&state.pool).await {
        Ok(rows) => Html(layout("Journal", &csrf, &insights::journal_html(&rows, reason_label))).into_response(),
        Err(error) => database_error(&error),
    }
}

async fn health_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    match insights::health(&state.pool).await {
        Ok(health) => Html(layout("Health", &csrf, &insights::health_html(&health, bytes))).into_response(),
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

    // Улики не живут дольше 30 дней (миграция 0030).
    if let Err(error) = cases::purge_old_evidence(&state.pool).await {
        return database_error(&error);
    }
    let rows = match cases::queue(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => return database_error(&error),
    };
    let channels = match queries::reported_channels(&state.pool).await {
        Ok(channels) => channels,
        Err(error) => return database_error(&error),
    };

    let mut body = cases::queue_html(&rows, channels.len(), flash.done.as_deref());
    body.push_str(&channel_reports_html(&channels, &csrf));

    Html(layout("Reports", &csrf, &body)).into_response()
}

/// Дело по аккаунту: сигналы, причины, улики, решение.
async fn case_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
) -> Response {
    let Some((_, csrf)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };

    match cases::case(&state.pool, account_id).await {
        Ok(Some(case)) => {
            let body = cases::case_html(&case, state.evidence.as_ref(), &csrf);
            Html(layout("Reports", &csrf, &body)).into_response()
        }
        Ok(None) => Redirect::to("/reports").into_response(),
        Err(error) => database_error(&error),
    }
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
    /// Что сделано — для строки «готово».
    done: Option<String>,
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
    let restricted = match card.as_ref().and_then(Option::as_ref) {
        Some(card) => match moderation::restriction(&state.pool, card.account_id).await {
            Ok(restricted) => restricted,
            Err(error) => return database_error(&error),
        },
        None => None,
    };

    Html(layout(
        "Account",
        &csrf,
        &account_html(&AccountView {
            wanted: wanted.as_deref(),
            card: card.as_ref().and_then(Option::as_ref),
            restricted: restricted.as_ref(),
            done: lookup.done.as_deref(),
            csrf: &csrf,
        }),
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
struct RestrictForm {
    csrf: String,
    /// Имя — только чтобы вернуться на карточку.
    username: String,
    /// `freeze` либо `block`.
    measure: String,
    days: Option<i32>,
    reason: String,
    confirm: Option<String>,
    /// `case` — решение из дела, иначе из карточки аккаунта.
    back: Option<String>,
}

/// Карточка аккаунта по имени (каноничному — в адрес без кодирования).
fn account_url(raw: &str, done: &str) -> String {
    let name = canonical_username(raw);
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        format!("/account?username={name}&done={done}")
    } else {
        "/account".to_owned()
    }
}

/// Замораживает либо блокирует аккаунт: мягче удаления, обратимо.
async fn restrict_account(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    Form(form): Form<RestrictForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(measure) = moderation::Measure::parse(&form.measure, form.days) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(reason) = Reason::parse(&form.reason).filter(|reason| *reason != Reason::Unfounded)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // Блокировка — только с подтверждением, как удаление.
    if measure == moderation::Measure::Block && form.confirm.as_deref() != Some("yes") {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match moderation::restrict(&state.pool, account_id, measure, reason).await {
        Ok(_) => {
            let done = if measure == moderation::Measure::Block { "blocked" } else { "frozen" };
            tracing::info!(reason = reason.code(), done, "админ-центр: аккаунт ограничен");
            if form.back.as_deref() == Some("case") {
                Redirect::to(&format!("/reports?done={done}")).into_response()
            } else {
                Redirect::to(&account_url(&form.username, done)).into_response()
            }
        }
        Err(error) => database_error(&error),
    }
}

/// Снимает заморозку либо блокировку.
async fn lift_restriction(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    Form(form): Form<RestrictLiftForm>,
) -> Response {
    let Some((id, _)) = session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !state.auth.csrf_matches(&id, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match moderation::lift(&state.pool, account_id).await {
        Ok(_) => {
            tracing::info!("админ-центр: ограничение снято");
            Redirect::to(&account_url(&form.username, "lifted")).into_response()
        }
        Err(error) => database_error(&error),
    }
}

#[derive(Deserialize)]
struct RestrictLiftForm {
    csrf: String,
    username: String,
}

#[derive(Deserialize)]
struct PremiumForm {
    csrf: String,
    /// Имя аккаунта — только чтобы вернуться на его карточку.
    username: String,
    /// `on` — выдать, иначе снять.
    premium: String,
    /// Откуда пришли: вид списка аккаунтов — вернуться туда же.
    back: Option<String>,
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

            if let Some(back) = form.back.as_deref() {
                // Вид — только из известного набора: в адрес без кодирования.
                let view = insights::AccountView::parse(Some(back));
                Redirect::to(&format!("/accounts?view={}", view.code())).into_response()
            } else if safe {
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
    let groups: [(&str, &[(&str, &str, &str)]); 3] = [
        (
            "Monitor",
            &[
                ("Overview", "/", "layout-dashboard"),
                ("Health", "/health", "heart-rate-monitor"),
                // Beszel (server/deploy/beszel.sh): тем же туннелем, что и
                // админ-центр, — admin.sh пробрасывает 8090.
                ("Servers", "http://127.0.0.1:8090/", "server"),
            ],
        ),
        (
            "Moderation",
            &[
                ("Reports", "/reports", "flag"),
                ("Journal", "/journal", "list-details"),
                ("Transparency", "/transparency", "report-analytics"),
            ],
        ),
        (
            "Directory",
            &[
                ("Accounts", "/accounts", "users"),
                ("Channels", "/channels", "broadcast"),
                ("Account", "/account", "user-search"),
            ],
        ),
    ];
    let mut nav = String::new();
    for (group, items) in groups {
        let _ = write!(nav, "<li class=\"nav-group\">{group}</li>");
        for (label, href, glyph) in items {
            let (active, current) = if *label == title {
                (" active", " aria-current=\"page\"")
            } else {
                ("", "")
            };
            let shown = if *label == "Account" { "Find account" } else { label };
            // Внешняя страница (Beszel) — в новой вкладке, без Referer.
            let (external, arrow) = if href.starts_with("http") {
                (" target=\"_blank\" rel=\"noopener noreferrer\"", icon("external-link"))
            } else {
                ("", String::new())
            };
            let _ = write!(
                nav,
                "<li class=\"nav-item{active}\"><a class=\"nav-link\" href=\"{href}\"{current}{external}>\
                 <span class=\"nav-link-icon\">{}</span><span class=\"nav-link-title\">{shown}</span>\
                 <span class=\"ms-auto text-secondary\">{arrow}</span></a></li>",
                icon(glyph)
            );
        }
    }
    format!(
        "<!doctype html><html lang=\"en\" data-bs-theme=\"dark\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"theme-color\" content=\"#0b0f2e\">\
         <title>{title} · GasApp Control</title>\
         <link rel=\"stylesheet\" href=\"/assets/tabler.min.css\"><style>{STYLE}</style></head><body>\
         <a class=\"skip-link\" href=\"#content\">Skip to content</a>\
         <div class=\"page\"><aside class=\"navbar navbar-vertical navbar-expand-lg\" data-bs-theme=\"dark\">\
         <div class=\"container-fluid\"><div class=\"navbar-brand py-3\"><a class=\"brand\" href=\"/\">\
         <span class=\"brand-mark\">GAS</span><span><b>GasApp</b><small>Control center</small></span></a></div>\
         <div class=\"navbar-collapse\" id=\"sidebar-menu\"><ul class=\"navbar-nav pt-lg-2\">{nav}</ul>\
         <div class=\"mt-auto px-3 py-3 border-top\"><span class=\"private-pill\">Private operator access</span>\
         <form method=\"post\" action=\"/logout\" class=\"mt-2\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <button class=\"sign-out\">Sign out →</button></form></div></div></div></aside>\
         <div class=\"page-wrapper\"><div class=\"page-header d-print-none\"><div class=\"container-xl\">\
         <div class=\"row g-2 align-items-center\"><div class=\"col\"><h2 class=\"page-title\">{title}</h2></div>\
         <div class=\"col-auto ms-auto\"><form class=\"header-search\" method=\"get\" action=\"/account\" role=\"search\">\
         <div class=\"input-icon\"><span class=\"input-icon-addon\">{search}</span>\
         <input class=\"form-control\" name=\"username\" placeholder=\"Jump to @username\" aria-label=\"Jump to account by exact username\" required>\
         </div></form></div></div></div></div>\
         <div class=\"page-body\"><main id=\"content\" class=\"container-xl workspace-legacy\">{body}</main></div></div></div>\
         </body></html>",
        title = escape(title),
        csrf = escape(csrf),
        search = icon("search"),
    )
}

fn login_html(error: Option<&str>) -> String {
    let error = error
        .map(|text| format!("<div class=\"alert alert-danger\" role=\"alert\">{}</div>", escape(text)))
        .unwrap_or_default();

    format!(
        "<!doctype html><html lang=\"en\" data-bs-theme=\"dark\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"theme-color\" content=\"#0b0f2e\">\
         <title>Sign in · GasApp Control</title>\
         <link rel=\"stylesheet\" href=\"/assets/tabler.min.css\"><style>{STYLE}</style></head><body>\
         <main class=\"login\"><div class=\"login-panel\"><div class=\"text-center mb-4\"><span class=\"brand\" style=\"justify-content:center\">\
         <span class=\"brand-mark\">GAS</span><span class=\"text-start\"><b>GasApp</b><small>Control center</small></span></span></div>\
         <div class=\"card card-md\"><div class=\"card-body\"><h1 class=\"h2 text-center mb-2\">Welcome back</h1>\
         <p class=\"text-secondary text-center mb-4\">Sign in to review reports and manage your service.</p>{error}\
         <form method=\"post\" action=\"/login\"><label class=\"form-label\" for=\"token\">Operator token</label>\
         <input class=\"form-control\" id=\"token\" type=\"password\" name=\"token\" autocomplete=\"off\" required>\
         <button class=\"btn btn-primary w-100 mt-3\">{lock} Sign in securely</button></form></div>\
         <div class=\"card-footer text-secondary small\">Access this page only through your SSH tunnel or private onion service.</div></div>\
         </div></main></body></html>",
        lock = icon("lock"),
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
         <button class=\"btn btn-sm ms-2\">{action}</button></form>",
        id = card.account_id,
        csrf = escape(csrf),
        name = escape(&card.username),
    )
}

/// Что показать на карточке аккаунта.
struct AccountView<'a> {
    wanted: Option<&'a str>,
    card: Option<&'a queries::AccountCard>,
    restricted: Option<&'a moderation::Restricted>,
    done: Option<&'a str>,
    csrf: &'a str,
}

fn account_html(view: &AccountView<'_>) -> String {
    let mut html = format!(
        "<form class=\"card card-body mb-4\" method=\"get\" action=\"/account\" role=\"search\">\
         <div class=\"input-group\"><span class=\"input-group-text\">@</span>\
         <input class=\"form-control\" name=\"username\" aria-label=\"Exact username\" placeholder=\"Exact username\" value=\"{}\" required autofocus>\
         <button class=\"btn btn-primary\">{} Find account</button></div>\
         <div class=\"form-hint mt-2\">Exact username only. There is no browsable directory of people.</div></form>",
        escape(view.wanted.unwrap_or_default()),
        icon("search"),
    );
    let flash = match view.done {
        Some("frozen") => Some("Account frozen. Open reports were closed."),
        Some("blocked") => Some("Account blocked. Open reports were closed."),
        Some("lifted") => Some("Restriction lifted. The account works again."),
        _ => None,
    };
    if let Some(text) = flash {
        let _ = write!(html, "<div class=\"alert alert-success\" role=\"status\">{text}</div>");
    }

    match (view.wanted, view.card) {
        (Some(name), None) => {
            let _ = write!(
                html,
                "<div class=\"empty\"><p class=\"empty-title\">No account @{}</p>\
                 <p class=\"empty-subtitle text-secondary\">Check the spelling: the name must match exactly.</p></div>",
                escape(name)
            );
        }
        (Some(_), Some(card)) => {
            html.push_str(&account_head(card, view.restricted));
            html.push_str(&account_stats(card));
            html.push_str(&account_details(card, view.csrf));
            html.push_str(&moderation::decision_html(&moderation::Decision {
                account_id: card.account_id,
                username: &card.username,
                restricted: view.restricted,
                suggested: Reason::Spam,
                csrf: view.csrf,
                dismiss: false,
            }));
        }
        (None, _) => {}
    }

    html
}

fn account_head(card: &queries::AccountCard, restricted: Option<&moderation::Restricted>) -> String {
    let mut badges = String::new();
    if card.bot_owner.is_some() {
        badges.push_str("<span class=\"badge bg-info-lt\">bot</span>");
    }
    if card.premium {
        badges.push_str("<span class=\"badge bg-primary-lt\">premium</span>");
    }
    badges.push_str(&moderation::status_badge(restricted));
    let case = if card.reporters > 0 {
        format!(
            "<a class=\"btn btn-outline-warning\" href=\"/reports/account/{}\">{} Open case</a>",
            card.account_id,
            icon("flag")
        )
    } else {
        String::new()
    };
    format!(
        "<div class=\"card mb-3\"><div class=\"card-body d-flex flex-wrap align-items-center gap-3\">\
         <span class=\"ava-lg\">{ava}</span><div class=\"flex-fill\"><div class=\"d-flex flex-wrap align-items-center gap-2\">\
         <h3 class=\"m-0\">@{name}</h3>{badges}</div>\
         <div class=\"text-secondary\">Last active {active} · {devices}</div></div>{case}</div></div>",
        ava = insights::avatar(&card.username),
        name = escape(&card.username),
        active = escape(&card.active_month),
        devices = cases_plural(card.devices, "device", "devices"),
    )
}

fn cases_plural(count: i64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

fn account_stats(card: &queries::AccountCard) -> String {
    format!(
        "<div class=\"row row-cards mb-3\">{}{}{}{}</div>",
        insights::stat("flag", if card.reporters > 0 { "bad" } else { "ok" }, "Reporters",
                       &card.reporters.to_string(), "different people"),
        insights::stat("shield-lock", "info", "Certificates", &card.certificates.to_string(),
                       "distinct sender proofs"),
        insights::stat("broadcast", "pink", "Channels", &card.channels.to_string(), "owned"),
        insights::stat("robot", "gold", "Bots", &card.bots.to_string(), "created by this account"),
    )
}

fn account_details(card: &queries::AccountCard, csrf: &str) -> String {
    let owner = card.bot_owner.as_deref().map_or_else(
        || "<span class=\"text-secondary\">—</span>".to_owned(),
        |name| format!("<a href=\"/account?username={name}\">@{name}</a> — a freeze or block of the owner also stops this bot", name = escape(name)),
    );
    format!(
        "<div class=\"card mb-4\"><div class=\"card-body\"><dl class=\"row m-0 details\">\
         <dt class=\"col-sm-3\">Premium</dt><dd class=\"col-sm-9\">{premium}</dd>\
         <dt class=\"col-sm-3\">Bot owner</dt><dd class=\"col-sm-9\">{owner}</dd></dl></div></div>",
        premium = premium_form(card, csrf),
    )
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
            "account_frozen" => "Account frozen",
            "account_blocked" => "Account blocked",
            "restriction_lifted" => "Restriction lifted",
            "channel_deleted" => "Channel deleted",
            "channel_reports_dismissed" => "Channel reports dismissed",
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
        let app = router(Arc::new(AdminState {
            pool,
            auth,
            evidence: None,
        }));

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
        assert!(login.contains("<html lang=\"en\""));
        assert!(login.contains("Operator token"));

        let overview = layout("Overview", "test-csrf", "<p>Body</p>");
        assert!(overview.contains("<html lang=\"en\""));
        assert!(overview.contains("aria-current=\"page\""));
        assert!(overview.contains("Skip to content"));
        assert!(overview.contains("name=\"csrf\" value=\"test-csrf\""));

        let reports = cases::queue_html(&[], 0, None);
        assert!(reports.contains("No account reports"));
        let channels = channel_reports_html(&[], "test-csrf");
        assert!(channels.contains("No channel reports"));
        let overview = insights::dashboard_html(
            &insights::Dashboard {
                reported_accounts: 2,
                reported_channels: 1,
                ..insights::Dashboard::default()
            },
            bytes,
        );
        assert!(overview.contains("3 cases waiting for review"));
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
        let report = cases::CaseRow {
            account_id: Uuid::nil(),
            username: "alice".to_owned(),
            last_report: "2026-10-02".to_owned(),
            signals: cases::Signals {
                reporters: 1,
                certificates: 1,
                reports: 1,
                ..cases::Signals::default()
            },
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
        let frozen = moderation::Restricted { blocked: false, until: Some("2026-11-20 14:00".into()),
            reason: Some("spam".into()) };
        let pages = [
            login_html(Some("Invalid operator token.")),
            insights::dashboard_html(&insights::Dashboard::default(), bytes),
            cases::queue_html(&[report], 1, Some("deleted")),
            channel_reports_html(&[channel], "csrf"),
            account_html(&AccountView { wanted: Some("alice"), card: Some(&account), restricted: Some(&frozen),
                done: Some("frozen"), csrf: "csrf" }),
            transparency_html(&[action]),
        ];
        assert!(pages[2].contains("href=\"/reports/account/"));
        assert!(pages[2].contains("Account deleted"));
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

    /// Предпросмотр страниц с примерными данными: `ADMIN_PREVIEW_DIR=путь
    /// cargo test -p gasapp-server-admin preview` пишет HTML туда.
    /// Без переменной — ничего не делает.
    #[test]
    fn preview_pages() {
        let Ok(dir) = std::env::var("ADMIN_PREVIEW_DIR") else { return };
        let dashboard = insights::Dashboard {
            accounts: 1284, bots: 12, premium: 37, active_this_month: 642, active_last_month: 211,
            dormant: 431, channels: 96, public_channels: 21, closed_channels: 14, posts: 5120,
            subscriptions: 8803, reported_accounts: 2, reported_channels: 1, devices: 1284,
            envelopes: 318, oldest_envelope_hours: Some(9), attachments: 702,
            attachments_bytes: 3_400_000_000, database_bytes: 912_000_000, kt_epoch: Some(4410),
            activity: vec![("2026-06".into(), 40), ("2026-07".into(), 88), ("2026-08".into(), 120),
                           ("2026-09".into(), 203), ("2026-10".into(), 211), ("2026-11".into(), 642)],
        };
        let accounts = vec![
            insights::AccountRow { account_id: Uuid::nil(), username: "anna_k".into(), active_month: "2026-11".into(),
                premium: true, bot: false, devices: 1, channels: 3, reporters: 0, restricted: None },
            insights::AccountRow { account_id: Uuid::nil(), username: "news_bot".into(), active_month: "2026-11".into(),
                premium: false, bot: true, devices: 1, channels: 0, reporters: 0, restricted: None },
            insights::AccountRow { account_id: Uuid::nil(), username: "spammer42".into(), active_month: "2026-10".into(),
                premium: false, bot: false, devices: 1, channels: 0, reporters: 4, restricted: Some(false) },
        ];
        let channels = vec![
            insights::ChannelRow { channel_id: Uuid::nil(), handle: Some("gas_news".into()), owner: "anna_k".into(),
                closed: false, created: "2026-10-12".into(), subscribers: 3120, posts: 214, reports: 0 },
            insights::ChannelRow { channel_id: Uuid::nil(), handle: None, owner: "mark".into(),
                closed: true, created: "2026-11-02".into(), subscribers: 48, posts: 12, reports: 1 },
        ];
        let health = insights::Health { version: "16.4".into(), uptime: "12 d 4 h".into(), connections: 9,
            database_bytes: 912_000_000, envelopes: 318, oldest_envelope_hours: Some(9),
            tables: vec![("attachments".into(), 3_400_000_000), ("envelopes".into(), 220_000_000)] };
        let journal = vec![insights::JournalRow { hour: "2026-11-12 21:00".into(), action: "account_deleted".into(),
            reason: "spam".into(), reporters: 4 }];
        let card = queries::AccountCard { account_id: Uuid::nil(), username: "spammer42".into(),
            active_month: "2026-11".into(), devices: 1, reporters: 4, certificates: 3, premium: false,
            channels: 0, bots: 0, bot_owner: None };
        let frozen = moderation::Restricted { blocked: false, until: Some("2026-11-20 14:00".into()),
            reason: Some("spam".into()) };
        let pages = [
            ("overview", layout("Overview", "c", &insights::dashboard_html(&dashboard, bytes))),
            ("accounts", layout("Accounts", "c", &insights::accounts_html(&accounts, insights::AccountView::All, "", 0, true, "c"))),
            ("channels", layout("Channels", "c", &insights::channels_html(&channels, insights::ChannelView::All, "", 0, false))),
            ("health", layout("Health", "c", &insights::health_html(&health, bytes))),
            ("journal", layout("Journal", "c", &insights::journal_html(&journal, reason_label))),
            ("account", layout("Account", "c", &account_html(&AccountView {
                wanted: Some("spammer42"), card: Some(&card), restricted: Some(&frozen), done: Some("frozen"), csrf: "c" }))),
        ];
        for (name, html) in pages {
            let _ = std::fs::write(format!("{dir}/{name}.html"), html);
        }
    }
}
