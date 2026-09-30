// SPDX-License-Identifier: AGPL-3.0-only

//! Админ-центр против живого Postgres.
//!
//! ```text
//! AEGIS_TEST_DATABASE_URL=postgres://aegis:aegis-dev@localhost:5433/aegis \
//!     cargo test -p aegis-server-admin --test admin
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use aegis_server_admin::auth::{token_hash_hex, Auth};
use aegis_server_admin::{router, AdminState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt as _;
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef-operator";

async fn state() -> Option<Arc<AdminState>> {
    let url = std::env::var("AEGIS_TEST_DATABASE_URL").ok()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("база");
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .expect("миграции");

    Some(Arc::new(AdminState {
        pool,
        auth: Auth::from_hash_hex(&token_hash_hex(TOKEN)).expect("хеш"),
    }))
}

async fn send(
    state: &Arc<AdminState>,
    request: Request<Body>,
) -> (StatusCode, String, Option<String>) {
    let response = router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("ответ");
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|value| value.to_str().unwrap().to_owned());
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("тело");

    (
        status,
        String::from_utf8_lossy(&body).into_owned(),
        location.or(cookie),
    )
}

fn get(path: &str, session: &str) -> Request<Body> {
    Request::get(path)
        .header(header::COOKIE, format!("aegis_admin={session}"))
        .body(Body::empty())
        .unwrap()
}

fn post(path: &str, session: &str, form: &str) -> Request<Body> {
    Request::post(path)
        .header(header::COOKIE, format!("aegis_admin={session}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_owned()))
        .unwrap()
}

/// Входит и возвращает идентификатор сессии.
async fn login(state: &Arc<AdminState>) -> String {
    let (status, _, cookie) = send(
        state,
        Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("token={TOKEN}")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Для входа `send` отдаёт Location; cookie берём отдельным запросом.
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={TOKEN}")))
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = cookie;
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));

    set_cookie
        .trim_start_matches("aegis_admin=")
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

/// Токен CSRF со страницы.
fn csrf_of(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("форма с csrf") + marker.len();
    html[start..start + 64].to_owned()
}

#[tokio::test]
async fn without_a_session_everything_leads_to_login() {
    let Some(state) = state().await else {
        eprintln!("AEGIS_TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };

    for path in ["/", "/reports", "/account?username=x", "/transparency"] {
        let (status, _, location) = send(&state, get(path, "forged")).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location.as_deref(), Some("/login"), "{path}");
    }

    let (status, _, _) = send(
        &state,
        Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("token=wrong"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// 🔐 Полный путь жалобы: видна с числом жалобщиков, подделанный CSRF
/// отвергается, удаление уносит аккаунт, а журнал хранит причину без имени.
#[tokio::test]
async fn a_reported_account_is_deleted_and_logged_without_its_name() {
    let Some(state) = state().await else {
        eprintln!("AEGIS_TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };

    let suffix = &Uuid::new_v4().simple().to_string()[..10];
    let spammer = format!("spam{suffix}");
    let (spam_account, spam_device) =
        aegis_server_db::repo::register_account(&state.pool, &spammer, &[1; 32], &[1; 32])
            .await
            .expect("спамер");

    for index in 0..2u8 {
        let (_, complainant) = aegis_server_db::repo::register_account(
            &state.pool,
            &format!("victim{index}{suffix}"),
            &[index + 2; 32],
            &[index + 2; 32],
        )
        .await
        .expect("жалобщик");
        aegis_server_db::repo::record_sealed_sender_report(
            &state.pool,
            spam_account,
            spam_device,
            complainant,
        )
        .await
        .expect("жалоба");
    }

    let session = login(&state).await;

    let (status, html, _) = send(&state, get("/reports", &session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(&format!("@{spammer}")),
        "аккаунт с жалобами виден"
    );

    let csrf = csrf_of(&html);

    // Подделанный CSRF — отказ, аккаунт на месте.
    let (status, _, _) = send(
        &state,
        post(
            &format!("/accounts/{spam_account}/delete"),
            &session,
            "csrf=forged&reason=spam&confirm=yes",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Без подтверждения — отказ.
    let (status, _, _) = send(
        &state,
        post(
            &format!("/accounts/{spam_account}/delete"),
            &session,
            &format!("csrf={csrf}&reason=spam"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _, location) = send(
        &state,
        post(
            &format!("/accounts/{spam_account}/delete"),
            &session,
            &format!("csrf={csrf}&reason=spam&confirm=yes"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/reports?done=deleted"));

    let gone: Option<Uuid> =
        sqlx::query_scalar("SELECT account_id FROM accounts WHERE username = $1")
            .bind(&spammer)
            .fetch_optional(&state.pool)
            .await
            .unwrap();
    assert!(gone.is_none(), "аккаунт удалён");

    // Журнал действий — без имени: в нём нет ни одного текстового поля
    // с пользовательскими данными.
    let logged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_actions
          WHERE action = 'account_deleted' AND reason = 'spam' AND reporters = 2",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert!(logged >= 1);

    let (status, html, _) = send(&state, get("/transparency", &session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Аккаунт удалён"));
    assert!(!html.contains(&spammer), "в отчёте о прозрачности нет имён");
}

/// Поиск — только по точному имени; неизвестное имя — «нет».
#[tokio::test]
async fn an_account_is_found_by_exact_name_only() {
    let Some(state) = state().await else {
        eprintln!("AEGIS_TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };

    let suffix = &Uuid::new_v4().simple().to_string()[..10];
    let name = format!("exact{suffix}");
    aegis_server_db::repo::register_account(&state.pool, &name, &[9; 32], &[9; 32])
        .await
        .expect("аккаунт");

    let session = login(&state).await;

    let (_, html, _) = send(&state, get(&format!("/account?username=@{name}"), &session)).await;
    assert!(html.contains("Устройств"), "найден по точному имени");

    let (_, html, _) = send(
        &state,
        get(&format!("/account?username={}", &name[..6]), &session),
    )
    .await;
    assert!(html.contains("нет."), "по части имени не находится");
}
