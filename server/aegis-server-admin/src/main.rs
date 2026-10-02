// SPDX-License-Identifier: AGPL-3.0-only

//! `aegis-server-admin` — админ-центр оператора.
//!
//! ```text
//! aegis-server-admin hash-token     # токен со stdin → SHA-256 для окружения
//! aegis-server-admin serve          # веб-интерфейс (по умолчанию)
//! aegis-server-admin watch-reports  # для cron: уведомить о новых жалобах
//! ```
//!
//! Окружение:
//!
//! * `DATABASE_URL` — база сервера AEGIS;
//! * `AEGIS_ADMIN_TOKEN_SHA256` — SHA-256 токена оператора (`hash-token`);
//! * `AEGIS_ADMIN_BIND` — адрес, по умолчанию `127.0.0.1:8480`.
//!   🔐 Только петля: другой адрес — отказ запуска;
//! * `AEGIS_NOTIFY_CMD` — команда уведомления (текст — на stdin), как у
//!   `deploy/check-nodes.sh`; без неё `watch-reports` печатает в stdout.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use aegis_server_admin::auth::{token_hash_hex, Auth};
use aegis_server_admin::{queries, router, AdminState};
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

/// Адрес по умолчанию — петля.
const DEFAULT_BIND: &str = "127.0.0.1:8480";

/// Соединений с базой: админ-центр — один оператор.
const MAX_DB_CONNECTIONS: u32 = 4;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_server_admin=info".into()),
        )
        .init();

    match std::env::args().nth(1).as_deref().unwrap_or("serve") {
        "hash-token" => hash_token().await,
        "serve" => serve().await,
        "watch-reports" => watch_reports().await,
        other => {
            eprintln!("неизвестная команда «{other}»: hash-token | serve | watch-reports");
            std::process::exit(2);
        }
    }
}

/// Токен со stdin → SHA-256 в hex.
async fn hash_token() -> Result<(), Box<dyn Error>> {
    let mut line = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await?;

    if line.trim().len() < 32 {
        return Err("токен короче 32 знаков — сгенерируйте: openssl rand -hex 32".into());
    }
    println!("{}", token_hash_hex(&line));

    Ok(())
}

async fn pool() -> Result<sqlx::PgPool, Box<dyn Error>> {
    // Секреты — из файла (`*_FILE`, учётные данные systemd) или окружения.
    let url = aegis_server_db::runtime::secret("DATABASE_URL")
        .ok_or("не задан DATABASE_URL (или DATABASE_URL_FILE)")?;

    // 🔐 Те же правила, что у узла: удалённая база — только по TLS
    // с проверкой её сертификата, и никогда — от root.
    if !aegis_server_db::runtime::database_link_protected(&url) {
        return Err("DATABASE_URL ведёт на другую машину без sslmode=verify-full                     (или verify-ca): связь с базой видна во внутренней сети"
            .into());
    }
    if aegis_server_db::runtime::running_as_root() {
        return Err("админ-центр запущен от root — запускайте от отдельного пользователя".into());
    }

    Ok(PgPoolOptions::new()
        .max_connections(MAX_DB_CONNECTIONS)
        .connect(&url)
        .await?)
}

async fn serve() -> Result<(), Box<dyn Error>> {
    let bind: SocketAddr = std::env::var("AEGIS_ADMIN_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()?;

    // 🔐 Наружу админ-центр не выставляется никогда: снаружи — только
    // через SSH-туннель или onion-сервис, которые ведут на петлю.
    if !bind.ip().is_loopback() {
        return Err(format!(
            "AEGIS_ADMIN_BIND={bind}: админ-центр слушает только петлю (127.0.0.1 или ::1)"
        )
        .into());
    }

    let auth = aegis_server_db::runtime::secret("AEGIS_ADMIN_TOKEN_SHA256")
        .and_then(|hash| Auth::from_hash_hex(&hash))
        .ok_or("не задан или негоден AEGIS_ADMIN_TOKEN_SHA256 (aegis-server-admin hash-token)")?;

    let pool = pool().await?;
    // Схема та же, что у сервера; миграции идемпотентны и под
    // блокировкой sqlx — кто бы ни запустился первым.
    sqlx::migrate!("../migrations").run(&pool).await?;

    let app = router(Arc::new(AdminState { pool, auth }));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(address = %bind, "админ-центр AEGIS слушает петлю");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Уведомляет оператора о новых жалобах — для cron.
///
/// 🔐 В тексте уведомления только число: имена и прочее — в самом
/// админ-центре. Канал уведомлений (Telegram, почта) — чужая служба.
async fn watch_reports() -> Result<(), Box<dyn Error>> {
    let pool = pool().await?;
    let fresh = queries::take_new_reports(&pool).await?;

    if fresh == 0 {
        return Ok(());
    }

    let text = format!("AEGIS: новых жалоб — {fresh}. Админ-центр → Жалобы.\n");

    match std::env::var("AEGIS_NOTIFY_CMD") {
        Ok(command) if !command.trim().is_empty() => {
            let mut child = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .stdin(std::process::Stdio::piped())
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes()).await?;
            }
            child.wait().await?;
        }
        _ => print!("{text}"),
    }

    Ok(())
}
