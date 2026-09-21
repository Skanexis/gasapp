// SPDX-License-Identifier: AGPL-3.0-only

//! Точка входа сервера AEGIS.
//!
//! # Что делает сервер
//!
//! Раздаёт prekey bundle и переносит запечатанные конверты между
//! устройствами. Содержимого сообщений он не видит и видеть не может:
//! ключи никогда не покидают устройств.
//!
//! # Настройка
//!
//! Через переменные окружения, а не файл конфигурации: в контейнере
//! это единственный способ, работающий одинаково везде.
//!
//! * `DATABASE_URL` — строка подключения к Postgres. Обязательна.
//! * `AEGIS_BIND` — адрес прослушивания, по умолчанию `0.0.0.0:8443`.
//! * `AEGIS_TLS_CERT`, `AEGIS_TLS_KEY` — пути к сертификату и ключу.
//!   🔐 Обязательны: без них переписка идёт открытым текстом.
//! * `AEGIS_CERTIFICATE_KEY` — 32 байта hex, которыми подписываются
//!   сертификаты отправителя. 🔐 Обязателен: без него берётся ключ
//!   из нулей, а он публично известен, и сертификат подделывает кто
//!   угодно (`openssl rand -hex 32`).
//! * `AEGIS_ALLOW_INSECURE=1` — разрешает запуск без двух предыдущих.
//!   Только для локальной проверки и тестов; см. `config`.
//!
//! # Про логи
//!
//! Адреса клиентов не пишутся никуда, включая логи доступа. Это не
//! упущение, а требование: журнал с адресами превращает сервер
//! в инструмент слежки за собственными пользователями, доступный
//! любому, кто получит к нему доступ (раздел 14.4 плана).

use std::net::SocketAddr;
use std::sync::Arc;

use aegis_server_api::config;
use aegis_server_api::routes::{router, AppState};
use rand::RngCore as _;
use sqlx::postgres::PgPoolOptions;

/// Адрес прослушивания по умолчанию.
///
/// `0.0.0.0`, а не `127.0.0.1`: сервер должен быть доступен телефонам
/// в локальной сети, иначе проверить обмен между двумя устройствами
/// невозможно.
const DEFAULT_BIND: &str = "0.0.0.0:8443";

/// Максимум соединений с базой.
const MAX_DB_CONNECTIONS: u32 = 16;

/// Задан ли ключ подписи сертификатов **и применим ли он**.
///
/// ⚠️ Проверяется не наличие переменной, а то, что из неё получился
/// ключ. `AEGIS_CERTIFICATE_KEY=не-hex` и отсутствие переменной дают
/// один и тот же результат — нули, — и отличать их по факту наличия
/// значило бы пропустить опечатку в секрете.
fn certificate_key_is_configured() -> bool {
    let Ok(encoded) = std::env::var("AEGIS_CERTIFICATE_KEY") else {
        return false;
    };

    let Ok(bytes) = hex::decode(&encoded) else {
        return false;
    };

    // Ключ из нулей запрещён и явно заданный: он публично известен,
    // и записать его руками — то же самое, что не задать.
    bytes.len() == 32 && bytes.iter().any(|byte| *byte != 0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_server_api=info,tower_http=warn".into()),
        )
        .init();

    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "не задана переменная окружения DATABASE_URL")?;

    // 🔐 Небезопасная настройка не запускается молча.
    //
    // Проверяется до подключения к базе: отказ должен быть быстрым
    // и не оставлять за собой половину поднятого сервера.
    //
    // Подробности и обоснование — в `config`.
    let tls = (
        std::env::var("AEGIS_TLS_CERT").ok(),
        std::env::var("AEGIS_TLS_KEY").ok(),
    );

    let has_tls = matches!(&tls, (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty());

    // Ключ считается заданным, только если он **применился**:
    // переменная из неверного hex даёт те же нули, что и её
    // отсутствие, и различать их здесь нельзя.
    let has_certificate_key = certificate_key_is_configured();

    let gaps = config::missing(has_tls, has_certificate_key);

    if !gaps.is_empty() {
        if std::env::var(config::ALLOW_INSECURE).is_ok() {
            tracing::warn!(
                "{}=1: сервер поднят без части защиты — так делать можно только \
                 в тестах",
                config::ALLOW_INSECURE
            );
        } else {
            // ⚠️ Печатается здесь, а не возвращается ошибкой.
            //
            // `Box<dyn Error>` из строки выводится через `Debug`,
            // то есть многострочная подсказка превращается в одну
            // строку с экранированными переносами — ровно то, что
            // читать нельзя. А она и существует ради чтения.
            eprintln!("{}", config::refusal(&gaps));

            std::process::exit(1);
        }
    }

    let bind: SocketAddr = std::env::var("AEGIS_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()?;

    let pool = PgPoolOptions::new()
        .max_connections(MAX_DB_CONNECTIONS)
        .connect(&database_url)
        .await?;

    // Миграции применяются при старте: расхождение схемы с кодом
    // проявилось бы как отказ произвольных запросов в бою, а не
    // как внятная ошибка запуска.
    sqlx::migrate!("../migrations").run(&pool).await?;

    // Соль ограничителя частоты живёт только в памяти процесса.
    // После перезапуска счётчики нельзя сопоставить с адресами даже
    // по дампу памяти — сервер и не должен уметь этого делать.
    let mut limiter_salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut limiter_salt);

    // Число узлов кластера: на него делятся лимиты частоты.
    //
    // 🔐 Без этого значения лимиты применяются целиком на каждом узле,
    // и заявленные 20 запросов в минуту превращаются в 60 на трёх
    // узлах. Значение по умолчанию — 1: одиночный запуск не должен
    // требовать настройки, а кластер обязан объявить себя явно.
    let cluster_nodes: u32 = std::env::var("AEGIS_CLUSTER_NODES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(aegis_server_api::rate_limit::DEFAULT_CLUSTER_NODES);

    if cluster_nodes > 1 {
        tracing::info!(
            nodes = cluster_nodes,
            "лимиты частоты поделены на число узлов кластера"
        );
    }

    let state = Arc::new(AppState::with_nodes(
        pool.clone(),
        limiter_salt,
        cluster_nodes,
    ));

    // Слушатель уведомлений от других узлов.
    //
    // Запускается до старта сервера: узел, начавший принимать запросы
    // раньше, чем слушать канал, пропустил бы уведомления о конвертах,
    // отправленных в этот промежуток.
    //
    // Отдельная задача, а не часть обработчика: она живёт всё время
    // работы процесса и переподключается сама при обрыве связи с базой.
    tokio::spawn(aegis_server_api::hub::listen(
        pool,
        Arc::clone(&state.hub),
        Arc::clone(&state.health),
    ));

    let app = router(state);

    // TLS обязателен: клиент запрещает открытый трафик через
    // network_security_config.xml. Сертификат и ключ задаются путями
    // в окружении — самоподписанный для локальной проверки,
    // выданный удостоверяющим центром в бою.
    if let (Ok(cert), Ok(key)) = (
        std::env::var("AEGIS_TLS_CERT"),
        std::env::var("AEGIS_TLS_KEY"),
    ) {
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
            .await
            .map_err(|error| format!("не удалось прочитать сертификат: {error}"))?;

        tracing::info!(address = %bind, "сервер AEGIS слушает по TLS");

        axum_server::bind_rustls(bind, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        // Открытый HTTP оставлен только для интеграционных тестов,
        // где сертификат не нужен, и сопровождается предупреждением:
        // молчаливый откат к незашифрованному каналу — худший вид
        // отказа защиты.
        tracing::warn!(
            address = %bind,
            "AEGIS_TLS_CERT и AEGIS_TLS_KEY не заданы: сервер слушает БЕЗ ШИФРОВАНИЯ"
        );

        let listener = tokio::net::TcpListener::bind(bind).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}
