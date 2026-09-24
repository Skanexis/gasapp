// SPDX-License-Identifier: AGPL-3.0-only

//! Интеграционные тесты против настоящего Postgres.
//!
//! # Зачем нужна живая база
//!
//! Половина гарантий сервера живёт в схеме, а не в коде: каскадное
//! удаление, ограничение размера конверта, уникальность имени,
//! `FOR UPDATE SKIP LOCKED` при выдаче одноразовых ключей. Ни одну
//! из них нельзя проверить моком — мок повторит предположения кода,
//! а не поведение Postgres.
//!
//! # Как запускать
//!
//! ```text
//! docker run -d --name aegis-postgres \
//!     -e POSTGRES_PASSWORD=aegis-dev -e POSTGRES_USER=aegis \
//!     -e POSTGRES_DB=aegis -p 5433:5432 postgres:16-alpine
//!
//! AEGIS_TEST_DATABASE_URL=postgres://aegis:aegis-dev@localhost:5433/aegis \
//!     cargo test -p aegis-server-db
//! ```
//!
//! Без переменной окружения тесты **пропускаются**, а не падают: база
//! есть не на каждой машине, и красный прогон из-за её отсутствия
//! приучает игнорировать красный прогон вообще.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_server_db::repo::{self, RepoError};
use sqlx::PgPool;
use uuid::Uuid;

// Общий с `aegis-server-api` файл: см. пояснение внутри него.
#[path = "../../test-support/schema.rs"]
mod schema;

/// Подключается к тестовой базе, либо сообщает о пропуске.
///
/// # Про изоляцию тестов
///
/// Схема создаётся **один раз** на весь прогон, а не в каждом тесте:
/// `cargo test` запускает тесты параллельно, и попытка пересоздать
/// таблицы из нескольких потоков приводит к гонке в системном каталоге
/// Postgres (`duplicate key ... pg_type_typname_nsp_index`).
///
/// Изоляция достигается иначе — уникальными именами аккаунтов
/// ([`unique_name`]): тесты не пересекаются по данным, поэтому им
/// незачем пересекаться по схеме.
async fn pool() -> Option<PgPool> {
    let url = schema::database_url()?;
    let pool = PgPool::connect(&url).await.ok()?;

    schema::bootstrap(&pool).await;

    Some(pool)
}

/// Пропускает тест, если базы нет.
macro_rules! require_pool {
    () => {
        match pool().await {
            Some(pool) => pool,
            None => {
                eprintln!("AEGIS_TEST_DATABASE_URL не задан — тест пропущен");
                return;
            }
        }
    };
}

fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

#[tokio::test]
async fn account_registers_with_first_device() {
    let pool = require_pool!();
    let username = unique_name("alice");

    let (account_id, device_id) = repo::register_account(&pool, &username, &[1u8; 32], &[2u8; 32])
        .await
        .expect("регистрация проходит");

    let found = repo::find_by_username(&pool, &username)
        .await
        .expect("аккаунт находится");

    assert_eq!(found.account_id, account_id);

    let devices = repo::list_devices(&pool, account_id).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices.first().map(|d| d.device_id), Some(device_id));
}

/// 🔐 Имя занято — повторная регистрация отвергается.
#[tokio::test]
async fn duplicate_username_is_rejected() {
    let pool = require_pool!();
    let username = unique_name("bob");

    repo::register_account(&pool, &username, &[1u8; 32], &[2u8; 32])
        .await
        .unwrap();

    let second = repo::register_account(&pool, &username, &[3u8; 32], &[4u8; 32]).await;

    assert!(matches!(second, Err(RepoError::UsernameTaken)));
}

/// 🔐 Неудачная регистрация не оставляет частичных данных.
///
/// Аккаунт и устройство создаются в одной транзакции: аккаунт без
/// устройства бесполезен и занимал бы имя навсегда.
#[tokio::test]
async fn failed_registration_leaves_nothing_behind() {
    let pool = require_pool!();
    let username = unique_name("carol");

    repo::register_account(&pool, &username, &[1u8; 32], &[2u8; 32])
        .await
        .unwrap();
    let before = repo::find_by_username(&pool, &username).await.unwrap();

    // Повторная попытка падает на уникальности имени.
    let _ = repo::register_account(&pool, &username, &[9u8; 32], &[9u8; 32]).await;

    let after = repo::find_by_username(&pool, &username).await.unwrap();
    assert_eq!(before.account_id, after.account_id, "аккаунт подменился");

    let devices = repo::list_devices(&pool, after.account_id).await.unwrap();
    assert_eq!(devices.len(), 1, "осталось лишнее устройство");
}

/// 🔐 Несуществующее имя и скрытое неразличимы по ошибке.
#[tokio::test]
async fn unknown_username_is_not_found() {
    let pool = require_pool!();

    let result = repo::find_by_username(&pool, &unique_name("ghost")).await;

    assert!(matches!(result, Err(RepoError::NotFound)));
}

#[tokio::test]
async fn prekey_bundle_round_trips() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("dave"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::publish_prekeys(
        &pool,
        device,
        (1, &[0x11; 32], &[0xAA; 64]),
        (2, &[0x22; 1568], &[0xBB; 64]),
        &[(10, vec![0x33; 32])],
        &[(20, vec![0x44; 1568], vec![0xCC; 64])],
    )
    .await
    .unwrap();

    let bundle = repo::take_prekey_bundle(&pool, device).await.unwrap();

    assert_eq!(bundle.signed_key_id, 1);
    assert_eq!(bundle.kem_key_id, 2);
    assert_eq!(bundle.one_time.map(|(id, _)| id), Some(10));
    assert_eq!(bundle.one_time_kem.map(|(id, _, _)| id), Some(20));
}

/// 🔐 Одноразовый предключ выдаётся ровно один раз.
///
/// Иначе две сессии получили бы один ключ, и он перестал бы быть
/// одноразовым — то есть forward secrecy первого сообщения исчезла бы
/// незаметно для обеих сторон.
#[tokio::test]
async fn one_time_prekey_is_consumed() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("erin"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::publish_prekeys(
        &pool,
        device,
        (1, &[0x11; 32], &[0xAA; 64]),
        (2, &[0x22; 1568], &[0xBB; 64]),
        &[(10, vec![0x33; 32])],
        &[],
    )
    .await
    .unwrap();

    let first = repo::take_prekey_bundle(&pool, device).await.unwrap();
    let second = repo::take_prekey_bundle(&pool, device).await.unwrap();

    assert!(first.one_time.is_some(), "первый запрос без ключа");
    assert!(second.one_time.is_none(), "одноразовый ключ выдан дважды");
}

/// Исчерпание пула — не отказ.
///
/// Bundle выдаётся без одноразового ключа, сессия помечается ослабленной.
/// Отказ означал бы, что вычерпав чужой пул, атакующий полностью лишает
/// контакт возможности принимать сообщения.
#[tokio::test]
async fn exhausted_pool_still_yields_a_bundle() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("frank"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::publish_prekeys(
        &pool,
        device,
        (1, &[0x11; 32], &[0xAA; 64]),
        (2, &[0x22; 1568], &[0xBB; 64]),
        &[],
        &[],
    )
    .await
    .unwrap();

    let bundle = repo::take_prekey_bundle(&pool, device).await.unwrap();

    assert!(bundle.one_time.is_none());
    assert_eq!(bundle.signed_key_id, 1, "подписанный предключ обязан быть");
}

/// Счётчик оставшихся ключей уменьшается при выдаче.
#[tokio::test]
async fn prekey_count_decreases() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("grace"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::publish_prekeys(
        &pool,
        device,
        (1, &[0x11; 32], &[0xAA; 64]),
        (2, &[0x22; 1568], &[0xBB; 64]),
        &[(10, vec![0x33; 32]), (11, vec![0x34; 32])],
        &[],
    )
    .await
    .unwrap();

    assert_eq!(
        repo::count_one_time_prekeys(&pool, device).await.unwrap(),
        2
    );

    repo::take_prekey_bundle(&pool, device).await.unwrap();

    assert_eq!(
        repo::count_one_time_prekeys(&pool, device).await.unwrap(),
        1
    );
}

/// Пополнение добавляет ключи, а не заменяет пул.
#[tokio::test]
async fn refill_adds_to_the_pool() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("heidi"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    let signed = (1, &[0x11; 32][..], &[0xAA; 64][..]);
    let kem = (2, &[0x22; 1568][..], &[0xBB; 64][..]);

    repo::publish_prekeys(&pool, device, signed, kem, &[(10, vec![0x33; 32])], &[])
        .await
        .unwrap();
    repo::publish_prekeys(&pool, device, signed, kem, &[(11, vec![0x34; 32])], &[])
        .await
        .unwrap();

    assert_eq!(
        repo::count_one_time_prekeys(&pool, device).await.unwrap(),
        2
    );
}

#[tokio::test]
async fn envelope_round_trips() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("ivan"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    let envelope_id = repo::enqueue_envelope(&pool, device, b"opaque ciphertext", 3600)
        .await
        .unwrap();

    let waiting = repo::fetch_envelopes(&pool, device, 10).await.unwrap();

    assert_eq!(waiting.len(), 1);
    let first = waiting.first().unwrap();
    assert_eq!(first.envelope_id, envelope_id);
    assert_eq!(first.ciphertext, b"opaque ciphertext");
}

/// Время постановки, **выдаваемое клиенту**, округлено до часа.
///
/// ⚠️ Этот тест проверяет выдачу, а не хранение — и был зелёным,
/// пока в базе лежало точное время. От дампа защищает то, что
/// проверяют `stored_envelope_times_are_hour_aligned` и соседние.
#[tokio::test]
async fn queued_time_is_bucketed_to_the_hour() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("judy"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::enqueue_envelope(&pool, device, b"payload", 3600)
        .await
        .unwrap();

    let waiting = repo::fetch_envelopes(&pool, device, 10).await.unwrap();
    let bucketed = waiting.first().map(|e| e.queued_at_bucketed).unwrap();

    assert_eq!(bucketed % 3600, 0, "метка не округлена до часа");
}

/// Сколько строк таблицы хранят время не кратное часу.
///
/// Смотрит на то, что лежит в базе, — то есть ровно на то, что увидел
/// бы дамп, а не на то, что сервер выдаёт клиенту.
async fn unaligned(pool: &PgPool, table: &str, column: &str, owner: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table} WHERE {owner} = $1 AND date_trunc('hour', {column}) <> {column}"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// 🔐 В базе нет точного времени отправки конверта.
///
/// Документ о сроках хранения обещал, что сервер не может выдать время
/// отправки: «перечисленного нет в базе». Оно было — `queued_at` и
/// `expires_at` хранили момент постановки с точностью до микросекунды.
/// Округление делалось только при выдаче клиенту.
#[tokio::test]
async fn stored_envelope_times_are_hour_aligned() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("kate"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::enqueue_envelope(&pool, device, b"payload", 30 * 24 * 3600)
        .await
        .unwrap();

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM envelopes WHERE destination_device_id = $1")
            .bind(device)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1, "заготовка теста: конверт не записан");

    for column in ["queued_at", "expires_at"] {
        assert_eq!(
            unaligned(&pool, "envelopes", column, "destination_device_id", device).await,
            0,
            "envelopes.{column} хранит время точнее часа"
        );
    }
}

/// 🔐 В базе нет точного времени загрузки вложения.
///
/// Вложение хранит, кто его загрузил. Точное время загрузки рядом
/// с точным временем конверта связывало загрузившего с получателем —
/// то есть обходило sealed sender для любого сообщения с вложением.
#[tokio::test]
async fn stored_attachment_times_are_hour_aligned() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("liam"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    repo::store_attachment(&pool, device, &[0xAB; 64], 30 * 24 * 3600)
        .await
        .unwrap();

    for column in ["uploaded_at", "expires_at"] {
        assert_eq!(
            unaligned(&pool, "attachments", column, "uploader_device_id", device).await,
            0,
            "attachments.{column} хранит время точнее часа"
        );
    }
}

/// 🔐 В базе нет точного времени публикации подписанного предключа.
///
/// Момент публикации — момент, когда устройство было в сети; ряд таких
/// моментов выдавал распорядок владельца. 0005 это место пропустила.
#[tokio::test]
async fn stored_prekey_time_is_hour_aligned() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("nina"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    // Дважды: вставка берёт умолчание столбца, обновление — выражение
    // в запросе. Точным могло остаться любое из двух.
    for _ in 0..2 {
        repo::publish_prekeys(
            &pool,
            device,
            (1, &[0x11; 32], &[0xAA; 64]),
            (2, &[0x22; 1568], &[0xBB; 64]),
            &[],
            &[],
        )
        .await
        .unwrap();

        assert_eq!(
            unaligned(&pool, "signed_prekeys", "updated_at", "device_id", device).await,
            0,
            "signed_prekeys.updated_at хранит время точнее часа"
        );
    }
}

/// 🔐 Жалоба на аккаунт хранится с часовой точностью и уходит вместе
/// с ним.
///
/// Жалобы переживали удаление: `reported_account` ни на что
/// не ссылался, и после удаления в базе оставалось «на этот аккаунт
/// жаловались вот эти устройства».
#[tokio::test]
async fn reports_about_an_account_are_hour_aligned_and_leave_with_it() {
    let pool = require_pool!();
    let (reported_account, reported_device) =
        repo::register_account(&pool, &unique_name("oscar"), &[3u8; 32], &[4u8; 32])
            .await
            .unwrap();
    let (_complainant, complainant_device) =
        repo::register_account(&pool, &unique_name("pia"), &[5u8; 32], &[6u8; 32])
            .await
            .unwrap();

    assert!(
        repo::record_sealed_sender_report(
            &pool,
            reported_account,
            reported_device,
            complainant_device
        )
        .await
        .unwrap(),
        "заготовка теста: жалоба не записана"
    );
    assert_eq!(
        unaligned(
            &pool,
            "sealed_sender_reports",
            "created_at",
            "reported_account",
            reported_account
        )
        .await,
        0,
        "sealed_sender_reports.created_at хранит время точнее часа"
    );

    repo::delete_account(&pool, reported_device).await.unwrap();

    let left: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sealed_sender_reports WHERE reported_account = $1",
    )
    .bind(reported_account)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(left, 0, "жалобы на удалённый аккаунт остались в базе");
}

/// Конверты одного часа доставляются в порядке отправки.
///
/// Время теперь часовое, и порядок держит позиция в очереди получателя.
/// Начальное сообщение сессии, пришедшее после следующего за ним,
/// не расшифровалось бы.
#[tokio::test]
async fn envelopes_within_one_hour_keep_their_order() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("mona"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    let mut sent = Vec::new();
    for index in 0u8..8 {
        sent.push(
            repo::enqueue_envelope(&pool, device, &[index], 3600)
                .await
                .unwrap(),
        );
    }

    let delivered: Vec<Uuid> = repo::fetch_envelopes(&pool, device, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|envelope| envelope.envelope_id)
        .collect();

    assert_eq!(delivered, sent, "конверты одного часа пришли не по порядку");
}

/// 🔐 Подтверждение доставки удаляет конверт немедленно.
///
/// Раздел 14.4: доставленное хранится ноль секунд.
#[tokio::test]
async fn acknowledged_envelope_is_deleted() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("karl"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    let envelope_id = repo::enqueue_envelope(&pool, device, b"payload", 3600)
        .await
        .unwrap();

    repo::acknowledge_envelope(&pool, device, envelope_id)
        .await
        .unwrap();

    assert!(repo::fetch_envelopes(&pool, device, 10)
        .await
        .unwrap()
        .is_empty());
}

/// 🔐 Чужое устройство не может удалить конверт.
#[tokio::test]
async fn foreign_device_cannot_acknowledge() {
    let pool = require_pool!();
    let (_a, first) = repo::register_account(&pool, &unique_name("liam"), &[1u8; 32], &[2u8; 32])
        .await
        .unwrap();
    let (_b, second) = repo::register_account(&pool, &unique_name("mia"), &[3u8; 32], &[4u8; 32])
        .await
        .unwrap();

    let envelope_id = repo::enqueue_envelope(&pool, first, b"payload", 3600)
        .await
        .unwrap();

    repo::acknowledge_envelope(&pool, second, envelope_id)
        .await
        .unwrap();

    assert_eq!(
        repo::fetch_envelopes(&pool, first, 10).await.unwrap().len(),
        1,
        "чужое устройство удалило конверт"
    );
}

/// 🔐 Конверт сверх лимита отвергается.
#[tokio::test]
async fn oversized_envelope_is_rejected() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("nina"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    let too_big = vec![0u8; aegis_server_db::MAX_ENVELOPE_BYTES + 1];
    let result = repo::enqueue_envelope(&pool, device, &too_big, 3600).await;

    assert!(matches!(result, Err(RepoError::EnvelopeTooLarge)));
}

/// Просроченные конверты удаляются и не выдаются.
#[tokio::test]
async fn expired_envelopes_are_purged() {
    let pool = require_pool!();
    let (_account, device) =
        repo::register_account(&pool, &unique_name("olga"), &[1u8; 32], &[2u8; 32])
            .await
            .unwrap();

    // Отрицательный TTL: конверт просрочен в момент создания.
    repo::enqueue_envelope(&pool, device, b"stale", -1)
        .await
        .unwrap();

    assert!(
        repo::fetch_envelopes(&pool, device, 10)
            .await
            .unwrap()
            .is_empty(),
        "просроченный конверт выдан клиенту"
    );

    let purged = repo::purge_expired(&pool).await.unwrap();
    assert!(purged >= 1, "просроченный конверт не удалён");
}

/// 🔐 Удаление аккаунта уносит устройства, ключи и конверты.
///
/// Каскад проверяется против настоящей базы: он живёт во внешних ключах
/// схемы, и мок повторил бы предположения кода, а не поведение Postgres.
#[tokio::test]
async fn account_deletion_cascades() {
    let pool = require_pool!();
    let username = unique_name("peter");
    let (account, device) = repo::register_account(&pool, &username, &[1u8; 32], &[2u8; 32])
        .await
        .unwrap();

    repo::publish_prekeys(
        &pool,
        device,
        (1, &[0x11; 32], &[0xAA; 64]),
        (2, &[0x22; 1568], &[0xBB; 64]),
        &[(10, vec![0x33; 32])],
        &[],
    )
    .await
    .unwrap();
    repo::enqueue_envelope(&pool, device, b"payload", 3600)
        .await
        .unwrap();

    sqlx::query("DELETE FROM accounts WHERE account_id = $1")
        .bind(account)
        .execute(&pool)
        .await
        .unwrap();

    let devices: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE account_id = $1")
        .bind(account)
        .fetch_one(&pool)
        .await
        .unwrap();
    let envelopes: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM envelopes WHERE destination_device_id = $1")
            .bind(device)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(devices.0, 0, "устройства пережили удаление аккаунта");
    assert_eq!(envelopes.0, 0, "конверты пережили удаление аккаунта");
}

/// 🔐 Сервер не хранит время регистрации, присутствие и имя устройства.
///
/// Столбцы заполнялись умолчаниями базы и не читались ни одним запросом
/// (миграция 0007). Проверка — по самой схеме: вернуть такой столбец
/// «для удобства» значит снова завести журнал того, кто и когда
/// появился и был в сети.
#[tokio::test]
async fn identifying_times_and_device_names_are_not_stored() {
    let pool = require_pool!();

    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name IN ('accounts', 'devices')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(!columns.is_empty(), "заготовка теста: таблиц нет");

    for (table, column) in &columns {
        assert!(
            !matches!(
                column.as_str(),
                "created_at" | "last_seen_at" | "device_name"
            ),
            "{table}.{column} снова хранится"
        );
    }
}
