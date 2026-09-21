// SPDX-License-Identifier: Apache-2.0

//! 🔐 Сроки хранения исполняются, а не только обещаны.
//!
//! `repo::purge_expired` и `purge_expired_attachments` существовали,
//! их комментарии говорили «вызывается по расписанию», а расписания
//! не было — их вызывал только тест. Истёкшее переставало выдаваться
//! и оставалось в базе навсегда, вместе с `uploader_device_id`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use aegis_server_api::retention;
use aegis_server_db::repo;
use uuid::Uuid;

macro_rules! require_state {
    () => {
        match common::state().await {
            Some(state) => state,
            None => {
                eprintln!("AEGIS_TEST_DATABASE_URL не задан — тест пропущен");
                return;
            }
        }
    };
}

async fn exists(pool: &sqlx::PgPool, table: &str, column: &str, id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS (SELECT 1 FROM {table} WHERE {column} = $1)"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// 🔐 Проход очистки удаляет истёкшее и не трогает живое.
#[tokio::test]
async fn a_purge_removes_expired_rows_and_keeps_live_ones() {
    let state = require_state!();
    let pool = &state.pool;

    let (_account, device) = repo::register_account(
        pool,
        &format!("retention-{}", Uuid::new_v4()),
        &[1u8; 32],
        &[2u8; 32],
    )
    .await
    .unwrap();

    // Нулевой срок: истекает в начале текущего часа, то есть уже.
    let expired_envelope = repo::enqueue_envelope(pool, device, b"old", 0)
        .await
        .unwrap();
    let live_envelope = repo::enqueue_envelope(pool, device, b"new", 3600)
        .await
        .unwrap();
    let expired_attachment = repo::store_attachment(pool, device, &[1; 32], 0)
        .await
        .unwrap();
    let live_attachment = repo::store_attachment(pool, device, &[2; 32], 3600)
        .await
        .unwrap();

    let purged = retention::purge_once(pool).await.unwrap();

    assert!(
        purged.envelopes >= 1 && purged.attachments >= 1,
        "проход ничего не удалил: {purged:?}"
    );

    assert!(
        !exists(pool, "envelopes", "envelope_id", expired_envelope).await,
        "истёкший конверт остался"
    );
    assert!(
        !exists(pool, "attachments", "attachment_id", expired_attachment).await,
        "истёкшее вложение осталось"
    );
    assert!(
        exists(pool, "envelopes", "envelope_id", live_envelope).await,
        "удалён живой конверт"
    );
    assert!(
        exists(pool, "attachments", "attachment_id", live_attachment).await,
        "удалено живое вложение"
    );
}

/// 🔐 Процесс сервера действительно запускает очистку.
///
/// Именно этого и не было: механизм существовал и был покрыт тестом,
/// а вызова в процессе не было. Проверка по исходнику грубая, но ловит
/// ровно тот дефект — снятый вызов.
#[test]
fn the_server_process_runs_the_purge() {
    let main = include_str!("../src/main.rs");

    assert!(
        main.contains("tokio::spawn(aegis_server_api::retention::run("),
        "main.rs не запускает retention::run: сроки хранения не исполняются"
    );
}
