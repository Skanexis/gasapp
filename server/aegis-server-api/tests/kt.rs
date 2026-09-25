// SPDX-License-Identifier: AGPL-3.0-only

//! 🔐 Журнал ключей (§9.7): эпохи, доказательства, версии, срок хранения.
//!
//! Один сценарий, а не несколько тестов: эпохи — общее состояние базы,
//! и параллельные тесты мешали бы друг другу строить их по порядку.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

mod common;

use std::sync::Arc;

use aegis_server_api::routes::AppState;
use aegis_server_db::kt;
use aegis_server_db::repo::{self, Rebind};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;
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

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let router = aegis_server_api::router(Arc::clone(state));
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    let request = match body {
        Some(value) => request.body(Body::from(value.to_string())).unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();

    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn to32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

/// Проверка доказательства — зеркало клиентской (`Proof::verify`):
/// сервер свою выдачу проверять не обязан, но тест — обязан.
fn root_from(proof: &serde_json::Value, index: &[u8; 32]) -> ([u8; 32], Option<(String, u64)>) {
    let siblings: Vec<[u8; 32]> = proof["siblings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| to32(s.as_str().unwrap()))
        .collect();

    let (mut hash, leaf) = if proof["leaf"].is_object() {
        let leaf = &proof["leaf"];
        let version = leaf["version"].as_u64().unwrap();
        let value = kt::leaf_value(
            index,
            &to32(leaf["identity_key"].as_str().unwrap()),
            &to32(leaf["pq_hash"].as_str().unwrap()),
            version,
        );
        (
            kt::leaf_hash(index, &value),
            Some((leaf["identity_key"].as_str().unwrap().to_owned(), version)),
        )
    } else if proof["other"].is_object() {
        let other = to32(proof["other"]["index"].as_str().unwrap());
        assert_ne!(&other, index);
        (
            kt::leaf_hash(&other, &to32(proof["other"]["value"].as_str().unwrap())),
            None,
        )
    } else {
        (kt::ZERO, None)
    };

    for (depth, sibling) in siblings.iter().enumerate().rev() {
        let right = index[depth / 8] >> (7 - depth % 8) & 1 == 1;
        hash = if right {
            kt::inner_hash(sibling, &hash)
        } else {
            kt::inner_hash(&hash, sibling)
        };
    }

    (hash, leaf)
}

async fn proof(state: &Arc<AppState>, name: &str, epochs: &[i64]) -> Vec<serde_json::Value> {
    let (status, body) = call(
        state,
        "POST",
        "/v1/kt/proofs",
        Some(serde_json::json!({ "index": hex::encode(kt::index(name)), "epochs": epochs })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");

    body["proofs"].as_array().unwrap().clone()
}

#[tokio::test]
async fn epochs_prove_keys_track_versions_and_expire() {
    let state = require_state!();
    let pool = &state.pool;

    let name = format!("kt_{}", &Uuid::new_v4().simple().to_string()[..16]);
    let absent = format!("kt_{}", &Uuid::new_v4().simple().to_string()[..16]);

    let (account, _device) = repo::register_account(pool, &name, &[7u8; 32], &[8u8; 32])
        .await
        .unwrap();
    repo::set_pq_identity(pool, account, &[0x51u8; 1952], &[0x52u8; 3373])
        .await
        .unwrap();

    let start = repo::kt_latest_epoch(pool)
        .await
        .unwrap()
        .map_or(1, |e| e.epoch + 1);

    // --- Эпоха 1: имя есть, ключ и версия 1.
    let first = repo::kt_build_epoch(pool, start)
        .await
        .unwrap()
        .expect("эпоха строится");
    assert!(
        repo::kt_build_epoch(pool, start).await.unwrap().is_none(),
        "эпоха строится дважды"
    );

    let proofs = proof(&state, &name, &[start]).await;
    let (root, leaf) = root_from(&proofs[0], &kt::index(&name));
    assert_eq!(root, first.root, "доказательство не сходится с корнем");
    assert_eq!(leaf, Some((hex::encode([7u8; 32]), 1)));

    let proofs = proof(&state, &absent, &[start]).await;
    let (root, leaf) = root_from(&proofs[0], &kt::index(&absent));
    assert_eq!(root, first.root);
    assert_eq!(leaf, None, "отсутствующее имя доказано присутствующим");

    // --- Эпоха 2: перепривязка — новый ключ, версия 2; эпоха 1 помнит старый.
    let new_device = repo::rebind_account(
        pool,
        account,
        Rebind {
            identity_key: &[9u8; 32],
            device_identity_key: &[10u8; 32],
            pq_identity_key: &[0x61u8; 1952],
            identity_binding: &[0x62u8; 3373],
            issued_at_millis: 1,
        },
    )
    .await
    .unwrap();
    let second = repo::kt_build_epoch(pool, start + 1)
        .await
        .unwrap()
        .unwrap();

    let proofs = proof(&state, &name, &[start, start + 1]).await;
    assert_eq!(proofs.len(), 2);
    let (root, leaf) = root_from(&proofs[0], &kt::index(&name));
    assert_eq!(
        (root, leaf),
        (first.root, Some((hex::encode([7u8; 32]), 1)))
    );
    let (root, leaf) = root_from(&proofs[1], &kt::index(&name));
    assert_eq!(
        (root, leaf),
        (second.root, Some((hex::encode([9u8; 32]), 2)))
    );

    // --- Цепочка вершин.
    let (status, heads) = call(&state, "GET", &format!("/v1/kt/heads/{start}"), None).await;
    assert_eq!(status, StatusCode::OK);
    let heads = heads["epochs"].as_array().unwrap();
    assert_eq!(heads[0]["head"].as_str().unwrap(), hex::encode(first.head));
    assert_eq!(
        to32(heads[1]["head"].as_str().unwrap()),
        kt::head(u64::try_from(start + 1).unwrap(), &second.root, &first.head),
    );

    // --- Эпоха 3: аккаунт удалён — имени нет; эпоха 2 его помнит.
    repo::delete_account(pool, new_device).await.unwrap();
    let third = repo::kt_build_epoch(pool, start + 2)
        .await
        .unwrap()
        .unwrap();
    let proofs = proof(&state, &name, &[start + 1, start + 2]).await;
    assert!(root_from(&proofs[0], &kt::index(&name)).1.is_some());
    let (root, leaf) = root_from(&proofs[1], &kt::index(&name));
    assert_eq!((root, leaf), (third.root, None));

    // --- 🔐 Срок хранения: через окно истории старые эпохи и строки уходят.
    let later = start + 2 + kt::HISTORY_EPOCHS + 1;
    repo::kt_build_epoch(pool, later).await.unwrap().unwrap();
    assert!(
        proof(&state, &name, &[start]).await.is_empty(),
        "эпоха вне окна отдаётся"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM kt_leaves WHERE idx = $1")
        .bind(kt::index(&name).as_slice())
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 0, "история имени пережила окно");
}
