// SPDX-License-Identifier: Apache-2.0

//! АУДИТ (2026-09-21): секреты в `Debug` и без обнуления.
//!
//! `OwnKeys` — производный `Debug` и `Clone` над `Vec<u8>` с приватным
//! identity-ключом и всеми секретами предключей. Правило 4 плана
//! («ни одного байта ключевого материала в Debug») здесь нарушено,
//! а `Vec<u8>` не обнуляется при уничтожении. Читается при каждом
//! `load_identity`/`persist_secrets` (то есть на каждой отправке и приёме).

#![allow(clippy::expect_used)]

use aegis_storage::Storage;
use aegis_types::Timestamp;

#[test]
fn audit_own_keys_debug_must_not_print_private_key() {
    let dir = tempfile::tempdir().expect("каталог");
    let path = dir.path().join("aegis.db").to_string_lossy().into_owned();
    let storage = Storage::new(&path, &[0x5A; 32]).expect("хранилище");

    let private = [0xC3u8; 32];
    storage
        .save_own_keys(
            &private,
            &[0x01; 32],
            &[0xD4; 64],
            None,
            None,
            Timestamp::from_millis(1),
        )
        .expect("сохранение");

    let keys = storage
        .load_own_keys()
        .expect("чтение")
        .expect("ключи есть");
    let rendered = format!("{keys:?}");

    assert!(
        !rendered.contains("195, 195, 195"),
        "приватный identity-ключ напечатан в Debug: {}",
        rendered.get(..160).unwrap_or(&rendered)
    );
}
