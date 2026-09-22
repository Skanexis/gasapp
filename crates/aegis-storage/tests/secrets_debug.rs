// SPDX-License-Identifier: Apache-2.0

//! 🔐 Приватные ключи не печатаются в `Debug`.
//!
//! `OwnKeys` выводил `Debug` и отдавал приватный identity-ключ и секреты
//! предключей байт за байтом: любой `{:?}` в журнале или сообщении
//! об ошибке выдал бы их целиком. Нашёл аудитор ядра; тест перенесён
//! из его рабочей копии.

#![allow(clippy::expect_used)]

use aegis_storage::Storage;
use aegis_types::Timestamp;

#[test]
fn own_keys_debug_does_not_print_secrets() {
    let dir = tempfile::tempdir().expect("каталог");
    let path = dir.path().join("aegis.db").to_string_lossy().into_owned();
    let storage = Storage::new(&path, &[0x5A; 32]).expect("хранилище");

    storage
        .save_own_keys(
            &[0xC3; 32],
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
        "приватный identity-ключ напечатан: {rendered}"
    );
    assert!(
        !rendered.contains("212, 212, 212"),
        "секреты предключей напечатаны: {rendered}"
    );
    assert!(rendered.contains("OwnKeys"), "заготовка теста: Debug пуст");
}
