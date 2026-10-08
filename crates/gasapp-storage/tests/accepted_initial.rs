// SPDX-License-Identifier: Apache-2.0

//! Записи о принятых конвертах инициации — защита от их повтора.

#![allow(clippy::expect_used)]

use gasapp_storage::Storage;
use gasapp_types::Timestamp;

fn open(dir: &tempfile::TempDir) -> Storage {
    let path = dir.path().join("gasapp.db").to_string_lossy().into_owned();
    Storage::new(&path, &[0x5A; 32]).expect("хранилище")
}

/// Запись живёт, пока жив подписанный предключ, принявший конверт,
/// и забывается, когда его нет: повтор без этого ключа
/// не расшифруется и так.
#[test]
fn records_of_dead_signed_prekeys_are_forgotten() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open(&dir);
    let now = Timestamp::from_millis(1_000);

    let live_key = vec![0x01; 32];
    let dead_key = vec![0x02; 32];

    storage
        .remember_initial(&[0xA1; 32], &live_key, now)
        .expect("запись");
    storage
        .remember_initial(&[0xB2; 32], &dead_key, now)
        .expect("запись");

    assert!(storage.initial_accepted(&[0xA1; 32]).expect("чтение"));
    assert!(storage.initial_accepted(&[0xB2; 32]).expect("чтение"));

    let forgotten = storage
        .forget_initials_except(std::slice::from_ref(&live_key))
        .expect("чистка");

    assert_eq!(forgotten, 1);
    assert!(
        storage.initial_accepted(&[0xA1; 32]).expect("чтение"),
        "забыта запись живого предключа — повтор снова прошёл бы"
    );
    assert!(!storage.initial_accepted(&[0xB2; 32]).expect("чтение"));
}

/// Незнакомый base key не считается принятым.
#[test]
fn an_unknown_base_key_is_not_accepted() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open(&dir);

    assert!(!storage.initial_accepted(&[0xC3; 32]).expect("чтение"));
}
