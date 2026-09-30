// SPDX-License-Identifier: Apache-2.0

//! Находка B-1 (аудит 2026-09-21, `docs/security/audit-2026-09-28.md`):
//! удалённое сообщение и усечённая цепочка копий.
//!
//! Надгробие удаления живёт в инкременте, а у цепочки нет признака
//! «последнее звено», которому можно верить: хранитель файлов (облако),
//! не умея их прочесть, отдаёт цепочку без хвоста — и восстановление
//! проходит, возвращая удалённое.
//!
//! Закрыть это целиком можно только внешним доверенным указателем на
//! последнее звено. Держать его пришлось бы на сервере AEGIS, и сервер
//! узнавал бы, когда человек делает копии, — это противоречит принципу
//! «сервер не знает ничего лишнего». Поэтому решение (2026-09-30) —
//! **видимость**: восстановление сообщает время последней применённой
//! копии, и приложение показывает его («копия — на …»). Усечённая цепочка
//! выдаёт себя более ранней датой.
//!
//! Тест закрепляет то, что гарантируется: полная цепочка удалённое
//! убирает, а усечённая отдаёт дату своего последнего звена, а не дату
//! отброшенного хвоста.

#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use aegis_backup::{KdfParams, RecoveryKey};
use aegis_core::backup::BackupService;
use aegis_storage::{MessageStatus, Storage, StoredMessage};
use aegis_types::{AccountId, ChatId, Ciphertext, MessageId, Timestamp};
use rand_core::OsRng;

fn cheap() -> KdfParams {
    KdfParams {
        memory_kib: aegis_backup::kdf::MIN_MEMORY_KIB,
        iterations: aegis_backup::kdf::MIN_ITERATIONS,
        parallelism: 1,
    }
}

fn at(offset: i64) -> Timestamp {
    Timestamp::from_millis(1_760_000_000_000 + offset)
}

fn open_storage(dir: &tempfile::TempDir, name: &str) -> Storage {
    let path = dir.path().join(name).to_string_lossy().into_owned();

    Storage::new(&path, &[0x5A; 32]).expect("база")
}

#[test]
fn a_truncated_backup_chain_shows_its_older_date() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open_storage(&dir, "device.db");
    let chat = ChatId::generate();

    // Сообщение, которое потом удалят «у всех»: срока у него нет, и
    // чистка по сроку его после восстановления не уберёт.
    let deleted = StoredMessage {
        id: MessageId::generate(),
        chat_id: chat,
        sender_id: AccountId::generate(),
        timestamp: at(0),
        content: Ciphertext::new(b"DELETED-LATER".to_vec()),
        status: MessageStatus::Delivered,
        message_type: 0,
        expires_at: None,
    };
    storage.save_message(&deleted).expect("сообщение");

    let key = RecoveryKey::generate(&mut OsRng);
    let service = BackupService::with_params(&storage, cheap());

    let full = service
        .create(&key, None, at(0), &mut OsRng)
        .expect("снимок");
    storage
        .delete_message(&deleted.id, at(2_500))
        .expect("удаление");
    let tail = service
        .create(&key, None, at(3_000), &mut OsRng)
        .expect("инкремент с надгробием");

    // Полная цепочка: удалённое не возвращается, дата — последнего звена.
    let whole = open_storage(&dir, "whole.db");
    let outcome = BackupService::with_params(&whole, cheap())
        .restore(&key, &[full.archive.clone(), tail.archive], at(4_000))
        .expect("полная цепочка");
    assert_eq!(outcome.created_at, at(3_000));
    assert!(whole.load_messages(&chat, 10).expect("чтение").is_empty());

    // Усечённая цепочка: восстановление проходит (проверить полноту
    // нечем), но дата — отброшенного хвоста раньше, и человек это видит.
    let truncated = open_storage(&dir, "truncated.db");
    let outcome = BackupService::with_params(&truncated, cheap())
        .restore(&key, &[full.archive], at(4_000))
        .expect("усечённая цепочка");
    assert_eq!(
        outcome.created_at,
        at(0),
        "усечённая цепочка должна выдавать дату своего последнего звена"
    );
}
