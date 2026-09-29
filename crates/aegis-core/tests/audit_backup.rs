// SPDX-License-Identifier: Apache-2.0

//! АУДИТ (2026-09-21): исчезающие сообщения и резервная копия.
//!
//! Надгробие (`backup_tombstones`) убирает исчезнувшее сообщение только
//! при восстановлении **всей** цепочки. Само сообщение при этом лежит
//! в полном снимке в облаке и после истечения таймера, а цепочка не
//! несёт аутентифицированного признака «последнее звено»: тот, кто
//! хранит файлы, отдаёт снимок без хвоста — и восстановление
//! проходит успешно, возвращая исчезнувшее.
//!
//! Падает, пока дефект не исправлен: выключен (`ignore`) и числится
//! открытой находкой B-1 в `docs/security/audit-2026-09-28.md`.

#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use aegis_backup::{BackupChain, KdfParams, RecoveryKey};
use aegis_core::backup::BackupService;
use aegis_storage::{MessageStatus, Storage, StoredMessage};
use aegis_types::{AccountId, ChatId, Ciphertext, MessageId, Timestamp};
use rand_core::OsRng;

const CANARY: &[u8] = b"VANISHING-CANARY";

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
#[ignore = "открытая находка B-1: удалённое возвращается из усечённой цепочки копий"]
fn audit_expired_message_must_not_come_back_from_a_truncated_chain() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open_storage(&dir, "device.db");
    let chat = ChatId::generate();

    let vanishing = StoredMessage {
        id: MessageId::generate(),
        chat_id: chat,
        sender_id: AccountId::generate(),
        timestamp: at(0),
        content: Ciphertext::new(CANARY.to_vec()),
        status: MessageStatus::Delivered,
        message_type: 0,
        expires_at: Some(at(1_000)),
    };
    storage.save_message(&vanishing).expect("сообщение");

    // Второе — удалённое вручную («удалить у всех» от собеседника
    // приходит сюда же): срока у него нет, и чистка по сроку его
    // после восстановления не уберёт.
    let deleted = StoredMessage {
        id: MessageId::generate(),
        expires_at: None,
        ..vanishing.clone()
    };
    storage.save_message(&deleted).expect("сообщение");

    let key = RecoveryKey::generate(&mut OsRng);
    let service = BackupService::with_params(&storage, cheap());

    let full = service
        .create(&key, None, at(0), &mut OsRng)
        .expect("снимок");
    assert_eq!(storage.purge_expired(at(2_000)).expect("чистка"), 1);
    storage
        .delete_message(&deleted.id, at(2_500))
        .expect("удаление");
    let _tombstone = service
        .create(&key, None, at(3_000), &mut OsRng)
        .expect("инкремент с надгробием");

    // (а) Полный снимок после истечения по-прежнему содержит текст.
    let opened = BackupChain::restore(&key, std::slice::from_ref(&full.archive))
        .expect("снимок открывается");
    let still_there = opened
        .bundle
        .messages
        .iter()
        .any(|record| record.content == CANARY);

    // (б) Хранитель файлов отдаёт цепочку без хвоста — восстановление
    // проходит и возвращает исчезнувшее сообщение.
    let fresh = open_storage(&dir, "restored.db");
    BackupService::with_params(&fresh, cheap())
        .restore(&key, &[full.archive], at(4_000))
        .expect("восстановление усечённой цепочки прошло");
    // Приложение чистит истёкшее сразу после открытия базы.
    fresh.purge_expired(at(5_000)).expect("чистка");
    let resurrected = fresh.load_messages(&chat, 10).expect("чтение").len();

    assert!(
        !still_there && resurrected == 0,
        "исчезнувшее сообщение осталось в снимке ({still_there}) \
         и вернулось из усечённой цепочки ({resurrected} шт.)"
    );
}
