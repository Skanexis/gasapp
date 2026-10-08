// SPDX-License-Identifier: Apache-2.0

//! 🔐 Исчезающие сообщения не попадают в резервную копию.
//!
//! Надгробие убирает исчезнувшее сообщение только при восстановлении
//! **всей** цепочки. Полный снимок, сделанный до истечения таймера,
//! держал текст всегда — у того, кто хранит файлы копии, — а цепочку
//! без хвоста восстановление принимает: признака «последнее звено»,
//! которому можно верить, у неё нет. Нашёл аудитор (A6); проверка
//! перенесена из его рабочей копии — та её часть, которую код может
//! выполнить: исчезающее сообщение не попадает в копию вовсе.

#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use gasapp_backup::{BackupChain, KdfParams, RecoveryKey};
use gasapp_core::backup::BackupService;
use gasapp_storage::{MessageStatus, Storage, StoredMessage};
use gasapp_types::{AccountId, ChatId, Ciphertext, MessageId, Timestamp};
use rand_core::OsRng;

const CANARY: &[u8] = b"VANISHING-CANARY";
const LASTING: &[u8] = b"LASTING-MESSAGE";

fn cheap() -> KdfParams {
    KdfParams {
        memory_kib: gasapp_backup::kdf::MIN_MEMORY_KIB,
        iterations: gasapp_backup::kdf::MIN_ITERATIONS,
        parallelism: 1,
    }
}

fn at(offset: i64) -> Timestamp {
    Timestamp::from_millis(1_760_000_000_000 + offset)
}

fn message(chat: ChatId, content: &[u8], expires_at: Option<Timestamp>) -> StoredMessage {
    StoredMessage {
        id: MessageId::generate(),
        chat_id: chat,
        sender_id: AccountId::generate(),
        timestamp: at(0),
        content: Ciphertext::new(content.to_vec()),
        status: MessageStatus::Delivered,
        message_type: 0,
        expires_at,
    }
}

#[test]
fn a_disappearing_message_never_enters_a_backup() {
    let dir = tempfile::tempdir().expect("каталог");
    let path = dir.path().join("device.db").to_string_lossy().into_owned();
    let storage = Storage::new(&path, &[0x5A; 32]).expect("база");
    let chat = ChatId::generate();

    // Снимок делается, пока исчезающее сообщение ещё живо.
    storage
        .save_message(&message(chat, CANARY, Some(at(60_000))))
        .expect("исчезающее");
    storage
        .save_message(&message(chat, LASTING, None))
        .expect("обычное");

    let key = RecoveryKey::generate(&mut OsRng);
    let full = BackupService::with_params(&storage, cheap())
        .create(&key, None, at(1_000), &mut OsRng)
        .expect("снимок");

    let opened = BackupChain::restore(&key, std::slice::from_ref(&full.archive))
        .expect("снимок открывается");
    let contents: Vec<&[u8]> = opened
        .bundle
        .messages
        .iter()
        .map(|record| record.content.as_slice())
        .collect();

    assert!(
        !contents.contains(&CANARY),
        "исчезающее сообщение попало в снимок"
    );
    assert!(
        contents.contains(&LASTING),
        "заготовка теста: обычное сообщение в снимок не попало"
    );
}
