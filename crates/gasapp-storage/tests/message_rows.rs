// SPDX-License-Identifier: Apache-2.0

//! Строки сообщений: удаление с вложениями и сохранение без замены.

#![allow(clippy::expect_used)]

use gasapp_storage::{MessageStatus, Storage, StoredAttachment, StoredMessage};
use gasapp_types::{AccountId, ChatId, Ciphertext, MessageId, Timestamp};

fn open(dir: &tempfile::TempDir) -> Storage {
    let path = dir.path().join("gasapp.db").to_string_lossy().into_owned();
    Storage::new(&path, &[0x5A; 32]).expect("хранилище")
}

fn message(
    id: MessageId,
    chat: ChatId,
    text: &str,
    expires_at: Option<Timestamp>,
) -> StoredMessage {
    StoredMessage {
        id,
        chat_id: chat,
        sender_id: AccountId::generate(),
        timestamp: Timestamp::from_millis(1_000),
        content: Ciphertext::new(text.as_bytes().to_vec()),
        status: MessageStatus::Delivered,
        message_type: 0,
        expires_at,
    }
}

fn with_attachment(storage: &Storage, id: MessageId, chat: ChatId, expires_at: Option<Timestamp>) {
    storage
        .save_message(&message(id, chat, "договор", expires_at))
        .expect("сообщение");
    storage
        .save_attachment(&StoredAttachment {
            message_id: id,
            attachment_type: 3,
            description: Some("описание файла".to_owned()),
            size: 1_000,
            created_at: Timestamp::from_millis(1_000),
            descriptor: Some(vec![0xA7; 64]),
        })
        .expect("вложение");
}

/// 🔐 Сообщение с вложением удаляется.
///
/// `attachments` ссылается на `messages` внешним ключом, а собранный
/// `SQLite` (`libsqlite3-sys`, в том числе с `SQLCipher`) включает проверку
/// внешних ключей по умолчанию. `DELETE FROM messages` для сообщения
/// с вложением отвергался: «удалить у меня» и «удалить у всех» падали
/// ошибкой хранилища, сообщение с файлом не удалялось никак.
#[test]
fn a_message_with_an_attachment_can_be_deleted() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open(&dir);
    let chat = ChatId::generate();
    let id = MessageId::generate();

    with_attachment(&storage, id, chat, None);

    storage
        .delete_message(&id, Timestamp::from_millis(2_000))
        .expect("сообщение с вложением удаляется");

    assert!(storage.load_messages(&chat, 10).expect("чтение").is_empty());
    assert!(
        storage.load_attachments(&id).expect("чтение").is_empty(),
        "описание вложения пережило сообщение"
    );
}

/// 🔐 Истёкшее сообщение с вложением исчезает — и не мешает исчезать
/// остальным.
///
/// Чистка удаляет все истёкшие одним запросом. Одно сообщение с файлом
/// роняло весь запрос: с этого момента в чате с таймером не исчезало
/// уже ничего.
#[test]
fn an_expired_message_with_an_attachment_is_purged() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open(&dir);
    let chat = ChatId::generate();
    let expired = Some(Timestamp::from_millis(1_500));

    let with_file = MessageId::generate();
    with_attachment(&storage, with_file, chat, expired);
    storage
        .save_message(&message(
            MessageId::generate(),
            chat,
            "просто текст",
            expired,
        ))
        .expect("сообщение");

    storage
        .purge_expired(Timestamp::from_millis(2_000))
        .expect("чистка проходит");

    assert!(
        storage.load_messages(&chat, 10).expect("чтение").is_empty(),
        "истёкшие сообщения остались"
    );
    assert!(storage
        .load_attachments(&with_file)
        .expect("чтение")
        .is_empty());
}

/// 🔐 Сохранение нового сообщения не заменяет существующее.
///
/// Идентификатор входящего сообщения выбирает собеседник. Сообщение
/// с идентификатором уже сохранённого не должно его переписать —
/// ни текст, ни чат.
#[test]
fn inserting_under_a_taken_id_changes_nothing() {
    let dir = tempfile::tempdir().expect("каталог");
    let storage = open(&dir);
    let ours = ChatId::generate();
    let id = MessageId::generate();

    assert!(storage
        .insert_message(&message(id, ours, "моё", None))
        .expect("первое"));

    let replaced = storage
        .insert_message(&message(id, ChatId::generate(), "подделка", None))
        .expect("второе");

    assert!(!replaced, "занятый идентификатор принят");

    let kept = storage.load_messages(&ours, 10).expect("чтение");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].content.as_bytes(), "моё".as_bytes());
}
