// SPDX-License-Identifier: Apache-2.0

//! АУДИТ (2026-09-21): прежние состояния храповика в журнале WAL.
//!
//! Спецификация (§10.1) обещает: «each message key is consumed and
//! destroyed immediately». `save_session` делает `INSERT OR REPLACE`
//! без контрольной точки, поэтому прежние версии страницы с состоянием
//! сессии остаются кадрами в файле `-wal` до ближайшей контрольной
//! точки. Тот, у кого есть ключ базы и снимок файлов, достаёт их,
//! обрезая журнал по границе более ранней фиксации: `SQLite` сам
//! воспроизводит базу на тот момент.
//!
//! Тест утверждает правильное поведение (прежнее состояние не
//! извлекается) и потому падает, пока дефект не исправлен: он выключен
//! (`ignore`) и числится открытой находкой W-1 в
//! `docs/security/audit-2026-09-28.md`. Исправлено — снять `ignore`.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

use std::path::Path;

use aegis_protocol::keys::SessionState;
use aegis_storage::Storage;
use aegis_types::{ChatId, Secret, Timestamp};

const KEY: [u8; 32] = [0x5A; 32];
const PAGE: usize = 4096;
const WAL_HEADER: usize = 32;
const FRAME_HEADER: usize = 24;

/// Открывает копию базы тем же ключом и параметрами шифра.
fn open_copy(path: &Path) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(path).expect("копия открывается");
    connection
        .execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(KEY)))
        .expect("ключ");
    for pragma in [
        "PRAGMA cipher_page_size = 4096;",
        "PRAGMA cipher_hmac_algorithm = HMAC_SHA512;",
        "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
    ] {
        connection.execute_batch(pragma).expect("параметры шифра");
    }
    connection
}

/// Все состояния сессии чата, которые извлекаются из снимка файлов
/// обрезкой журнала по каждой фиксации.
fn recoverable_states(db: &Path, wal: &[u8], chat: &ChatId) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let frame = FRAME_HEADER + PAGE;
    let frames = (wal.len() - WAL_HEADER) / frame;

    for index in 0..frames {
        let header = WAL_HEADER + index * frame;
        let commit = u32::from_be_bytes(wal[header + 4..header + 8].try_into().expect("4 байта"));
        if commit == 0 {
            continue;
        }

        let dir = tempfile::tempdir().expect("каталог");
        let copy = dir.path().join("copy.db");
        std::fs::copy(db, &copy).expect("копия базы");
        std::fs::write(dir.path().join("copy.db-wal"), &wal[..header + frame])
            .expect("копия журнала");

        let connection = open_copy(&copy);
        let state: Option<Vec<u8>> = connection
            .query_row(
                "SELECT state FROM sessions WHERE chat_id = ?",
                [chat.as_bytes().to_vec()],
                |row| row.get(0),
            )
            .ok();

        if let Some(state) = state {
            if !found.contains(&state) {
                found.push(state);
            }
        }
    }

    found
}

#[test]
#[ignore = "открытая находка W-1: прежнее состояние храповика живёт в WAL до контрольной точки"]
fn audit_previous_ratchet_state_must_not_survive_in_wal() {
    let dir = tempfile::tempdir().expect("каталог");
    let path = dir.path().join("aegis.db");
    let storage = Storage::new(path.to_str().expect("путь"), &KEY).expect("хранилище");

    let chat = ChatId::generate();
    let now = Timestamp::from_millis(1_760_000_000_000);

    // «Состояние до сообщения» с узнаваемым ключом цепочки и
    // «состояние после» — как делает `receive_messages`.
    let before = vec![0xAA; 200];
    let after = vec![0xBB; 200];

    storage
        .save_session(
            &chat,
            &SessionState::from_serialized(Secret::new(before.clone())),
            now,
        )
        .expect("сохранение");
    storage
        .save_session(
            &chat,
            &SessionState::from_serialized(Secret::new(after.clone())),
            now,
        )
        .expect("сохранение");

    // Снимок файлов при живом приложении (или после того, как система
    // убила процесс, не закрыв базу, — обычное дело на Android).
    let wal = std::fs::read(dir.path().join("aegis.db-wal")).expect("журнал WAL есть");

    let states = recoverable_states(&path, &wal, &chat);

    assert!(states.contains(&after), "текущее состояние должно читаться");
    assert!(
        !states.contains(&before),
        "прежнее состояние храповика извлечено из журнала WAL ключом базы: \
         израсходованные ключи цепочки не уничтожены"
    );

    drop(storage);
}
