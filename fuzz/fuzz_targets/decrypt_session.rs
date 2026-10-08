// SPDX-License-Identifier: Apache-2.0
#![no_main]

//! Фаззинг расшифровки со **случайным состоянием** сессии.
//!
//! Отличие от `parse_message`: там состояние корректное, а фаззится
//! сообщение. Здесь фаззится и то, и другое — состояние восстанавливается
//! из произвольных байт, как если бы файл базы был повреждён.
//!
//! Такое сочетание проверяет, что разбор состояния и разбор сообщения
//! согласованы: восстановленное состояние с неправдоподобными счётчиками
//! не должно приводить к панике при последующей расшифровке — например,
//! из-за вычитания счётчиков с переполнением при подсчёте пропущенных.

use gasapp_protocol::{double_ratchet::RatchetState, keys::SessionState};
use gasapp_types::{Ciphertext, Secret, Timestamp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Первая половина входа — состояние, вторая — сообщение.
    let split = data.len() / 2;
    let (state_bytes, message_bytes) = data.split_at(split);

    let session = SessionState::from_serialized(Secret::new(state_bytes.to_vec()));

    // Повреждённое состояние обязано отвергаться, а не паниковать.
    let Ok(mut state) = RatchetState::deserialize(&session) else {
        return;
    };

    let _ = state.decrypt(
        &Ciphertext::new(message_bytes.to_vec()),
        Timestamp::from_millis(0),
    );
});
