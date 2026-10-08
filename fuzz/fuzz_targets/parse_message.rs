// SPDX-License-Identifier: Apache-2.0
#![no_main]

//! Фаззинг разбора входящего сообщения Double Ratchet.
//!
//! Первое, что делает клиент с байтами из сети, — разбирает заголовок
//! и выбирает по нему ключ. Разбор выполняется **до** проверки
//! аутентичности, поэтому он обрабатывает данные, которые никто не
//! подтверждал: отправитель волен прислать что угодно.
//!
//! Что ищется: паника на усечённом, удлинённом или бессмысленном входе.

use gasapp_protocol::{double_ratchet::RatchetState, x25519::X25519PrivateKey};
use gasapp_types::{Ciphertext, Timestamp};
use libfuzzer_sys::fuzz_target;
use rand_core::OsRng;

fuzz_target!(|data: &[u8]| {
    // Состояние-приёмник строится детерминированно: фаззится разбор
    // сообщения, а не генерация ключей.
    let shared = [0x11u8; 32];
    let our_ratchet = X25519PrivateKey::generate(&mut OsRng);
    let mut state = RatchetState::accept(&shared, our_ratchet);

    // Любые байты обязаны дать ошибку, а не панику. Успех тоже допустим
    // теоретически, но требует подбора корректного тега AEAD.
    let _ = state.decrypt(&Ciphertext::new(data.to_vec()), Timestamp::from_millis(0));
});
