// SPDX-License-Identifier: Apache-2.0

//! Argon2id совпадает с RFC 9106 (раздел 5.3).
//!
//! PIN растягивается Argon2id (`pin::derive_key`); ошибка в реализации
//! дала бы ключ, который не воспроизведёт никакая другая, — копию базы
//! было бы не открыть, — либо слабее заявленного. Проверяется тот же
//! крейт и та же версия (0x13), что в `pin.rs`, на официальном векторе
//! со всеми входами: пароль, соль, секрет и связанные данные.

#![allow(clippy::unwrap_used)]

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn argon2id_matches_rfc9106() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();

    let argon =
        Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();

    let mut tag = [0u8; 32];
    argon
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag)
        .unwrap();

    assert_eq!(
        tag.as_slice(),
        hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659").as_slice(),
        "Argon2id разошёлся с RFC 9106"
    );
}
