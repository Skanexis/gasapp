// SPDX-License-Identifier: Apache-2.0
#![no_main]

//! Фаззинг разбора и проверки prekey bundle.
//!
//! Bundle приходит **с сервера**, а сервер в модели угроз недоверенный:
//! он раздаёт чужие предключи и может подменить в них что угодно. Именно
//! поэтому подписи проверяются ключом владельца bundle — и именно этот
//! путь здесь фаззится.
//!
//! Что ищется:
//!
//! * паника при разборе ключей неверной длины или некорректной кодировки;
//! * ветка, в которой bundle с неверной подписью всё же принимается.

use aegis_protocol::{
    keys::{
        IdentityKey, KemPublicKey, PreKeyBundle, PreKeyId, SignedKemPreKey, SignedPreKey,
    },
    pqxdh,
};
use aegis_types::{DeviceId, PublicKeyBytes};
use libfuzzer_sys::fuzz_target;

/// Считывает 32 байта, дополняя нулями при нехватке входа.
fn take_key(data: &[u8], offset: usize) -> PublicKeyBytes {
    let mut out = [0u8; 32];
    if let Some(slice) = data.get(offset..offset + 32) {
        out.copy_from_slice(slice);
    }

    PublicKeyBytes::new(out)
}

fuzz_target!(|data: &[u8]| {
    // Раскладка входа: identity(32) ‖ spk(32) ‖ подпись spk(64)
    //                  ‖ подпись kem(64) ‖ остаток — публичный ключ ML-KEM.
    let identity = take_key(data, 0);
    let signed_pre_key = take_key(data, 32);

    let spk_signature = data.get(64..128).unwrap_or(&[]).to_vec();
    let kem_signature = data.get(128..192).unwrap_or(&[]).to_vec();
    let kem_public = data.get(192..).unwrap_or(&[]).to_vec();

    let bundle = PreKeyBundle {
        device_id: DeviceId::generate(),
        identity_key: IdentityKey::new(identity),
        signed_pre_key: SignedPreKey {
            id: PreKeyId::new(1),
            public: signed_pre_key,
            signature: spk_signature,
        },
        one_time_pre_key: None,
        signed_kem_pre_key: SignedKemPreKey {
            id: PreKeyId::new(2),
            public: KemPublicKey::new(kem_public),
            signature: kem_signature,
        },
        one_time_kem_pre_key: None,
    };

    // Подделать подпись, не имея приватного ключа, фаззер не может, поэтому
    // ожидается отказ. Успех означал бы найденную подпись — событие
    // настолько маловероятное, что его наступление само по себе сигнал.
    assert!(
        pqxdh::verify_bundle(&bundle).is_err(),
        "bundle со случайной подписью принят"
    );
});
