// SPDX-License-Identifier: Apache-2.0
#![no_main]

//! Фаззинг разбора запечатанного конверта (sealed sender, раздел 15.2).
//!
//! # Почему этот вход недоверенный
//!
//! Запечатанный конверт приходит из сети **без аутентификации
//! отправителя** — в этом и смысл sealed sender. Метка формата, эфемерный
//! ключ и длина сертификата внутри читаются до того, как что-либо
//! подтверждено. Отправить такой конверт может любой, у кого есть ключ
//! доступа получателя, а при `allow_from_anyone` — вообще любой.
//!
//! Что проверяется:
//!
//! * `is_sealed` — различение по метке на любом входе;
//! * `unseal` — разбор внешнего слоя: эфемерный ключ, шифротекст
//!   ML-KEM (декапсуляция идёт до проверки тега), AEAD, длина
//!   сертификата внутри расшифрованного;
//! * `SenderCertificate::from_bytes` — разбор сертификата, который
//!   получатель затем предъявляет в жалобе;
//! * `padding::unpad` — снятие дополнения до бакета, через которое
//!   проходит каждое расшифрованное сообщение.
//!
//! Что ищется: паника на усечённом, удлинённом или бессмысленном входе
//! и чтение по длине, не сверенной с остатком буфера.

use gasapp_protocol::mlkem::MlKem1024PrivateKey;
use gasapp_protocol::padding;
use gasapp_protocol::sealed_sender::{self, SenderCertificate};
use gasapp_protocol::x25519::X25519PrivateKey;
use gasapp_types::PrivateKeyBytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Ключ получателя фиксирован: фаззится разбор, а не генерация ключей.
    // Расшифровать случайный вход фаззер не сможет — тег AEAD не сойдётся, —
    // поэтому глубже внешнего слоя его ведут отдельные вызовы ниже.
    let Ok(recipient) = X25519PrivateKey::from_bytes(PrivateKeyBytes::new([0x42u8; 32])) else {
        return;
    };

    // Ключ ML-KEM — тоже фиксированный: внешний слой гибридный, и
    // разбор шифротекста KEM идёт до проверки тега AEAD.
    let kem = MlKem1024PrivateKey::from_seed([0x24u8; 64]);

    let _ = sealed_sender::is_sealed(data);
    let _ = sealed_sender::unseal(&recipient, &kem, data);
    let _ = SenderCertificate::from_bytes(data);
    let _ = padding::unpad(data);
});
