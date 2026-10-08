// SPDX-License-Identifier: Apache-2.0
#![no_main]

//! Фаззинг ресборки чанков SPQR.
//!
//! Чанки приходят из сети вместе с сообщениями, то есть это недоверенный
//! вход, полностью подконтрольный отправителю. Сборщик обязан на любой
//! последовательности либо вернуть данные, либо ошибку — но не паниковать
//! и не расти в памяти без предела.
//!
//! Что ищется:
//!
//! * паника при разборе (индексация за границу, переполнение счётчика);
//! * неограниченный рост потребления памяти при подаче чанков
//!   с растущими индексами и чередующимися эпохами;
//! * рассогласование состояния между эпохами.

use gasapp_protocol::spqr::{Chunk, ChunkAssembler, EpochId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Каждые 9 байт входа описывают один чанк: эпоха (4), индекс (2),
    // общее число (2), длина полезной нагрузки (1). Такое разбиение даёт
    // фаззеру прямой доступ к полям заголовка, а не заставляет угадывать
    // их через сериализацию.
    let mut assembler = ChunkAssembler::new();
    let mut cursor = 0usize;

    while let Some(header) = data.get(cursor..cursor + 9) {
        cursor += 9;

        let epoch = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let index = u16::from_be_bytes([header[4], header[5]]);
        let total = u16::from_be_bytes([header[6], header[7]]);
        let payload_len = usize::from(header[8]);

        let payload = match data.get(cursor..cursor + payload_len) {
            Some(slice) => {
                cursor += payload_len;
                slice.to_vec()
            }
            None => Vec::new(),
        };

        let chunk = Chunk {
            epoch: EpochId::from_u32(epoch),
            index,
            total,
            payload,
        };

        // Результат не важен — важно отсутствие паники и то, что сборщик
        // остаётся в согласованном состоянии для следующего чанка.
        let _ = assembler.accept(&chunk);
    }
});
