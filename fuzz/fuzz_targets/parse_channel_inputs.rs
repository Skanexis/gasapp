// SPDX-License-Identifier: Apache-2.0
//
// Всё, что о каналах и ботах приходит снаружи: ссылка на канал и заявка
// на администрирование (их вставляет человек — из чата, QR, буфера),
// ссылка-приглашение в закрытый канал, кнопки бота под сообщением
// и описание вложения записи (их присылает автор канала или бот).
//
// Разбор не должен паниковать ни на каком входе, а разобранное —
// записываться обратно.

#![no_main]

use gasapp_media::descriptor::AttachmentDescriptor;
use gasapp_protocol::channel::{AdminRequest, ChannelAccess};
use gasapp_protocol::channel_join::JoinLink;
use gasapp_protocol::keyboard::Keyboard;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ChannelAccess::parse(text);
        let _ = AdminRequest::parse(text);
        let _ = JoinLink::parse(text);
    }

    if let Ok(keyboard) = Keyboard::from_bytes(data) {
        let again = keyboard
            .to_bytes()
            .expect("разобранные кнопки обязаны записываться");
        Keyboard::from_bytes(&again).expect("записанные кнопки обязаны читаться");
    }

    if let Ok(descriptor) = AttachmentDescriptor::from_bytes(data) {
        let again = descriptor
            .to_bytes()
            .expect("разобранное описание обязано записываться");
        AttachmentDescriptor::from_bytes(&again).expect("записанное описание обязано читаться");
    }
});
