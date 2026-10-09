// SPDX-License-Identifier: Apache-2.0

//! Кнопки под сообщениями на границе с платформой.
//!
//! Интерфейс получает только подписи и вид кнопки: ни данных, которые
//! кнопка отправит, ни ссылки до нажатия. Ссылку ядро отдаёт в ответ на
//! нажатие — и интерфейс обязан показать её человеку целиком, прежде
//! чем открыть.

use gasapp_types::{MessageId, Timestamp};

use crate::messenger::Messenger;
use crate::{guard, FfiError};

/// Кнопка под сообщением.
///
/// 🔐 Подпись написал собеседник: показывать можно, доверять — нет.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMessageButton {
    /// Подпись.
    pub label: String,
    /// Кнопка открывает ссылку, а не отправляет данные автору.
    pub is_link: bool,
}

fn message_id(raw: &str) -> Result<MessageId, FfiError> {
    uuid::Uuid::parse_str(raw)
        .map(MessageId::from_uuid)
        .map_err(|_| FfiError::InvalidArgument)
}

#[uniffi::export]
impl Messenger {
    /// Ряды кнопок под сообщением; пусто — кнопок нет. Без сети.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор не разбирается;
    /// [`FfiError::Core`] — чтение хранилища не удалось.
    pub fn message_buttons(
        &self,
        message_id_text: String,
    ) -> Result<Vec<Vec<FfiMessageButton>>, FfiError> {
        let id = message_id(&message_id_text)?;
        let client = self.reader()?;

        guard(|| client.message_keyboard(&id)).map(|keyboard| {
            keyboard.map_or_else(Vec::new, |keyboard| {
                keyboard
                    .rows
                    .into_iter()
                    .map(|row| {
                        row.into_iter()
                            .map(|button| FfiMessageButton {
                                label: button.label,
                                is_link: matches!(
                                    button.action,
                                    gasapp_protocol::keyboard::ButtonAction::Url(_)
                                ),
                            })
                            .collect()
                    })
                    .collect()
            })
        })
    }

    /// Нажимает кнопку под сообщением собеседника.
    ///
    /// Кнопка со ссылкой возвращает ссылку и ничего не отправляет:
    /// открыть её или нет, решает человек. Кнопка с данными отправляет
    /// их автору сообщения (сетевой вызов) и возвращает `None`.
    ///
    /// 🔐 Нажатие кнопки с данными сообщает автору, что человек сейчас
    /// у телефона, — как любой ответ.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — идентификатор не разбирается;
    /// [`FfiError::Core`] — кнопки уже нет либо отправка не удалась.
    pub fn press_message_button(
        &self,
        message_id_text: String,
        row: u32,
        column: u32,
        now_millis: i64,
    ) -> Result<Option<String>, FfiError> {
        let id = message_id(&message_id_text)?;
        let client = self.client()?;

        guard(|| {
            client.press_button(
                &id,
                row,
                column,
                Timestamp::from_millis(now_millis),
                &mut rand_core::OsRng,
            )
        })
    }
}
