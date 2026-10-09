// SPDX-License-Identifier: Apache-2.0

//! Кнопки под сообщениями: отправить, показать, нажать, принять нажатие.
//!
//! Формат и пределы — в `gasapp_protocol::keyboard`. Здесь — правила:
//!
//! * кнопки прикладываются только к **своему** сообщению и принимаются
//!   только к сообщению **собеседника** в этом же чате;
//! * нажатие принимается, только если под нашим сообщением в этом чате
//!   действительно есть кнопка с такими данными: собеседник не может
//!   прислать «нажатие» с данными, которых ему не предлагали;
//! * кнопка со ссылкой никому ничего не отправляет — ядро возвращает
//!   ссылку, а открывать её или нет, решает человек.
//!
//! 🔐 Всё это едет внутри сквозного шифрования переписки: сервер не
//! видит ни кнопок, ни нажатий.

use gasapp_net::client::Transport;
use gasapp_protocol::content::Content;
use gasapp_protocol::keyboard::{ButtonAction, Keyboard};
use gasapp_storage::keyboards::StoredCallback;
use gasapp_types::{ChatId, GasAppError, MessageId, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::Client;

/// Нажатие кнопки под нашим сообщением.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ButtonCallback {
    /// Чат, в котором нажали.
    pub chat_id: ChatId,
    /// Сообщение, под которым нажали.
    pub message_id: MessageId,
    /// Данные нажатой кнопки.
    pub data: Vec<u8>,
}

impl<T: Transport> Client<T> {
    /// Прикладывает кнопки к своему сообщению (пустая клавиатура —
    /// убирает их) и отправляет собеседнику.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — это не своё сообщение либо
    ///   клавиатура нарушает пределы;
    /// * те же, что у [`Client::send_message`].
    pub fn send_keyboard<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        target: &MessageId,
        keyboard: &Keyboard,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<()> {
        let encoded = keyboard.to_bytes()?;
        let own = self.storage.get_account_id()?;

        let Some((chat_id, sender)) = self.storage.message_origin(target)? else {
            return Err(GasAppError::Malformed);
        };

        if own.as_ref() != Some(&sender) {
            return Err(GasAppError::Malformed);
        }

        let sent_to = self.send_content(
            peer_username,
            &Content::Keyboard {
                target: *target.as_uuid().as_bytes(),
                keyboard: if keyboard.rows.is_empty() {
                    Keyboard::default().to_bytes()?
                } else {
                    encoded.clone()
                },
            },
            now,
            rng,
        )?;

        // 🔐 Кнопки ушли не в тот чат, где лежит сообщение: нажатий по
        // ним принимать нельзя.
        if sent_to != chat_id {
            return Err(GasAppError::Malformed);
        }

        self.storage.put_message_keyboard(
            target,
            &chat_id,
            true,
            if keyboard.rows.is_empty() {
                &[]
            } else {
                &encoded
            },
        )
    }

    /// Кнопки под сообщением — для показа. Без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn message_keyboard(&self, message_id: &MessageId) -> Result<Option<Keyboard>> {
        Ok(self
            .storage
            .message_keyboard(message_id)?
            .and_then(|stored| Keyboard::from_bytes(&stored.keyboard).ok())
            .filter(|keyboard| !keyboard.rows.is_empty()))
    }

    /// Нажимает кнопку под сообщением собеседника.
    ///
    /// Кнопка со ссылкой — возвращает ссылку и ничего не отправляет.
    /// Кнопка с данными — отправляет их автору сообщения.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::SessionNotFound`] — кнопки нет либо собеседник
    ///   этого чата неизвестен;
    /// * те же, что у [`Client::send_message`].
    pub fn press_button<R: RngCore + CryptoRng>(
        &self,
        message_id: &MessageId,
        row: u32,
        column: u32,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<Option<String>> {
        let stored = self
            .storage
            .message_keyboard(message_id)?
            .filter(|stored| !stored.outgoing)
            .ok_or(GasAppError::SessionNotFound)?;
        let keyboard = Keyboard::from_bytes(&stored.keyboard)?;
        let button = usize::try_from(row)
            .ok()
            .zip(usize::try_from(column).ok())
            .and_then(|(row, column)| keyboard.button(row, column))
            .ok_or(GasAppError::SessionNotFound)?;

        let data = match &button.action {
            ButtonAction::Url(url) => return Ok(Some(url.clone())),
            ButtonAction::Callback(data) => data.clone(),
        };

        // Нажатие уходит автору сообщения — собеседнику этого чата.
        let peer = self
            .contacts()?
            .into_iter()
            .find(|contact| contact.chat_id == Some(stored.chat_id) && !contact.replaced)
            .and_then(|contact| contact.username)
            .ok_or(GasAppError::SessionNotFound)?;

        self.send_content(
            &peer,
            &Content::Callback {
                target: *message_id.as_uuid().as_bytes(),
                data,
            },
            now,
            rng,
        )?;

        Ok(None)
    }

    /// Забирает нажатия кнопок под нашими сообщениями. Без сети.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — сбой базы.
    pub fn take_button_callbacks(&self) -> Result<Vec<ButtonCallback>> {
        Ok(self
            .storage
            .take_button_callbacks()?
            .into_iter()
            .map(|callback| ButtonCallback {
                chat_id: callback.chat_id,
                message_id: callback.message_id,
                data: callback.data,
            })
            .collect())
    }

    /// Принимает кнопки, которые собеседник приложил к своему сообщению.
    /// Негодная клавиатура молча отбрасывается.
    pub(super) fn accept_keyboard(
        &self,
        chat_id: &ChatId,
        target: &MessageId,
        encoded: &[u8],
    ) -> Result<()> {
        let Ok(keyboard) = Keyboard::from_bytes(encoded) else {
            return Ok(());
        };

        self.storage.put_message_keyboard(
            target,
            chat_id,
            false,
            if keyboard.rows.is_empty() {
                &[]
            } else {
                encoded
            },
        )
    }

    /// Принимает нажатие кнопки под нашим сообщением.
    ///
    /// 🔐 Только если под этим сообщением в этом чате есть наша кнопка
    /// с такими данными: иначе собеседник слал бы «нажатия» с данными,
    /// которые выбрал сам, и программа бота приняла бы их за выбор из
    /// предложенного.
    pub(super) fn accept_callback(
        &self,
        chat_id: &ChatId,
        target: &MessageId,
        data: Vec<u8>,
        now: Timestamp,
    ) -> Result<()> {
        let offered = self
            .storage
            .message_keyboard(target)?
            .filter(|stored| stored.outgoing && stored.chat_id == *chat_id)
            .and_then(|stored| Keyboard::from_bytes(&stored.keyboard).ok())
            .is_some_and(|keyboard| keyboard.has_callback(&data));

        if !offered {
            return Ok(());
        }

        self.storage.push_button_callback(&StoredCallback {
            chat_id: *chat_id,
            message_id: *target,
            data,
            received_at: now,
        })
    }
}
