// SPDX-License-Identifier: Apache-2.0

//! Блокировка собеседника и жалоба на него.
//!
//! **Блокировка** — только на этом устройстве (`aegis-storage::blocks`):
//! конверты заблокированного собеседника принимаются и молча
//! отбрасываются, в ответ не уходит ничего, запроса на переписку не
//! возникает. Сервер о ней не знает — узнай он, узнал бы, что двое были
//! знакомы.
//!
//! **Жалоба** уходит оператору сервера и доказывается сертификатом
//! отправителя, снятым с его запечатанного конверта: сервер проверяет
//! свою подпись (`/v1/sealed/report`). Жалобу нельзя навесить на того,
//! кто тебе не писал. 🔐 Жалоба раскрывает серверу пару «кто пожаловался —
//! на кого»: без этого жалобы нельзя было бы ни считать, ни проверять.
//! Содержимое переписки в жалобу не уходит — его у сервера нет и не будет.

use aegis_net::api::SealedReportRequest;
use aegis_net::client::Transport;
use aegis_storage::blocks::BlockedChat;
use aegis_types::{AegisError, ChatId, Result, Timestamp};

use super::{hex, Client, DeviceSigner};

/// Итог жалобы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOutcome {
    /// Учтена ли жалоба; повторная на того же собеседника — нет.
    pub recorded: bool,
}

impl<T: Transport> Client<T> {
    /// Блокирует собеседника чата.
    ///
    /// `username` — имя, под которым человек видит собеседника, для
    /// списка «Заблокированные».
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn block_chat(
        &self,
        chat_id: &ChatId,
        username: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        self.storage.block_chat(chat_id, username, now)?;
        self.storage
            .log_security_event("contact_blocked", None, now)
    }

    /// Снимает блокировку.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — запись не удалась.
    pub fn unblock_chat(&self, chat_id: &ChatId) -> Result<()> {
        self.storage.unblock_chat(chat_id)
    }

    /// Заблокирован ли собеседник чата.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn is_chat_blocked(&self, chat_id: &ChatId) -> Result<bool> {
        self.storage.is_chat_blocked(chat_id)
    }

    /// Заблокированные — свежие первыми.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn blocked_chats(&self) -> Result<Vec<BlockedChat>> {
        self.storage.blocked_chats()
    }

    /// Можно ли пожаловаться на собеседника чата: пришёл ли от него хоть
    /// один запечатанный конверт, сертификат которого докажет жалобу.
    ///
    /// # Errors
    ///
    /// [`AegisError::Storage`] — чтение не удалось.
    pub fn can_report_chat(&self, chat_id: &ChatId) -> Result<bool> {
        Ok(self.storage.report_certificate(chat_id)?.is_some())
    }

    /// Жалуется оператору сервера на собеседника чата.
    ///
    /// # Errors
    ///
    /// * [`AegisError::Uninitialized`] — доказать жалобу нечем: от
    ///   собеседника не приходило запечатанных конвертов;
    /// * [`AegisError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// * [`AegisError::Network`] — сервер недоступен или отказал.
    pub fn report_chat(&self, chat_id: &ChatId, now: Timestamp) -> Result<ReportOutcome> {
        let certificate = self
            .storage
            .report_certificate(chat_id)?
            .ok_or(AegisError::Uninitialized)?;

        let device_id = self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id)
            .ok_or(AegisError::SessionNotFound)?;

        let (identity, _) = self.load_identity()?;

        let response = self.api.report_sealed_sender(
            &device_id,
            &SealedReportRequest {
                certificate: hex(&certificate),
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .log_security_event("contact_reported", None, now)?;

        Ok(ReportOutcome {
            recorded: response.recorded,
        })
    }
}
