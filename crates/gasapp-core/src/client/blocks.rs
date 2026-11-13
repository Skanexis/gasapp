// SPDX-License-Identifier: Apache-2.0

//! Блокировка собеседника и жалоба на него.
//!
//! **Блокировка** — только на этом устройстве (`gasapp-storage::blocks`):
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
//! Содержимое переписки в жалобу само не уходит — его у сервера нет.
//! Показать его оператору может только жалобщик, по своему выбору:
//! улики (сообщения обидчика, скриншоты) запечатываются на телефоне
//! ключом админ-центра (`gasapp_protocol::report_evidence`), и сервер
//! хранит лишь шифр.

use gasapp_net::api::SealedReportRequest;
use gasapp_net::client::Transport;
use gasapp_protocol::report_evidence::{self, Evidence};
use gasapp_storage::blocks::BlockedChat;
use gasapp_types::{ChatId, GasAppError, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::{hex, Client, DeviceSigner};

/// Итог жалобы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportOutcome {
    /// Учтена ли жалоба; повторная на того же собеседника — нет.
    pub recorded: bool,
    /// Приняты ли улики. `false`, если их не было или сервер улик не
    /// принимает (ключа оператора нет).
    pub evidence_stored: bool,
}

/// Причина жалобы — коды те же, что у сервера.
pub const REPORT_REASON_MAX: u8 = 6;

impl<T: Transport> Client<T> {
    /// Блокирует собеседника чата.
    ///
    /// `username` — имя, под которым человек видит собеседника, для
    /// списка «Заблокированные».
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — запись не удалась.
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
    /// [`GasAppError::Storage`] — запись не удалась.
    pub fn unblock_chat(&self, chat_id: &ChatId) -> Result<()> {
        self.storage.unblock_chat(chat_id)
    }

    /// Заблокирован ли собеседник чата.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn is_chat_blocked(&self, chat_id: &ChatId) -> Result<bool> {
        self.storage.is_chat_blocked(chat_id)
    }

    /// Заблокированные — свежие первыми.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn blocked_chats(&self) -> Result<Vec<BlockedChat>> {
        self.storage.blocked_chats()
    }

    /// Можно ли пожаловаться на собеседника чата: пришёл ли от него хоть
    /// один запечатанный конверт, сертификат которого докажет жалобу.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Storage`] — чтение не удалось.
    pub fn can_report_chat(&self, chat_id: &ChatId) -> Result<bool> {
        Ok(self.storage.report_certificate(chat_id)?.is_some())
    }

    /// Жалуется оператору сервера на собеседника чата.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Uninitialized`] — доказать жалобу нечем: от
    ///   собеседника не приходило запечатанных конвертов;
    /// * [`GasAppError::SessionNotFound`] — аккаунт не зарегистрирован;
    /// * [`GasAppError::Network`] — сервер недоступен или отказал.
    pub fn report_chat(&self, chat_id: &ChatId, now: Timestamp) -> Result<ReportOutcome> {
        self.report_chat_with_evidence(
            chat_id,
            None,
            &Evidence::default(),
            now,
            &mut rand_core::OsRng,
        )
    }

    /// Жалоба с причиной и уликами.
    ///
    /// 🔐 Улики запечатываются ключом оператора, который сервер отдаёт
    /// по `/v1/sealed/report-key`. Сервер, подменивший ключ, прочитал бы
    /// улики сам, — но он и есть их адресат: оператор. Узлы и база видят
    /// только шифр.
    ///
    /// # Errors
    ///
    /// Как у [`Self::report_chat`]; [`GasAppError::Malformed`] — причина
    /// вне 1–6 или улики не проходят пределы.
    pub fn report_chat_with_evidence<R: RngCore + CryptoRng>(
        &self,
        chat_id: &ChatId,
        reason: Option<u8>,
        evidence: &Evidence,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<ReportOutcome> {
        if reason.is_some_and(|code| code == 0 || code > REPORT_REASON_MAX) {
            return Err(GasAppError::Malformed);
        }
        // Пределы — до сети: не уходить в Tor ради заведомого отказа.
        report_evidence::encode(evidence)?;

        let certificate = self
            .storage
            .report_certificate(chat_id)?
            .ok_or(GasAppError::Uninitialized)?;

        let device_id = self
            .storage
            .load_own_keys()?
            .and_then(|keys| keys.device_id)
            .ok_or(GasAppError::SessionNotFound)?;

        let (identity, _) = self.load_identity()?;

        let sealed = if evidence.is_empty() {
            None
        } else {
            // Старый сервер маршрута ключа не знает — жалоба уходит без
            // улик, а не не уходит вовсе.
            self.api
                .report_evidence_key()
                .ok()
                .and_then(|response| response.key)
                .and_then(|key| hex::decode(key).ok())
                .and_then(|key| <[u8; 32]>::try_from(key.as_slice()).ok())
                .map(|key| report_evidence::seal(&key, evidence, rng))
                .transpose()?
                .map(|sealed| hex(&sealed))
        };

        let response = self.api.report_sealed_sender(
            &device_id,
            &SealedReportRequest {
                certificate: hex(&certificate),
                reason,
                evidence: sealed,
            },
            &DeviceSigner::new(&identity, now),
        )?;

        self.storage
            .log_security_event("contact_reported", None, now)?;

        Ok(ReportOutcome {
            recorded: response.recorded,
            evidence_stored: response.evidence_stored,
        })
    }
}
