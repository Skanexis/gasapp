// SPDX-License-Identifier: Apache-2.0

//! Общий таймер исчезающих сообщений — для всех чатов сразу.
//!
//! В настройках человек выбирает срок для всех чатов; в отдельном чате
//! можно задать свой или выключить — настройка чата сильнее общей. Чат
//! без своей настройки следует общей: и сообщения у себя, и собеседнику —
//! перед первым сообщением после смены общего срока уходит таймер, чтобы
//! они исчезали у обоих (таймер общий для двоих, см. `Content::DisappearingTimer`).

use gasapp_net::client::Transport;
use gasapp_protocol::content::Content;
use gasapp_storage::DEFAULT_DISAPPEARING_SETTING;
use gasapp_types::{ChatId, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};

use super::Client;

/// Таймер чата для интерфейса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatTimer {
    /// Действующий срок в секундах; `None` — сообщения не исчезают.
    pub seconds: Option<u32>,
    /// Чат следует общему таймеру из настроек.
    pub follows_default: bool,
}

/// Что собеседнику уже сообщено об общем таймере в этом чате.
fn announced_key(chat_id: &ChatId) -> String {
    format!("timer_announced:{}", chat_id.as_uuid())
}

impl<T: Transport> Client<T> {
    /// Общий таймер для всех чатов (без своей настройки); `None` — выключен.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — чтение не удалось.
    pub fn default_disappearing_timer(&self) -> Result<Option<u32>> {
        self.storage.default_disappearing_timer()
    }

    /// Меняет общий таймер. Собеседники чатов без своей настройки узнают о
    /// нём с ближайшим сообщением ([`Client::announce_default_timer`]).
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Malformed`] — срок больше года.
    pub fn set_default_disappearing_timer(&self, seconds: Option<u32>) -> Result<()> {
        let value = seconds.unwrap_or(0);
        if value > gasapp_protocol::content::MAX_DISAPPEARING_SECONDS {
            return Err(gasapp_types::GasAppError::Malformed);
        }
        self.storage
            .set_setting_int(DEFAULT_DISAPPEARING_SETTING, i64::from(value))
    }

    /// Таймер чата: действующий срок и откуда он.
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Storage`] — чтение не удалось.
    pub fn chat_disappearing_timer(&self, chat_id: &ChatId) -> Result<ChatTimer> {
        Ok(match self.storage.explicit_disappearing_timer(chat_id)? {
            Some(seconds) => ChatTimer {
                seconds,
                follows_default: false,
            },
            None => ChatTimer {
                seconds: self.storage.default_disappearing_timer()?,
                follows_default: true,
            },
        })
    }

    /// Чат снова следует общему таймеру; собеседник узнаёт действующий
    /// срок сразу.
    ///
    /// # Errors
    ///
    /// Как у отправки.
    pub fn follow_default_disappearing_timer<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<ChatId> {
        let seconds = self.storage.default_disappearing_timer()?;
        let chat_id = self.send_content(
            peer_username,
            &Content::DisappearingTimer { seconds },
            now,
            rng,
        )?;
        self.storage.follow_default_disappearing_timer(&chat_id)?;
        self.storage
            .set_setting_int(&announced_key(&chat_id), i64::from(seconds.unwrap_or(0)))?;
        Ok(chat_id)
    }

    /// Перед сообщением в чат без своей настройки: собеседнику — общий
    /// срок, если он ещё не знает именно этот. Сбой не мешает сообщению.
    pub(crate) fn announce_default_timer<R: RngCore + CryptoRng>(
        &self,
        peer_username: &str,
        chat_id: &ChatId,
        now: Timestamp,
        rng: &mut R,
    ) {
        let Ok(None) = self.storage.explicit_disappearing_timer(chat_id) else {
            return;
        };
        let Ok(seconds) = self.storage.default_disappearing_timer() else {
            return;
        };
        let code = i64::from(seconds.unwrap_or(0));
        let key = announced_key(chat_id);
        let Ok(announced) = self.storage.setting_int(&key, -1) else {
            return;
        };
        // Сообщено это же — или общий выключен и не сообщалось ничего.
        if announced == code || (announced < 0 && code == 0) {
            return;
        }
        if self
            .send_content(
                peer_username,
                &Content::DisappearingTimer { seconds },
                now,
                rng,
            )
            .is_ok()
        {
            let _ = self.storage.set_setting_int(&key, code);
        }
    }
}
