// SPDX-License-Identifier: Apache-2.0

//! Токен уведомлений (ADR-040).
//!
//! В фоне приложение заперто PIN, и подписать запрос ему нечем. Поэтому
//! устройство заводит отдельный случайный токен: платформа хранит его
//! вне зашифрованной базы и по нему спрашивает сервер только одно —
//! непуста ли очередь. Сервер получает SHA-256 токена; регистрация и
//! отзыв идут за подписью устройства.
//!
//! 🔐 Токен не открывает ничего, кроме «да» или «нет»: забрать или
//! прочитать очередь по нему нельзя.

use gasapp_net::api::NotifyTokenRequest;
use gasapp_net::client::Transport;
use gasapp_types::{GasAppError, Result, Timestamp};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};

use super::{hex, Client, DeviceSigner};

/// Длина токена уведомлений.
pub const NOTIFY_TOKEN_LEN: usize = 32;

/// Новый случайный токен уведомлений.
#[must_use]
pub fn new_notify_token<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; NOTIFY_TOKEN_LEN] {
    let mut token = [0u8; NOTIFY_TOKEN_LEN];
    rng.fill_bytes(&mut token);
    token
}

impl<T: Transport> Client<T> {
    /// Называет серверу токен уведомлений этого устройства — хешем.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — токен не той длины;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn register_notify_token(&self, token: &[u8], now: Timestamp) -> Result<()> {
        if token.len() != NOTIFY_TOKEN_LEN {
            return Err(GasAppError::Malformed);
        }

        let (device_id, identity) = self.own_device()?;

        self.api.set_notify_token(
            &device_id,
            &NotifyTokenRequest {
                token_hash: hex(&Sha256::digest(token)),
            },
            &DeviceSigner::new(&identity, now),
        )
    }

    /// Отзывает токен уведомлений: сервер его забывает.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn unregister_notify_token(&self, now: Timestamp) -> Result<()> {
        let (device_id, identity) = self.own_device()?;

        self.api
            .delete_notify_token(&device_id, &DeviceSigner::new(&identity, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random() {
        let mut rng = rand_core::OsRng;

        assert_ne!(new_notify_token(&mut rng), new_notify_token(&mut rng));
    }
}
