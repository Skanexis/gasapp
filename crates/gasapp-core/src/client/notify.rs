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

use gasapp_net::api::{NotifyTokenRequest, PushTokenRequest};
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

    /// Называет серверу токен пуш-уведомлений платформы (APNs, FCM).
    ///
    /// 🔐 Пуш пустой: сервер просит провайдера показать «Новое
    /// сообщение» и ничего больше. Провайдер видит факт и время, но не
    /// текст и не отправителя.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Malformed`] — токен не похож на токен провайдера;
    /// * [`GasAppError::Network`] — сервер недоступен.
    pub fn register_push_token(
        &self,
        provider: PushProvider,
        token: &str,
        now: Timestamp,
    ) -> Result<()> {
        if !provider.accepts(token) {
            return Err(GasAppError::Malformed);
        }

        let (device_id, identity) = self.own_device()?;

        self.api.set_push_token(
            &device_id,
            &PushTokenRequest {
                provider: provider.as_str().to_owned(),
                token: token.to_owned(),
            },
            &DeviceSigner::new(&identity, now),
        )
    }

    /// Отзывает токен пуш-уведомлений.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — сервер недоступен.
    pub fn unregister_push_token(&self, now: Timestamp) -> Result<()> {
        let (device_id, identity) = self.own_device()?;

        self.api
            .delete_push_token(&device_id, &DeviceSigner::new(&identity, now))
    }
}

/// Провайдер пуш-уведомлений.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushProvider {
    /// Apple, выпускная сборка.
    Apns,
    /// Apple, отладочная сборка (песочница APNs).
    ApnsSandbox,
    /// Google Firebase Cloud Messaging.
    Fcm,
}

impl PushProvider {
    /// Имя провайдера в протоколе.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::ApnsSandbox => "apns-sandbox",
            Self::Fcm => "fcm",
        }
    }

    /// Похож ли `token` на токен этого провайдера — то же правило, что
    /// у сервера (`push_token_valid`). Токен APNs — hex (32 байта и
    /// больше), FCM — до 4 КБ печатного ASCII.
    #[must_use]
    pub fn accepts(self, token: &str) -> bool {
        match self {
            Self::Apns | Self::ApnsSandbox => {
                (64..=200).contains(&token.len())
                    && token.len().is_multiple_of(2)
                    && token.bytes().all(|b| b.is_ascii_hexdigit())
            }
            Self::Fcm => {
                !token.is_empty()
                    && token.len() <= 4096
                    && token.bytes().all(|b| b.is_ascii_graphic())
            }
        }
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

    #[test]
    fn push_tokens_are_checked_per_provider() {
        let apns = "a1".repeat(32);
        assert!(PushProvider::Apns.accepts(&apns));
        assert!(PushProvider::ApnsSandbox.accepts(&apns));
        assert!(!PushProvider::Apns.accepts("a1b2"));
        assert!(!PushProvider::Apns.accepts(&"zz".repeat(32)));

        let fcm = "dGVzdA:APA91b".to_owned() + &"x".repeat(140);
        assert!(PushProvider::Fcm.accepts(&fcm));
        assert!(!PushProvider::Fcm.accepts(""));
        assert!(!PushProvider::Fcm.accepts("with space"));
        assert!(!PushProvider::Fcm.accepts(&"x".repeat(5000)));
    }
}
