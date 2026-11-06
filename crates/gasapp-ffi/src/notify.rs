// SPDX-License-Identifier: Apache-2.0

//! Токен уведомлений на границе с платформой (ADR-040).
//!
//! Платформа хранит токен вне зашифрованной базы и в фоне, без PIN,
//! спрашивает по нему сервер, непуста ли очередь. Здесь — только
//! создание токена и его регистрация за подписью устройства.

use gasapp_core::client::PushProvider;
use gasapp_types::Timestamp;

use crate::messenger::Messenger;
use crate::{guard, FfiError};

/// Новый случайный токен уведомлений. Без сети и без базы.
#[uniffi::export]
#[must_use]
pub fn generate_notify_token() -> Vec<u8> {
    gasapp_core::client::new_notify_token(&mut rand_core::OsRng).to_vec()
}

#[uniffi::export]
impl Messenger {
    /// Называет серверу токен уведомлений устройства. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — токен не той длины либо сервер недоступен.
    pub fn register_notify_token(&self, token: Vec<u8>, now_millis: i64) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.register_notify_token(&token, Timestamp::from_millis(now_millis)))
    }

    /// Отзывает токен уведомлений. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn unregister_notify_token(&self, now_millis: i64) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.unregister_notify_token(Timestamp::from_millis(now_millis)))
    }

    /// Называет серверу токен пуш-уведомлений (APNs на iOS, FCM в сборке
    /// для Google Play). Сетевой вызов.
    ///
    /// 🔐 Пуш пустой: Apple или Google показывают «Новое сообщение» —
    /// без текста и отправителя.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — токен не похож на токен провайдера либо
    /// сервер недоступен.
    pub fn register_push_token(
        &self,
        provider: FfiPushProvider,
        token: String,
        now_millis: i64,
    ) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| {
            client.register_push_token(provider.into(), &token, Timestamp::from_millis(now_millis))
        })
    }

    /// Отзывает токен пуш-уведомлений. Сетевой вызов.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — сервер недоступен.
    pub fn unregister_push_token(&self, now_millis: i64) -> Result<(), FfiError> {
        let client = self.client()?;

        guard(|| client.unregister_push_token(Timestamp::from_millis(now_millis)))
    }
}

/// Провайдер пуш-уведомлений.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPushProvider {
    /// Apple, выпускная сборка.
    Apns,
    /// Apple, отладочная сборка (песочница APNs).
    ApnsSandbox,
    /// Google Firebase Cloud Messaging.
    Fcm,
}

impl From<FfiPushProvider> for PushProvider {
    fn from(provider: FfiPushProvider) -> Self {
        match provider {
            FfiPushProvider::Apns => Self::Apns,
            FfiPushProvider::ApnsSandbox => Self::ApnsSandbox,
            FfiPushProvider::Fcm => Self::Fcm,
        }
    }
}
