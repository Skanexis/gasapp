// SPDX-License-Identifier: Apache-2.0

//! HTTP и WebSocket клиент, cert pinning, offline-очередь.
//!
//! # Состояние
//!
//! Реализована логика, не зависящая от транспорта: проверка пинов
//! ([`pinning`]) и офлайн-очередь с экспоненциальным backoff ([`queue`]).
//! Обе части чистые — не ходят в сеть, не берут системное время, — поэтому
//! проверяются тестами детерминированно.
//!
//! HTTP- и WebSocket-транспорт появятся вместе с сервером: сейчас их не
//! к чему подключать, а писать клиент к несуществующему API значило бы
//! закреплять догадки о его форме.
//!
//! # Почему пиннинг и очередь написаны до транспорта
//!
//! Это две части, где ошибка обходится дороже всего. Неверная ротация
//! пинов обрывает связь со всеми клиентами и чинится только обновлением
//! через магазин приложений; отсутствие backoff превращает восстановление
//! сервера в повторное падение под лавиной повторов. Обе достаточно
//! самостоятельны, чтобы проверить их без сети.

pub mod api;
pub mod auth;
pub mod client;
pub mod pinning;
pub mod pow;
pub mod proxy;
pub mod queue;

pub use api::{
    AccountDeletedResponse, BundleResponse, DiscoveryResponse, EnvelopeResponse,
    PublishKeysRequest, RegisterRequest, RegisterResponse, SendRequest,
};
pub use client::{ApiClient, HttpRequest, HttpResponse, Method, Transport};
pub use pinning::{pin_from_spki, PinSet, MIN_PINS, PIN_LEN};
pub use queue::{OfflineQueue, QueuedRequest, MAX_ATTEMPTS, MAX_QUEUE_LEN};

/// Версия крейта, доступная во время выполнения.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    /// Версия крейта должна следовать формату MAJOR.MINOR.PATCH.
    ///
    /// Проверка не декоративная: версия ядра пересекает границу FFI
    /// и используется клиентами для контроля совместимости биндингов
    /// с собранной библиотекой (раздел 9.3 плана).
    #[test]
    fn crate_version_is_semver() {
        let parts: Vec<&str> = super::VERSION.split('.').collect();

        assert_eq!(parts.len(), 3, "ожидался формат MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "компонент версии не является числом: {part}"
            );
        }
    }
}
