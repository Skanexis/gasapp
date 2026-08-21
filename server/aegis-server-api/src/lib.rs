// SPDX-License-Identifier: AGPL-3.0-only

//! REST API сервера AEGIS.
//!
//! # Что сервер знает о переписке
//!
//! Ничего. Он маршрутизирует конверты (`envelope_ciphertext`), не разбирая
//! их, хранит публичные ключи и недоставленные сообщения — и удаляет
//! последние сразу после подтверждения доставки (раздел 14.4 плана).
//!
//! Это не декларация, а ограничение конструкции: у сервера нет ключей,
//! которыми конверт можно открыть.
//!
//! # Что реализовано
//!
//! Три части, где ошибка стоит дороже всего и которые проверяются
//! без базы и сети:
//!
//! * [`pow`] — proof-of-work при регистрации. Единственный барьер против
//!   массовой регистрации: номера телефона нет (ADR-007), инвайты
//!   отвергнуты, потому что заставили бы хранить социальный граф;
//! * [`auth`] — аутентификация подписью identity-ключа. Пароля нет,
//!   поэтому и красть с сервера нечего;
//! * [`rate_limit`] — ограничение частоты, не хранящее IP-адреса.
//!
//! HTTP-обвязка (`axum`-роуты) и работа с Postgres появятся следующими:
//! их форма определяется этими тремя частями, а не наоборот.
//!
//! # Лицензия
//!
//! AGPL-3.0. Сервер не распространяется через магазины приложений,
//! поэтому конфликта с их условиями нет, а AGPL не даёт хостить
//! модифицированный закрытый форк (ADR-006).

pub mod push;
pub mod authz;
pub mod hub;
pub mod auth;
pub mod pow;
pub mod rate_limit;
pub mod routes;

pub use auth::{AuthError, CHALLENGE_TTL_MILLIS};
pub use pow::{PowError, DEFAULT_DIFFICULTY};
pub use rate_limit::{RateLimiter, DISCOVERY_PER_MINUTE, MESSAGES_PER_MINUTE};
pub use routes::{router, ApiError, AppState};

/// Версия крейта, доступная во время выполнения.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();

        assert_eq!(parts.len(), 3, "ожидался формат MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "компонент версии не является числом: {part}"
            );
        }
    }
}
