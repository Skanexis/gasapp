// SPDX-License-Identifier: Apache-2.0

//! Фасад для UI: состояние, оркестрация, поток событий.
//!
//! # Что это за слой
//!
//! Между UI и криптографией. UI не знает про храповики и предключи,
//! криптография не знает про экраны и уведомления. Ядро переводит одно
//! в другое: принимает намерения («отправить сообщение»), выполняет
//! последовательность операций и сообщает результат событиями.
//!
//! # Границы
//!
//! * **Не содержит криптографии.** Всё, что считает ключи, живёт
//!   в `aegis-protocol` и `aegis-keystore`. Здесь — порядок вызовов.
//! * **Не хранит PIN.** См. [`lock`]: проверка PIN — успех расшифровки
//!   хранилища, а не сравнение строк в памяти.
//! * **Не берёт системное время.** Оно передаётся аргументом, поэтому
//!   автоблокировка и backoff проверяются в тестах детерминированно
//!   (раздел 9.2 плана).
//!
//! # Состояние
//!
//! Реализованы поток событий ([`events`]) и управление блокировкой
//! ([`lock`]) — части, не зависящие от сети. Оркестрация отправки
//! и приёма появится вместе с сервером: последовательность вызовов
//! определяется его API, а писать её вслепую значило бы закреплять
//! догадки о форме, которой пока нет.

pub mod backup;
pub mod client;
pub mod session;
pub mod events;
pub mod lock;
pub mod vault;

pub use backup::{BackupOutcome, BackupService, RestoreOutcome};
pub use events::{AegisEvent, ConnState, DeliveryStatus, SecurityAlert};
pub use lock::{LockGuard, LockState, DEFAULT_AUTO_LOCK_MILLIS};
pub use vault::{VaultGuard, VaultState, DEFAULT_IDLE_TIMEOUT_MILLIS};

use aegis_types::AccountId;

/// Версия крейта, доступная во время выполнения.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Решает, что делать при расхождении identity-ключа контакта.
///
/// # Зачем отдельная функция
///
/// Это место, где встречаются хранилище (какой ключ known) и UI (какую
/// тревогу показать). Логика короткая, но ошибиться в ней легко в обе
/// стороны: пропустить подмену либо утопить пользователя в ложных
/// тревогах, после чего он перестанет их читать — и пропустит настоящую.
///
/// Возвращает `None`, когда тревожиться не о чем: ключ прежний либо
/// контакт видится впервые.
#[must_use]
pub fn identity_change_alert(
    peer: AccountId,
    known_identity: Option<&[u8]>,
    presented_identity: &[u8],
    was_verified: bool,
) -> Option<SecurityAlert> {
    let known = known_identity?;

    if known == presented_identity {
        return None;
    }

    Some(SecurityAlert::IdentityKeyChanged { peer, was_verified })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Версия крейта должна следовать формату MAJOR.MINOR.PATCH.
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

    /// Первая встреча с контактом тревоги не вызывает.
    ///
    /// Иначе каждый новый собеседник выглядел бы как подмена.
    #[test]
    fn first_contact_raises_no_alert() {
        let alert = identity_change_alert(AccountId::generate(), None, &[1u8; 32], false);

        assert!(alert.is_none());
    }

    /// Прежний ключ тревоги не вызывает.
    #[test]
    fn unchanged_identity_raises_no_alert() {
        let key = [7u8; 32];
        let alert = identity_change_alert(AccountId::generate(), Some(&key), &key, true);

        assert!(alert.is_none());
    }

    /// 🔐 Смена ключа у верифицированного контакта — критичная тревога.
    #[test]
    fn identity_change_of_verified_peer_is_critical() {
        let peer = AccountId::generate();
        let alert = identity_change_alert(peer, Some(&[1u8; 32]), &[2u8; 32], true)
            .expect("смена ключа обязана дать тревогу");

        assert!(alert.is_critical());
        assert_eq!(
            alert,
            SecurityAlert::IdentityKeyChanged {
                peer,
                was_verified: true
            }
        );
    }

    /// Смена ключа у неверифицированного контакта — информативная тревога.
    #[test]
    fn identity_change_of_unverified_peer_is_informational() {
        let alert =
            identity_change_alert(AccountId::generate(), Some(&[1u8; 32]), &[2u8; 32], false)
                .expect("смена ключа обязана дать тревогу");

        assert!(!alert.is_critical());
    }

    /// 🔐 Разница в один бит уже считается сменой ключа.
    #[test]
    fn single_bit_difference_is_detected() {
        let mut presented = [3u8; 32];
        presented[31] ^= 0x01;

        let alert =
            identity_change_alert(AccountId::generate(), Some(&[3u8; 32]), &presented, true);

        assert!(alert.is_some(), "подмена одного бита осталась незамеченной");
    }
}
