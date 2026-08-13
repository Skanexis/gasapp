// SPDX-License-Identifier: Apache-2.0

//! Идентификаторы сущностей AEGIS.
//!
//! Все идентификаторы — отдельные типы, а не псевдонимы `Uuid`. Это исключает
//! целый класс ошибок вида «передали `DeviceId` туда, где ждали `AccountId`»,
//! который в системе доставки шифротекста означал бы отправку сообщения
//! не тому устройству.

use core::fmt;

use uuid::Uuid;

/// Создаёт newtype поверх [`Uuid`] со стандартным набором реализаций.
macro_rules! uuid_newtype {
    ($(#[$meta:meta])* $name:ident, $debug_label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// Генерирует новый случайный идентификатор.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Оборачивает существующий UUID.
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Возвращает внутренний UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Представление в виде 16 байт — формат хранения в БД.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($debug_label, "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_newtype!(
    /// Идентификатор аккаунта.
    ///
    /// Случайный UUID, не связанный ни с телефоном, ни с email (ADR-007).
    AccountId,
    "AccountId"
);

uuid_newtype!(
    /// Идентификатор устройства внутри аккаунта.
    ///
    /// Каждое устройство имеет собственную identity (раздел 13.1), поэтому
    /// адресация при доставке идёт именно по устройствам, а не по аккаунтам.
    DeviceId,
    "DeviceId"
);

uuid_newtype!(
    /// Идентификатор чата — как личного, так и группового.
    ChatId,
    "ChatId"
);

uuid_newtype!(
    /// Идентификатор сообщения.
    ///
    /// Генерируется отправителем, чтобы сервер не мог влиять на нумерацию.
    MessageId,
    "MessageId"
);

/// Момент времени в миллисекундах от Unix epoch.
///
/// # Чьё это время
///
/// Для сообщений здесь всегда стоит время **отправителя**, зашифрованное
/// внутри содержимого (раздел 6.5 плана). Серверное время используется
/// исключительно для TTL очереди доставки и никогда не показывается
/// пользователю как время сообщения.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Оборачивает миллисекунды от Unix epoch.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Возвращает миллисекунды от Unix epoch.
    #[must_use]
    pub const fn as_millis(&self) -> i64 {
        self.0
    }

    /// Округляет время вниз до целого часа.
    ///
    /// Используется на сервере для минимизации метаданных: точное время
    /// постановки в очередь — это сигнал о распорядке дня пользователя
    /// (раздел 15.4 плана).
    #[must_use]
    pub fn truncated_to_hour(&self) -> Self {
        const MILLIS_PER_HOUR: i64 = 3_600_000;
        Self(self.0.saturating_sub(self.0.rem_euclid(MILLIS_PER_HOUR)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_unique() {
        assert_ne!(AccountId::generate(), AccountId::generate());
    }

    #[test]
    fn ids_round_trip_through_uuid() {
        let id = ChatId::generate();
        assert_eq!(ChatId::from_uuid(*id.as_uuid()), id);
    }

    #[test]
    fn timestamp_truncates_down_to_the_hour() {
        // 1970-01-01 03:45:30.500 UTC
        let precise = Timestamp::from_millis(3 * 3_600_000 + 45 * 60_000 + 30_500);
        assert_eq!(precise.truncated_to_hour().as_millis(), 3 * 3_600_000);
    }

    #[test]
    fn timestamp_truncation_is_idempotent() {
        let t = Timestamp::from_millis(1_754_900_123_456);
        let once = t.truncated_to_hour();
        assert_eq!(once.truncated_to_hour(), once);
    }

    /// Округление должно работать и для времени до Unix epoch:
    /// `rem_euclid` даёт неотрицательный остаток, в отличие от `%`.
    #[test]
    fn timestamp_truncation_handles_negative_time() {
        let before_epoch = Timestamp::from_millis(-1);
        assert_eq!(before_epoch.truncated_to_hour().as_millis(), -3_600_000);
    }
}
