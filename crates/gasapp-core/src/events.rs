// SPDX-License-Identifier: Apache-2.0

//! Поток событий для UI.
//!
//! # Почему события, а не опрос
//!
//! UI не должен спрашивать ядро «не пришло ли чего»: опрос либо тратит
//! батарею, либо задерживает доставку. Ядро само сообщает, что изменилось,
//! а UI решает, что показать.
//!
//! # Почему в событиях нет содержимого сообщений
//!
//! [`GasAppEvent::MessageReceived`] несёт только идентификаторы. Открытый
//! текст живёт в `Plaintext`, который намеренно не сериализуется и не
//! пересекает границу FFI (раздел 8.2 плана). UI, получив событие,
//! запрашивает содержимое отдельно — и получает его ровно тогда, когда
//! собирается показать на экране.
//!
//! Это не лишний шаг: событие может пережить сериализацию в очереди
//! платформенного слоя, а расшифрованный текст — не должен.

use gasapp_types::{AccountId, ChatId, DeviceId, MessageId};

/// Статус доставки сообщения в терминах UI.
///
/// Отдельный тип от `gasapp_storage::MessageStatus`: хранилище знает
/// про строки в базе, UI — про галочки в интерфейсе. Совпадение
/// вариантов сегодня не повод связывать слои навсегда.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryStatus {
    /// Поставлено в очередь, ждёт отправки.
    Pending,
    /// Ушло на сервер.
    Sent,
    /// Доставлено на устройство получателя.
    Delivered,
    /// Прочитано.
    Read,
    /// Отправить не удалось: попытки исчерпаны.
    Failed,
}

/// Состояние соединения с сервером.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnState {
    /// Соединения нет.
    Offline,
    /// Идёт подключение.
    Connecting,
    /// Соединение установлено.
    Online,
}

/// Предупреждение безопасности.
///
/// Питает Security Center: каждый вариант — строка в списке, по которой
/// пользователь принимает решение. Поэтому формулировки здесь не
/// технические, а такие, чтобы их можно было показать человеку.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SecurityAlert {
    /// У контакта сменился identity-ключ.
    ///
    /// `was_verified` решает, насколько это серьёзно: смена ключа
    /// у неверифицированного контакта — обычное дело (переустановил
    /// приложение), у верифицированного — повод остановиться, потому
    /// что пользователь ранее лично сверил safety number.
    IdentityKeyChanged {
        /// Чей ключ сменился.
        peer: AccountId,
        /// Был ли контакт верифицирован до смены.
        was_verified: bool,
    },
    /// К аккаунту привязано новое устройство.
    NewDeviceLinked {
        /// Идентификатор устройства.
        device_id: DeviceId,
        /// Имя, под которым устройство представилось.
        name: String,
    },
    /// Среди устройств контакта есть неверифицированное.
    UnverifiedDevicePresent {
        /// Идентификатор устройства.
        device_id: DeviceId,
    },
    /// Аппаратное хранилище ключей недоступно.
    ///
    /// Не отказ: приложение продолжает работать на программном
    /// fallback, но ключи защищены слабее, и пользователь вправе
    /// об этом знать.
    HardwareProtectionUnavailable,
    /// Резервная копия давно не обновлялась.
    BackupOverdue {
        /// Сколько дней прошло с последней копии.
        days: u32,
    },
}

impl SecurityAlert {
    /// Требует ли предупреждение немедленного внимания.
    ///
    /// Смена ключа у **верифицированного** контакта — единственный случай,
    /// когда пользователя нужно остановить: он лично сверял safety number,
    /// и расхождение означает либо переустановку, либо подмену. Остальные
    /// предупреждения информативны и ждут своей очереди в Security Center.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::IdentityKeyChanged {
                was_verified: true,
                ..
            }
        )
    }
}

/// Событие, которое ядро отдаёт UI.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GasAppEvent {
    /// Пришло новое сообщение.
    ///
    /// Содержимого здесь нет намеренно — см. документацию модуля.
    MessageReceived {
        /// Чат, в который пришло сообщение.
        chat_id: ChatId,
        /// Идентификатор сообщения.
        message_id: MessageId,
    },
    /// Изменился статус доставки.
    MessageStatusChanged {
        /// О каком сообщении речь.
        message_id: MessageId,
        /// Новый статус.
        status: DeliveryStatus,
    },
    /// Собеседник начал набирать текст.
    TypingStarted {
        /// В каком чате.
        chat_id: ChatId,
        /// Кто набирает.
        from: AccountId,
    },
    /// Предупреждение безопасности.
    SecurityAlert(SecurityAlert),
    /// Изменилось состояние соединения.
    ConnectionStateChanged(ConnState),
    /// Прогресс синхронизации.
    SyncProgress {
        /// Сколько сделано.
        done: u32,
        /// Сколько всего.
        total: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 Смена ключа у верифицированного контакта критична.
    #[test]
    fn identity_change_of_verified_peer_is_critical() {
        let alert = SecurityAlert::IdentityKeyChanged {
            peer: AccountId::generate(),
            was_verified: true,
        };

        assert!(alert.is_critical());
    }

    /// Смена ключа у неверифицированного контакта критичной не считается.
    ///
    /// Иначе пользователь получал бы тревогу при каждой переустановке
    /// приложения собеседником и перестал бы обращать на неё внимание —
    /// а вместе с ней пропустил бы настоящую подмену.
    #[test]
    fn identity_change_of_unverified_peer_is_informational() {
        let alert = SecurityAlert::IdentityKeyChanged {
            peer: AccountId::generate(),
            was_verified: false,
        };

        assert!(!alert.is_critical());
    }

    /// Остальные предупреждения информативны.
    #[test]
    fn other_alerts_are_not_critical() {
        let alerts = [
            SecurityAlert::NewDeviceLinked {
                device_id: DeviceId::generate(),
                name: "iPhone".to_owned(),
            },
            SecurityAlert::UnverifiedDevicePresent {
                device_id: DeviceId::generate(),
            },
            SecurityAlert::HardwareProtectionUnavailable,
            SecurityAlert::BackupOverdue { days: 30 },
        ];

        for alert in alerts {
            assert!(!alert.is_critical(), "неожиданно критично: {alert:?}");
        }
    }

    /// 🔐 Событие о новом сообщении не несёт содержимого.
    ///
    /// Проверка на уровне системы типов: если в вариант когда-нибудь
    /// добавят поле с текстом, тест перестанет компилироваться.
    #[test]
    fn message_event_carries_only_identifiers() {
        let event = GasAppEvent::MessageReceived {
            chat_id: ChatId::generate(),
            message_id: MessageId::generate(),
        };

        let GasAppEvent::MessageReceived {
            chat_id,
            message_id,
        } = event
        else {
            panic!("ожидалось MessageReceived");
        };

        // Деструктуризация исчерпывающая: других полей в варианте нет.
        let _ = (chat_id, message_id);
    }

    /// Отладочный вывод события не раскрывает содержимого.
    #[test]
    fn event_debug_has_no_payload() {
        let event = GasAppEvent::MessageReceived {
            chat_id: ChatId::generate(),
            message_id: MessageId::generate(),
        };

        let rendered = format!("{event:?}");

        assert!(rendered.contains("MessageReceived"));
        assert!(!rendered.to_lowercase().contains("plaintext"));
    }
}
