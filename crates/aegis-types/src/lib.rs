// SPDX-License-Identifier: Apache-2.0

//! Общие типы AEGIS.
//!
//! Крейт не имеет зависимостей от других крейтов проекта и лежит в основании
//! графа (раздел 9.1 плана). Здесь живут три группы типов:
//!
//! * [`Secret`] и производные — секретный материал (Правила 4 и 5);
//! * [`Plaintext`] / [`Ciphertext`] / ключи — разделение открытых и
//!   зашифрованных данных на уровне системы типов (раздел 8.2);
//! * идентификаторы и [`AegisError`] — общий словарь всего проекта.

mod ids;
mod secret;
mod wire;

pub use ids::{AccountId, ChatId, DeviceId, MessageId, Timestamp};
pub use secret::{Secret, SecretBytes, SecretKey32};
pub use wire::{Ciphertext, Plaintext, PrivateKeyBytes, PublicKeyBytes};

/// Ошибки уровня всего приложения.
///
/// # Правило: ошибки не раскрывают секреты
///
/// Ни один вариант не содержит ключевого материала, открытого текста или
/// иных чувствительных данных. Сообщения об ошибках попадают в логи и
/// пересекают границу FFI, поэтому они намеренно неинформативны о содержимом
/// (раздел 10.3 плана).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AegisError {
    /// Криптографическая операция не удалась.
    ///
    /// Причина сознательно не детализируется: разница между «неверный тег
    /// аутентификации» и «неверная длина» — это оракул для атакующего.
    #[error("cryptographic operation failed")]
    Crypto,

    /// Проверка подписи не прошла.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Сессия с этим устройством не найдена.
    #[error("session not found")]
    SessionNotFound,

    /// Превышен лимит пропущенных сообщений.
    ///
    /// Защита от DoS: см. `MAX_SKIP` в разделе 6.3 плана.
    #[error("too many skipped messages")]
    TooManySkippedMessages,

    /// Версия протокола не поддерживается.
    ///
    /// В частности, так отвергается попытка downgrade до версии без
    /// post-quantum ratchet (ADR-021).
    #[error("unsupported protocol version")]
    UnsupportedProtocolVersion,

    /// Хранилище недоступно или повреждено.
    #[error("storage error")]
    Storage,

    /// Аппаратное хранилище ключей недоступно или ключ инвалидирован.
    #[error("hardware key store unavailable")]
    HardwareKeyStore,

    /// Приложение заблокировано, операция требует разблокировки.
    #[error("client is locked")]
    Locked,

    /// Сетевая ошибка.
    #[error("network error")]
    Network,

    /// Данные не прошли валидацию.
    #[error("malformed data")]
    Malformed,
}

/// Результат операции AEGIS.
pub type Result<T> = core::result::Result<T, AegisError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Ни один текст ошибки не должен намекать на содержимое данных.
    #[test]
    fn error_messages_do_not_leak_detail() {
        let forbidden = ["key", "plaintext", "nonce", "tag", "password", "pin"];

        for error in [
            AegisError::Crypto,
            AegisError::InvalidSignature,
            AegisError::SessionNotFound,
            AegisError::TooManySkippedMessages,
            AegisError::UnsupportedProtocolVersion,
            AegisError::Storage,
            AegisError::Locked,
            AegisError::Network,
            AegisError::Malformed,
        ] {
            let text = error.to_string().to_lowercase();
            for word in forbidden {
                assert!(
                    !text.contains(word),
                    "error message {text:?} leaks the word {word:?}"
                );
            }
        }
    }
}
