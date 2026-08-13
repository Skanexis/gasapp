// SPDX-License-Identifier: Apache-2.0

//! Граница FFI между `aegis-core` и клиентами на Swift и Kotlin.
//!
//! # Правила этого крейта
//!
//! 1. **Тонкий слой.** Здесь только конвертация типов и перехват паник.
//!    Любая логика принадлежит `aegis-core`.
//! 2. **Никакого ключевого материала.** Через границу не проходят ключи —
//!    только открытый текст, идентификаторы и непрозрачные handle
//!    (раздел 10.3 плана). В публичном API ниже нет ни одной функции,
//!    возвращающей приватный ключ, состояние ratchet или message key.
//! 3. **Паника не пересекает границу.** Разворачивание стека через границу
//!    FFI — неопределённое поведение, поэтому каждая точка входа
//!    оборачивается в [`catch_unwind`](std::panic::catch_unwind).
//! 4. **Ошибки не раскрывают деталей.** Текст ошибки уходит в логи
//!    платформы, поэтому [`FfiError`] намеренно неинформативен о содержимом.
//!
//! # Как получаются биндинги
//!
//! Используется библиотечный режим UniFFI: Swift и Kotlin генерируются
//! по собранной библиотеке, а не по отдельному файлу описания интерфейса.
//! Отдельное описание неизбежно расходится с кодом — компилятор его
//! не проверяет.

use std::panic::{catch_unwind, AssertUnwindSafe};

use aegis_protocol::{Fingerprint, ProtocolVersion, SafetyNumber};
use aegis_types::AegisError;

uniffi::setup_scaffolding!();

/// Длина отпечатка identity-ключа в байтах.
const FINGERPRINT_LEN: usize = 30;

/// Ошибка, пересекающая границу FFI.
///
/// Варианты намеренно грубые. Различие между «неверный тег аутентификации»
/// и «неверная длина» — это оракул для атакующего, а сообщение об ошибке
/// попадает в системный лог платформы, который читается кем угодно.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum FfiError {
    /// Ошибка ядра AEGIS.
    #[error("aegis error: {0}")]
    Core(#[from] AegisError),

    /// Входные данные не прошли валидацию на границе.
    #[error("invalid argument")]
    InvalidArgument,

    /// В ядре произошла паника.
    ///
    /// Сообщение паники сознательно **не** передаётся: оно может содержать
    /// значения переменных, а значит потенциально — чувствительные данные.
    #[error("internal error")]
    Panic,
}

/// Выполняет операцию ядра, не позволяя панике пересечь границу FFI.
///
/// # Почему это обязательно
///
/// Разворачивание стека Rust через C-ABI — неопределённое поведение.
/// Без этой обёртки паника в ядре означала бы аварийное завершение
/// приложения в лучшем случае и повреждение памяти в худшем (риск R17).
///
/// # Errors
///
/// [`FfiError::Panic`], если операция запаниковала; иначе — ошибка операции.
///
/// # Примеры
///
/// ```
/// use aegis::guard;
///
/// let ok = guard(|| Ok(2 + 2));
/// assert_eq!(ok.unwrap(), 4);
///
/// let panicked: Result<i32, _> = guard(|| panic!("boom"));
/// assert!(panicked.is_err());
/// ```
pub fn guard<T, F>(operation: F) -> Result<T, FfiError>
where
    F: FnOnce() -> Result<T, AegisError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result.map_err(FfiError::Core),
        Err(_) => Err(FfiError::Panic),
    }
}

/// Версия ядра AEGIS.
///
/// Клиент сверяет её с версией сгенерированных биндингов: несовпадение
/// означает, что в сборку попала библиотека от другой версии приложения.
#[uniffi::export]
#[must_use]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Версия протокола, которую использует это ядро.
#[uniffi::export]
#[must_use]
pub fn protocol_version() -> u8 {
    ProtocolVersion::CURRENT.as_u8()
}

/// Проверяет номер версии протокола из входящего сообщения.
///
/// Вынесено в публичный API намеренно: это позволяет платформенным
/// интеграционным тестам убедиться, что отказ от понижения версии
/// (ADR-021) действительно работает через границу FFI, а не только
/// внутри Rust.
///
/// # Errors
///
/// [`FfiError::Core`] с [`AegisError::UnsupportedProtocolVersion`], если
/// версия ниже минимально поддерживаемой (попытка отключить пост-квантовый
/// ratchet) или выше текущей (неизвестная семантика).
#[uniffi::export]
pub fn check_protocol_version(raw: u8) -> Result<u8, FfiError> {
    guard(|| ProtocolVersion::parse(raw).map(ProtocolVersion::as_u8))
}

/// Форматирует safety number по двум отпечаткам identity-ключей.
///
/// Возвращает строку в раскладке ADR-022: 4 строки по 3 группы из 5 цифр.
///
/// # Errors
///
/// [`FfiError::InvalidArgument`], если длина любого из отпечатков
/// не равна 30 байтам.
#[uniffi::export]
pub fn format_safety_number(local: Vec<u8>, remote: Vec<u8>) -> Result<String, FfiError> {
    let local: [u8; FINGERPRINT_LEN] = local.try_into().map_err(|_| FfiError::InvalidArgument)?;
    let remote: [u8; FINGERPRINT_LEN] = remote.try_into().map_err(|_| FfiError::InvalidArgument)?;

    let number = SafetyNumber::new(
        &Fingerprint::from_bytes(local),
        &Fingerprint::from_bytes(remote),
    );

    Ok(number.to_display_block())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_passes_through_success() {
        assert_eq!(guard(|| Ok(42)).unwrap(), 42);
    }

    #[test]
    fn guard_converts_core_errors() {
        let result: Result<(), _> = guard(|| Err(AegisError::Locked));
        assert!(matches!(result, Err(FfiError::Core(AegisError::Locked))));
    }

    /// Паника не должна пересекать границу FFI.
    #[test]
    fn guard_catches_panics() {
        let result: Result<(), _> = guard(|| panic!("secret value: hunter2"));
        assert!(matches!(result, Err(FfiError::Panic)));
    }

    /// Сообщение паники может содержать чувствительные данные,
    /// поэтому наружу оно не передаётся.
    #[test]
    fn panic_message_does_not_leak() {
        let result: Result<(), _> = guard(|| panic!("private key = 0xDEADBEEF"));
        let message = result.unwrap_err().to_string();

        assert_eq!(message, "internal error");
        assert!(!message.contains("DEADBEEF"));
    }

    #[test]
    fn core_version_is_reported() {
        assert!(!core_version().is_empty());
    }

    #[test]
    fn protocol_version_is_current() {
        assert_eq!(protocol_version(), ProtocolVersion::CURRENT.as_u8());
    }

    /// ADR-021 через границу FFI: понижение отвергается.
    #[test]
    fn protocol_downgrade_is_rejected_across_ffi() {
        assert!(check_protocol_version(0).is_err());
        assert!(check_protocol_version(2).is_err());
        assert_eq!(check_protocol_version(1).unwrap(), 1);
    }

    #[test]
    fn safety_number_is_formatted_for_display() {
        let block = format_safety_number(vec![0x11; 30], vec![0x22; 30]).unwrap();
        let lines: Vec<&str> = block.lines().collect();

        assert_eq!(lines.len(), 4);
        for line in lines {
            assert_eq!(line.split(' ').count(), 3);
        }
    }

    /// Длина отпечатка приходит с платформы и является недоверенным вводом.
    #[test]
    fn safety_number_rejects_wrong_fingerprint_length() {
        assert!(matches!(
            format_safety_number(vec![0; 29], vec![0; 30]),
            Err(FfiError::InvalidArgument)
        ));
        assert!(matches!(
            format_safety_number(vec![0; 30], vec![0; 31]),
            Err(FfiError::InvalidArgument)
        ));
        assert!(matches!(
            format_safety_number(Vec::new(), Vec::new()),
            Err(FfiError::InvalidArgument)
        ));
    }
}
