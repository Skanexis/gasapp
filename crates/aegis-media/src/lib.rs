// SPDX-License-Identifier: Apache-2.0

//! Шифрование вложений, чанки, превью.
//!
//! Крейт создан как скелет на этапе M0. Реализация — см. дорожную карту
//! в `AEGIS_MASTER_PLAN.md`.

/// Версия крейта, доступная во время выполнения.
pub mod attachment;
pub mod descriptor;
pub mod preview;

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
