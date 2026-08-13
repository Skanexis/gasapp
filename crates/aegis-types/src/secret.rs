// SPDX-License-Identifier: Apache-2.0

//! Тип-обёртка для секретного материала.
//!
//! Этот модуль реализует два правила безопасности из `AEGIS_MASTER_PLAN.md`:
//!
//! * **Правило 4** — секреты не попадают в логи никогда.
//!   [`Secret`] не реализует [`Display`](core::fmt::Display), а его [`Debug`]
//!   печатает `Secret<redacted>` вместо содержимого.
//! * **Правило 5** — ключи стираются из памяти детерминированно.
//!   [`Secret`] обнуляет своё содержимое при уничтожении.
//!
//! Дополнительно [`Secret`] сознательно **не** реализует `Clone`,
//! `serde::Serialize` и `PartialEq`:
//!
//! * без `Clone` невозможно случайно размножить копии ключа по памяти;
//! * без `Serialize` секрет физически не может уйти в сеть или на диск
//!   в открытом виде (см. раздел 8.2 плана);
//! * без `PartialEq` невозможно сравнить секреты за переменное время —
//!   для сравнения есть [`Secret::ct_eq`], работающий за константное время.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Обёртка над секретным значением.
///
/// # Примеры
///
/// ```
/// use aegis_types::Secret;
///
/// let key = Secret::new([0x42u8; 32]);
///
/// // Debug никогда не раскрывает содержимое.
/// assert_eq!(format!("{key:?}"), "Secret<redacted>");
///
/// // Доступ к значению всегда явный.
/// assert_eq!(key.expose_secret()[0], 0x42);
/// ```
#[derive(ZeroizeOnDrop)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Оборачивает значение, помечая его как секретное.
    #[inline]
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Возвращает ссылку на секретное значение.
    ///
    /// Метод назван намеренно длинно и неудобно: каждое его появление
    /// в коде — точка, которую обязан просмотреть ревьюер и аудитор.
    #[inline]
    #[must_use]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Возвращает изменяемую ссылку на секретное значение.
    #[inline]
    #[must_use]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize + AsRef<[u8]>> Secret<T> {
    /// Сравнивает два секрета за константное время.
    ///
    /// Обычное `==` для секретов не реализовано намеренно: сравнение
    /// за переменное время раскрывает информацию о содержимом через
    /// тайминг-канал.
    ///
    /// Ограничение задано через [`AsRef<[u8]>`], а не через
    /// [`ConstantTimeEq`], потому что `subtle` реализует последний
    /// для срезов, но не для массивов фиксированной длины — а основной
    /// ключевой тип проекта это как раз `[u8; 32]`.
    #[inline]
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_ref().ct_eq(other.0.as_ref())
    }
}

// --- Правило 4: содержимое не попадает в вывод ни при каких условиях ---

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret<redacted>")
    }
}

impl<T: Zeroize + Default> Default for Secret<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// Секретный байтовый буфер переменной длины.
pub type SecretBytes = Secret<Vec<u8>>;

/// Секретный 256-битный ключ — основной размер ключа в AEGIS.
pub type SecretKey32 = Secret<[u8; 32]>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Правило 4: Debug не раскрывает содержимое.
    #[test]
    fn debug_output_is_redacted() {
        let secret = Secret::new(*b"super secret key material!!!!!!!");
        let rendered = format!("{secret:?}");

        assert_eq!(rendered, "Secret<redacted>");
        assert!(!rendered.contains("secret key"));
    }

    /// Правило 4: вложенный секрет не течёт через Debug структуры-владельца.
    #[test]
    fn debug_output_is_redacted_when_nested() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Session {
            id: u32,
            root_key: SecretKey32,
        }

        let session = Session {
            id: 7,
            root_key: Secret::new([0xAB; 32]),
        };

        let rendered = format!("{session:?}");

        assert!(rendered.contains("Secret<redacted>"));
        assert!(!rendered.contains("171")); // 0xAB в десятичном виде
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn exposing_returns_the_original_value() {
        let secret = Secret::new([0x42u8; 32]);
        assert_eq!(secret.expose_secret(), &[0x42u8; 32]);
    }

    /// Сравнение секретов идёт за константное время и даёт корректный результат.
    #[test]
    fn constant_time_comparison_is_correct() {
        let a = Secret::new([1u8; 32]);
        let b = Secret::new([1u8; 32]);
        let c = Secret::new([2u8; 32]);

        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    /// Правило 5: содержимое обнуляется при уничтожении.
    ///
    /// Проверяем прямым вызовом `zeroize` на извлечённом буфере — читать
    /// освобождённую память в безопасном Rust нельзя, а полноценная
    /// проверка через дамп памяти живёт в интеграционных тестах
    /// (`secrets_zeroized`, раздел 24.4 плана).
    #[test]
    fn zeroize_clears_the_buffer() {
        let mut buffer = *b"key material that must vanish!!!";
        buffer.zeroize();
        assert_eq!(buffer, [0u8; 32]);
    }
}
