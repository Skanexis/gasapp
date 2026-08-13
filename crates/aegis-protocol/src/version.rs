// SPDX-License-Identifier: Apache-2.0

//! Версия протокола и защита от понижения.
//!
//! ADR-021 требует, чтобы пост-квантовый ratchet был обязателен с версии 1.0.
//! Это означает, что версия должна не просто передаваться в сообщении, но и
//! **проверяться при разборе**: иначе активный атакующий подменит номер версии
//! и заставит стороны договориться о варианте без SPQR.
//!
//! Классическая ошибка в этом месте — принимать «любую версию не выше нашей»
//! ради совместимости. Здесь так делать нельзя: версия 0 существует только
//! как значение, которое надо отвергнуть.

use aegis_types::{AegisError, Result};

/// Версия протокола AEGIS.
///
/// # Примеры
///
/// ```
/// use aegis_protocol::ProtocolVersion;
///
/// assert!(ProtocolVersion::parse(1).is_ok());
///
/// // Понижение до версии без пост-квантового ratchet невозможно.
/// assert!(ProtocolVersion::parse(0).is_err());
///
/// // Неизвестная будущая версия тоже отвергается: мы не знаем её семантики.
/// assert!(ProtocolVersion::parse(2).is_err());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProtocolVersion(u8);

impl ProtocolVersion {
    /// Версия 1: PQXDH + Triple Ratchet (Double Ratchet ⊕ SPQR).
    ///
    /// Пост-квантовая составляющая обязательна и не отключается (ADR-021).
    pub const V1: Self = Self(1);

    /// Версия, которую отправляет этот клиент.
    pub const CURRENT: Self = Self::V1;

    /// Минимальная версия, которую этот клиент готов принять.
    ///
    /// Совпадает с [`Self::CURRENT`] намеренно: механизма деградации нет.
    pub const MINIMUM_SUPPORTED: Self = Self::V1;

    /// Разбирает номер версии из входящего сообщения.
    ///
    /// # Errors
    ///
    /// [`AegisError::UnsupportedProtocolVersion`], если версия ниже
    /// [`Self::MINIMUM_SUPPORTED`] (попытка понижения) или выше
    /// [`Self::CURRENT`] (неизвестная семантика).
    pub fn parse(raw: u8) -> Result<Self> {
        if raw < Self::MINIMUM_SUPPORTED.0 || raw > Self::CURRENT.0 {
            return Err(AegisError::UnsupportedProtocolVersion);
        }
        Ok(Self(raw))
    }

    /// Числовое представление для сериализации.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Требует ли версия пост-квантового ratchet.
    ///
    /// Сейчас всегда `true`. Метод существует, чтобы вызывающий код был
    /// написан в терминах свойства, а не номера версии.
    #[must_use]
    pub const fn requires_post_quantum_ratchet(self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-021: версия 0 означала бы Double Ratchet без SPQR.
    /// Принять её — значит позволить атакующему отключить пост-квантовую защиту.
    #[test]
    fn downgrade_to_version_zero_is_rejected() {
        assert!(matches!(
            ProtocolVersion::parse(0),
            Err(AegisError::UnsupportedProtocolVersion)
        ));
    }

    #[test]
    fn current_version_is_accepted() {
        assert_eq!(ProtocolVersion::parse(1).unwrap(), ProtocolVersion::V1);
    }

    /// Версию из будущего принимать нельзя: мы не знаем, что она означает.
    /// Атакующий мог бы указать заведомо большой номер, рассчитывая на
    /// снисходительный разбор.
    #[test]
    fn unknown_future_versions_are_rejected() {
        for raw in [2u8, 3, 42, 127, 255] {
            assert!(
                ProtocolVersion::parse(raw).is_err(),
                "версия {raw} не должна приниматься"
            );
        }
    }

    /// Полный перебор: принимается ровно одно значение из 256.
    #[test]
    fn exactly_one_byte_value_is_accepted() {
        let accepted: Vec<u8> = (0u8..=255)
            .filter(|v| ProtocolVersion::parse(*v).is_ok())
            .collect();
        assert_eq!(accepted, vec![1]);
    }

    #[test]
    fn post_quantum_ratchet_is_mandatory() {
        assert!(ProtocolVersion::CURRENT.requires_post_quantum_ratchet());
    }

    #[test]
    fn version_round_trips_through_u8() {
        let v = ProtocolVersion::CURRENT;
        assert_eq!(ProtocolVersion::parse(v.as_u8()).unwrap(), v);
    }
}
