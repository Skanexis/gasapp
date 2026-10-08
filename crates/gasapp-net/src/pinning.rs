// SPDX-License-Identifier: Apache-2.0

//! Проверка пинов TLS-сертификата.
//!
//! # Что пиннится
//!
//! Хеш **SPKI** (`SubjectPublicKeyInfo`), а не сертификата целиком.
//! Сертификат перевыпускается при каждом продлении и меняет отпечаток,
//! даже если ключ остался прежним; SPKI меняется только вместе с ключом.
//! Пиннинг по сертификату ломал бы связь при каждом продлении Let's Encrypt.
//!
//! # Правило двух пинов
//!
//! Набор всегда содержит **минимум два** пина: текущий и следующий.
//! Следующий добавляется за 90 дней до ротации, поэтому клиент,
//! не обновлявшийся три месяца, переживёт смену ключа.
//!
//! Это не перестраховка. Ошибка в ротации пинов — единственный отказ,
//! который **невозможно починить с сервера**: клиент перестаёт доверять
//! серверу и не может получить ни новый пин, ни сообщение об ошибке.
//! Чинится только обновлением через магазин приложений, то есть днями
//! простоя (раздел 14.3 плана).
//!
//! # Чего здесь нет
//!
//! Установления TLS-соединения. Модуль проверяет **уже полученный**
//! SPKI против набора пинов; сам TLS ведёт платформенный стек, где
//! и включается эта проверка. Такое разделение делает логику пиннинга
//! проверяемой без сети.

use gasapp_types::{GasAppError, Result};
use sha2::{Digest, Sha256};

/// Длина пина: SHA-256 от SPKI.
pub const PIN_LEN: usize = 32;

/// Минимальное число пинов в наборе.
///
/// Ровно один пин означает, что ротация ключа обрывает связь со всеми
/// клиентами: следующий ключ ещё никому не известен.
pub const MIN_PINS: usize = 2;

/// Набор пинов для одного домена.
#[derive(Clone, Debug)]
pub struct PinSet {
    pins: Vec<[u8; PIN_LEN]>,
}

impl PinSet {
    /// Собирает набор пинов.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — пинов меньше [`MIN_PINS`]. Отказ
    /// намеренный: набор из одного пина выглядит рабочим ровно до
    /// ротации, после которой чинить его поздно.
    pub fn new(pins: Vec<[u8; PIN_LEN]>) -> Result<Self> {
        if pins.len() < MIN_PINS {
            return Err(GasAppError::Malformed);
        }

        Ok(Self { pins })
    }

    /// Проверяет SPKI сервера против набора.
    ///
    /// # Про сравнение
    ///
    /// Сравнение обычное, не constant-time, и это осознанно: пины —
    /// **публичные** значения, они лежат в открытом виде в конфиге
    /// приложения. Скрывать здесь нечего, а тайминг-канал раскрыл бы
    /// разве что сам пин, который атакующему и так известен.
    ///
    /// # Errors
    ///
    /// [`GasAppError::InvalidSignature`] — SPKI не совпал ни с одним пином.
    /// Вариант выбран намеренно: с точки зрения приложения это подмена
    /// личности сервера, а не сетевой сбой, и повторять запрос бессмысленно.
    pub fn verify(&self, spki: &[u8]) -> Result<()> {
        let actual = pin_from_spki(spki);

        if self.pins.contains(&actual) {
            Ok(())
        } else {
            Err(GasAppError::InvalidSignature)
        }
    }

    /// Сколько пинов в наборе.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Пуст ли набор.
    ///
    /// Всегда `false`: конструктор не допускает набор короче [`MIN_PINS`].
    /// Метод существует, потому что `len` без `is_empty` — ловушка clippy
    /// и повод для недоразумений у читателя.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

/// Вычисляет пин из SPKI сервера.
#[must_use]
pub fn pin_from_spki(spki: &[u8]) -> [u8; PIN_LEN] {
    let mut pin = [0u8; PIN_LEN];
    pin.copy_from_slice(&Sha256::digest(spki));

    pin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> Vec<[u8; PIN_LEN]> {
        vec![pin_from_spki(b"current key"), pin_from_spki(b"next key")]
    }

    /// 🔐 Совпадающий SPKI принимается.
    #[test]
    fn matching_spki_is_accepted() {
        let set = PinSet::new(pins()).unwrap();

        assert!(set.verify(b"current key").is_ok());
    }

    /// 🔐 Следующий пин принимается наравне с текущим.
    ///
    /// Это и есть механизм ротации: клиент принимает оба ключа, пока
    /// сервер переходит с одного на другой.
    #[test]
    fn next_pin_is_accepted_during_rotation() {
        let set = PinSet::new(pins()).unwrap();

        assert!(set.verify(b"next key").is_ok());
    }

    /// 🔐 Чужой SPKI отвергается — это MITM.
    #[test]
    fn foreign_spki_is_rejected() {
        let set = PinSet::new(pins()).unwrap();

        assert!(matches!(
            set.verify(b"attacker key"),
            Err(GasAppError::InvalidSignature)
        ));
    }

    /// 🔐 Набор из одного пина не создаётся.
    ///
    /// Ровно один пин переживает разработку и ломается в проде при первой
    /// же ротации — причём так, что починить с сервера нельзя.
    #[test]
    fn single_pin_set_is_rejected() {
        assert!(matches!(
            PinSet::new(vec![pin_from_spki(b"only one")]),
            Err(GasAppError::Malformed)
        ));
        assert!(matches!(
            PinSet::new(Vec::new()),
            Err(GasAppError::Malformed)
        ));
    }

    /// Пин зависит от каждого бита SPKI.
    #[test]
    fn pin_depends_on_whole_spki() {
        assert_ne!(pin_from_spki(b"key a"), pin_from_spki(b"key b"));
        assert_eq!(pin_from_spki(b"same"), pin_from_spki(b"same"));
    }

    /// Пустой SPKI не совпадает с настоящим ключом.
    #[test]
    fn empty_spki_is_rejected() {
        let set = PinSet::new(pins()).unwrap();

        assert!(set.verify(b"").is_err());
    }
}
