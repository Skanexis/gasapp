// SPDX-License-Identifier: Apache-2.0

//! Контракт криптографического движка.
//!
//! [`ProtocolEngine`] — точка переключения реализаций из ADR-005. Пока
//! существует одна реализация (собственная, на permissive-примитивах), но
//! трейт нужен по трём причинам:
//!
//! 1. **План отступления.** Если аудит не будет профинансирован (ADR-026),
//!    возврат к libsignal стоит одну неделю, а не переписывания проекта.
//! 2. **Дифференциальное тестирование.** Один и тот же набор тестов
//!    прогоняется против любой реализации.
//! 3. **Изоляция для аудита.** Аудитор получает один трейт и одну
//!    реализацию без примеси сетевого кода и хранилища.
//!
//! # Почему здесь нет ни времени, ни случайности
//!
//! Источник случайности и часы передаются снаружи ([`CryptoRng`](rand_core::CryptoRng), [`Clock`]).
//! Криптографический код, который сам берёт `OsRng` и системное время,
//! невозможно протестировать детерминированно — а значит невозможно
//! воспроизвести найденную ошибку. Инъекция делает поведение движка
//! полностью воспроизводимым (раздел 9.2 плана).

use gasapp_types::{Ciphertext, Plaintext, Result, Timestamp};
use rand_core::CryptoRngCore;

use crate::{
    keys::{IdentityKey, IdentityKeyPair, PreKeyBundle, SessionState},
    Fingerprint, ProtocolVersion,
};

/// Источник времени.
///
/// Отдельный трейт, а не `SystemTime::now()`, чтобы тесты могли проверять
/// истечение срока действия предключей и TTL пропущенных message key
/// без ожидания реального времени.
pub trait Clock: Send + Sync {
    /// Текущее время.
    fn now(&self) -> Timestamp;
}

/// Сообщение, устанавливающее сессию (тип PREKEY).
///
/// Отправляется первым, когда сессии ещё нет: содержит эфемерный ключ
/// инициатора, инкапсуляцию ML-KEM и идентификаторы израсходованных
/// предключей получателя.
#[derive(Clone, Debug)]
pub struct InitialMessage {
    /// Версия протокола. Проверяется при разборе (ADR-021).
    pub version: ProtocolVersion,
    /// Сериализованное содержимое сообщения.
    pub payload: Ciphertext,
}

/// Результат установления сессии инициатором.
#[derive(Debug)]
pub struct InitiatedSession {
    /// Состояние сессии для сохранения в хранилище.
    pub session: SessionState,
    /// Сообщение, которое нужно отправить получателю.
    pub message: InitialMessage,
    /// Была ли forward secrecy ослаблена из-за исчерпания пула предключей.
    ///
    /// Не ошибка, но повод для записи в журнал безопасности.
    pub degraded: bool,
}

/// Криптографический движок протокола GasApp.
///
/// Реализация обязана быть чистой: никакого ввода-вывода, никакого доступа
/// к диску или сети, никаких глобальных источников времени и случайности.
pub trait ProtocolEngine: Send + Sync {
    /// Устанавливает сессию как инициатор, используя набор ключей получателя.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::InvalidSignature`] — подпись предключа не сходится
    ///   с identity-ключом. Сессия **не** устанавливается: мягкого режима нет,
    ///   потому что неверная подпись означает либо подмену на сервере,
    ///   либо повреждение данных, и оба случая одинаково неприемлемы.
    /// * [`GasAppError::Crypto`] — сбой криптографической операции.
    ///
    /// [`GasAppError::InvalidSignature`]: gasapp_types::GasAppError::InvalidSignature
    /// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
    /// Источник случайности принимается как [`CryptoRngCore`], а не
    /// `&mut dyn CryptoRng`: последний бесполезен, потому что `CryptoRng` —
    /// маркерный трейт без методов, и получить из него байты нельзя.
    /// `CryptoRngCore` существует ровно для использования в виде
    /// объекта трейта и даёт доступ к `RngCore`.
    fn initiate_session(
        &self,
        our_identity: &IdentityKeyPair,
        their_bundle: &PreKeyBundle,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<InitiatedSession>;

    /// Устанавливает сессию как получатель по входящему PREKEY-сообщению.
    ///
    /// # Errors
    ///
    /// [`GasAppError::UnsupportedProtocolVersion`] при попытке понижения версии,
    /// [`GasAppError::Crypto`] при сбое расшифровки.
    ///
    /// [`GasAppError::UnsupportedProtocolVersion`]: gasapp_types::GasAppError::UnsupportedProtocolVersion
    /// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
    fn accept_session(
        &self,
        our_identity: &IdentityKeyPair,
        message: &InitialMessage,
    ) -> Result<(SessionState, Plaintext)>;

    /// Шифрует сообщение, продвигая ratchet.
    ///
    /// Состояние изменяется: каждый вызов расходует одно звено цепочки.
    /// Message key уничтожается сразу после использования.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] при сбое шифрования.
    ///
    /// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
    fn encrypt(&self, session: &mut SessionState, plaintext: &Plaintext) -> Result<Ciphertext>;

    /// Расшифровывает сообщение, продвигая ratchet.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::TooManySkippedMessages`] — превышен лимит пропущенных
    ///   сообщений. Без этого лимита сообщение со счётчиком `u32::MAX`
    ///   заставило бы клиент вычислить миллиарды ключей (раздел 6.3 плана).
    /// * [`GasAppError::UnsupportedProtocolVersion`] — попытка понижения версии.
    /// * [`GasAppError::Crypto`] — сбой расшифровки или проверки тега.
    ///
    /// [`GasAppError::TooManySkippedMessages`]: gasapp_types::GasAppError::TooManySkippedMessages
    /// [`GasAppError::UnsupportedProtocolVersion`]: gasapp_types::GasAppError::UnsupportedProtocolVersion
    /// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
    fn decrypt(&self, session: &mut SessionState, ciphertext: &Ciphertext) -> Result<Plaintext>;

    /// Вычисляет отпечаток identity-ключа для safety number.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Crypto`] при сбое хеширования.
    ///
    /// [`GasAppError::Crypto`]: gasapp_types::GasAppError::Crypto
    fn fingerprint(&self, identity: &IdentityKey, identifier: &[u8]) -> Result<Fingerprint>;

    /// Версия протокола, которую использует эта реализация.
    fn version(&self) -> ProtocolVersion {
        ProtocolVersion::CURRENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Трейт должен быть object-safe: `gasapp-core` хранит его как
    /// `Box<dyn ProtocolEngine>`, чтобы реализацию можно было подменить
    /// без параметризации всего приложения типом движка.
    #[test]
    fn protocol_engine_is_object_safe() {
        fn assert_object_safe(_: Option<&dyn ProtocolEngine>) {}
        assert_object_safe(None);
    }

    /// Движок используется из нескольких потоков (отправка и приём идут
    /// параллельно), поэтому требования Send + Sync — часть контракта.
    #[test]
    fn protocol_engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn ProtocolEngine>();
        assert_send_sync::<dyn Clock>();
    }
}
