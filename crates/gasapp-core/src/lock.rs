// SPDX-License-Identifier: Apache-2.0

//! Состояние блокировки приложения.
//!
//! # Что здесь не хранится
//!
//! **PIN.** Ни в открытом виде, ни в зашифрованном. Первая редакция
//! `gasapp-core` держала PIN в памяти как `Secret<String>` и сравнивала
//! его обычным `==` — с комментарием «в реальной реализации здесь должно
//! быть сравнение за постоянное время». Обе части плохи:
//!
//! * PIN в памяти процесса переживает блокировку экрана и попадает
//!   в дампы. Смысл блокировки в том, чтобы после неё в памяти **не
//!   осталось** ничего, чем можно открыть данные;
//! * сравнение строк за переменное время раскрывает длину общего
//!   префикса, а PIN короткий — счёт идёт на тысячи вариантов.
//!
//! Проверка PIN — задача `gasapp-keystore`: там он растягивается Argon2id
//! и превращается в ключ, которым расшифровывается хранилище. Успех
//! расшифровки и есть проверка. Ядро лишь помнит, разблокировано ли
//! приложение, и это **не секрет**.
//!
//! # Почему блокировка отдельно от инициализации
//!
//! Неинициализированное приложение и заблокированное — разные состояния
//! с разной реакцией. Первое чинится настройкой, второе — вводом PIN,
//! и пользователю нельзя показывать одно вместо другого.

use gasapp_types::{GasAppError, Result, Timestamp};

/// Состояние блокировки.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockState {
    /// Приложение ещё не настроено: нет аккаунта и ключей.
    Uninitialized,
    /// Настроено, но заблокировано: нужен PIN или биометрия.
    Locked,
    /// Разблокировано и готово к работе.
    Unlocked,
}

/// Управление блокировкой.
///
/// Хранит **только** состояние и время последней активности. Ключевого
/// материала здесь нет по построению — см. документацию модуля.
#[derive(Clone, Copy, Debug)]
pub struct LockGuard {
    state: LockState,
    /// Когда пользователь последний раз что-то делал.
    last_activity: Timestamp,
    /// Через сколько бездействия блокировать, миллисекунды.
    auto_lock_after: i64,
}

/// Значение по умолчанию: блокировать через 5 минут бездействия.
pub const DEFAULT_AUTO_LOCK_MILLIS: i64 = 5 * 60 * 1000;

impl LockGuard {
    /// Создаёт хранитель в ненастроенном состоянии.
    #[must_use]
    pub const fn new(now: Timestamp) -> Self {
        Self {
            state: LockState::Uninitialized,
            last_activity: now,
            auto_lock_after: DEFAULT_AUTO_LOCK_MILLIS,
        }
    }

    /// Задаёт таймаут автоблокировки.
    ///
    /// Ноль означает «блокировать немедленно после каждой операции» —
    /// допустимый выбор для параноидального режима.
    pub const fn set_auto_lock(&mut self, millis: i64) {
        self.auto_lock_after = millis;
    }

    /// Текущее состояние с учётом бездействия.
    ///
    /// Автоблокировка вычисляется, а не наступает по таймеру: ядро
    /// не владеет часами и не крутит фоновых задач. Состояние
    /// определяется в момент запроса — этого достаточно, потому что
    /// любое обращение к данным проходит через проверку.
    #[must_use]
    pub fn state(&self, now: Timestamp) -> LockState {
        if self.state != LockState::Unlocked {
            return self.state;
        }

        let idle = now
            .as_millis()
            .saturating_sub(self.last_activity.as_millis());

        if idle >= self.auto_lock_after {
            LockState::Locked
        } else {
            LockState::Unlocked
        }
    }

    /// Отмечает завершение настройки: приложение переходит в разблокированное
    /// состояние.
    pub const fn mark_initialized(&mut self, now: Timestamp) {
        self.state = LockState::Unlocked;
        self.last_activity = now;
    }

    /// Разблокирует приложение.
    ///
    /// Вызывается **после** того, как `gasapp-keystore` успешно
    /// расшифровал хранилище: успех расшифровки и есть доказательство
    /// знания PIN. Само ядро PIN не видит.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Uninitialized`] — приложение ещё не настроено,
    /// разблокировать нечего.
    pub const fn unlock(&mut self, now: Timestamp) -> Result<()> {
        if matches!(self.state, LockState::Uninitialized) {
            return Err(GasAppError::Uninitialized);
        }

        self.state = LockState::Unlocked;
        self.last_activity = now;

        Ok(())
    }

    /// Блокирует приложение.
    ///
    /// Идемпотентно: блокировать уже заблокированное — не ошибка.
    /// Ненастроенное состояние сохраняется: блокировать нечего.
    pub const fn lock(&mut self) {
        if matches!(self.state, LockState::Unlocked) {
            self.state = LockState::Locked;
        }
    }

    /// Продлевает сессию после действия пользователя.
    ///
    /// Не разблокирует: продлить можно только уже открытую сессию.
    /// Иначе любое фоновое обращение отодвигало бы автоблокировку
    /// бесконечно.
    pub fn touch(&mut self, now: Timestamp) {
        if self.state(now) == LockState::Unlocked {
            self.last_activity = now;
        }
    }

    /// Разблокировано ли приложение прямо сейчас.
    #[must_use]
    pub fn is_unlocked(&self, now: Timestamp) -> bool {
        self.state(now) == LockState::Unlocked
    }

    /// Проверяет, что приложение разблокировано.
    ///
    /// # Errors
    ///
    /// * [`GasAppError::Uninitialized`] — приложение не настроено.
    /// * [`GasAppError::Locked`] — настроено, но заблокировано.
    ///
    /// Ошибки различаются намеренно: первая чинится настройкой,
    /// вторая — вводом PIN, и путать их в UI нельзя.
    pub fn require_unlocked(&self, now: Timestamp) -> Result<()> {
        match self.state(now) {
            LockState::Unlocked => Ok(()),
            LockState::Locked => Err(GasAppError::Locked),
            LockState::Uninitialized => Err(GasAppError::Uninitialized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn later(millis: i64) -> Timestamp {
        Timestamp::from_millis(now().as_millis().saturating_add(millis))
    }

    #[test]
    fn starts_uninitialized() {
        let guard = LockGuard::new(now());

        assert_eq!(guard.state(now()), LockState::Uninitialized);
        assert!(matches!(
            guard.require_unlocked(now()),
            Err(GasAppError::Uninitialized)
        ));
    }

    /// 🔐 Ненастроенное приложение нельзя разблокировать.
    #[test]
    fn uninitialized_cannot_be_unlocked() {
        let mut guard = LockGuard::new(now());

        assert!(matches!(
            guard.unlock(now()),
            Err(GasAppError::Uninitialized)
        ));
    }

    #[test]
    fn initialization_unlocks() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());

        assert!(guard.is_unlocked(now()));
    }

    /// 🔐 Заблокированное и ненастроенное различаются в ошибке.
    ///
    /// UI показывает разное: «настройте приложение» против «введите PIN».
    #[test]
    fn locked_and_uninitialized_differ() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());
        guard.lock();

        assert!(matches!(
            guard.require_unlocked(now()),
            Err(GasAppError::Locked)
        ));
    }

    /// 🔐 Автоблокировка срабатывает после бездействия.
    #[test]
    fn auto_lock_engages_after_idle() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());

        assert!(guard.is_unlocked(later(DEFAULT_AUTO_LOCK_MILLIS - 1)));
        assert!(!guard.is_unlocked(later(DEFAULT_AUTO_LOCK_MILLIS)));
    }

    /// Активность продлевает сессию.
    #[test]
    fn activity_extends_the_session() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());

        // Половина таймаута: значение выписано явно, чтобы не делить
        // в тесте — деление запрещено правилом 4.2.
        let midway = later(150_000);
        guard.touch(midway);

        // От момента активности снова отсчитывается полный таймаут.
        assert!(guard.is_unlocked(Timestamp::from_millis(
            midway.as_millis() + DEFAULT_AUTO_LOCK_MILLIS - 1
        )));
    }

    /// 🔐 Активность не воскрешает заблокированную сессию.
    ///
    /// Иначе фоновый запрос, пришедший после автоблокировки, молча
    /// открывал бы доступ к данным без ввода PIN.
    #[test]
    fn activity_does_not_revive_a_locked_session() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());

        let after_timeout = later(DEFAULT_AUTO_LOCK_MILLIS);
        guard.touch(after_timeout);

        assert!(
            !guard.is_unlocked(after_timeout),
            "touch разблокировал сессию в обход PIN"
        );
    }

    /// Явная блокировка действует немедленно.
    #[test]
    fn explicit_lock_is_immediate() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());
        guard.lock();

        assert!(!guard.is_unlocked(now()));
    }

    /// Повторная блокировка не ошибка.
    #[test]
    fn locking_twice_is_idempotent() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());
        guard.lock();
        guard.lock();

        assert_eq!(guard.state(now()), LockState::Locked);
    }

    /// Блокировка не отменяет факт настройки.
    #[test]
    fn lock_preserves_initialization() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());
        guard.lock();
        guard.unlock(now()).unwrap();

        assert!(guard.is_unlocked(now()));
    }

    /// Нулевой таймаут блокирует сразу после операции.
    #[test]
    fn zero_timeout_locks_immediately() {
        let mut guard = LockGuard::new(now());
        guard.mark_initialized(now());
        guard.set_auto_lock(0);

        assert!(!guard.is_unlocked(now()));
    }

    /// Ненастроенное состояние не меняется блокировкой.
    #[test]
    fn lock_does_not_affect_uninitialized() {
        let mut guard = LockGuard::new(now());
        guard.lock();

        assert_eq!(guard.state(now()), LockState::Uninitialized);
    }
}
