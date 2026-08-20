// SPDX-License-Identifier: AGPL-3.0-only

//! Ограничение частоты запросов.
//!
//! # Что здесь не хранится
//!
//! **IP-адреса.** Раздел 14.4 плана прямо запрещает их логировать,
//! и ограничитель это соблюдает: ключом служит хеш, а не адрес.
//! Хеш позволяет считать запросы с одного источника, но не позволяет
//! восстановить источник — в том числе тому, кто получил дамп памяти
//! сервера.
//!
//! Соль хеша живёт только в памяти процесса и меняется при перезапуске:
//! даже полный дамп не даёт сопоставить счётчики с адресами задним числом.
//!
//! # Почему скользящее окно, а не фиксированное
//!
//! Фиксированное окно допускает всплеск на границе: 20 запросов
//! в последнюю секунду одной минуты плюс 20 в первую секунду следующей —
//! 40 запросов за две секунды при лимите «20 в минуту». Скользящее окно
//! считает запросы за последние 60 секунд от текущего момента.
//!
//! # Границы
//!
//! Модуль не берёт системное время: оно передаётся аргументом, поэтому
//! поведение на границах окна проверяется в тестах детерминированно.

use std::collections::{HashMap, VecDeque};

/// Ключ ограничителя: непрозрачный идентификатор источника.
///
/// Получается хешированием адреса с солью процесса. Обратно
/// не восстанавливается.
pub type LimitKey = [u8; 32];

/// Лимит discovery: 20 запросов в минуту.
///
/// Против перебора username — иначе злоумышленник за сутки составил бы
/// список всех зарегистрированных имён.
pub const DISCOVERY_PER_MINUTE: u32 = 20;

/// Лимит отправки сообщений: 60 в минуту на устройство.
pub const MESSAGES_PER_MINUTE: u32 = 60;

/// Длина окна в миллисекундах.
const WINDOW_MILLIS: i64 = 60 * 1000;

/// Максимум отслеживаемых ключей.
///
/// Ограничение существует, чтобы сам ограничитель не стал вектором
/// исчерпания памяти: атакующий с миллионом источников иначе заставил бы
/// сервер хранить миллион очередей.
const MAX_TRACKED_KEYS: usize = 100_000;

/// Скользящее окно запросов.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: HashMap<LimitKey, VecDeque<i64>>,
    limit: u32,
}

impl RateLimiter {
    /// Создаёт ограничитель с заданным лимитом за минуту.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            windows: HashMap::new(),
            limit,
        }
    }

    /// Регистрирует запрос. Возвращает `false`, если лимит исчерпан.
    ///
    /// Отклонённый запрос **не** попадает в окно: иначе клиент, упёршийся
    /// в лимит и продолжающий стучаться, продлевал бы себе блокировку
    /// бесконечно.
    pub fn allow(&mut self, key: LimitKey, now_millis: i64) -> bool {
        self.evict_if_needed();

        let window = self.windows.entry(key).or_default();
        let cutoff = now_millis.saturating_sub(WINDOW_MILLIS);

        while window.front().is_some_and(|stamp| *stamp <= cutoff) {
            window.pop_front();
        }

        if u32::try_from(window.len()).unwrap_or(u32::MAX) >= self.limit {
            return false;
        }

        window.push_back(now_millis);

        true
    }

    /// Сколько запросов ещё разрешено ключу.
    #[must_use]
    pub fn remaining(&self, key: &LimitKey, now_millis: i64) -> u32 {
        let cutoff = now_millis.saturating_sub(WINDOW_MILLIS);
        let used = self.windows.get(key).map_or(0, |window| {
            window.iter().filter(|stamp| **stamp > cutoff).count()
        });

        self.limit
            .saturating_sub(u32::try_from(used).unwrap_or(u32::MAX))
    }

    /// Сколько ключей отслеживается.
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.windows.len()
    }

    /// Вытесняет ключи при переполнении.
    ///
    /// Стратегия грубая — очистка целиком, — и это осознанно: при
    /// достижении потолка сервер уже под атакой, и точность учёта важнее
    /// не для отдельного клиента, а для того, чтобы не исчерпать память.
    /// Полная очистка даёт всем шанс заново, что честнее произвольного
    /// выбора жертв.
    fn evict_if_needed(&mut self) {
        if self.windows.len() >= MAX_TRACKED_KEYS {
            self.windows.clear();
        }
    }
}

/// Строит ключ ограничителя из адреса и соли процесса.
///
/// # Про необратимость
///
/// Результат — SHA-256 от соли и адреса. Соль случайна, живёт только
/// в памяти и не переживает перезапуск, поэтому сопоставить ключ
/// с адресом нельзя даже имея дамп: подбор потребовал бы знания соли.
#[must_use]
pub fn key_from_addr(salt: &[u8; 32], addr: &str) -> LimitKey {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(addr.as_bytes());

    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn key(value: u8) -> LimitKey {
        [value; 32]
    }

    /// Запросы в пределах лимита проходят.
    #[test]
    fn requests_within_limit_pass() {
        let mut limiter = RateLimiter::new(3);

        for _ in 0..3 {
            assert!(limiter.allow(key(1), NOW));
        }
    }

    /// 🔐 Запрос сверх лимита отклоняется.
    #[test]
    fn request_over_limit_is_rejected() {
        let mut limiter = RateLimiter::new(3);

        for _ in 0..3 {
            limiter.allow(key(1), NOW);
        }

        assert!(!limiter.allow(key(1), NOW));
    }

    /// Окно скользит: старые запросы перестают учитываться.
    #[test]
    fn window_slides() {
        let mut limiter = RateLimiter::new(2);

        limiter.allow(key(1), NOW);
        limiter.allow(key(1), NOW);
        assert!(!limiter.allow(key(1), NOW));

        // Через минуту с секундой оба запроса вышли из окна.
        assert!(limiter.allow(key(1), NOW + WINDOW_MILLIS + 1));
    }

    /// 🔐 Отклонённые запросы не продлевают блокировку.
    ///
    /// Иначе бот, стучащийся непрерывно, блокировал бы сам себя навсегда —
    /// а вместе с собой и добросовестного клиента за тем же NAT.
    #[test]
    fn rejected_requests_do_not_extend_the_window() {
        let mut limiter = RateLimiter::new(1);

        limiter.allow(key(1), NOW);

        // Стучимся всю минуту.
        for offset in 0..60 {
            limiter.allow(key(1), NOW + offset * 1000);
        }

        // Ровно через минуту после единственного учтённого запроса
        // лимит обязан освободиться.
        assert!(limiter.allow(key(1), NOW + WINDOW_MILLIS + 1));
    }

    /// Ключи независимы: лимит одного не влияет на другого.
    #[test]
    fn keys_are_independent() {
        let mut limiter = RateLimiter::new(1);

        assert!(limiter.allow(key(1), NOW));
        assert!(!limiter.allow(key(1), NOW));
        assert!(limiter.allow(key(2), NOW));
    }

    /// Остаток считается корректно.
    #[test]
    fn remaining_is_reported() {
        let mut limiter = RateLimiter::new(3);

        assert_eq!(limiter.remaining(&key(1), NOW), 3);
        limiter.allow(key(1), NOW);
        assert_eq!(limiter.remaining(&key(1), NOW), 2);
    }

    /// 🔐 Ключ не раскрывает адрес.
    ///
    /// Разные адреса дают разные ключи, но по ключу адрес не восстановить:
    /// это и позволяет считать запросы, не храня IP.
    #[test]
    fn key_hides_the_address() {
        let salt = [0x5Au8; 32];

        let first = key_from_addr(&salt, "203.0.113.7");
        let second = key_from_addr(&salt, "203.0.113.8");

        assert_ne!(first, second);
        assert_eq!(first, key_from_addr(&salt, "203.0.113.7"));

        // Адрес не содержится в ключе ни в каком виде.
        let rendered = hex::encode(first);
        assert!(!rendered.contains("203"));
    }

    /// 🔐 Смена соли меняет ключи.
    ///
    /// Соль не переживает перезапуск, поэтому счётчики нельзя
    /// сопоставить с адресами задним числом.
    #[test]
    fn salt_rotation_changes_keys() {
        let addr = "203.0.113.7";

        assert_ne!(
            key_from_addr(&[0x01u8; 32], addr),
            key_from_addr(&[0x02u8; 32], addr)
        );
    }

    /// 🔐 Ограничитель не растёт без предела.
    #[test]
    fn tracked_keys_are_bounded() {
        let mut limiter = RateLimiter::new(1);

        for index in 0..(MAX_TRACKED_KEYS + 10) {
            let mut source = [0u8; 32];
            source[..8].copy_from_slice(&(index as u64).to_be_bytes());
            limiter.allow(source, NOW);
        }

        assert!(
            limiter.tracked_keys() <= MAX_TRACKED_KEYS,
            "ограничитель превысил лимит ключей: {}",
            limiter.tracked_keys()
        );
    }

    /// Лимиты из плана заданы верно.
    #[test]
    fn plan_limits_are_configured() {
        assert_eq!(DISCOVERY_PER_MINUTE, 20);
        assert_eq!(MESSAGES_PER_MINUTE, 60);
    }
}
