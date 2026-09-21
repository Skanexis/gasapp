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

/// Лимит discovery на весь кластер: 20 запросов в минуту.
///
/// Против перебора username — иначе злоумышленник за сутки составил бы
/// список всех зарегистрированных имён.
///
/// Это лимит **кластера**, а не узла: перед использованием он делится
/// на число узлов через [`per_node`].
pub const DISCOVERY_PER_MINUTE: u32 = 20;

/// Лимит отправки сообщений на кластер: 60 в минуту на устройство.
///
/// Как и `DISCOVERY_PER_MINUTE`, делится на число узлов.
pub const MESSAGES_PER_MINUTE: u32 = 60;

/// Лимит выдачи prekey bundle на кластер: 10 в минуту на устройство.
///
/// 🔐 Каждая выдача **расходует** одноразовый предключ, и до внутреннего
/// пентеста (раздел 23.6) этот маршрут был единственным расходующим
/// ресурс без ограничителя: запас жертвы вычерпывался одним циклом
/// анонимных запросов, после чего все новые сессии с ней заводились
/// в режиме `degraded` — без одноразового предключа.
///
/// Десять, а не шестьдесят: bundle берут **один раз на собеседника**,
/// а не на сообщение. Десять новых собеседников в минуту — это уже
/// далеко за пределами того, как заводят переписку люди, и при этом
/// вычерпывание запаса из сотни ключей занимает десять минут вместо
/// нескольких секунд.
///
/// ⚠️ Мера неполная: ограничитель считает по **получателю**, потому что
/// адреса сервер не хранит, — значит, упорный вычерпыватель всё же
/// вычерпает запас, просто медленно, и попутно помешает честным
/// собеседникам жертвы. Полное решение — учёт по отправителю, которого
/// при анонимной отправке нет по замыслу.
pub const BUNDLE_PER_MINUTE: u32 = 10;

/// Делит лимит кластера на число узлов.
///
/// # Почему деление, а не общий счётчик
///
/// Счётчики живут в памяти процесса. При трёх узлах без деления
/// фактический предел утроился бы — заявленные 20 запросов в минуту
/// превратились бы в 60, и заявление перестало бы быть правдой.
///
/// Общий счётчик решил бы это точнее, но потребовал бы либо Redis
/// (новый сервис, который надо поднимать и защищать), либо записи
/// в базу при **каждом** запросе, включая отвергнутые — то есть
/// готовую мишень для исчерпания диска: атакующему достаточно слать
/// заведомо отвергаемые запросы.
///
/// Деление даёт верхнюю границу без общего состояния. Цена —
/// неравномерность: клиент, чьи запросы балансировщик раскидал
/// по узлам, упрётся в лимит позже, чем клиент, попавший на один
/// узел. Для защиты от перебора это несущественно, потому что важна
/// именно верхняя граница.
///
/// # Про округление вверх
///
/// При числе узлов больше лимита деление дало бы ноль, то есть
/// запрет вообще всех запросов. Минимум — единица: лучше пропустить
/// немного больше, чем сломать сервис арифметикой.
#[must_use]
pub const fn per_node(cluster_limit: u32, nodes: u32) -> u32 {
    if nodes <= 1 {
        return cluster_limit;
    }

    // `match` вместо `unwrap_or`: последний ещё не стабилен в const.
    // Деление на ноль отсекается выше, но проверка стоит здесь —
    // паника на сервере означает отказ в обслуживании.
    let divided = match cluster_limit.checked_div(nodes) {
        Some(value) => value,
        None => cluster_limit,
    };

    if divided == 0 {
        1
    } else {
        divided
    }
}

/// Сколько узлов в кластере по умолчанию.
///
/// Единица: одиночный запуск — самый частый случай, и он не должен
/// требовать настройки. Кластер обязан объявить своё число явно
/// через `AEGIS_CLUSTER_NODES`, иначе лимиты окажутся втрое выше
/// заявленных, и никто этого не заметит.
pub const DEFAULT_CLUSTER_NODES: u32 = 1;
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
        self.evict_if_needed(now_millis);

        // 🔐 Переполненная карта не заводит новых ключей.
        //
        // Ключ строится по данным запроса — имени пользователя,
        // идентификатору устройства, — то есть выбирается тем, кто
        // запрос шлёт. Значит любой может набрать сколько угодно
        // разных ключей.
        //
        // Прежде переполнение вызывало очистку целиком: атакующий
        // набирал [`MAX_TRACKED_KEYS`] ключей и обнулял **чужие**
        // окна вместе со своим, снимая ограничение со всех разом.
        //
        // Теперь неизвестный ключ при полной карте получает отказ,
        // а известные продолжают учитываться. Это отказ в худшую
        // для атакующего сторону: под давлением ограничитель
        // ограничивает сильнее, а не перестаёт.
        //
        // ⚠️ Цена — первый запрос к новому имени в этот момент тоже
        // получит 429. Это ухудшение обслуживания, но не обход
        // защиты, и оно временное: мёртвые окна вытесняются
        // на следующем же вызове, когда истечёт минута.
        if !self.windows.contains_key(&key) && self.windows.len() >= MAX_TRACKED_KEYS {
            return false;
        }

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
    /// # ⚠️ Почему не просто `clear()`
    ///
    /// Раньше здесь стояла очистка целиком, и это давало обход
    /// ограничителя: ключ строится по данным запроса (имя
    /// пользователя, идентификатор устройства), то есть атакующий
    /// выбирает его сам. Набрав [`MAX_TRACKED_KEYS`] разных ключей,
    /// он вызывал очистку — и вместе со своим окном обнулял **чужие**.
    /// Повторяя это, он снимал ограничение и с себя, и со всех
    /// остальных.
    ///
    /// Теперь сначала выбрасываются окна, в которых не осталось
    /// ни одной отметки за последнюю минуту. Именно они и составляют
    /// почти всё переполнение: ключ, по которому был один запрос
    /// минуту назад, занимает место, но ничего не ограничивает.
    ///
    /// ⚠️ Полной очистки здесь больше нет — она и была обходом.
    /// Что делать, когда живых окон действительно
    /// [`MAX_TRACKED_KEYS`], решает [`RateLimiter::allow`]: новые
    /// ключи не заводятся, известные продолжают учитываться.
    fn evict_if_needed(&mut self, now_millis: i64) {
        if self.windows.len() < MAX_TRACKED_KEYS {
            return;
        }

        let cutoff = now_millis.saturating_sub(WINDOW_MILLIS);

        self.windows
            .retain(|_key, window| window.back().is_some_and(|stamp| *stamp > cutoff));
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

    /// 🔐 Переполнение ключами не снимает ограничение с остальных.
    ///
    /// Ключ строится по данным запроса, то есть выбирается
    /// атакующим. Прежняя стратегия вытеснения очищала карту
    /// целиком, и набор `MAX_TRACKED_KEYS` разных ключей обнулял
    /// чужие окна вместе со своим — то есть снимал ограничение
    /// со всех разом.
    #[test]
    fn filling_the_map_does_not_reset_an_active_window() {
        let mut limiter = RateLimiter::new(2);

        // Жертва исчерпала свой лимит.
        assert!(limiter.allow(key(0), NOW));
        assert!(limiter.allow(key(0), NOW));
        assert!(!limiter.allow(key(0), NOW), "лимит должен быть исчерпан");

        // Атакующий заполняет карту — в том же окне времени,
        // иначе окно жертвы просто истечёт само.
        for index in 1..=(MAX_TRACKED_KEYS as u64 + 10) {
            limiter.allow(key_n(index), NOW);
        }

        assert!(
            !limiter.allow(key(0), NOW),
            "переполнение карты сняло ограничение с чужого ключа"
        );
    }

    /// Мёртвые окна вытесняются, и память не растёт бесконечно.
    #[test]
    fn stale_windows_are_evicted() {
        let mut limiter = RateLimiter::new(2);

        for index in 0..(MAX_TRACKED_KEYS as u64) {
            limiter.allow(key_n(index), NOW);
        }

        // Спустя окно все прежние отметки мертвы.
        limiter.allow(key_n(u64::MAX), NOW + WINDOW_MILLIS + 1);

        assert!(
            limiter.tracked_keys() < MAX_TRACKED_KEYS,
            "мёртвые окна не вытеснены: {} ключей",
            limiter.tracked_keys()
        );
    }

    const NOW: i64 = 1_700_000_000_000;

    fn key(value: u8) -> LimitKey {
        [value; 32]
    }

    /// Много различных ключей: `key` даёт только 256.
    fn key_n(value: u64) -> LimitKey {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());

        bytes
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
        assert_eq!(BUNDLE_PER_MINUTE, 10);
    }
}

#[cfg(test)]
mod cluster_tests {
    use super::*;

    /// Одиночный узел получает лимит целиком.
    #[test]
    fn single_node_keeps_full_limit() {
        assert_eq!(per_node(DISCOVERY_PER_MINUTE, 1), DISCOVERY_PER_MINUTE);
        assert_eq!(per_node(DISCOVERY_PER_MINUTE, 0), DISCOVERY_PER_MINUTE);
    }

    /// 🔐 На трёх узлах суммарный лимит не превышает заявленного.
    ///
    /// Главная проверка: без деления заявленные 20 запросов в минуту
    /// превратились бы в 60, и заявление перестало бы быть правдой.
    #[test]
    fn cluster_total_does_not_exceed_declared() {
        let nodes = 3;
        let per = per_node(DISCOVERY_PER_MINUTE, nodes);

        assert!(
            per * nodes <= DISCOVERY_PER_MINUTE,
            "суммарный лимит {} превышает заявленные {}",
            per * nodes,
            DISCOVERY_PER_MINUTE
        );
    }

    /// Лимит не обнуляется при большом числе узлов.
    ///
    /// Деление 20 на 50 дало бы ноль — то есть запрет всех запросов.
    /// Лучше пропустить немного больше, чем сломать сервис
    /// арифметикой.
    #[test]
    fn limit_never_reaches_zero() {
        assert_eq!(per_node(DISCOVERY_PER_MINUTE, 50), 1);
        assert_eq!(per_node(1, 100), 1);
    }

    /// Лимит убывает с ростом числа узлов.
    #[test]
    fn limit_shrinks_with_more_nodes() {
        assert!(per_node(60, 2) > per_node(60, 3));
        assert!(per_node(60, 3) > per_node(60, 6));
    }
}
