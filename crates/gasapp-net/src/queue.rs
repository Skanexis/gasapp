// SPDX-License-Identifier: Apache-2.0

//! Офлайн-очередь отправки с экспоненциальным backoff.
//!
//! # Зачем очередь
//!
//! Мессенджер работает в метро и в самолёте. Сообщение, набранное без
//! сети, обязано уйти, когда сеть появится, — а не потеряться и не
//! заставить пользователя набирать его заново.
//!
//! # Почему backoff экспоненциальный
//!
//! Сеть чаще всего пропадает у всех сразу: упал сервер, легла вышка,
//! отключили район. Если все клиенты будут повторять запрос раз в секунду,
//! они добьют сервер в момент, когда он поднимается. Экспоненциальный рост
//! интервала разводит попытки во времени.
//!
//! # Почему с джиттером
//!
//! Чистая экспонента даёт синхронный «стук»: клиенты, потерявшие связь
//! в одну секунду, повторяют попытки тоже в одну секунду — на 2-й, 4-й,
//! 8-й. Джиттер размазывает их по интервалу и убирает синхронизацию.
//!
//! # Границы
//!
//! Модуль не ходит в сеть и не берёт время из системных часов: текущее
//! время передаётся аргументом (раздел 9.2 плана). Благодаря этому
//! поведение при любой длительности офлайна проверяется в тестах
//! мгновенно и детерминированно.

use std::collections::VecDeque;

use gasapp_types::{GasAppError, Result, Timestamp};

/// Базовая задержка перед первой повторной попыткой, миллисекунды.
pub const BASE_DELAY_MILLIS: i64 = 1_000;

/// Потолок задержки, миллисекунды.
///
/// Час — компромисс: реже бессмысленно (пользователь уже считает
/// сообщение потерянным), чаще — лишняя нагрузка при долгом отключении.
pub const MAX_DELAY_MILLIS: i64 = 60 * 60 * 1000;

/// Максимальное число попыток, после которого отправка признаётся неудачной.
///
/// При базовой задержке в секунду это около двух часов ожидания —
/// после чего пользователю честнее показать ошибку, чем бесконечно
/// делать вид, что сообщение вот-вот уйдёт.
pub const MAX_ATTEMPTS: u32 = 12;

/// Максимальный размер очереди.
///
/// Ограничение существует, чтобы долгий офлайн не съел память и диск:
/// при переполнении вытесняются **самые старые** записи.
pub const MAX_QUEUE_LEN: usize = 10_000;

/// Доля джиттера от вычисленной задержки: ±25 %.
const JITTER_PERCENT: i64 = 25;

/// Запись очереди.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedRequest {
    /// Путь запроса относительно базового URL.
    pub path: String,
    /// Тело запроса. Всегда шифротекст: открытый текст в сеть не уходит.
    pub body: Vec<u8>,
    /// Сколько попыток отправки уже было.
    pub attempts: u32,
    /// Когда запись поставлена в очередь.
    pub queued_at: Timestamp,
    /// Не раньше этого момента имеет смысл повторять.
    pub retry_after: Timestamp,
}

impl QueuedRequest {
    /// Создаёт запись, готовую к немедленной отправке.
    #[must_use]
    pub fn new(path: String, body: Vec<u8>, now: Timestamp) -> Self {
        Self {
            path,
            body,
            attempts: 0,
            queued_at: now,
            retry_after: now,
        }
    }

    /// Исчерпаны ли попытки.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.attempts >= MAX_ATTEMPTS
    }
}

/// Очередь исходящих запросов.
#[derive(Debug, Default)]
pub struct OfflineQueue {
    entries: VecDeque<QueuedRequest>,
    /// Сколько записей вытеснено переполнением — для журнала и диагностики.
    dropped: u64,
}

impl OfflineQueue {
    /// Пустая очередь.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            dropped: 0,
        }
    }

    /// Ставит запрос в очередь.
    ///
    /// При переполнении вытесняется самая старая запись: свежее сообщение
    /// пользователю нужнее, чем попытка недельной давности.
    pub fn push(&mut self, request: QueuedRequest) {
        if self.entries.len() >= MAX_QUEUE_LEN {
            self.entries.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }

        self.entries.push_back(request);
    }

    /// Извлекает следующий запрос, готовый к отправке.
    ///
    /// Возвращает `None`, если очередь пуста либо ни одна запись ещё
    /// не дождалась своего `retry_after`.
    pub fn take_ready(&mut self, now: Timestamp) -> Option<QueuedRequest> {
        let position = self
            .entries
            .iter()
            .position(|entry| entry.retry_after.as_millis() <= now.as_millis())?;

        self.entries.remove(position)
    }

    /// Возвращает запрос в очередь после неудачной попытки.
    ///
    /// Счётчик попыток увеличивается, следующая попытка откладывается
    /// по экспоненте с джиттером.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Network`] — попытки исчерпаны. Запрос **не**
    /// возвращается в очередь: вызывающий код обязан показать ошибку
    /// пользователю, а не ждать вечно.
    pub fn requeue(&mut self, mut request: QueuedRequest, now: Timestamp) -> Result<()> {
        request.attempts = request.attempts.saturating_add(1);

        if request.is_exhausted() {
            return Err(GasAppError::Network);
        }

        let delay = backoff_delay(request.attempts, &request);
        request.retry_after = Timestamp::from_millis(now.as_millis().saturating_add(delay));

        self.push(request);

        Ok(())
    }

    /// Сколько запросов ждёт отправки.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Пуста ли очередь.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Сколько записей вытеснено переполнением за всё время.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Вычисляет задержку перед попыткой номер `attempt`.
///
/// Растёт как `BASE * 2^(attempt-1)`, ограничивается [`MAX_DELAY_MILLIS`]
/// и размазывается джиттером ±25 %.
///
/// # Про источник джиттера
///
/// Джиттер выводится из самой записи (путь, время постановки, номер
/// попытки), а не из генератора случайных чисел. Причины две: поведение
/// остаётся воспроизводимым в тестах, и модулю не нужен источник
/// случайности — а значит, не нужно тащить его через весь вызывающий код.
/// Криптографической стойкости здесь не требуется: джиттер расстраивает
/// синхронизацию клиентов, а не защищает секрет.
#[must_use]
fn backoff_delay(attempt: u32, request: &QueuedRequest) -> i64 {
    // Сдвиг ограничен, чтобы не переполнить i64 при большом номере попытки.
    // `checked_shl` возвращает `None` только при сдвиге за разрядность —
    // здесь недостижимо из-за `min(20)`, но ветка обработана явно.
    let exponent = attempt.saturating_sub(1).min(20);
    let multiplier = 1_i64.checked_shl(exponent).unwrap_or(i64::MAX);
    let base = BASE_DELAY_MILLIS.saturating_mul(multiplier);
    let capped = base.min(MAX_DELAY_MILLIS);

    // Псевдослучайное, но детерминированное смещение из полей записи.
    let path_len = i64::try_from(request.path.len()).unwrap_or(i64::MAX);
    let seed = request
        .queued_at
        .as_millis()
        .wrapping_add(i64::from(attempt))
        .wrapping_add(path_len);

    // Ширина джиттера: доля от вычисленной задержки. Делитель — константа,
    // деление на ноль невозможно.
    let spread = capped
        .saturating_mul(JITTER_PERCENT)
        .checked_div(100)
        .unwrap_or(0);

    let offset = match spread.checked_mul(2) {
        Some(window) if window > 0 => seed.rem_euclid(window).saturating_sub(spread),
        _ => 0,
    };

    capped.saturating_add(offset).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn at(offset: i64) -> Timestamp {
        Timestamp::from_millis(now().as_millis().saturating_add(offset))
    }

    fn request() -> QueuedRequest {
        QueuedRequest::new("/messages".to_owned(), vec![1, 2, 3], now())
    }

    /// Свежий запрос готов к отправке немедленно.
    #[test]
    fn fresh_request_is_ready_at_once() {
        let mut queue = OfflineQueue::new();
        queue.push(request());

        assert!(queue.take_ready(now()).is_some());
        assert!(queue.is_empty());
    }

    /// После неудачи запрос возвращается, но не сразу.
    #[test]
    fn failed_request_waits_before_retry() {
        let mut queue = OfflineQueue::new();
        queue.push(request());

        let taken = queue.take_ready(now()).unwrap();
        queue.requeue(taken, now()).unwrap();

        assert_eq!(queue.len(), 1);
        assert!(
            queue.take_ready(now()).is_none(),
            "повтор не должен быть готов немедленно"
        );
        assert!(
            queue.take_ready(at(MAX_DELAY_MILLIS)).is_some(),
            "через час повтор обязан быть готов"
        );
    }

    /// 🔐 Задержка растёт экспоненциально.
    #[test]
    fn delay_grows_exponentially() {
        let base = backoff_delay(1, &request());
        let second = backoff_delay(2, &request());
        let third = backoff_delay(3, &request());

        assert!(second > base, "вторая попытка ждёт дольше первой");
        assert!(third > second, "третья дольше второй");
    }

    /// Задержка не превышает потолок.
    #[test]
    fn delay_is_capped() {
        for attempt in 1..=MAX_ATTEMPTS {
            let delay = backoff_delay(attempt, &request());

            assert!(delay > 0, "задержка обязана быть положительной");
            assert!(
                delay <= MAX_DELAY_MILLIS.saturating_mul(2),
                "задержка {delay} превысила потолок с джиттером"
            );
        }
    }

    /// Джиттер разводит запросы, поставленные в разное время.
    ///
    /// Без этого клиенты, потерявшие связь одновременно, повторяли бы
    /// попытки тоже одновременно и добивали бы поднимающийся сервер.
    #[test]
    fn jitter_separates_simultaneous_clients() {
        let first = QueuedRequest::new("/a".to_owned(), Vec::new(), Timestamp::from_millis(1_000));
        let second = QueuedRequest::new("/b".to_owned(), Vec::new(), Timestamp::from_millis(1_007));

        assert_ne!(
            backoff_delay(3, &first),
            backoff_delay(3, &second),
            "джиттер не развёл запросы"
        );
    }

    /// Задержка воспроизводима: те же входы дают ту же величину.
    #[test]
    fn delay_is_deterministic() {
        assert_eq!(backoff_delay(4, &request()), backoff_delay(4, &request()));
    }

    /// 🔐 Попытки исчерпываются, а не длятся вечно.
    #[test]
    fn attempts_are_exhausted_eventually() {
        let mut queue = OfflineQueue::new();
        let mut current = request();

        for _ in 0..MAX_ATTEMPTS.saturating_sub(1) {
            queue.requeue(current, now()).unwrap();
            current = queue
                .take_ready(at(MAX_DELAY_MILLIS.saturating_mul(4)))
                .expect("запись возвращается в очередь");
        }

        assert!(matches!(
            queue.requeue(current, now()),
            Err(GasAppError::Network)
        ));
        assert!(
            queue.is_empty(),
            "исчерпанный запрос не должен оставаться в очереди"
        );
    }

    /// 🔐 Переполнение очереди вытесняет старые записи, а не растёт без предела.
    #[test]
    fn overflow_drops_oldest_entries() {
        let mut queue = OfflineQueue::new();

        for index in 0..=MAX_QUEUE_LEN {
            queue.push(QueuedRequest::new(
                format!("/{index}"),
                Vec::new(),
                Timestamp::from_millis(i64::try_from(index).unwrap_or(0)),
            ));
        }

        assert_eq!(queue.len(), MAX_QUEUE_LEN, "очередь превысила лимит");
        assert_eq!(queue.dropped(), 1);

        // Самая старая запись вытеснена, первой отдаётся следующая за ней.
        let first = queue.take_ready(at(MAX_DELAY_MILLIS)).unwrap();
        assert_eq!(first.path, "/1");
    }

    /// Запись, чей срок не подошёл, не мешает готовым.
    ///
    /// Очередь не строго FIFO: отложенный запрос пропускает вперёд те,
    /// что готовы, иначе один неудачник блокировал бы всю отправку.
    #[test]
    fn delayed_entry_does_not_block_ready_ones() {
        let mut queue = OfflineQueue::new();

        let delayed = queue_delayed();
        queue.push(delayed);
        queue.push(request());

        let taken = queue.take_ready(now()).expect("готовая запись найдена");
        assert_eq!(taken.path, "/messages");
    }

    fn queue_delayed() -> QueuedRequest {
        let mut delayed = QueuedRequest::new("/delayed".to_owned(), Vec::new(), now());
        delayed.retry_after = at(MAX_DELAY_MILLIS);
        delayed.attempts = 1;

        delayed
    }

    /// Пустая очередь ничего не отдаёт.
    #[test]
    fn empty_queue_yields_nothing() {
        let mut queue = OfflineQueue::new();

        assert!(queue.take_ready(now()).is_none());
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }
}
