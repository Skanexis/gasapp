// SPDX-License-Identifier: AGPL-3.0-only

//! Наблюдение за здоровьем узла.
//!
//! # Что здесь есть и чего нет
//!
//! 🔐 Наблюдаем **работоспособность узла**, а не активность
//! пользователей. Это принципиально разные вещи, и разница проходит
//! ровно по границе метаданных.
//!
//! Отдаётся:
//!
//! * доступна ли база;
//! * жив ли слушатель уведомлений;
//! * версия и время работы процесса.
//!
//! **Не** отдаётся:
//!
//! * число подключённых устройств — это «сколько людей сейчас в сети»;
//! * число конвертов в очереди — это «сколько сейчас переписываются»;
//! * число аккаунтов — размер сообщества и его рост;
//! * частота запросов — суточный ритм активности.
//!
//! Каждая из этих величин выглядит безобидной метрикой, а на деле
//! описывает поведение пользователей. Собранные за месяц, они
//! показывают, когда сообщество активно, растёт ли оно и когда
//! случаются всплески — то есть ровно то, ради чего наблюдают
//! за мессенджерами.
//!
//! # Почему счётчики нельзя «просто добавить потом»
//!
//! Метрика, однажды появившаяся в дашборде, переживает того, кто её
//! завёл: её начинают использовать, на неё ставят алерты, и удалить
//! её становится нельзя. Поэтому граница проводится сразу.
//!
//! # Кому доступна эта информация
//!
//! Ручка не требует аутентификации: в ней нет ничего, чего не видно
//! снаружи по факту работы сервера. Но она **не должна** торчать
//! в интернет — балансировщик обязан отдавать её только внутренней
//! сети (см. `deploy/РАЗВЁРТЫВАНИЕ.md`): версия узла подсказывает
//! атакующему, какие уязвимости пробовать.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::routes::AppState;

/// Состояние узла для наблюдения.
///
/// Все поля — про сам процесс. Ни одно не описывает пользователей.
#[derive(Debug)]
pub struct HealthState {
    /// Момент запуска процесса, секунды Unix.
    started_at: u64,

    /// Работает ли слушатель уведомлений.
    ///
    /// Отдельный флаг, потому что его отказ **невидим** снаружи:
    /// узел продолжает отвечать на запросы и принимать сообщения,
    /// молча перестав будить клиентов. Без этого флага такой отказ
    /// обнаружился бы только по жалобам пользователей.
    listener_alive: AtomicBool,

    /// Сколько раз слушатель переподключался.
    ///
    /// Растущее число означает нестабильную связь с базой. Это
    /// свойство инфраструктуры, а не пользователей: сколько бы
    /// их ни было, число переподключений от этого не меняется.
    listener_reconnects: AtomicU64,
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthState {
    /// Фиксирует момент запуска.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: unix_seconds(),
            listener_alive: AtomicBool::new(false),
            listener_reconnects: AtomicU64::new(0),
        }
    }

    /// Отмечает, что слушатель подключился.
    pub fn listener_connected(&self) {
        self.listener_alive.store(true, Ordering::Relaxed);
    }

    /// Отмечает обрыв слушателя.
    pub fn listener_lost(&self) {
        self.listener_alive.store(false, Ordering::Relaxed);
        self.listener_reconnects.fetch_add(1, Ordering::Relaxed);
    }
}

/// Ответ ручки здоровья.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Версия сервера.
    pub version: &'static str,

    /// Сколько секунд процесс работает.
    ///
    /// Время работы, а не момент запуска: второе позволило бы
    /// сопоставить перезапуски узлов между собой и с внешними
    /// событиями.
    pub uptime_seconds: u64,

    /// Отвечает ли база.
    pub database: bool,

    /// Жив ли слушатель уведомлений.
    pub listener: bool,

    /// Сколько раз слушатель переподключался.
    pub listener_reconnects: u64,
}

/// Проверка готовности узла.
///
/// Отдаёт `503`, если база недоступна или слушатель мёртв: в обоих
/// случаях узел выглядит рабочим, но обслуживает не полностью —
/// балансировщик должен убрать его из ротации, а не продолжать слать
/// на него клиентов.
pub async fn health(State(state): State<Arc<AppState>>) -> (StatusCode, Json<HealthResponse>) {
    // Простейший запрос: проверяется доступность соединения,
    // а не содержимое базы. Считать строки здесь нельзя — это
    // и была бы метрика активности.
    let database = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();

    let listener = state.health.listener_alive.load(Ordering::Relaxed);

    let response = HealthResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: unix_seconds().saturating_sub(state.health.started_at),
        database,
        listener,
        listener_reconnects: state.health.listener_reconnects.load(Ordering::Relaxed),
    };

    let status = if database && listener {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Текущее время в секундах Unix.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_starts_dead() {
        let state = HealthState::new();

        // Узел не считается готовым, пока слушатель не подключился:
        // иначе балансировщик пустит на него клиентов раньше, чем он
        // сможет их будить.
        assert!(!state.listener_alive.load(Ordering::Relaxed));
    }

    #[test]
    fn connection_and_loss_are_tracked() {
        let state = HealthState::new();

        state.listener_connected();
        assert!(state.listener_alive.load(Ordering::Relaxed));

        state.listener_lost();
        assert!(!state.listener_alive.load(Ordering::Relaxed));
        assert_eq!(state.listener_reconnects.load(Ordering::Relaxed), 1);
    }

    /// Переподключения накапливаются.
    ///
    /// Растущее число — признак нестабильной связи с базой, и оно
    /// должно быть видно, а не теряться при каждом успешном
    /// подключении.
    #[test]
    fn reconnects_accumulate() {
        let state = HealthState::new();

        for _ in 0..3 {
            state.listener_connected();
            state.listener_lost();
        }

        assert_eq!(state.listener_reconnects.load(Ordering::Relaxed), 3);
    }
}
