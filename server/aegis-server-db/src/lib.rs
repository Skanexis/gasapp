// SPDX-License-Identifier: AGPL-3.0-only

//! Схема и доступ к Postgres.
//!
//! # Что сервер хранит
//!
//! Минимум для маршрутизации: аккаунты, устройства, публичные предключи
//! и очередь недоставленных конвертов. Содержимого сообщений нет —
//! конверт приходит зашифрованным, и ключа от него у сервера не существует.
//!
//! Каждая таблица в `migrations/0001_initial.sql` сопровождается ответом
//! на вопрос «что узнает тот, кто получит дамп». Это не украшение
//! комментария: раздел 15 плана требует, чтобы объём знания сервера был
//! отслеживаемым, а не выяснялся постфактум.
//!
//! # Про retention
//!
//! Доставленный конверт удаляется немедленно после подтверждения,
//! недоставленный — через 30 дней по `expires_at`. Обе границы заданы
//! разделом 14.4 и вынесены в константы ниже.

pub mod repo;

pub use repo::{Account, Device, Envelope, PreKeyBundle, RepoError};

use std::time::Duration;

/// Сколько хранится недоставленный конверт.
///
/// 30 дней — компромисс раздела 14.4: дольше означает, что сервер
/// накапливает данные о том, кто с кем не связывался, короче — что
/// уехавший в отпуск теряет сообщения.
// `Duration::from_days(30)` читался бы лучше, но конструктор ещё
// нестабилен (`duration_constructors`), а проект собирается стабильным
// компилятором. 2_592_000 секунд — это ровно 30 суток.
#[allow(clippy::duration_suboptimal_units)]
pub const ENVELOPE_TTL: Duration = Duration::from_secs(2_592_000);

/// Максимальный размер конверта: 256 КБ (раздел 14.5).
///
/// Ограничение продублировано в схеме (`CHECK`), чтобы действовать
/// и для запросов в обход этого крейта.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// Округляет отметку времени до часа.
///
/// # Зачем
///
/// Клиенту сообщается, когда сообщение встало в очередь. Точное время
/// с точностью до миллисекунды — сильный признак для корреляции:
/// наблюдатель, видящий трафик отправителя и метку получателя, связывает
/// их по совпадению момента. Округление до часа делает такое сопоставление
/// бесполезным, не мешая сортировке (раздел 15 плана).
#[must_use]
pub const fn bucket_to_hour(unix_seconds: i64) -> i64 {
    const HOUR: i64 = 3600;

    // `rem_euclid` вместо `%`: для отрицательных отметок обычный остаток
    // даёт отрицательный результат и округлял бы вверх, а не вниз.
    //
    // `saturating_sub`: вычитаемое лежит в [0, HOUR), поэтому переполнение
    // недостижимо, но арифметика без насыщения запрещена правилом 4.2.
    unix_seconds.saturating_sub(unix_seconds.rem_euclid(HOUR))
}

/// Версия крейта, доступная во время выполнения.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();

        assert_eq!(parts.len(), 3, "ожидался формат MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "не число: {part}");
        }
    }

    /// 🔐 Округление скрывает точный момент постановки в очередь.
    #[test]
    fn bucketing_hides_exact_time() {
        // 12:34:56 и 12:00:00 одного часа неразличимы после округления.
        let precise = 1_700_000_096;
        let same_hour = 1_700_000_000;

        assert_eq!(bucket_to_hour(precise), bucket_to_hour(same_hour));
    }

    /// Округление идёт вниз и не перескакивает час.
    #[test]
    fn bucketing_rounds_down() {
        let bucketed = bucket_to_hour(1_700_003_599);

        assert!(bucketed <= 1_700_003_599);
        assert_eq!(bucketed.rem_euclid(3600), 0, "результат не кратен часу");
    }

    /// Соседние часы различимы: сортировка сохраняется.
    #[test]
    fn adjacent_hours_stay_distinct() {
        let first = bucket_to_hour(1_700_000_000);
        let second = bucket_to_hour(1_700_000_000 + 3600);

        assert_ne!(first, second);
        assert!(second > first);
    }

    /// Отрицательные отметки округляются вниз, а не вверх.
    #[test]
    fn negative_timestamps_round_down() {
        let bucketed = bucket_to_hour(-1);

        assert!(bucketed <= -1);
        assert_eq!(bucketed.rem_euclid(3600), 0);
    }

    /// Границы retention соответствуют плану.
    #[test]
    fn retention_matches_the_plan() {
        assert_eq!(ENVELOPE_TTL.as_secs(), 30 * 24 * 60 * 60);
        assert_eq!(MAX_ENVELOPE_BYTES, 262_144);
    }
}
