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

pub mod bots;
pub mod channels;
pub mod email;
pub mod kt;
pub mod notify;
pub mod repo;
pub mod runtime;

pub use repo::{Account, AccountDeletion, Device, Envelope, PreKeyBundle, RepoError};

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

/// Сколько хранится вложение.
///
/// Столько же, сколько недоставленный конверт. Короче нельзя: файл
/// становится недоступен раньше, чем сообщение, которое на него
/// ссылается, и получатель видит описание вложения, которого уже нет.
///
/// 🔐 Дольше — тоже нельзя, и по более важной причине: строка вложения
/// не знает получателя, поэтому удалить её вместе с аккаунтом
/// невозможно. Срок хранения — единственное, что вообще стирает
/// вложения с сервера.
#[allow(clippy::duration_suboptimal_units)]
pub const ATTACHMENT_TTL: Duration = Duration::from_secs(2_592_000);

/// Потолок очереди одного устройства: 64 МБ неполученных конвертов.
///
/// 🔐 Без него незнакомец (первый контакт стоит миллисекунды работы)
/// клал по десять конвертов по 256 КБ в минуту в очередь любого, кто
/// сейчас не в сети, — 3,7 ГБ в сутки на человека на тридцать суток
/// хранения, а перебором людей — сколько угодно диска. Потолок держит
/// диск; получатель, выйдя в сеть, забирает очередь, и место
/// освобождается. 64 МБ — сотни тысяч текстовых сообщений.
pub const MAX_QUEUE_BYTES_PER_DEVICE: i64 = 64 * 1024 * 1024;

/// Максимальный размер конверта: 256 КБ (раздел 14.5).
///
/// Ограничение продублировано в схеме (`CHECK`), чтобы действовать
/// и для запросов в обход этого крейта.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// Предел размера зашифрованного вложения.
///
/// 100 МБ открытого файла (`gasapp-media::descriptor`) плюс накладные
/// расходы шифрования: 16 байт тега на каждый чанк в 64 КБ, то есть
/// примерно 1/4096 объёма. Округлено вверх до 101 МБ с запасом.
///
/// Должен совпадать с ограничением схемы в `0003_attachments.sql`:
/// расхождение означало бы отказ на уровне CHECK вместо внятной ошибки.
pub const MAX_ATTACHMENT_BYTES: usize = 101 * 1024 * 1024;

/// Сколько вложений сервер держит всего.
///
/// 🔐 Загрузка анонимна (миграция 0009), и квоты на устройство больше
/// нет — считать по загрузчику нечего. Без общего потолка анонимный
/// поток занял бы диск целиком, и сервер перестал бы принимать
/// сообщения у всех. 64 ГиБ при сроке хранения в 30 дней.
pub const TOTAL_ATTACHMENT_STORAGE_BYTES: i64 = 64 * 1024 * 1024 * 1024;

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

    /// Предел вложения совпадает с ограничением схемы.
    ///
    /// Расхождение означало бы отказ на уровне CHECK вместо внятной
    /// ошибки: клиент получил бы 500 там, где ждал «слишком большой
    /// файл».
    #[test]
    fn attachment_limit_matches_schema() {
        let schema = include_str!("../../migrations/0003_attachments.sql");

        assert_eq!(MAX_ATTACHMENT_BYTES, 101 * 1024 * 1024);
        assert!(
            schema.contains("101 * 1024 * 1024"),
            "ограничение схемы разошлось с MAX_ATTACHMENT_BYTES"
        );
    }

    /// Вложение живёт столько же, сколько недоставленный конверт.
    ///
    /// Короче нельзя: файл стал бы недоступен раньше сообщения,
    /// которое на него ссылается, и получатель увидел бы описание
    /// вложения, которого уже нет.
    #[test]
    fn attachment_ttl_matches_envelope_ttl() {
        assert_eq!(ATTACHMENT_TTL, ENVELOPE_TTL);
    }

    /// Квота вмещает хотя бы одно предельное вложение.
    ///
    /// Иначе самый большой допустимый файл не загрузился бы никогда,
    /// и предел размера означал бы не то, что написано.
    #[test]
    fn quota_admits_a_maximum_attachment() {
        assert!(
            TOTAL_ATTACHMENT_STORAGE_BYTES
                >= i64::try_from(MAX_ATTACHMENT_BYTES).unwrap_or(i64::MAX),
            "квота меньше одного предельного вложения"
        );
    }

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

/// Каноничное ли имя пользователя.
///
/// 🔐 Строчные латинские буквы, цифры и подчёркивание, первая — буква,
/// от 3 до 32 символов. Прежде `UNIQUE` сравнивал имена побайтно:
/// «alice», «Alice» и «аlice» с кириллической «а» были разными
/// аккаунтами и выглядели одинаково — самозванец регистрировал двойника.
/// То же правило — в схеме (`0010_canonical_usernames.sql`) и в клиенте
/// (`gasapp-types::canonical_username`).
#[must_use]
pub fn is_canonical_username(username: &str) -> bool {
    let bytes = username.as_bytes();

    (3..=32).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod username_tests {
    use super::is_canonical_username;

    #[test]
    fn canonical_names_are_accepted() {
        for name in ["bob", "alice_1", "a23", "abcdefghijklmnopqrstuvwxyz012345"] {
            assert!(is_canonical_username(name), "{name} отвергнуто");
        }
    }

    /// 🔐 Двойники и мусор — отказ.
    #[test]
    fn lookalikes_and_junk_are_refused() {
        for name in [
            "Alice",
            "\u{430}lice",
            "alice\u{200b}",
            "al ice",
            "al-ice",
            "@alice",
            "1alice",
            "_alice",
            "ab",
            "abcdefghijklmnopqrstuvwxyz0123456",
            "",
        ] {
            assert!(!is_canonical_username(name), "{name:?} принято");
        }
    }
}
