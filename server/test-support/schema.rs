// SPDX-License-Identifier: AGPL-3.0-only

//! Подготовка схемы тестовой базы — одна на все наборы тестов.
//!
//! # ⚠️ Почему это общий файл, а не по копии в каждом наборе
//!
//! Было по копии. `gasapp-server-api/tests/http.rs` применял четыре
//! миграции, `client_contract.rs` — одну, `gasapp-server-db/tests/
//! postgres.rs` — тоже одну, и все три начинали с `DROP TABLE`.
//!
//! База при этом одна. Наборы тестов — разные исполняемые файлы,
//! и cargo запускает их одновременно: один сносил таблицы ровно
//! тогда, когда второй с ними работал. Какая схема достанется
//! в итоге, зависело от того, кто успел последним, — то есть набор
//! мог оказаться красным или зелёным без единого изменения в коде.
//!
//! Заметить это было нечем: без `GASAPP_TEST_DATABASE_URL` все три
//! набора молча пропускались, и гонка не разыгрывалась ни разу.
//!
//! Подключается через `#[path]`, а не крейтом: крейт с тестовыми
//! приспособлениями пришлось бы объявить зависимостью, а Cargo
//! объединяет признаки — и приспособления уехали бы в боевую сборку
//! сервера.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

/// Малая сложность proof-of-work: боевые 18 бит считались бы
/// секундами на каждый тест.
pub const TEST_DIFFICULTY: u32 = 4;

/// Номер консультативной блокировки Postgres на время подготовки схемы.
///
/// Произвольный, но постоянный: важно лишь, что все наборы тестов
/// берут один и тот же.
const BOOTSTRAP_LOCK: i64 = 0x0AE6_1500;

/// Отпечаток схемы: меняется вместе со списком миграций.
///
/// Хранится в базе. Пока он совпадает, схема не пересоздаётся —
/// значит второй набор тестов не снесёт таблицы из-под первого.
const SCHEMA_FINGERPRINT: &str =
    "0001+0002+0003+0004+0005+0006+0007+0008+0009+0010+0011+0012+0013+0014+0015+0016+0017+0018+0019b+0020+0021";

/// Адрес тестовой базы, если он задан.
///
/// # 🔐 Почему пропуск бывает запрещён
///
/// Набор тестов, который молча не запускается, — это зелёная отметка
/// ни над чем (правило 0.1). Ровно так семь тестов из семнадцати
/// в `http.rs` были красными всё время, пока считались пройденными:
/// подпись в них делалась не тем алгоритмом, и сервер отвечал `401`.
///
/// Поэтому в CI выставляется `GASAPP_REQUIRE_DATABASE`, и отсутствие
/// адреса становится падением, а не тишиной. На машине разработчика
/// без Postgres тесты по-прежнему пропускаются.
#[must_use]
pub fn database_url() -> Option<String> {
    match std::env::var("GASAPP_TEST_DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            assert!(
                std::env::var("GASAPP_REQUIRE_DATABASE").is_err(),
                "GASAPP_REQUIRE_DATABASE задан, а GASAPP_TEST_DATABASE_URL — нет: \
                 интеграционные тесты обязаны выполняться, а не пропускаться"
            );

            None
        }
    }
}

/// Приводит схему базы к текущему списку миграций.
///
/// Пересоздание происходит один раз на базу, под консультативной
/// блокировкой, и только если отпечаток схемы не совпал. Второй
/// процесс ждёт на блокировке и застаёт готовую схему.
///
/// Изоляция тестов друг от друга достигается не схемой, а уникальными
/// именами аккаунтов: данные не пересекаются, поэтому и пересоздавать
/// таблицы под каждый набор незачем.
pub async fn bootstrap(pool: &sqlx::PgPool) {
    let mut conn = pool.acquire().await.expect("соединение для подготовки");

    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(BOOTSTRAP_LOCK)
        .execute(&mut *conn)
        .await
        .expect("блокировка подготовки");

    let current: Option<String> =
        sqlx::query_scalar("SELECT fingerprint FROM gasapp_test_schema LIMIT 1")
            .fetch_optional(&mut *conn)
            .await
            .unwrap_or(None);

    if current.as_deref() != Some(SCHEMA_FINGERPRINT) {
        // `IF NOT EXISTS` в самих миграциях нет: они рассчитаны
        // на пустую базу. Здесь схема готовится к прогону, поэтому
        // прежняя сносится целиком.
        sqlx::raw_sql(
            "DROP TABLE IF EXISTS gasapp_test_schema, pass_quota, spent_passes, channel_admins, channel_reaction_counts, channel_reactions,
                 channel_subscribers, channel_media, channel_posts, channels,
                 email_codes, admin_actions, admin_state,
                 kt_leaves, kt_epochs, sealed_sender_reports,
                 sealed_sender_access, attachments, push_tokens, envelopes,
                 one_time_prekeys, signed_prekeys, devices, accounts CASCADE",
        )
        .execute(&mut *conn)
        .await
        .expect("прежняя схема снимается");

        // ⚠️ Новая миграция добавляется в три места: сюда, в список
        // DROP выше и в SCHEMA_FINGERPRINT. Без последнего базы,
        // подготовленные прежней версией, останутся со старой схемой.
        for migration in [
            include_str!("../migrations/0001_initial.sql"),
            include_str!("../migrations/0002_push_tokens.sql"),
            include_str!("../migrations/0003_attachments.sql"),
            include_str!("../migrations/0004_sealed_sender.sql"),
            include_str!("../migrations/0005_hour_buckets.sql"),
            include_str!("../migrations/0006_reports_and_prekey_times.sql"),
            include_str!("../migrations/0007_drop_identifying_times.sql"),
            include_str!("../migrations/0008_sealed_sender_kem.sql"),
            include_str!("../migrations/0009_anonymous_attachments.sql"),
            include_str!("../migrations/0010_canonical_usernames.sql"),
            include_str!("../migrations/0011_inactive_accounts.sql"),
            include_str!("../migrations/0012_pq_identity.sql"),
            include_str!("../migrations/0013_account_recovery.sql"),
            include_str!("../migrations/0014_key_transparency.sql"),
            include_str!("../migrations/0015_admin_center.sql"),
            include_str!("../migrations/0016_report_certificates.sql"),
            include_str!("../migrations/0017_email_registration.sql"),
            include_str!("../migrations/0018_premium_channels.sql"),
            include_str!("../migrations/0019_channel_features.sql"),
            include_str!("../migrations/0020_channel_admins.sql"),
            include_str!("../migrations/0021_passes.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&mut *conn)
                .await
                .expect("миграция применяется");
        }

        sqlx::raw_sql("CREATE TABLE gasapp_test_schema (fingerprint TEXT NOT NULL)")
            .execute(&mut *conn)
            .await
            .expect("метка схемы создаётся");

        sqlx::query("INSERT INTO gasapp_test_schema (fingerprint) VALUES ($1)")
            .bind(SCHEMA_FINGERPRINT)
            .execute(&mut *conn)
            .await
            .expect("метка схемы пишется");
    }

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BOOTSTRAP_LOCK)
        .execute(&mut *conn)
        .await
        .expect("блокировка снимается");
}
