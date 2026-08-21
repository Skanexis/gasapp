// SPDX-License-Identifier: AGPL-3.0-only

//! Запросы к Postgres.
//!
//! # Почему запросы, а не ORM
//!
//! Каждый запрос здесь виден целиком, включая то, какие поля он читает.
//! Для сервера, чья главная характеристика — «сколько он знает
//! о пользователях», это важнее удобства: ORM прячет выборку за
//! абстракцией, и лишнее поле в результате легко не заметить.
//!
//! # Что здесь не делается
//!
//! Не разбирается содержимое конвертов. Сервер принимает `ciphertext`
//! как непрозрачный массив байт и отдаёт его получателю — ключей у него
//! нет, и разбирать нечем.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{bucket_to_hour, DEVICE_ATTACHMENT_QUOTA_BYTES, MAX_ATTACHMENT_BYTES, MAX_ENVELOPE_BYTES};

/// Ошибка доступа к хранилищу.
///
/// # Про единообразие
///
/// [`RepoError::NotFound`] намеренно не различает «нет аккаунта»
/// и «нет устройства»: разница между ними — оракул, по которому
/// перебором выясняется, какие аккаунты существуют.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// Запрошенного не существует.
    #[error("not found")]
    NotFound,
    /// Имя уже занято.
    #[error("username already taken")]
    UsernameTaken,
    /// Конверт превышает допустимый размер.
    #[error("envelope too large")]
    EnvelopeTooLarge,
    /// Вложение больше предела.
    #[error("attachment too large")]
    AttachmentTooLarge,
    /// Устройство исчерпало квоту на вложения.
    #[error("quota exceeded")]
    QuotaExceeded,
    /// Сбой базы данных.
    ///
    /// Текст ошибки Postgres наружу не отдаётся: он может содержать
    /// фрагменты запроса и имена таблиц.
    #[error("database error")]
    Database,
}

impl From<sqlx::Error> for RepoError {
    fn from(error: sqlx::Error) -> Self {
        // Причина пишется в журнал разработчика, но не возвращается
        // вызывающему: журнал и ответ клиенту — разные каналы.
        tracing::warn!("database operation failed: {error}");

        match &error {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(db) if db.is_unique_violation() => Self::UsernameTaken,
            _ => Self::Database,
        }
    }
}

/// Аккаунт в том виде, в каком его отдаёт discovery.
#[derive(Debug, Clone)]
pub struct Account {
    /// Идентификатор аккаунта.
    pub account_id: Uuid,
    /// Публичный identity-ключ.
    pub identity_key: Vec<u8>,
}

/// Устройство аккаунта.
#[derive(Debug, Clone)]
pub struct Device {
    /// Идентификатор устройства.
    pub device_id: Uuid,
    /// Публичный identity-ключ устройства.
    pub identity_key: Vec<u8>,
}

/// Prekey bundle, выдаваемый по запросу.
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    /// Устройство, которому принадлежит набор.
    pub device_id: Uuid,
    /// Identity-ключ устройства.
    pub identity_key: Vec<u8>,
    /// Идентификатор подписанного предключа.
    pub signed_key_id: i32,
    /// Публичная часть подписанного предключа.
    pub signed_public: Vec<u8>,
    /// Подпись подписанного предключа.
    pub signed_signature: Vec<u8>,
    /// Идентификатор пост-квантового предключа.
    pub kem_key_id: i32,
    /// Публичная часть пост-квантового предключа.
    pub kem_public: Vec<u8>,
    /// Подпись пост-квантового предключа.
    pub kem_signature: Vec<u8>,
    /// Одноразовый предключ, если пул не исчерпан.
    pub one_time: Option<(i32, Vec<u8>)>,
    /// Одноразовый пост-квантовый предключ вместе с подписью.
    pub one_time_kem: Option<(i32, Vec<u8>, Vec<u8>)>,
}

/// Конверт, ожидающий доставки.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Идентификатор конверта.
    pub envelope_id: Uuid,
    /// Непрозрачный шифротекст.
    pub ciphertext: Vec<u8>,
    /// Время постановки в очередь, **округлённое до часа**.
    ///
    /// Точная метка не отдаётся: она служила бы признаком для корреляции
    /// отправителя с получателем (раздел 15 плана).
    pub queued_at_bucketed: i64,
}

/// Регистрирует аккаунт вместе с первым устройством.
///
/// Операция атомарна: аккаунт без устройства бесполезен, а устройство
/// без аккаунта невозможно по внешнему ключу.
///
/// # Errors
///
/// * [`RepoError::UsernameTaken`] — имя занято.
/// * [`RepoError::Database`] — сбой базы.
pub async fn register_account(
    pool: &PgPool,
    username: &str,
    identity_key: &[u8],
    device_identity: &[u8],
) -> Result<(Uuid, Uuid), RepoError> {
    let mut transaction: Transaction<'_, Postgres> = pool.begin().await?;

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    sqlx::query("INSERT INTO accounts (account_id, username, identity_key) VALUES ($1, $2, $3)")
        .bind(account_id)
        .bind(username)
        .bind(identity_key)
        .execute(&mut *transaction)
        .await?;

    sqlx::query("INSERT INTO devices (device_id, account_id, identity_key) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(account_id)
        .bind(device_identity)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok((account_id, device_id))
}

/// Находит аккаунт по имени — эндпоинт discovery.
///
/// # Errors
///
/// [`RepoError::NotFound`] — имени нет. Формулировка не различает
/// «нет такого» и «скрыт»: иначе перебор выявлял бы существующие имена.
pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Account, RepoError> {
    let row: (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT account_id, identity_key FROM accounts WHERE username = $1")
            .bind(username)
            .fetch_one(pool)
            .await?;

    Ok(Account {
        account_id: row.0,
        identity_key: row.1,
    })
}

/// Возвращает устройства аккаунта.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn list_devices(pool: &PgPool, account_id: Uuid) -> Result<Vec<Device>, RepoError> {
    let rows: Vec<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT device_id, identity_key FROM devices WHERE account_id = $1")
            .bind(account_id)
            .fetch_all(pool)
            .await?;

    Ok(rows
        .into_iter()
        .map(|(device_id, identity_key)| Device {
            device_id,
            identity_key,
        })
        .collect())
}

/// Возвращает устройство по идентификатору.
///
/// Нужен аутентификации: публичный ключ для проверки подписи берётся
/// из базы, а не из запроса — иначе клиент подписал бы челлендж
/// собственным ключом и прошёл бы проверку кем угодно.
///
/// # Errors
///
/// [`RepoError::NotFound`] — устройства нет.
pub async fn list_devices_by_id(pool: &PgPool, device_id: Uuid) -> Result<Device, RepoError> {
    let row: (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT device_id, identity_key FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(pool)
            .await?;

    Ok(Device {
        device_id: row.0,
        identity_key: row.1,
    })
}

/// Публикует предключи устройства, заменяя прежние подписанные.
///
/// Одноразовые **добавляются** к имеющимся, а не заменяют их: клиент
/// пополняет пул, а не публикует его заново.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn publish_prekeys(
    pool: &PgPool,
    device_id: Uuid,
    signed: (i32, &[u8], &[u8]),
    kem: (i32, &[u8], &[u8]),
    one_time: &[(i32, Vec<u8>)],
    one_time_kem: &[(i32, Vec<u8>, Vec<u8>)],
) -> Result<(), RepoError> {
    let mut transaction: Transaction<'_, Postgres> = pool.begin().await?;

    sqlx::query(
        "
        INSERT INTO signed_prekeys
            (device_id, key_id, public_key, signature, kem_key_id, kem_public, kem_signature)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (device_id) DO UPDATE SET
            key_id        = excluded.key_id,
            public_key    = excluded.public_key,
            signature     = excluded.signature,
            kem_key_id    = excluded.kem_key_id,
            kem_public    = excluded.kem_public,
            kem_signature = excluded.kem_signature,
            updated_at    = now()
        ",
    )
    .bind(device_id)
    .bind(signed.0)
    .bind(signed.1)
    .bind(signed.2)
    .bind(kem.0)
    .bind(kem.1)
    .bind(kem.2)
    .execute(&mut *transaction)
    .await?;

    for (key_id, public) in one_time {
        sqlx::query(
            "
            INSERT INTO one_time_prekeys (device_id, key_id, public_key, is_kem)
            VALUES ($1, $2, $3, FALSE)
            ON CONFLICT (device_id, key_id, is_kem) DO NOTHING
            ",
        )
        .bind(device_id)
        .bind(key_id)
        .bind(public)
        .execute(&mut *transaction)
        .await?;
    }

    for (key_id, public, signature) in one_time_kem {
        sqlx::query(
            "
            INSERT INTO one_time_prekeys (device_id, key_id, public_key, signature, is_kem)
            VALUES ($1, $2, $3, $4, TRUE)
            ON CONFLICT (device_id, key_id, is_kem) DO NOTHING
            ",
        )
        .bind(device_id)
        .bind(key_id)
        .bind(public)
        .bind(signature)
        .execute(&mut *transaction)
        .await?;
    }

    transaction.commit().await?;

    Ok(())
}

/// Выдаёт prekey bundle, **расходуя** по одному одноразовому предключу.
///
/// # Почему расход, а не пометка
///
/// Израсходованный ключ удаляется. Пометка означала бы, что сервер
/// накапливает историю «кто у кого спрашивал ключи» — фрагмент
/// социального графа, который раздел 15 требует не хранить.
///
/// # Про исчерпание пула
///
/// Пустой пул — не ошибка: bundle выдаётся без одноразового ключа,
/// и клиент помечает сессию как ослабленную. Отказ здесь означал бы,
/// что вычерпав чужой пул, атакующий лишает контакт возможности
/// получать сообщения вовсе.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — устройства нет либо предключи не опубликованы.
/// * [`RepoError::Database`] — сбой базы.
pub async fn take_prekey_bundle(pool: &PgPool, device_id: Uuid) -> Result<PreKeyBundle, RepoError> {
    let mut transaction: Transaction<'_, Postgres> = pool.begin().await?;

    let signed: (Vec<u8>, i32, Vec<u8>, Vec<u8>, i32, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "
        SELECT d.identity_key, s.key_id, s.public_key, s.signature,
               s.kem_key_id, s.kem_public, s.kem_signature
        FROM signed_prekeys s
        JOIN devices d ON d.device_id = s.device_id
        WHERE s.device_id = $1
        ",
    )
    .bind(device_id)
    .fetch_one(&mut *transaction)
    .await?;

    // `FOR UPDATE SKIP LOCKED`: два одновременных запроса не получат один
    // и тот же одноразовый ключ. Без этого «одноразовый» перестаёт быть
    // одноразовым при параллельной выдаче.
    let one_time: Option<(i32, Vec<u8>)> = sqlx::query_as(
        "
        DELETE FROM one_time_prekeys
        WHERE id = (
            SELECT id FROM one_time_prekeys
            WHERE device_id = $1 AND is_kem = FALSE
            ORDER BY id
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING key_id, public_key
        ",
    )
    .bind(device_id)
    .fetch_optional(&mut *transaction)
    .await?;

    let one_time_kem: Option<(i32, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "
        DELETE FROM one_time_prekeys
        WHERE id = (
            SELECT id FROM one_time_prekeys
            WHERE device_id = $1 AND is_kem = TRUE
            ORDER BY id
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING key_id, public_key, signature
        ",
    )
    .bind(device_id)
    .fetch_optional(&mut *transaction)
    .await?;

    transaction.commit().await?;

    Ok(PreKeyBundle {
        device_id,
        identity_key: signed.0,
        signed_key_id: signed.1,
        signed_public: signed.2,
        signed_signature: signed.3,
        kem_key_id: signed.4,
        kem_public: signed.5,
        kem_signature: signed.6,
        one_time,
        one_time_kem: one_time_kem
            .and_then(|(id, public, signature)| signature.map(|sig| (id, public, sig))),
    })
}

/// Сколько одноразовых предключей осталось у устройства.
///
/// Клиент опрашивает это, чтобы вовремя пополнить пул.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn count_one_time_prekeys(pool: &PgPool, device_id: Uuid) -> Result<i64, RepoError> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1 AND is_kem = FALSE",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// Ставит конверт в очередь доставки.
///
/// # Errors
///
/// * [`RepoError::EnvelopeTooLarge`] — превышен лимит в 256 КБ.
/// * [`RepoError::NotFound`] — устройства-получателя нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn enqueue_envelope(
    pool: &PgPool,
    destination_device_id: Uuid,
    ciphertext: &[u8],
    ttl_seconds: i64,
) -> Result<Uuid, RepoError> {
    // Проверка до обращения к базе: ограничение продублировано в схеме,
    // но осмысленная ошибка лучше, чем нарушение CHECK.
    if ciphertext.len() > MAX_ENVELOPE_BYTES {
        return Err(RepoError::EnvelopeTooLarge);
    }

    let envelope_id = Uuid::new_v4();

    // Интервал строится умножением на `1 second`, а не через
    // `make_interval(secs => …)`: последний принимает `double precision`,
    // и приведение i64 → f64 теряло бы точность на больших сроках.
    sqlx::query(
        "
        INSERT INTO envelopes (envelope_id, destination_device_id, ciphertext, expires_at)
        VALUES ($1, $2, $3, now() + ($4 * INTERVAL '1 second'))
        ",
    )
    .bind(envelope_id)
    .bind(destination_device_id)
    .bind(ciphertext)
    .bind(ttl_seconds)
    .execute(pool)
    .await?;

    Ok(envelope_id)
}

/// Забирает ожидающие конверты устройства.
///
/// Время постановки округляется до часа — см. [`Envelope::queued_at_bucketed`].
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn fetch_envelopes(
    pool: &PgPool,
    device_id: Uuid,
    limit: i64,
) -> Result<Vec<Envelope>, RepoError> {
    let rows: Vec<(Uuid, Vec<u8>, i64)> = sqlx::query_as(
        "
        SELECT envelope_id, ciphertext, EXTRACT(EPOCH FROM queued_at)::BIGINT
        FROM envelopes
        WHERE destination_device_id = $1 AND expires_at > now()
        ORDER BY queued_at
        LIMIT $2
        ",
    )
    .bind(device_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(envelope_id, ciphertext, queued_at)| Envelope {
            envelope_id,
            ciphertext,
            queued_at_bucketed: bucket_to_hour(queued_at),
        })
        .collect())
}

/// Удаляет доставленный конверт.
///
/// Вызывается после подтверждения от клиента. Раздел 14.4: доставленное
/// хранится ноль секунд — сервер, который «на всякий случай» оставляет
/// копию, перестаёт быть тем, за что его выдают.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn acknowledge_envelope(
    pool: &PgPool,
    device_id: Uuid,
    envelope_id: Uuid,
) -> Result<(), RepoError> {
    // Проверка получателя в условии: иначе одно устройство удаляло бы
    // конверты другого, зная только идентификатор.
    sqlx::query("DELETE FROM envelopes WHERE envelope_id = $1 AND destination_device_id = $2")
        .bind(envelope_id)
        .bind(device_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Удаляет просроченные конверты.
///
/// Вызывается по расписанию. TTL задан разделом 14.4: 30 дней.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_expired(pool: &PgPool) -> Result<u64, RepoError> {
    let result = sqlx::query("DELETE FROM envelopes WHERE expires_at <= now()")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Сохраняет зашифрованное вложение.
///
/// # 🔐 Что здесь не сохраняется
///
/// Получатель. Строка вложения не называет, кому файл предназначен:
/// связь между файлом и разговором существует только внутри сообщения,
/// которое сервер прочитать не может. Добавь сюда устройство-получателя
/// — и оператор строил бы граф «кто кому шлёт файлы», не расшифровав
/// ни байта.
///
/// Имя файла, его тип и длительность голосового тоже отсутствуют: они
/// уходят получателю внутри сообщения, под сквозным шифрованием.
///
/// # Errors
///
/// * [`RepoError::AttachmentTooLarge`] — блоб больше предела.
/// * [`RepoError::QuotaExceeded`] — устройство исчерпало квоту.
/// * [`RepoError::NotFound`] — устройства-загрузчика нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn store_attachment(
    pool: &PgPool,
    uploader_device_id: Uuid,
    payload: &[u8],
    ttl_seconds: i64,
) -> Result<Uuid, RepoError> {
    // Проверка до обращения к базе: ограничение продублировано в схеме,
    // но осмысленная ошибка лучше, чем нарушение CHECK.
    if payload.len() > MAX_ATTACHMENT_BYTES {
        return Err(RepoError::AttachmentTooLarge);
    }

    // 🔐 Квота считается до вставки: без неё один аккаунт занял бы диск
    // целиком, и сервер перестал бы принимать сообщения у всех
    // остальных.
    //
    // Гонка здесь возможна: два параллельных запроса увидят один и тот
    // же итог и оба пройдут. Плата за это — небольшое превышение
    // квоты, а не её обход: следующая загрузка уже упрётся. Блокировка
    // ради точной цифры держала бы транзакцию на всё время вставки
    // стомегабайтного блоба.
    let used: i64 = sqlx::query_scalar(
        "
        SELECT COALESCE(SUM(octet_length(payload)), 0)
        FROM attachments
        WHERE uploader_device_id = $1
        ",
    )
    .bind(uploader_device_id)
    .fetch_one(pool)
    .await?;

    let after = used.saturating_add(i64::try_from(payload.len()).unwrap_or(i64::MAX));

    if after > DEVICE_ATTACHMENT_QUOTA_BYTES {
        return Err(RepoError::QuotaExceeded);
    }

    let attachment_id = Uuid::new_v4();

    sqlx::query(
        "
        INSERT INTO attachments (attachment_id, uploader_device_id, payload, expires_at)
        VALUES ($1, $2, $3, now() + ($4 * INTERVAL '1 second'))
        ",
    )
    .bind(attachment_id)
    .bind(uploader_device_id)
    .bind(payload)
    .bind(ttl_seconds)
    .execute(pool)
    .await?;

    Ok(attachment_id)
}

/// Отдаёт вложение по адресу.
///
/// # 🔐 Почему любой может скачать любое вложение
///
/// Проверить право на скачивание невозможно, не зная, кому файл
/// предназначен, — а этого сервер не знает намеренно. Защита здесь
/// не в проверке доступа, а в том, что адрес — случайный UUID,
/// а содержимое зашифровано ключом, которого у сервера нет.
///
/// Угадать адрес нельзя: 122 бита случайности. Угадав — получишь
/// шифроблоб, к которому нет ключа.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — вложения нет либо срок истёк.
/// * [`RepoError::Database`] — сбой базы.
pub async fn fetch_attachment(pool: &PgPool, attachment_id: Uuid) -> Result<Vec<u8>, RepoError> {
    // Истёкшее не отдаётся, даже если уборщик до него ещё не дошёл:
    // иначе срок хранения зависел бы от расписания очистки.
    let payload: Option<Vec<u8>> = sqlx::query_scalar(
        "
        SELECT payload
        FROM attachments
        WHERE attachment_id = $1 AND expires_at > now()
        ",
    )
    .bind(attachment_id)
    .fetch_optional(pool)
    .await?;

    payload.ok_or(RepoError::NotFound)
}

/// Удаляет просроченные вложения.
///
/// Вызывается тем же расписанием, что и [`purge_expired`].
///
/// 🔐 Единственный способ, которым вложения вообще удаляются: строка
/// не знает получателя, поэтому удалить её «вместе с аккаунтом»
/// нельзя. Это осознанная плата за то, что сервер не видит, кто кому
/// шлёт файлы.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_expired_attachments(pool: &PgPool) -> Result<u64, RepoError> {
    let result = sqlx::query("DELETE FROM attachments WHERE expires_at <= now()")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Токен push-уведомлений устройства.
#[derive(Debug, Clone)]
pub struct PushToken {
    /// Провайдер: `fcm`, `apns` или `unified`.
    pub provider: String,
    /// Сам токен, как его выдал провайдер.
    pub token: String,
}

/// Сохраняет токен устройства, заменяя прежний.
///
/// 🔐 Замена, а не добавление: второй токен для одного устройства
/// означал бы доставку на аппарат, с которого пользователь уже ушёл.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы либо неизвестный провайдер
/// (проверяется ограничением схемы).
pub async fn save_push_token(
    pool: &PgPool,
    device_id: Uuid,
    provider: &str,
    token: &str,
) -> Result<(), RepoError> {
    sqlx::query(
        "INSERT INTO push_tokens (device_id, provider, token)
         VALUES ($1, $2, $3)
         ON CONFLICT (device_id) DO UPDATE
         SET provider = EXCLUDED.provider, token = EXCLUDED.token",
    )
    .bind(device_id)
    .bind(provider)
    .bind(token)
    .execute(pool)
    .await
    .map_err(|_| RepoError::Database)?;

    Ok(())
}

/// Читает токен устройства.
///
/// Возвращает `None`, если устройство не регистрировало токен: это
/// штатный случай для foss-сборки, которая обходится WebSocket.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn find_push_token(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Option<PushToken>, RepoError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT provider, token FROM push_tokens WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| RepoError::Database)?;

    Ok(row.map(|(provider, token)| PushToken { provider, token }))
}

/// Удаляет токен устройства.
///
/// 🔐 Вызывается, когда провайдер сообщил, что токен недействителен.
/// Хранить мёртвый токен незачем: он остаётся связью между устройством
/// и аккаунтом у посредника, не давая ничего взамен.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn delete_push_token(pool: &PgPool, device_id: Uuid) -> Result<(), RepoError> {
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .map_err(|_| RepoError::Database)?;

    Ok(())
}
