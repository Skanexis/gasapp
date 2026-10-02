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

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    bucket_to_hour, MAX_ATTACHMENT_BYTES, MAX_ENVELOPE_BYTES, MAX_QUEUE_BYTES_PER_DEVICE,
    TOTAL_ATTACHMENT_STORAGE_BYTES,
};

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
    /// Состояние уже новее запроса (повтор перепривязки).
    #[error("conflict")]
    Conflict,
    /// Ключ identity уже принадлежит другому аккаунту.
    #[error("identity key in use")]
    IdentityInUse,
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

/// 🔐 Занят ли ключ identity другим аккаунтом.
///
/// Владение ключом при регистрации не доказывается: открытый ключ
/// любого человека отдаёт discovery. Без этой проверки его можно было
/// зарегистрировать под своим именем — журнал ключей и discovery
/// называли бы один ключ двумя именами, и собеседник, добавивший
/// «двойника», видел бы переписку с настоящим владельцем под чужим
/// именем, а отправленное туда уходило бы в очередь двойника (аудит
/// 2026-10-02, S-1). Свежий ключ настоящего владельца до регистрации
/// не известен никому, так что первым его занять нельзя.
///
/// Ключ устройства не проверяется: сервер находит устройство по
/// идентификатору, а не по ключу, и чужой открытый ключ устройства
/// без его приватной половины ни на что не годится.
///
/// `except` — аккаунт, которому ключ и так принадлежит (перепривязка).
async fn identity_in_use(
    transaction: &mut Transaction<'_, Postgres>,
    identity_key: &[u8],
    except: Option<Uuid>,
) -> Result<bool, RepoError> {
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts
                         WHERE identity_key = $1 AND account_id IS DISTINCT FROM $2)",
    )
    .bind(identity_key)
    .bind(except)
    .fetch_one(&mut **transaction)
    .await?;

    Ok(taken)
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

    if identity_in_use(&mut transaction, identity_key, None).await? {
        return Err(RepoError::IdentityInUse);
    }

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // 🔐 Занятое имя — не ошибка базы, а ноль вставленных строк.
    //
    // Прежде нарушение уникальности ловилось как ошибка, и Postgres
    // писал её в свой журнал вместе со строкой `DETAIL: Key
    // (username)=(…) already exists` и меткой времени. Журнал сервера
    // превращался в список имён, которые кто-то пытался занять, — при
    // том что документ о сроках хранения обещает, что журнала
    // активности нет. `ON CONFLICT DO NOTHING` ошибки не порождает,
    // и в журнал писать нечего.
    let inserted = sqlx::query(
        "INSERT INTO accounts (account_id, username, identity_key) VALUES ($1, $2, $3)
         ON CONFLICT (username) DO NOTHING",
    )
    .bind(account_id)
    .bind(username)
    .bind(identity_key)
    .execute(&mut *transaction)
    .await?
    .rows_affected();

    if inserted == 0 {
        return Err(RepoError::UsernameTaken);
    }

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

/// Сохраняет ключ ML-KEM sealed sender устройства и его подпись.
///
/// Подпись не проверяется: её проверяет отправитель своим знанием
/// identity-ключа получателя. Сервер лишь хранит и раздаёт.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы либо длина не та (ограничение схемы).
pub async fn set_sealed_kem(
    pool: &PgPool,
    device_id: Uuid,
    public: &[u8],
    signature: &[u8],
) -> Result<(), RepoError> {
    sqlx::query(
        "UPDATE devices SET sealed_kem_public = $2, sealed_kem_signature = $3 WHERE device_id = $1",
    )
    .bind(device_id)
    .bind(public)
    .bind(signature)
    .execute(pool)
    .await?;

    Ok(())
}

/// Ключ ML-KEM sealed sender устройства и подпись, если опубликованы.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn sealed_kem_of(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, RepoError> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT sealed_kem_public, sealed_kem_signature FROM devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        Some((Some(public), Some(signature))) => Some((public, signature)),
        _ => None,
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

    // 🔐 Пул не растёт без предела. Прежде устройство добавляло сколько
    // угодно одноразовых ключей с новыми номерами, и любой
    // зарегистрированный аккаунт забивал диск сервера. Предел — вдвое
    // больше пула клиента: пополнение до полного всегда проходит.
    for (is_kem, adding) in [(false, one_time.len()), (true, one_time_kem.len())] {
        if adding == 0 {
            continue;
        }

        let existing: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM one_time_prekeys WHERE device_id = $1 AND is_kem = $2",
        )
        .bind(device_id)
        .bind(is_kem)
        .fetch_one(&mut *transaction)
        .await?;

        if existing.saturating_add(i64::try_from(adding).unwrap_or(i64::MAX)) > MAX_ONE_TIME_PREKEYS
        {
            return Err(RepoError::QuotaExceeded);
        }
    }

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
            -- До часа: точный момент публикации — распорядок владельца
            -- (миграция 0006).
            updated_at    = date_trunc('hour', now())
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

/// Сколько одноразовых предключей каждого вида держит устройство.
///
/// Вдвое больше пула клиента (100): пополнение до полного проходит
/// всегда, а бесконечный рост — нет.
pub const MAX_ONE_TIME_PREKEYS: i64 = 200;

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
    prekey_bundle(pool, device_id, true).await
}

/// Bundle **без** одноразовых предключей — пул не расходуется.
///
/// Выдаётся сверх бюджета расхода (см. маршрут `take_bundle`): сессия
/// заводится на подписанных предключах, как при исчерпанном пуле.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — устройства нет либо предключи не опубликованы.
/// * [`RepoError::Database`] — сбой базы.
pub async fn signed_prekey_bundle(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<PreKeyBundle, RepoError> {
    prekey_bundle(pool, device_id, false).await
}

async fn prekey_bundle(
    pool: &PgPool,
    device_id: Uuid,
    consume_one_time: bool,
) -> Result<PreKeyBundle, RepoError> {
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
    if !consume_one_time {
        transaction.commit().await?;

        return Ok(PreKeyBundle {
            device_id,
            identity_key: signed.0,
            signed_key_id: signed.1,
            signed_public: signed.2,
            signed_signature: signed.3,
            kem_key_id: signed.4,
            kem_public: signed.5,
            kem_signature: signed.6,
            one_time: None,
            one_time_kem: None,
        });
    }

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
/// * [`RepoError::QuotaExceeded`] — очередь получателя полна.
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

    // 🔐 Потолок очереди получателя (см. `MAX_QUEUE_BYTES_PER_DEVICE`).
    // Гонка двух постановок даёт небольшое превышение, а не обход.
    let queued: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(ciphertext)), 0)::BIGINT FROM envelopes WHERE destination_device_id = $1",
    )
    .bind(destination_device_id)
    .fetch_one(pool)
    .await?;

    let after = queued.saturating_add(i64::try_from(ciphertext.len()).unwrap_or(i64::MAX));
    if after > MAX_QUEUE_BYTES_PER_DEVICE {
        return Err(RepoError::QuotaExceeded);
    }

    let envelope_id = Uuid::new_v4();

    // Интервал строится умножением на `1 second`, а не через
    // `make_interval(secs => …)`: последний принимает `double precision`,
    // и приведение i64 → f64 теряло бы точность на больших сроках.
    //
    // 🔐 Время — с точностью до часа, и в `queued_at`, и в `expires_at`
    // (миграция 0005). Точный момент постановки — это момент отправки;
    // рядом с точным временем загрузки вложения он связывал отправителя
    // с получателем в обход sealed sender.
    //
    // Порядок держит позиция в очереди **этого** получателя: на час
    // приходится много конвертов, а начальное сообщение сессии обязано
    // прийти раньше следующих. Позиция считается от лежащих в очереди
    // и сбрасывается вместе с ней — счётчиком полученного она не служит.
    sqlx::query(
        "
        INSERT INTO envelopes
            (envelope_id, destination_device_id, ciphertext, queued_at, expires_at, queue_position)
        VALUES (
            $1, $2, $3,
            date_trunc('hour', now()),
            date_trunc('hour', now()) + ($4 * INTERVAL '1 second'),
            COALESCE(
                (SELECT MAX(queue_position) FROM envelopes WHERE destination_device_id = $2),
                0
            ) + 1
        )
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
        ORDER BY queue_position, envelope_id
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

/// Что исчезло вместе с аккаунтом.
///
/// Возвращается пользователю: право на удаление, подтверждённое
/// словом «готово», ничем не отличается от отсутствия удаления.
/// Числа — про его собственные данные и больше ничьи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountDeletion {
    /// Сколько устройств было у аккаунта.
    pub devices: u64,
    /// Сколько недоставленных конвертов лежало в очередях этих устройств.
    pub envelopes: u64,
    /// Сколько вложений, загруженных этими устройствами, удалено.
    pub attachments: u64,
}

/// Удаляет аккаунт целиком — по любому из его устройств.
///
/// # 🔐 Что именно удаляется
///
/// Строка `accounts` и всё, что на неё ссылается: устройства,
/// подписанные и одноразовые предключи, очереди конвертов, токены
/// push, ключи доступа sealed sender, жалобы и вложения, загруженные
/// этими устройствами. Каскады объявлены в схеме, а не собраны здесь
/// перечислением: перечисление разошлось бы со схемой при добавлении
/// следующей таблицы, и остаток пережил бы удаление молча.
///
/// # Почему по устройству, а не по аккаунту
///
/// Право на удаление доказывается подписью, а подписывает устройство.
/// Аккаунт вычисляется из него здесь, чтобы обработчик не мог
/// передать чужой идентификатор.
///
/// # ⚠️ Удаление уносит все устройства аккаунта
///
/// Это и есть удаление аккаунта, а не выход с одного телефона.
/// Остальные устройства узнают об этом, когда их подпись перестанет
/// приниматься.
///
/// # ⚠️ Что переживает удаление
///
/// Вложения, которые этому аккаунту **прислали**: их загрузил
/// отправитель, и сервер не знает, кому они предназначались, —
/// связь лежит внутри шифротекста (`0003_attachments.sql`).
/// Они исчезают по общему сроку в тридцать суток.
///
/// Копии конвертов, уже доставленные другим устройствам, тоже
/// остаются: они лежат у получателей, а не здесь.
///
/// # ⚠️ Имя пользователя освобождается
///
/// Его сможет занять кто угодно. Выдать себя за прежнего владельца
/// это не позволяет: identity-ключ будет другим, и у тех, кто сверял
/// отпечаток, сработает предупреждение о смене ключа. Удерживать имя
/// вечно значило бы хранить запись об удалённом аккаунте — то есть
/// не удалять его.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — устройства нет; аккаунт уже удалён.
/// * [`RepoError::Database`] — сбой базы.
pub async fn delete_account(pool: &PgPool, device_id: Uuid) -> Result<AccountDeletion, RepoError> {
    // Всё в одной транзакции: подсчёт и удаление обязаны видеть
    // одно состояние, иначе отчёт сообщит о конвертах, которые
    // пришли уже после него, и разойдётся с тем, что удалено.
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let account_id: Uuid =
        sqlx::query_scalar("SELECT account_id FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RepoError::NotFound)?;

    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;

    let envelopes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM envelopes e
           JOIN devices d ON d.device_id = e.destination_device_id
          WHERE d.account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

    let attachments: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM attachments a
           JOIN devices d ON d.device_id = a.uploader_device_id
          WHERE d.account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

    // Одна строка. Остальное уносят каскады схемы.
    let removed = sqlx::query("DELETE FROM accounts WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if removed == 0 {
        // Аккаунт исчез между выборкой и удалением — второй запрос
        // на удаление, пришедший одновременно. Фиксировать нечего.
        tx.rollback().await?;

        return Err(RepoError::NotFound);
    }

    tx.commit().await?;

    Ok(AccountDeletion {
        devices: devices.max(0).unsigned_abs(),
        envelopes: envelopes.max(0).unsigned_abs(),
        attachments: attachments.max(0).unsigned_abs(),
    })
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
/// Загрузчик тоже не сохраняется: загрузка анонимна (миграция 0009).
///
/// Имя файла, его тип и длительность голосового тоже отсутствуют: они
/// уходят получателю внутри сообщения, под сквозным шифрованием.
///
/// # Errors
///
/// * [`RepoError::AttachmentTooLarge`] — блоб больше предела.
/// * [`RepoError::QuotaExceeded`] — общий потолок хранилища исчерпан.
/// * [`RepoError::Database`] — сбой базы.
pub async fn store_attachment(
    pool: &PgPool,
    payload: &[u8],
    ttl_seconds: i64,
) -> Result<Uuid, RepoError> {
    // Проверка до обращения к базе: ограничение продублировано в схеме,
    // но осмысленная ошибка лучше, чем нарушение CHECK.
    if payload.len() > MAX_ATTACHMENT_BYTES {
        return Err(RepoError::AttachmentTooLarge);
    }

    // 🔐 Общий потолок вместо квоты на устройство: загрузка анонимна,
    // и считать по загрузчику нечего. Без потолка анонимный поток
    // занял бы диск целиком, и сервер перестал бы принимать сообщения
    // у всех. Гонка двух загрузок даёт небольшое превышение, а не обход.
    let used: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(octet_length(payload)), 0) FROM attachments")
            .fetch_one(pool)
            .await?;

    let after = used.saturating_add(i64::try_from(payload.len()).unwrap_or(i64::MAX));

    if after > TOTAL_ATTACHMENT_STORAGE_BYTES {
        return Err(RepoError::QuotaExceeded);
    }

    let attachment_id = Uuid::new_v4();

    sqlx::query(
        "
        INSERT INTO attachments (attachment_id, uploader_device_id, payload, uploaded_at, expires_at)
        VALUES (
            $1, NULL, $2,
            date_trunc('hour', now()),
            date_trunc('hour', now()) + ($3 * INTERVAL '1 second')
        )
        ",
    )
    .bind(attachment_id)
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

// --- Sealed sender (раздел 15.2) ---

/// Аккаунт и identity-ключ устройства — то, что попадает в сертификат.
#[derive(Debug, Clone)]
pub struct DeviceSubject {
    /// Аккаунт, которому принадлежит устройство.
    pub account_id: Uuid,
    /// Публичный identity-ключ устройства.
    pub identity_key: Vec<u8>,
}

/// Читает аккаунт и ключ устройства для выдачи сертификата.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы либо устройства нет.
pub async fn device_subject(pool: &PgPool, device_id: Uuid) -> Result<DeviceSubject, RepoError> {
    let row: (Uuid, Vec<u8>) =
        sqlx::query_as("SELECT account_id, identity_key FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(pool)
            .await?;

    Ok(DeviceSubject {
        account_id: row.0,
        identity_key: row.1,
    })
}

/// Сохраняет хеш ключа доступа устройства.
///
/// 🔐 Принимается именно хеш: сам ключ сервер знать не должен, иначе
/// утечка дампа позволила бы писать анонимно любому пользователю.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn set_sealed_sender_access(
    pool: &PgPool,
    device_id: Uuid,
    access_key_hash: &[u8],
    allow_from_anyone: bool,
) -> Result<(), RepoError> {
    sqlx::query(
        "
        INSERT INTO sealed_sender_access (device_id, access_key_hash, allow_from_anyone, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (device_id) DO UPDATE
            SET access_key_hash = EXCLUDED.access_key_hash,
                allow_from_anyone = EXCLUDED.allow_from_anyone,
                updated_at = now()
        ",
    )
    .bind(device_id)
    .bind(access_key_hash)
    .bind(allow_from_anyone)
    .execute(pool)
    .await?;

    Ok(())
}

/// Проверяет предъявленный ключ доступа получателя.
///
/// Возвращает `true`, если анонимную отправку этому устройству
/// разрешено принять.
///
/// # 🔐 Про сравнение
///
/// Сравниваются хеши, и сравнение идёт за постоянное время: обычное
/// `==` на срезах выходит по первому расхождению, и по времени ответа
/// подбирался бы правильный префикс.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn check_sealed_sender_access(
    pool: &PgPool,
    device_id: Uuid,
    presented_key: Option<&[u8]>,
) -> Result<bool, RepoError> {
    let row: Option<(Vec<u8>, bool)> = sqlx::query_as(
        "SELECT access_key_hash, allow_from_anyone FROM sealed_sender_access WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    // Устройство не публиковало ключ доступа — значит, анонимную
    // отправку не включало. Отказ, а не разрешение: умолчание обязано
    // быть в пользу тишины.
    let Some((stored_hash, allow_from_anyone)) = row else {
        return Ok(false);
    };

    if allow_from_anyone {
        return Ok(true);
    }

    let Some(presented) = presented_key else {
        return Ok(false);
    };

    let presented_hash = Sha256::digest(presented);

    Ok(bool::from(presented_hash.as_slice().ct_eq(&stored_hash)))
}

/// Записывает жалобу на отправителя.
///
/// Возвращает `false`, если такая жалоба уже была: повторная от того
/// же жалобщика на того же отправителя не считается второй.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn record_sealed_sender_report(
    pool: &PgPool,
    reported_account: Uuid,
    reported_device: Uuid,
    complainant_device: Uuid,
    certificate_hash: &[u8; 32],
) -> Result<bool, RepoError> {
    let result = sqlx::query(
        "
        INSERT INTO sealed_sender_reports
            (report_id, reported_account, reported_device, complainant_device, certificate_hash)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (complainant_device, reported_device) DO NOTHING
        ",
    )
    .bind(Uuid::new_v4())
    .bind(reported_account)
    .bind(reported_device)
    .bind(complainant_device)
    .bind(certificate_hash.as_slice())
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Сколько разных людей пожаловались на аккаунт.
///
/// Считаются жалобщики, а не жалобы: один человек, пожаловавшийся
/// десять раз, — это один недовольный, а не десять.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn sealed_sender_report_count(
    pool: &PgPool,
    reported_account: Uuid,
) -> Result<i64, RepoError> {
    let row: (i64,) = sqlx::query_as(
        "
        SELECT count(DISTINCT complainant_device)
        FROM sealed_sender_reports
        WHERE reported_account = $1
        ",
    )
    .bind(reported_account)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// Сколько месяцев без входа аккаунт живёт (миграция 0011).
pub const INACTIVE_ACCOUNT_MONTHS: i32 = 12;

/// Отмечает, что аккаунт устройства был активен в этом месяце.
///
/// Пишет не чаще раза в месяц: условие `active_month < …` делает
/// повторные вызовы пустыми, и частые запросы клиента не превращаются
/// в поток записей.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn touch_account_activity(pool: &PgPool, device_id: Uuid) -> Result<(), RepoError> {
    sqlx::query(
        "
        UPDATE accounts SET active_month = date_trunc('month', now())::date
        WHERE account_id = (SELECT account_id FROM devices WHERE device_id = $1)
          AND active_month < date_trunc('month', now())::date
        ",
    )
    .bind(device_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Удаляет аккаунты, не появлявшиеся [`INACTIVE_ACCOUNT_MONTHS`] месяцев.
///
/// Каскады схемы уносят устройства, ключи, очереди и токены — то же,
/// что при удалении владельцем. Имя освобождается.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_inactive_accounts(pool: &PgPool) -> Result<u64, RepoError> {
    let result = sqlx::query(
        "
        DELETE FROM accounts
        WHERE active_month < (date_trunc('month', now()) - make_interval(months => $1))::date
        ",
    )
    .bind(INACTIVE_ACCOUNT_MONTHS)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Пост-квантовая половина identity аккаунта (миграция 0012):
/// открытый ключ ML-DSA-65 и гибридная привязка к классическому.
pub type PqIdentity = (Vec<u8>, Vec<u8>);

/// Записывает пост-квантовую половину identity аккаунта.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы (в том числе неверная длина).
pub async fn set_pq_identity(
    pool: &PgPool,
    account_id: Uuid,
    public: &[u8],
    binding: &[u8],
) -> Result<(), RepoError> {
    sqlx::query(
        "UPDATE accounts SET pq_identity_key = $2, identity_binding = $3 WHERE account_id = $1",
    )
    .bind(account_id)
    .bind(public)
    .bind(binding)
    .execute(pool)
    .await?;

    Ok(())
}

/// Пост-квантовая половина identity аккаунта, если опубликована.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn pq_identity_of(
    pool: &PgPool,
    account_id: Uuid,
) -> Result<Option<PqIdentity>, RepoError> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT pq_identity_key, identity_binding FROM accounts WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    Ok(match row {
        Some((Some(public), Some(binding))) => Some((public, binding)),
        _ => None,
    })
}

/// Аккаунт устройства.
///
/// # Errors
///
/// [`RepoError::NotFound`] — устройства нет; [`RepoError::Database`] — сбой базы.
pub async fn account_of_device(pool: &PgPool, device_id: Uuid) -> Result<Uuid, RepoError> {
    let account: Uuid = sqlx::query_scalar("SELECT account_id FROM devices WHERE device_id = $1")
        .bind(device_id)
        .fetch_one(pool)
        .await?;

    Ok(account)
}

/// Записывает открытые половины ключа восстановления аккаунта.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы (в том числе неверная длина).
pub async fn set_recovery_key(
    pool: &PgPool,
    account_id: Uuid,
    public: &[u8],
    pq_public: &[u8],
) -> Result<(), RepoError> {
    sqlx::query(
        "UPDATE accounts SET recovery_key = $2, recovery_pq_key = $3 WHERE account_id = $1",
    )
    .bind(account_id)
    .bind(public)
    .bind(pq_public)
    .execute(pool)
    .await?;

    Ok(())
}

/// Открытые половины ключа восстановления аккаунта, если заведены.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn recovery_key_of(
    pool: &PgPool,
    account_id: Uuid,
) -> Result<Option<([u8; 32], Vec<u8>)>, RepoError> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT recovery_key, recovery_pq_key FROM accounts WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;

    Ok(match row {
        Some((Some(public), Some(pq_public))) => public
            .as_slice()
            .try_into()
            .ok()
            .map(|public: [u8; 32]| (public, pq_public)),
        _ => None,
    })
}

/// Новая identity аккаунта при перепривязке.
#[derive(Debug, Clone, Copy)]
pub struct Rebind<'a> {
    /// Новый identity-ключ.
    pub identity_key: &'a [u8],
    /// Identity-ключ нового устройства.
    pub device_identity_key: &'a [u8],
    /// Пост-квантовая половина identity.
    pub pq_identity_key: &'a [u8],
    /// Её привязка.
    pub identity_binding: &'a [u8],
    /// Момент подписи запроса, мс.
    pub issued_at_millis: i64,
}

/// Перепривязывает аккаунт к новой identity: прежние устройства
/// удаляются (каскадом — их предключи, очереди, токены, ключи
/// доступа), identity заменяется, заводится новое устройство. Имя
/// остаётся.
///
/// Одной транзакцией: наполовину перепривязанный аккаунт не принимал
/// бы ни старое устройство, ни новое.
///
/// # Errors
///
/// * [`RepoError::Conflict`] — запрос не новее прошлой перепривязки
///   (повтор перехваченного запроса);
/// * [`RepoError::NotFound`] — аккаунта нет;
/// * [`RepoError::Database`] — сбой базы.
pub async fn rebind_account(
    pool: &PgPool,
    account_id: Uuid,
    rebind: Rebind<'_>,
) -> Result<Uuid, RepoError> {
    let mut transaction: Transaction<'_, Postgres> = pool.begin().await?;

    let recovered_at: Option<i64> =
        sqlx::query_scalar("SELECT recovered_at FROM accounts WHERE account_id = $1 FOR UPDATE")
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;

    if recovered_at.is_some_and(|previous| previous >= rebind.issued_at_millis) {
        return Err(RepoError::Conflict);
    }

    if identity_in_use(&mut transaction, rebind.identity_key, Some(account_id)).await? {
        return Err(RepoError::IdentityInUse);
    }

    sqlx::query("DELETE FROM devices WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;

    sqlx::query(
        "
        UPDATE accounts SET
            identity_key     = $2,
            pq_identity_key  = $3,
            identity_binding = $4,
            recovered_at     = $5,
            active_month     = date_trunc('month', now())::date,
            -- Новая identity — новая версия листа в журнале ключей
            -- (миграция 0014): владелец имени отличает свою смену
            -- ключа от подмены.
            key_version      = key_version + 1
        WHERE account_id = $1
        ",
    )
    .bind(account_id)
    .bind(rebind.identity_key)
    .bind(rebind.pq_identity_key)
    .bind(rebind.identity_binding)
    .bind(rebind.issued_at_millis)
    .execute(&mut *transaction)
    .await?;

    let device_id = Uuid::new_v4();

    sqlx::query("INSERT INTO devices (device_id, account_id, identity_key) VALUES ($1, $2, $3)")
        .bind(device_id)
        .bind(account_id)
        .bind(rebind.device_identity_key)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok(device_id)
}

// ---------------------------------------------------------------------------
// Прозрачность ключей (миграция 0014, `crate::kt`)
// ---------------------------------------------------------------------------

/// Строка `kt_leaves`: индекс, ключ, хеш половины, версия.
type KtLeafRow = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, i64);

/// Ключ advisory-блокировки построения эпохи: эпоху строит один узел.
const KT_LOCK: i64 = 0x4145_4749_535f_4b54; // "AEGIS_KT"

/// Лист журнала в эпохе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtLeaf {
    /// Индекс (хеш имени).
    pub idx: [u8; 32],
    /// Identity-ключ.
    pub identity_key: [u8; 32],
    /// Хеш пост-квантовой половины.
    pub pq_hash: [u8; 32],
    /// Версия ключа имени.
    pub version: u64,
}

impl KtLeaf {
    /// Пара «индекс, значение листа» для дерева.
    #[must_use]
    pub fn entry(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.idx,
            crate::kt::leaf_value(&self.idx, &self.identity_key, &self.pq_hash, self.version),
        )
    }
}

/// Эпоха журнала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtEpoch {
    /// Номер.
    pub epoch: i64,
    /// Корень дерева.
    pub root: [u8; 32],
    /// Вершина хеш-цепочки.
    pub head: [u8; 32],
}

fn to32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// Строит эпоху `epoch`, если её ещё нет, и возвращает её.
///
/// Одна транзакция под advisory-блокировкой: узлов API несколько,
/// и эпоху строит тот, кто первым взял блокировку; остальные находят
/// её готовой. Эпоха не строится задним числом — только после последней.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
// Одна транзакция от начала до конца: разбивка на функции потребовала
// бы передавать транзакцию и промежуточные карты, не упростив чтение.
#[allow(clippy::too_many_lines)]
pub async fn kt_build_epoch(pool: &PgPool, epoch: i64) -> Result<Option<KtEpoch>, RepoError> {
    let mut transaction: Transaction<'_, Postgres> = pool.begin().await?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(KT_LOCK)
        .execute(&mut *transaction)
        .await?;

    let latest: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT epoch, head FROM kt_epochs ORDER BY epoch DESC LIMIT 1")
            .fetch_optional(&mut *transaction)
            .await?;

    if latest.as_ref().is_some_and(|(last, _)| *last >= epoch) {
        return Ok(None);
    }

    let previous = latest
        .and_then(|(_, head)| to32(&head))
        .unwrap_or(crate::kt::ZERO);

    // Желаемое состояние — из аккаунтов. Аккаунты без пост-квантовой
    // половины (созданные до неё) в журнал не попадают: их ключ
    // по-прежнему подтверждается только лично.
    let accounts: Vec<(String, Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT username, identity_key, pq_identity_key, key_version
         FROM accounts WHERE pq_identity_key IS NOT NULL",
    )
    .fetch_all(&mut *transaction)
    .await?;

    let mut desired: std::collections::BTreeMap<[u8; 32], KtLeaf> =
        std::collections::BTreeMap::new();
    for (username, identity_key, pq_key, version) in accounts {
        let (Some(identity_key), Ok(version)) = (to32(&identity_key), u64::try_from(version))
        else {
            continue;
        };
        let idx = crate::kt::index(&username);
        desired.insert(
            idx,
            KtLeaf {
                idx,
                identity_key,
                pq_hash: crate::kt::pq_identity_hash(&pq_key),
                version,
            },
        );
    }

    // Текущее состояние журнала — последняя строка по каждому индексу.
    let current: Vec<KtLeafRow> = sqlx::query_as(
        "SELECT DISTINCT ON (idx) idx, identity_key, pq_hash, version
         FROM kt_leaves ORDER BY idx, epoch_from DESC",
    )
    .fetch_all(&mut *transaction)
    .await?;

    let mut present: std::collections::BTreeMap<[u8; 32], Option<KtLeaf>> =
        std::collections::BTreeMap::new();
    for (idx, identity_key, pq_hash, version) in current {
        let Some(idx) = to32(&idx) else { continue };
        let leaf = match (
            identity_key.as_deref().and_then(to32),
            pq_hash.as_deref().and_then(to32),
        ) {
            (Some(identity_key), Some(pq_hash)) => {
                u64::try_from(version).ok().map(|version| KtLeaf {
                    idx,
                    identity_key,
                    pq_hash,
                    version,
                })
            }
            _ => None,
        };
        present.insert(idx, leaf);
    }

    // Изменившиеся и новые листы.
    for (idx, leaf) in &desired {
        if present.get(idx).and_then(Option::as_ref) != Some(leaf) {
            sqlx::query(
                "INSERT INTO kt_leaves (idx, epoch_from, identity_key, pq_hash, version)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(idx.as_slice())
            .bind(epoch)
            .bind(leaf.identity_key.as_slice())
            .bind(leaf.pq_hash.as_slice())
            .bind(i64::try_from(leaf.version).unwrap_or(i64::MAX))
            .execute(&mut *transaction)
            .await?;
        }
    }

    // Исчезнувшие имена — надгробие.
    for (idx, leaf) in &present {
        if let (Some(leaf), false) = (leaf, desired.contains_key(idx)) {
            sqlx::query(
                "INSERT INTO kt_leaves (idx, epoch_from, identity_key, pq_hash, version)
                 VALUES ($1, $2, NULL, NULL, $3)",
            )
            .bind(idx.as_slice())
            .bind(epoch)
            .bind(i64::try_from(leaf.version).unwrap_or(i64::MAX))
            .execute(&mut *transaction)
            .await?;
        }
    }

    let tree = crate::kt::Tree::new(desired.values().map(KtLeaf::entry).collect());
    let root = tree.root();
    let head = crate::kt::head(u64::try_from(epoch).unwrap_or(0), &root, &previous);

    sqlx::query("INSERT INTO kt_epochs (epoch, root, head) VALUES ($1, $2, $3)")
        .bind(epoch)
        .bind(root.as_slice())
        .bind(head.as_slice())
        .execute(&mut *transaction)
        .await?;

    // 🔐 Срок хранения: строка удаляется, когда её сменила строка
    // старше окна истории, — то есть в окне она уже нигде не
    // действовала. Надгробия и эпохи старше окна — тоже.
    let cutoff = epoch.saturating_sub(crate::kt::HISTORY_EPOCHS);

    sqlx::query(
        "DELETE FROM kt_leaves a WHERE EXISTS (
             SELECT 1 FROM kt_leaves b
             WHERE b.idx = a.idx AND b.epoch_from > a.epoch_from AND b.epoch_from <= $1)",
    )
    .bind(cutoff)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM kt_leaves WHERE identity_key IS NULL AND epoch_from <= $1")
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM kt_epochs WHERE epoch < $1")
        .bind(cutoff)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok(Some(KtEpoch { epoch, root, head }))
}

/// Эпохи начиная с `from` (включительно), не больше `limit`.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn kt_epochs_from(
    pool: &PgPool,
    from: i64,
    limit: i64,
) -> Result<Vec<KtEpoch>, RepoError> {
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT epoch, root, head FROM kt_epochs WHERE epoch >= $1 ORDER BY epoch LIMIT $2",
    )
    .bind(from)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(epoch, root, head)| {
            Some(KtEpoch {
                epoch,
                root: to32(&root)?,
                head: to32(&head)?,
            })
        })
        .collect())
}

/// Последняя эпоха.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn kt_latest_epoch(pool: &PgPool) -> Result<Option<KtEpoch>, RepoError> {
    kt_epochs_before(pool, i64::MAX).await
}

/// Последняя эпоха не позже `epoch`.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn kt_epochs_before(pool: &PgPool, epoch: i64) -> Result<Option<KtEpoch>, RepoError> {
    let row: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT epoch, root, head FROM kt_epochs WHERE epoch <= $1 ORDER BY epoch DESC LIMIT 1",
    )
    .bind(epoch)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(epoch, root, head)| {
        Some(KtEpoch {
            epoch,
            root: to32(&root)?,
            head: to32(&head)?,
        })
    }))
}

/// С какой эпохи действует состояние журнала на эпоху `epoch`:
/// последняя эпоха изменения не позже неё. Эпохи с одинаковым
/// значением — одно и то же дерево (ключ кеша).
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn kt_state_epoch(pool: &PgPool, epoch: i64) -> Result<Option<i64>, RepoError> {
    Ok(
        sqlx::query_scalar("SELECT max(epoch_from) FROM kt_leaves WHERE epoch_from <= $1")
            .bind(epoch)
            .fetch_one(pool)
            .await?,
    )
}

/// Листы журнала, действующие в эпоху `epoch`.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn kt_leaves_at(pool: &PgPool, epoch: i64) -> Result<Vec<KtLeaf>, RepoError> {
    let rows: Vec<KtLeafRow> = sqlx::query_as(
        "SELECT DISTINCT ON (idx) idx, identity_key, pq_hash, version
         FROM kt_leaves WHERE epoch_from <= $1 ORDER BY idx, epoch_from DESC",
    )
    .bind(epoch)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(idx, identity_key, pq_hash, version)| {
            Some(KtLeaf {
                idx: to32(&idx)?,
                identity_key: to32(identity_key.as_deref()?)?,
                pq_hash: to32(pq_hash.as_deref()?)?,
                version: u64::try_from(version).ok()?,
            })
        })
        .collect())
}

/// Лист индекса, действующий в эпоху `epoch`.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn kt_leaf_at(
    pool: &PgPool,
    idx: &[u8; 32],
    epoch: i64,
) -> Result<Option<KtLeaf>, RepoError> {
    let row: Option<KtLeafRow> = sqlx::query_as(
        "SELECT idx, identity_key, pq_hash, version FROM kt_leaves
         WHERE idx = $1 AND epoch_from <= $2 ORDER BY epoch_from DESC LIMIT 1",
    )
    .bind(idx.as_slice())
    .bind(epoch)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(idx, identity_key, pq_hash, version)| {
        Some(KtLeaf {
            idx: to32(&idx)?,
            identity_key: to32(identity_key.as_deref()?)?,
            pq_hash: to32(pq_hash.as_deref()?)?,
            version: u64::try_from(version).ok()?,
        })
    }))
}
