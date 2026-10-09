// SPDX-License-Identifier: AGPL-3.0-only

//! Премиум и каналы (миграции 0018 и 0019).
//!
//! # 🔐 Что сервер знает о канале
//!
//! Владельца, число записей, их размер и час публикации. Название,
//! описание и текст записей — шифротекст: ключ канала живёт в
//! ссылке-приглашении. У **публичного** канала (с `@именем`) автор сам
//! отдаёт серверу эту ссылку — такой канал сервер прочитать может.
//!
//! Подписчик — аккаунт: один аккаунт — один подписчик. Сервер знает,
//! какие аккаунты подписаны на канал и до какой записи каждый дочитал.
//! Читать канал по ссылке можно и без подписки — этого сервер не видит.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repo::RepoError;

/// Предел шифротекста записи.
pub const MAX_POST_BYTES: usize = 65_536;

/// Предел шифротекста описания канала.
///
/// Описание несёт название, текст, аватар и список администраторов;
/// самое большое дополняется до бакета 8 КБ, и с подписью и тегом
/// в прежние 8 КБ уже не помещалось.
pub const MAX_META_BYTES: usize = 16_384;

/// Сколько администраторов может быть у канала одновременно.
pub const MAX_ADMINS_PER_CHANNEL: i64 = 16;

/// Предел одного медиаблоба канала — 32 МБ.
pub const MAX_MEDIA_BYTES: usize = 32 * 1024 * 1024;

/// Сколько медиаблобов может держать один канал.
pub const MAX_MEDIA_PER_CHANNEL: i64 = 5_000;

/// Сколько байт медиа может держать один канал — 4 ГБ.
///
/// Без этого предела один аккаунт с премиумом занял бы диск узла:
/// пять тысяч блобов по 32 МБ — это 160 ГБ на канал.
pub const MAX_MEDIA_TOTAL_BYTES: i64 = 4 * 1024 * 1024 * 1024;

/// Сколько записей может держать один канал.
pub const MAX_POSTS_PER_CHANNEL: i64 = 100_000;

/// Скольким самым свежим записям засчитывается просмотр одной отметкой
/// «дочитал» (см. [`mark_seen`]).
pub const MAX_VIEWS_PER_MARK: i64 = 200;

/// Сколько каналов может держать один аккаунт.
pub const MAX_CHANNELS_PER_ACCOUNT: i64 = 10;

/// Сколько записей отдаётся за один запрос.
pub const MAX_POSTS_PER_PAGE: i64 = 100;

/// Сколько каналов отдаёт поиск.
pub const MAX_SEARCH_RESULTS: i64 = 20;

/// Предел ссылки-приглашения публичного канала.
pub const MAX_LINK_LEN: usize = 512;

/// Реакции, которые принимает сервер. Тот же список — в схеме
/// (`channel_reactions.emoji`) и в приложении.
pub const REACTIONS: [&str; 8] = ["👍", "❤️", "🔥", "😂", "😮", "😢", "👏", "🎉"];

/// Канал в том виде, в каком его получает читатель.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Идентификатор.
    pub channel_id: Uuid,
    /// Публичный ключ подписи записей.
    pub verify_key: Vec<u8>,
    /// Зашифрованное описание.
    pub meta: Vec<u8>,
    /// Номер последней записи.
    pub last_seq: i64,
    /// Номер последнего изменения канала.
    pub last_rev: i64,
    /// Публичное имя, если канал публичный.
    pub handle: Option<String>,
    /// Ссылка-приглашение публичного канала.
    pub public_link: Option<String>,
    /// Число подписчиков.
    pub subscribers: i64,
    /// Закрытый ли канал: вход по одобренной заявке, записи — только
    /// участникам.
    pub closed: bool,
    /// Номер действующего ключа чтения: растёт с каждой сменой ключа.
    pub key_epoch: i32,
}

/// Запись канала.
#[derive(Debug, Clone)]
pub struct Post {
    /// Порядковый номер в канале, с единицы.
    pub seq: i64,
    /// Номер изменения, которым запись создана, исправлена или удалена.
    pub rev: i64,
    /// Шифротекст записи либо подписанная отметка об удалении.
    pub body: Vec<u8>,
    /// Удалена ли запись автором.
    pub deleted: bool,
    /// Час публикации, миллисекунды эпохи.
    pub posted_at_millis: i64,
    /// Сколько подписчиков дочитали до этой записи.
    pub views: i64,
    /// Реакции в виде `эмодзи:число,…`; пусто, если их нет.
    pub reactions: String,
}

type PostRow = (i64, i64, Vec<u8>, bool, i64, i64, Option<String>);

/// Столбцы записи вместе со счётчиками.
///
/// 🔐 Счётчики — готовые числа, а не подсчёт строк: чтение канала
/// анонимно, и его цена не должна расти с числом подписчиков.
const POST_COLUMNS: &str = "p.seq, p.rev, p.body, p.deleted,
        (extract(epoch FROM p.posted_at) * 1000)::bigint,
        p.views,
        (SELECT string_agg(r.emoji || ':' || r.n, ',' ORDER BY r.n DESC, r.emoji COLLATE \"C\")
           FROM channel_reaction_counts r
          WHERE r.channel_id = p.channel_id AND r.seq = p.seq AND r.n > 0)";

fn post_from_row(row: PostRow) -> Post {
    let (seq, rev, body, deleted, posted_at_millis, views, reactions) = row;

    Post {
        seq,
        rev,
        body,
        deleted,
        posted_at_millis,
        views,
        reactions: reactions.unwrap_or_default(),
    }
}

type ChannelRow = (
    Uuid,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<String>,
    Option<String>,
    i64,
    bool,
    i32,
);

const CHANNEL_COLUMNS: &str = "c.channel_id, c.verify_key, c.meta, c.last_seq, c.last_rev,
        c.handle, c.public_link, c.subscribers, c.closed, c.key_epoch";

fn channel_from_row(row: ChannelRow) -> Channel {
    let (
        channel_id,
        verify_key,
        meta,
        last_seq,
        last_rev,
        handle,
        public_link,
        subscribers,
        closed,
        key_epoch,
    ) = row;

    Channel {
        channel_id,
        verify_key,
        meta,
        last_seq,
        last_rev,
        handle,
        public_link,
        subscribers,
        closed,
        key_epoch,
    }
}

/// Аккаунт устройства и его премиум.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — устройства нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn account_status(pool: &PgPool, device_id: Uuid) -> Result<(Uuid, bool), RepoError> {
    Ok(sqlx::query_as(
        "SELECT a.account_id, a.premium
           FROM accounts a JOIN devices d ON d.account_id = a.account_id
          WHERE d.device_id = $1",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await?)
}

/// Выдаёт или снимает премиум по точному имени.
///
/// Возвращает `false`, если аккаунта нет.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn set_premium(pool: &PgPool, username: &str, premium: bool) -> Result<bool, RepoError> {
    let changed = sqlx::query("UPDATE accounts SET premium = $2 WHERE username = $1")
        .bind(username)
        .bind(premium)
        .execute(pool)
        .await?
        .rows_affected();

    Ok(changed > 0)
}

/// Выдаёт или снимает премиум по идентификатору аккаунта.
///
/// Возвращает `false`, если аккаунта нет.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn set_premium_by_id(
    pool: &PgPool,
    account_id: Uuid,
    premium: bool,
) -> Result<bool, RepoError> {
    let changed = sqlx::query("UPDATE accounts SET premium = $2 WHERE account_id = $1")
        .bind(account_id)
        .bind(premium)
        .execute(pool)
        .await?
        .rows_affected();

    Ok(changed > 0)
}

/// Создаёт канал. Право (премиум) проверяет вызывающий — здесь только
/// предел числа каналов.
///
/// # Errors
///
/// * [`RepoError::QuotaExceeded`] — у аккаунта уже предел каналов.
/// * [`RepoError::Conflict`] — идентификатор занят.
/// * [`RepoError::Database`] — сбой базы.
pub async fn create_channel(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    verify_key: &[u8],
    meta: &[u8],
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки аккаунта: два одновременных создания не
    // перешагнут предел.
    sqlx::query("SELECT 1 FROM accounts WHERE account_id = $1 FOR UPDATE")
        .bind(owner_account)
        .fetch_one(&mut *tx)
        .await?;

    let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM channels WHERE owner_account = $1")
        .bind(owner_account)
        .fetch_one(&mut *tx)
        .await?;

    if owned >= MAX_CHANNELS_PER_ACCOUNT {
        return Err(RepoError::QuotaExceeded);
    }

    let inserted = sqlx::query(
        "INSERT INTO channels (channel_id, owner_account, verify_key, meta)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (channel_id) DO NOTHING",
    )
    .bind(channel_id)
    .bind(owner_account)
    .bind(verify_key)
    .bind(meta)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if inserted == 0 {
        return Err(RepoError::Conflict);
    }

    tx.commit().await?;

    Ok(())
}

/// Заменяет зашифрованное описание канала.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой (не различается).
/// * [`RepoError::Database`] — сбой базы.
pub async fn update_meta(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    meta: &[u8],
) -> Result<(), RepoError> {
    let changed =
        sqlx::query("UPDATE channels SET meta = $3 WHERE channel_id = $1 AND owner_account = $2")
            .bind(channel_id)
            .bind(owner_account)
            .bind(meta)
            .execute(pool)
            .await?
            .rows_affected();

    if changed == 0 {
        return Err(RepoError::NotFound);
    }

    Ok(())
}

/// Делает канал публичным (`handle` и ссылка) или снова закрытым (`None`).
///
/// 🔐 Вместе с именем сервер получает ссылку-приглашение, а в ней ключ
/// чтения: публичный канал сервер прочитать может. Снятие имени ключ
/// у сервера не «забирает» — он его уже видел.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::UsernameTaken`] — имя занято другим каналом.
/// * [`RepoError::Database`] — сбой базы.
pub async fn set_handle(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    public: Option<(&str, &str)>,
) -> Result<(), RepoError> {
    let (handle, link) = public.unzip();

    // Занятое имя — ноль обновлённых строк, а не ошибка уникальности:
    // по той же причине, что и у имён аккаунтов (журнал Postgres).
    let changed = sqlx::query(
        "UPDATE channels SET handle = $3, public_link = $4
          WHERE channel_id = $1 AND owner_account = $2
            AND ($3::text IS NULL OR NOT EXISTS (
                    SELECT 1 FROM channels other
                     WHERE other.handle = $3 AND other.channel_id <> $1))",
    )
    .bind(channel_id)
    .bind(owner_account)
    .bind(handle)
    .bind(link)
    .execute(pool)
    .await?
    .rows_affected();

    if changed > 0 {
        return Ok(());
    }

    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channels WHERE channel_id = $1 AND owner_account = $2)",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_one(pool)
    .await?;

    Err(if owned {
        RepoError::UsernameTaken
    } else {
        RepoError::NotFound
    })
}

/// Удаляет канал вместе с записями, медиа, подписчиками и реакциями.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::Database`] — сбой базы.
pub async fn delete_channel(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
) -> Result<(), RepoError> {
    let removed = sqlx::query("DELETE FROM channels WHERE channel_id = $1 AND owner_account = $2")
        .bind(channel_id)
        .bind(owner_account)
        .execute(pool)
        .await?
        .rows_affected();

    if removed == 0 {
        return Err(RepoError::NotFound);
    }

    Ok(())
}

/// Публикует запись; возвращает её номер и номер изменения.
///
/// Номера выдаёт сервер: `UPDATE … RETURNING` берёт блокировку строки
/// канала, и две одновременные записи получают разные номера.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет либо аккаунт в него не пишет.
/// * [`RepoError::Conflict`] — следующий номер записи не тот, которого
///   ждал автор: в канал только что написал кто-то ещё.
/// * [`RepoError::QuotaExceeded`] — у канала предел числа записей.
/// * [`RepoError::Database`] — сбой базы.
pub async fn publish_post(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    body: &[u8],
    expected_seq: Option<i64>,
) -> Result<(i64, i64), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let numbers: Option<(i64, i64)> = sqlx::query_as(
        "UPDATE channels SET last_seq = last_seq + 1, last_rev = last_rev + 1
          WHERE channel_id = $1 AND (owner_account = $2 OR EXISTS (SELECT 1 FROM channel_admins a WHERE a.channel_id = channels.channel_id AND a.account_id = $2))
      RETURNING last_seq, last_rev",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((seq, rev)) = numbers else {
        return Err(RepoError::NotFound);
    };

    // 🔐 Номер записи автор кладёт внутрь шифротекста, и читатели
    // сверяют его с этим. Когда в канал пишут несколько человек, двое
    // могут назвать один и тот же следующий номер: второму запись не
    // сохраняется вовсе — иначе в ленте осталась бы запись, которую
    // читатели отвергают.
    if expected_seq.is_some_and(|expected| expected != seq) {
        tx.rollback().await?;

        return Err(RepoError::Conflict);
    }

    if seq > MAX_POSTS_PER_CHANNEL {
        // Откат: номер на несостоявшуюся запись не тратится.
        tx.rollback().await?;

        return Err(RepoError::QuotaExceeded);
    }

    sqlx::query("INSERT INTO channel_posts (channel_id, seq, rev, body) VALUES ($1, $2, $3, $4)")
        .bind(channel_id)
        .bind(seq)
        .bind(rev)
        .bind(body)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok((seq, rev))
}

/// Заменяет запись: правка (`deleted = false`) или удаление
/// (`deleted = true`, в `body` — подписанная отметка об удалении).
/// Возвращает новый номер изменения канала.
///
/// Удалённую запись исправить нельзя: удаление окончательно.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала или записи нет, канал чужой либо
///   запись уже удалена.
/// * [`RepoError::Database`] — сбой базы.
pub async fn replace_post(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    seq: i64,
    body: &[u8],
    deleted: bool,
) -> Result<i64, RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let rev: Option<i64> = sqlx::query_scalar(
        "UPDATE channels SET last_rev = last_rev + 1
          WHERE channel_id = $1 AND (owner_account = $2 OR EXISTS (SELECT 1 FROM channel_admins a WHERE a.channel_id = channels.channel_id AND a.account_id = $2))
      RETURNING last_rev",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(rev) = rev else {
        return Err(RepoError::NotFound);
    };

    let changed = sqlx::query(
        "UPDATE channel_posts SET body = $3, deleted = $4, rev = $5
          WHERE channel_id = $1 AND seq = $2 AND NOT deleted",
    )
    .bind(channel_id)
    .bind(seq)
    .bind(body)
    .bind(deleted)
    .bind(rev)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if changed == 0 {
        // Откат: номер изменения не тратится на несостоявшуюся правку.
        tx.rollback().await?;

        return Err(RepoError::NotFound);
    }

    // Реакции на удалённую запись не нужны никому.
    if deleted {
        for table in ["channel_reactions", "channel_reaction_counts"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE channel_id = $1 AND seq = $2"
            ))
            .bind(channel_id)
            .bind(seq)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;

    Ok(rev)
}

/// Канал по идентификатору — для читателя.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn find_channel(pool: &PgPool, channel_id: Uuid) -> Result<Channel, RepoError> {
    let row: ChannelRow = sqlx::query_as(&format!(
        "SELECT {CHANNEL_COLUMNS} FROM channels c WHERE c.channel_id = $1"
    ))
    .bind(channel_id)
    .fetch_one(pool)
    .await?;

    Ok(channel_from_row(row))
}

/// Публичный канал по точному имени.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — такого имени нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn find_by_handle(pool: &PgPool, handle: &str) -> Result<Channel, RepoError> {
    let row: ChannelRow = sqlx::query_as(&format!(
        "SELECT {CHANNEL_COLUMNS} FROM channels c WHERE c.handle = $1"
    ))
    .bind(handle)
    .fetch_one(pool)
    .await?;

    Ok(channel_from_row(row))
}

/// Публичные каналы, чьё имя начинается с `prefix`: сначала те, у кого
/// больше подписчиков.
///
/// Только по имени: названия сервер не знает — они зашифрованы.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn search_public(pool: &PgPool, prefix: &str) -> Result<Vec<Channel>, RepoError> {
    // `prefix` — уже каноничное имя (буквы, цифры, `_`); `_` в LIKE —
    // подстановочный знак, поэтому экранируется.
    let pattern = format!("{}%", prefix.replace('_', "\\_"));

    let rows: Vec<ChannelRow> = sqlx::query_as(&format!(
        "SELECT {CHANNEL_COLUMNS} FROM channels c
          WHERE c.handle LIKE $1
          ORDER BY 8 DESC, c.handle
          LIMIT $2"
    ))
    .bind(pattern)
    .bind(MAX_SEARCH_RESULTS)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(channel_from_row).collect())
}

/// Изменения канала после ревизии `after_rev`, по возрастанию ревизии:
/// новые, исправленные и удалённые записи.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn changes_since(
    pool: &PgPool,
    channel_id: Uuid,
    after_rev: i64,
    limit: i64,
) -> Result<Vec<Post>, RepoError> {
    let rows: Vec<PostRow> = sqlx::query_as(&format!(
        "SELECT {POST_COLUMNS} FROM channel_posts p
          WHERE p.channel_id = $1 AND p.rev > $2
          ORDER BY p.rev
          LIMIT $3"
    ))
    .bind(channel_id)
    .bind(after_rev)
    .bind(limit.clamp(1, MAX_POSTS_PER_PAGE))
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(post_from_row).collect())
}

/// Страница ленты: записи с номером меньше `before_seq` (или самые
/// свежие, если он `None`), от новых к старым. Удалённые не отдаются.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn page_before(
    pool: &PgPool,
    channel_id: Uuid,
    before_seq: Option<i64>,
    limit: i64,
) -> Result<Vec<Post>, RepoError> {
    let rows: Vec<PostRow> = sqlx::query_as(&format!(
        "SELECT {POST_COLUMNS} FROM channel_posts p
          WHERE p.channel_id = $1 AND NOT p.deleted
            AND ($2::bigint IS NULL OR p.seq < $2)
          ORDER BY p.seq DESC
          LIMIT $3"
    ))
    .bind(channel_id)
    .bind(before_seq)
    .bind(limit.clamp(1, MAX_POSTS_PER_PAGE))
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(post_from_row).collect())
}

/// Кладёт медиаблоб канала.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::QuotaExceeded`] — у канала предел числа блобов либо
///   их общего объёма.
/// * [`RepoError::AttachmentTooLarge`] — блоб больше предела.
/// * [`RepoError::Database`] — сбой базы.
pub async fn store_media(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    blob: &[u8],
) -> Result<Uuid, RepoError> {
    if blob.is_empty() || blob.len() > MAX_MEDIA_BYTES {
        return Err(RepoError::AttachmentTooLarge);
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки канала: счёт и вставка видят одно состояние.
    let owned: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM channels WHERE channel_id = $1 AND (owner_account = $2 OR EXISTS (SELECT 1 FROM channel_admins a WHERE a.channel_id = channels.channel_id AND a.account_id = $2)) FOR UPDATE",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_optional(&mut *tx)
    .await?;

    if owned.is_none() {
        return Err(RepoError::NotFound);
    }

    // Размер лежит отдельным столбцом: сумма не читает сами блобы.
    let (stored, bytes): (i64, i64) = sqlx::query_as(
        "SELECT count(*), COALESCE(sum(size), 0)::bigint
           FROM channel_media WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_one(&mut *tx)
    .await?;

    let size = i32::try_from(blob.len()).map_err(|_| RepoError::AttachmentTooLarge)?;

    if stored >= MAX_MEDIA_PER_CHANNEL
        || bytes.saturating_add(i64::from(size)) > MAX_MEDIA_TOTAL_BYTES
    {
        return Err(RepoError::QuotaExceeded);
    }

    let media_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO channel_media (channel_id, media_id, blob, size) VALUES ($1, $2, $3, $4)",
    )
    .bind(channel_id)
    .bind(media_id)
    .bind(blob)
    .bind(size)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(media_id)
}

/// Отдаёт медиаблоб канала.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — блоба нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn fetch_media(
    pool: &PgPool,
    channel_id: Uuid,
    media_id: Uuid,
) -> Result<Vec<u8>, RepoError> {
    Ok(
        sqlx::query_scalar(
            "SELECT blob FROM channel_media WHERE channel_id = $1 AND media_id = $2",
        )
        .bind(channel_id)
        .bind(media_id)
        .fetch_one(pool)
        .await?,
    )
}

/// Удаляет медиаблоб своего канала — вместе с записью, к которой он
/// был приложен. Отсутствующий блоб — не ошибка.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::Database`] — сбой базы.
pub async fn delete_media(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    media_id: Uuid,
) -> Result<(), RepoError> {
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channels WHERE channel_id = $1 AND (owner_account = $2 OR EXISTS (SELECT 1 FROM channel_admins a WHERE a.channel_id = channels.channel_id AND a.account_id = $2)))",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_one(pool)
    .await?;

    if !owned {
        return Err(RepoError::NotFound);
    }

    sqlx::query("DELETE FROM channel_media WHERE channel_id = $1 AND media_id = $2")
        .bind(channel_id)
        .bind(media_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Подписывает аккаунт на канал. Повтор ничего не меняет.
///
/// Счётчик подписчиков канала растёт здесь же: считать строки при
/// каждом чтении канала значило бы дать анонимному запросу работу,
/// растущую с числом подписчиков.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет.
/// * [`RepoError::Conflict`] — канал закрытый: в него входят по заявке.
/// * [`RepoError::Database`] — сбой базы.
pub async fn subscribe(pool: &PgPool, channel_id: Uuid, account_id: Uuid) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки канала: вставка и счётчик меняются вместе.
    let closed: Option<bool> =
        sqlx::query_scalar("SELECT closed FROM channels WHERE channel_id = $1 FOR UPDATE")
            .bind(channel_id)
            .fetch_optional(&mut *tx)
            .await?;

    let Some(closed) = closed else {
        return Err(RepoError::NotFound);
    };

    // 🔐 В закрытый канал подписчиком делает только одобренная заявка
    // (`answer_request`). Уже подписанному повтор ничего не меняет.
    if closed {
        let subscribed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM channel_subscribers
                             WHERE channel_id = $1 AND account_id = $2)",
        )
        .bind(channel_id)
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;

        return if subscribed {
            Ok(())
        } else {
            Err(RepoError::Conflict)
        };
    }

    let added = sqlx::query(
        "INSERT INTO channel_subscribers (channel_id, account_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(channel_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if added > 0 {
        sqlx::query("UPDATE channels SET subscribers = subscribers + 1 WHERE channel_id = $1")
            .bind(channel_id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    Ok(())
}

/// Отписывает аккаунт от канала вместе с его реакциями.
///
/// Просмотры остаются: запись, которую человек видел, он видел.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn unsubscribe(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Тот же порядок блокировок, что у подписки: сначала канал.
    sqlx::query("SELECT 1 FROM channels WHERE channel_id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *tx)
        .await?;

    // Счётчики подписчиков и реакций уменьшают триггеры базы
    // (миграция 0019): они срабатывают и здесь, и при каскадном
    // удалении вместе с аккаунтом.
    sqlx::query("DELETE FROM channel_subscribers WHERE channel_id = $1 AND account_id = $2")
        .bind(channel_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(())
}

/// Отмечает, что подписчик дочитал до записи `seq`. Назад отметка не
/// двигается; номер больше последней записи канала обрезается до неё.
///
/// Просмотр засчитывается записям, которые отметка прошла, — но не
/// больше чем [`MAX_VIEWS_PER_MARK`] самым свежим: читатель, догнавший
/// канал за год, не переписывает год записей одним запросом.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — такого подписчика у канала нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn mark_seen(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
    seq: i64,
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки подписчика: два одновременных запроса одного
    // аккаунта не засчитают просмотр дважды.
    let known: Option<(i64, i64)> = sqlx::query_as(
        "SELECT s.seen_seq, c.last_seq
           FROM channel_subscribers s
           JOIN channels c ON c.channel_id = s.channel_id
          WHERE s.channel_id = $1 AND s.account_id = $2
            FOR UPDATE OF s",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((seen, last_seq)) = known else {
        return Err(RepoError::NotFound);
    };

    let reached = seq.clamp(0, last_seq);

    if reached > seen {
        sqlx::query(
            "UPDATE channel_subscribers SET seen_seq = $3
              WHERE channel_id = $1 AND account_id = $2",
        )
        .bind(channel_id)
        .bind(account_id)
        .bind(reached)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE channel_posts SET views = views + 1
              WHERE channel_id = $1 AND seq > $2 AND seq <= $3 AND NOT deleted",
        )
        .bind(channel_id)
        .bind(seen.max(reached.saturating_sub(MAX_VIEWS_PER_MARK)))
        .bind(reached)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(())
}

/// Ставит, меняет или снимает (`None`) реакцию подписчика на запись.
///
/// Счётчики реакций записи меняются в той же транзакции.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — нет такого подписчика либо записи (или
///   она удалена).
/// * [`RepoError::Database`] — сбой базы.
pub async fn react(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
    seq: i64,
    emoji: Option<&str>,
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки подписчика: реакции одного аккаунта идут по
    // очереди, и счётчик не расходится с таблицей реакций.
    let subscribed: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM channel_subscribers
          WHERE channel_id = $1 AND account_id = $2
            FOR UPDATE",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channel_posts
                         WHERE channel_id = $1 AND seq = $2 AND NOT deleted)",
    )
    .bind(channel_id)
    .bind(seq)
    .fetch_one(&mut *tx)
    .await?;

    if subscribed.is_none() || !live {
        return Err(RepoError::NotFound);
    }

    let previous: Option<String> = sqlx::query_scalar(
        "SELECT emoji FROM channel_reactions
          WHERE channel_id = $1 AND seq = $2 AND account_id = $3",
    )
    .bind(channel_id)
    .bind(seq)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;

    if previous.as_deref() == emoji {
        return Ok(());
    }

    match emoji {
        Some(emoji) => {
            sqlx::query(
                "INSERT INTO channel_reactions (channel_id, seq, account_id, emoji)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (channel_id, seq, account_id) DO UPDATE SET emoji = EXCLUDED.emoji",
            )
            .bind(channel_id)
            .bind(seq)
            .bind(account_id)
            .bind(emoji)
            .execute(&mut *tx)
            .await?;

            // Строка счётчика заводится нулём заранее: дальше обе
            // строки — прежней и новой реакции — меняются одним
            // запросом, в одном порядке у всех.
            sqlx::query(
                "INSERT INTO channel_reaction_counts (channel_id, seq, emoji, n)
                 VALUES ($1, $2, $3, 0)
                 ON CONFLICT DO NOTHING",
            )
            .bind(channel_id)
            .bind(seq)
            .bind(emoji)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query(
                "DELETE FROM channel_reactions
                  WHERE channel_id = $1 AND seq = $2 AND account_id = $3",
            )
            .bind(channel_id)
            .bind(seq)
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        }
    }

    // Снятую реакцию считает триггер базы; здесь — только смена
    // и новая реакция: прежняя строка счётчика убывает, новая растёт.
    if emoji.is_some() {
        sqlx::query(
            "UPDATE channel_reaction_counts
                SET n = CASE WHEN emoji = $4 THEN n + 1 ELSE GREATEST(n - 1, 0) END
              WHERE channel_id = $1 AND seq = $2
                AND (emoji = $3 OR emoji = $4)",
        )
        .bind(channel_id)
        .bind(seq)
        .bind(previous)
        .bind(emoji)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(())
}

/// Даёт аккаунту устройства `device_id` право писать в канал.
///
/// `verify_key` — ключ, которым администратор подписывает записи.
/// Серверу он нужен только как имя строки: снимают администратора по
/// нему. Подписи записей сервер не проверяет — их проверяют читатели
/// по списку из описания канала, подписанного владельцем.
///
/// Повтор для того же аккаунта заменяет ключ.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет, он чужой либо устройства нет.
/// * [`RepoError::Conflict`] — устройство принадлежит самому владельцу.
/// * [`RepoError::QuotaExceeded`] — у канала предел администраторов.
/// * [`RepoError::Database`] — сбой базы.
pub async fn add_admin(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    device_id: Uuid,
    verify_key: &[u8; 32],
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки канала: счёт и вставка видят одно состояние.
    let owned: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM channels WHERE channel_id = $1 AND owner_account = $2 FOR UPDATE",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_optional(&mut *tx)
    .await?;

    let admin_account: Option<Uuid> =
        sqlx::query_scalar("SELECT account_id FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?;

    let (Some(_), Some(admin_account)) = (owned, admin_account) else {
        return Err(RepoError::NotFound);
    };

    if admin_account == owner_account {
        return Err(RepoError::Conflict);
    }

    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM channel_admins WHERE channel_id = $1 AND account_id <> $2",
    )
    .bind(channel_id)
    .bind(admin_account)
    .fetch_one(&mut *tx)
    .await?;

    if others >= MAX_ADMINS_PER_CHANNEL {
        return Err(RepoError::QuotaExceeded);
    }

    // Тот же ключ у другого аккаунта канала — прежняя строка уходит:
    // ключ называет одного администратора.
    sqlx::query("DELETE FROM channel_admins WHERE channel_id = $1 AND verify_key = $2")
        .bind(channel_id)
        .bind(verify_key.as_slice())
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO channel_admins (channel_id, account_id, verify_key) VALUES ($1, $2, $3)
         ON CONFLICT (channel_id, account_id) DO UPDATE SET verify_key = EXCLUDED.verify_key",
    )
    .bind(channel_id)
    .bind(admin_account)
    .bind(verify_key.as_slice())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

/// Отнимает право писать у администратора с ключом `verify_key`.
/// Отсутствующий администратор — не ошибка: цель достигнута.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::Database`] — сбой базы.
pub async fn remove_admin(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    verify_key: &[u8; 32],
) -> Result<(), RepoError> {
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channels WHERE channel_id = $1 AND owner_account = $2)",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_one(pool)
    .await?;

    if !owned {
        return Err(RepoError::NotFound);
    }

    sqlx::query("DELETE FROM channel_admins WHERE channel_id = $1 AND verify_key = $2")
        .bind(channel_id)
        .bind(verify_key.as_slice())
        .execute(pool)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
//  Закрытые каналы: приглашения, заявки, участники (миграция 0021)
// ---------------------------------------------------------------------------

/// Сколько действующих ссылок-приглашений может быть у канала.
pub const MAX_INVITES_PER_CHANNEL: i64 = 20;

/// Сколько заявок может ждать ответа в одном канале.
pub const MAX_PENDING_REQUESTS_PER_CHANNEL: i64 = 1_000;

/// Сколько заявок одного аккаунта может ждать ответа во всех каналах.
pub const MAX_PENDING_REQUESTS_PER_ACCOUNT: i64 = 50;

/// Предел заявки и ответа на неё, в байтах.
pub const MAX_JOIN_BLOB_BYTES: usize = 512;

/// Сколько заявок или подписчиков отдаётся за один запрос.
pub const MAX_MEMBERS_PER_PAGE: i64 = 100;

/// Заявка на вход в закрытый канал.
#[derive(Debug, Clone)]
pub struct JoinRequest {
    /// Аккаунт заявителя.
    pub account_id: Uuid,
    /// Его имя — чтобы владельцу было кого одобрять.
    pub username: String,
    /// Открытый ключ заявителя с подписью; сервер его не разбирает.
    pub request: Vec<u8>,
}

/// Подписчик канала глазами владельца и администраторов.
#[derive(Debug, Clone)]
pub struct Member {
    /// Аккаунт.
    pub account_id: Uuid,
    /// Имя.
    pub username: String,
}

/// Что с заявкой аккаунта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinStatus {
    /// Заявки нет: не подавалась, отклонена либо человек удалён.
    None,
    /// Ждёт ответа.
    Pending,
    /// Одобрена: ответ с зашифрованным ключом чтения.
    Approved(Vec<u8>),
}

/// Пишет ли аккаунт в канал: владелец либо администратор.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn writes(pool: &PgPool, channel_id: Uuid, account_id: Uuid) -> Result<bool, RepoError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM channels c
              WHERE c.channel_id = $1
                AND (c.owner_account = $2
                     OR EXISTS (SELECT 1 FROM channel_admins a
                                 WHERE a.channel_id = c.channel_id AND a.account_id = $2)))",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_one(pool)
    .await?)
}

/// Участник ли аккаунт канала: владелец, администратор либо подписчик.
/// Участникам отдаются записи закрытого канала.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn is_member(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
) -> Result<bool, RepoError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM channels c
              WHERE c.channel_id = $1
                AND (c.owner_account = $2
                     OR EXISTS (SELECT 1 FROM channel_admins a
                                 WHERE a.channel_id = c.channel_id AND a.account_id = $2)
                     OR EXISTS (SELECT 1 FROM channel_subscribers s
                                 WHERE s.channel_id = c.channel_id AND s.account_id = $2)))",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_one(pool)
    .await?)
}

/// Делает свой канал закрытым либо снова открытым.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет или он чужой.
/// * [`RepoError::Conflict`] — у канала меняли ключ (такой остаётся
///   закрытым) либо у канала есть публичное имя: по имени
///   раздаётся ссылка с ключом, и закрытым такой канал быть не может.
/// * [`RepoError::Database`] — сбой базы.
pub async fn set_closed(
    pool: &PgPool,
    owner_account: Uuid,
    channel_id: Uuid,
    closed: bool,
) -> Result<(), RepoError> {
    let changed = sqlx::query(
        "UPDATE channels SET closed = $3
          WHERE channel_id = $1 AND owner_account = $2
            AND (NOT $3 OR handle IS NULL) AND ($3 OR key_epoch = 0)",
    )
    .bind(channel_id)
    .bind(owner_account)
    .bind(closed)
    .execute(pool)
    .await?
    .rows_affected();

    if changed > 0 {
        return Ok(());
    }

    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channels WHERE channel_id = $1 AND owner_account = $2)",
    )
    .bind(channel_id)
    .bind(owner_account)
    .fetch_one(pool)
    .await?;

    Err(if owned {
        RepoError::Conflict
    } else {
        RepoError::NotFound
    })
}

/// Заводит ссылку-приглашение: сервер запоминает хеш её метки.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::QuotaExceeded`] — у канала предел действующих ссылок.
/// * [`RepoError::Database`] — сбой базы.
pub async fn add_invite(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    invite_hash: &[u8; 32],
) -> Result<(), RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM channel_invites WHERE channel_id = $1 AND NOT revoked",
    )
    .bind(channel_id)
    .fetch_one(pool)
    .await?;

    if live >= MAX_INVITES_PER_CHANNEL {
        return Err(RepoError::QuotaExceeded);
    }

    sqlx::query(
        "INSERT INTO channel_invites (channel_id, invite_hash) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(channel_id)
    .bind(invite_hash.as_slice())
    .execute(pool)
    .await?;

    Ok(())
}

/// Отзывает ссылку-приглашение: новые заявки по ней не принимаются.
/// Уже поданные заявки остаются.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn revoke_invite(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    invite_hash: &[u8; 32],
) -> Result<(), RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    sqlx::query(
        "UPDATE channel_invites SET revoked = true WHERE channel_id = $1 AND invite_hash = $2",
    )
    .bind(channel_id)
    .bind(invite_hash.as_slice())
    .execute(pool)
    .await?;

    Ok(())
}

/// Подаёт заявку на вход по ссылке-приглашению. Повторная заявка
/// заменяет прежнюю: ключ в ней мог смениться.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет, он не закрытый либо ссылка
///   не действует.
/// * [`RepoError::Conflict`] — человек удалён из этого канала.
/// * [`RepoError::QuotaExceeded`] — слишком много заявок ждёт ответа.
/// * [`RepoError::Database`] — сбой базы.
pub async fn request_join(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
    invite_hash: &[u8; 32],
    request: &[u8],
) -> Result<(), RepoError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Блокировка строки канала: счёт заявок и вставка видят одно состояние.
    let invited: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM channels c
          WHERE c.channel_id = $1 AND c.closed
            AND EXISTS (SELECT 1 FROM channel_invites i
                         WHERE i.channel_id = c.channel_id
                           AND i.invite_hash = $2 AND NOT i.revoked)
            FOR UPDATE OF c",
    )
    .bind(channel_id)
    .bind(invite_hash.as_slice())
    .fetch_optional(&mut *tx)
    .await?;

    if invited.is_none() {
        return Err(RepoError::NotFound);
    }

    let banned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channel_bans WHERE channel_id = $1 AND account_id = $2)",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

    if banned {
        return Err(RepoError::Conflict);
    }

    let (in_channel, of_account): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM channel_join_requests
                  WHERE channel_id = $1 AND account_id <> $2),
                (SELECT count(*) FROM channel_join_requests
                  WHERE account_id = $2 AND channel_id <> $1)",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;

    if in_channel >= MAX_PENDING_REQUESTS_PER_CHANNEL
        || of_account >= MAX_PENDING_REQUESTS_PER_ACCOUNT
    {
        return Err(RepoError::QuotaExceeded);
    }

    sqlx::query(
        "INSERT INTO channel_join_requests (channel_id, account_id, request)
         VALUES ($1, $2, $3)
         ON CONFLICT (channel_id, account_id) DO UPDATE SET request = EXCLUDED.request",
    )
    .bind(channel_id)
    .bind(account_id)
    .bind(request)
    .execute(&mut *tx)
    .await?;

    // Прежний ответ — под прежний ключ заявки: он больше не подходит.
    sqlx::query("DELETE FROM channel_grants WHERE channel_id = $1 AND account_id = $2")
        .bind(channel_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(())
}

/// Что с заявкой аккаунта в этот канал.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn join_status(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
) -> Result<JoinStatus, RepoError> {
    let grant: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT grant_blob FROM channel_grants WHERE channel_id = $1 AND account_id = $2",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    if let Some(grant) = grant {
        return Ok(JoinStatus::Approved(grant));
    }

    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM channel_join_requests
                         WHERE channel_id = $1 AND account_id = $2)",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    Ok(if pending {
        JoinStatus::Pending
    } else {
        JoinStatus::None
    })
}

/// Заявки, ждущие ответа, — для владельца и администраторов.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn list_requests(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
) -> Result<Vec<JoinRequest>, RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT r.account_id, a.username, r.request
           FROM channel_join_requests r
           JOIN accounts a ON a.account_id = r.account_id
          WHERE r.channel_id = $1
          ORDER BY r.requested_at, r.account_id
          LIMIT $2",
    )
    .bind(channel_id)
    .bind(MAX_MEMBERS_PER_PAGE)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(account_id, username, request)| JoinRequest {
            account_id,
            username,
            request,
        })
        .collect())
}

/// Отвечает на заявку. С `grant` — одобряет: заявитель становится
/// подписчиком, а `grant` (ключ чтения, зашифрованный под его заявку)
/// ждёт его на сервере. Без `grant` — отклоняет.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет либо заявки нет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn answer_request(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    account_id: Uuid,
    grant: Option<&[u8]>,
) -> Result<(), RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    // Тот же порядок блокировок, что у подписки: сначала канал.
    sqlx::query("SELECT 1 FROM channels WHERE channel_id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *tx)
        .await?;

    let answered: Option<Vec<u8>> = sqlx::query_scalar(
        "DELETE FROM channel_join_requests WHERE channel_id = $1 AND account_id = $2
      RETURNING request",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(request) = answered else {
        return Err(RepoError::NotFound);
    };

    if let Some(grant) = grant {
        sqlx::query(
            "INSERT INTO channel_grants (channel_id, account_id, grant_blob, epoch)
             SELECT $1, $2, $3, key_epoch FROM channels WHERE channel_id = $1
             ON CONFLICT (channel_id, account_id)
             DO UPDATE SET grant_blob = EXCLUDED.grant_blob, epoch = EXCLUDED.epoch",
        )
        .bind(channel_id)
        .bind(account_id)
        .bind(grant)
        .execute(&mut *tx)
        .await?;

        // Ключ из заявки становится ключом доставки участника: под него
        // же придёт ключ следующей эпохи.
        sqlx::query(
            "INSERT INTO channel_member_keys (channel_id, account_id, member_key)
             VALUES ($1, $2, $3)
             ON CONFLICT (channel_id, account_id) DO UPDATE SET member_key = EXCLUDED.member_key",
        )
        .bind(channel_id)
        .bind(account_id)
        .bind(&request)
        .execute(&mut *tx)
        .await?;

        let added = sqlx::query(
            "INSERT INTO channel_subscribers (channel_id, account_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(channel_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if added > 0 {
            sqlx::query("UPDATE channels SET subscribers = subscribers + 1 WHERE channel_id = $1")
                .bind(channel_id)
                .execute(&mut *tx)
                .await?;
        }
    }

    tx.commit().await?;

    Ok(())
}

/// Подписчики канала — для владельца и администраторов; страницами,
/// после аккаунта `after`.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn list_subscribers(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    after: Option<Uuid>,
) -> Result<Vec<Member>, RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT s.account_id, a.username
           FROM channel_subscribers s
           JOIN accounts a ON a.account_id = s.account_id
          WHERE s.channel_id = $1 AND ($2::uuid IS NULL OR s.account_id > $2)
          ORDER BY s.account_id
          LIMIT $3",
    )
    .bind(channel_id)
    .bind(after)
    .bind(MAX_MEMBERS_PER_PAGE)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(account_id, username)| Member {
            account_id,
            username,
        })
        .collect())
}

/// Удалённые из канала — для владельца и администраторов: кому можно
/// вернуть право подать заявку. Не больше страницы, от недавних.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn list_bans(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
) -> Result<Vec<Member>, RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT b.account_id, a.username
           FROM channel_bans b
           JOIN accounts a ON a.account_id = b.account_id
          WHERE b.channel_id = $1
          ORDER BY b.banned_at DESC, b.account_id
          LIMIT $2",
    )
    .bind(channel_id)
    .bind(MAX_MEMBERS_PER_PAGE)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(account_id, username)| Member {
            account_id,
            username,
        })
        .collect())
}

/// Удаляет подписчика из канала: подписка, реакции, ответ на заявку
/// и сама заявка исчезают, а новая заявка от него не принимается.
///
/// ⚠️ Ключ чтения он помнит: сервер перестаёт отдавать ему записи, но
/// сам ключ у канала прежний.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Conflict`] — удаляют владельца либо администратора:
///   администратора сначала снимает владелец.
/// * [`RepoError::Database`] — сбой базы.
pub async fn remove_subscriber(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    account_id: Uuid,
) -> Result<(), RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    // Тот, кто ведёт канал, — не подписчик, которого можно выставить:
    // иначе администратор удалил бы владельца.
    if writes(pool, channel_id, account_id).await? {
        return Err(RepoError::Conflict);
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    sqlx::query("SELECT 1 FROM channels WHERE channel_id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *tx)
        .await?;

    for table in [
        "channel_subscribers",
        "channel_grants",
        "channel_join_requests",
        "channel_member_keys",
    ] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE channel_id = $1 AND account_id = $2"
        ))
        .bind(channel_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "INSERT INTO channel_bans (channel_id, account_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(channel_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

/// Снимает запрет: человек снова может подать заявку.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn unban(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    account_id: Uuid,
) -> Result<(), RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    sqlx::query("DELETE FROM channel_bans WHERE channel_id = $1 AND account_id = $2")
        .bind(channel_id)
        .bind(account_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Сколько ключей доставки и ответов уходит одним запросом.
pub const MAX_MEMBER_KEYS_PER_PAGE: i64 = 500;

/// Предел звена цепочки ключей.
pub const MAX_EPOCH_RECORD_BYTES: usize = 512;

/// Ключ доставки участника: открытый ключ за подписью аккаунта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKey {
    /// Аккаунт участника.
    pub account_id: Uuid,
    /// Ключ доставки — для сервера непрозрачные байты.
    pub member_key: Vec<u8>,
}

/// Запоминает ключ доставки участника закрытого канала.
///
/// Сменившийся ключ делает прежний ответ бесполезным — он удаляется, и
/// участнику выдадут новый.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — канала нет, он открытый либо аккаунт не
///   участник.
/// * [`RepoError::Database`] — сбой базы.
pub async fn set_member_key(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
    member_key: &[u8],
) -> Result<(), RepoError> {
    if !is_member(pool, channel_id, account_id).await? {
        return Err(RepoError::NotFound);
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let closed: Option<bool> =
        sqlx::query_scalar("SELECT closed FROM channels WHERE channel_id = $1 FOR UPDATE")
            .bind(channel_id)
            .fetch_optional(&mut *tx)
            .await?;

    if closed != Some(true) {
        return Err(RepoError::NotFound);
    }

    let known: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT member_key FROM channel_member_keys WHERE channel_id = $1 AND account_id = $2",
    )
    .bind(channel_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;

    if known.as_deref() == Some(member_key) {
        return Ok(());
    }

    sqlx::query(
        "INSERT INTO channel_member_keys (channel_id, account_id, member_key) VALUES ($1, $2, $3)
         ON CONFLICT (channel_id, account_id) DO UPDATE SET member_key = EXCLUDED.member_key",
    )
    .bind(channel_id)
    .bind(account_id)
    .bind(member_key)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM channel_grants WHERE channel_id = $1 AND account_id = $2")
        .bind(channel_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(())
}

/// Ключи доставки участников — для того, кто ведёт канал; страницами
/// после аккаунта `after`. С `missing` — только тех, у кого нет ответа
/// с ключом действующей эпохи.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет.
/// * [`RepoError::Database`] — сбой базы.
pub async fn member_keys(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    missing: bool,
    after: Option<Uuid>,
) -> Result<Vec<MemberKey>, RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    // 🔐 Только действующие участники: ключ ушедшего либо снятого
    // администратора в выдачу не попадает.
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT k.account_id, k.member_key
           FROM channel_member_keys k
           JOIN channels c ON c.channel_id = k.channel_id
          WHERE k.channel_id = $1
            AND ($2::uuid IS NULL OR k.account_id > $2)
            AND (c.owner_account = k.account_id
                 OR EXISTS (SELECT 1 FROM channel_admins a
                             WHERE a.channel_id = k.channel_id AND a.account_id = k.account_id)
                 OR EXISTS (SELECT 1 FROM channel_subscribers s
                             WHERE s.channel_id = k.channel_id AND s.account_id = k.account_id))
            AND (NOT $3 OR NOT EXISTS (SELECT 1 FROM channel_grants g
                                        WHERE g.channel_id = k.channel_id
                                          AND g.account_id = k.account_id
                                          AND g.epoch >= c.key_epoch))
          ORDER BY k.account_id
          LIMIT $4",
    )
    .bind(channel_id)
    .bind(after)
    .bind(missing)
    .bind(MAX_MEMBER_KEYS_PER_PAGE)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(account_id, member_key)| MemberKey {
            account_id,
            member_key,
        })
        .collect())
}

/// Меняет ключ канала (`record` — звено к новой эпохе `epoch`) либо
/// досылает ответы участникам для действующей эпохи (`record` нет).
///
/// Ответ сохраняется только участнику с известным ключом доставки:
/// удалённому между «забрал список» и «прислал ответы» он не достанется.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт в канал не пишет либо канал
///   открытый.
/// * [`RepoError::Conflict`] — эпоха не та: ключ успел сменить кто-то ещё.
/// * [`RepoError::Database`] — сбой базы.
pub async fn rekey(
    pool: &PgPool,
    writer_account: Uuid,
    channel_id: Uuid,
    epoch: i32,
    record: Option<&[u8]>,
    grants: &[(Uuid, Vec<u8>)],
) -> Result<(), RepoError> {
    if !writes(pool, channel_id, writer_account).await? {
        return Err(RepoError::NotFound);
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let state: Option<(bool, i32)> =
        sqlx::query_as("SELECT closed, key_epoch FROM channels WHERE channel_id = $1 FOR UPDATE")
            .bind(channel_id)
            .fetch_optional(&mut *tx)
            .await?;

    let Some((true, current)) = state else {
        return Err(RepoError::NotFound);
    };

    match record {
        Some(record) => {
            if current.checked_add(1) != Some(epoch) {
                return Err(RepoError::Conflict);
            }

            sqlx::query(
                "INSERT INTO channel_epochs (channel_id, epoch, record) VALUES ($1, $2, $3)",
            )
            .bind(channel_id)
            .bind(epoch)
            .bind(record)
            .execute(&mut *tx)
            .await?;

            sqlx::query("UPDATE channels SET key_epoch = $2 WHERE channel_id = $1")
                .bind(channel_id)
                .bind(epoch)
                .execute(&mut *tx)
                .await?;
        }
        None => {
            if current != epoch {
                return Err(RepoError::Conflict);
            }
        }
    }

    for (account_id, grant) in grants {
        sqlx::query(
            "INSERT INTO channel_grants (channel_id, account_id, grant_blob, epoch)
             SELECT $1, $2, $3, $4
              WHERE EXISTS (SELECT 1 FROM channel_member_keys
                             WHERE channel_id = $1 AND account_id = $2)
             ON CONFLICT (channel_id, account_id)
             DO UPDATE SET grant_blob = EXCLUDED.grant_blob, epoch = EXCLUDED.epoch",
        )
        .bind(channel_id)
        .bind(account_id)
        .bind(grant)
        .bind(epoch)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(())
}

/// Звенья цепочки ключей с номером больше `after` — участнику.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — аккаунт не участник.
/// * [`RepoError::Database`] — сбой базы.
pub async fn epochs(
    pool: &PgPool,
    channel_id: Uuid,
    account_id: Uuid,
    after: i32,
) -> Result<Vec<(i32, Vec<u8>)>, RepoError> {
    if !is_member(pool, channel_id, account_id).await? {
        return Err(RepoError::NotFound);
    }

    Ok(sqlx::query_as(
        "SELECT epoch, record FROM channel_epochs
          WHERE channel_id = $1 AND epoch > $2
          ORDER BY epoch",
    )
    .bind(channel_id)
    .bind(after)
    .fetch_all(pool)
    .await?)
}
