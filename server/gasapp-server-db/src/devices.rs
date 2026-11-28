// SPDX-License-Identifier: AGPL-3.0-only

//! Несколько устройств на аккаунте (миграция 0032,
//! `docs/protocol/MULTI-DEVICE.md`).
//!
//! Подпись списка устройств ключом аккаунта проверяют клиенты — им её и
//! проверять: сервер в их модели угроз. Сервер же следит за тем, что ему
//! по силам и что закрывает обход владельца:
//!
//! * список меняет только **основное** устройство (его identity — ключ
//!   аккаунта), по подписанному запросу;
//! * версия только растёт;
//! * в списке — только устройства этого аккаунта и новое из запроса;
//! * устройств не больше [`MAX_DEVICES`].

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repo::RepoError;

/// Сколько устройств может быть у аккаунта.
pub const MAX_DEVICES: usize = 5;

/// Сколько живёт ящик связывания, секунды (QR — 60, плюс запас на ответ).
pub const LINK_TTL_SECS: i64 = 120;

/// Сколько ящиков может быть открыто разом — предел против забивания
/// базы без подписи.
///
/// 🔐 Прежде было 10 000: при двухминутном сроке это 84 ящика в секунду,
/// и тот, кто держал их занятыми, отрезал от связывания всех (аудит
/// 2026-11-28). Запрос — 3,2 КБ, двести тысяч ящиков — около 650 МБ, а
/// цену удержания поднимает работа, растущая с заполнением
/// (`pow::link_difficulty` в API).
pub const MAX_OPEN_BOXES: i64 = 200_000;

/// Сколько выданных, но не завершённых грантов может быть у аккаунта.
///
/// 🔐 Грант — до 1,2 МБ. Ящики открываются без входа, и без этого предела
/// один аккаунт, открыв тысячи ящиков, записал бы в каждый грант
/// предельного размера (аудит 2026-11-28). Больше подключаемых устройств,
/// чем `MAX_DEVICES - 1`, у аккаунта не бывает.
pub const MAX_PENDING_GRANTS: i64 = 4;

/// Длина подписи списка: XEdDSA (64) + ML-DSA-65 (3309).
const LIST_SIGNATURE_LEN: usize = 64 + 3309;
/// Запись устройства: идентификатор, X25519, ML-DSA-65.
const LIST_ENTRY_LEN: usize = 16 + 32 + 1952;
/// Длина запроса связывания (`gasapp_protocol::device_link::LinkRequest`).
pub const LINK_REQUEST_LEN: usize = 4 + 1 + 16 + 8 + 16 + 32 + 1952 + 32 + 1184;

/// Список устройств — то, что серверу нужно из него знать.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedList {
    /// Ключ аккаунта, чей это список.
    pub account_identity: [u8; 32],
    /// Версия.
    pub version: i64,
    /// Устройства: идентификатор и identity-ключ.
    pub devices: Vec<(Uuid, [u8; 32])>,
}

/// Разбирает список устройств (без проверки подписи — её проверяют
/// клиенты). `None` — не тот формат.
#[must_use]
pub fn parse_device_list(bytes: &[u8]) -> Option<ParsedList> {
    let body = bytes.get(..bytes.len().checked_sub(LIST_SIGNATURE_LEN)?)?;
    let mut reader = Reader(body);
    if reader.take(4)? != b"GDL1" {
        return None;
    }
    let account_identity = reader.array()?;
    let version = i64::try_from(u64::from_be_bytes(reader.array()?)).ok()?;
    reader.take(8)?;
    let [count] = reader.array::<1>()?;
    let count = usize::from(count);
    if count == 0 || count > MAX_DEVICES {
        return None;
    }
    let mut devices = Vec::with_capacity(count);
    for _ in 0..count {
        let id = Uuid::from_bytes(reader.array()?);
        let identity = reader.array()?;
        reader.take(LIST_ENTRY_LEN.checked_sub(48)?)?;
        if devices.iter().any(|(other, _)| *other == id) {
            return None;
        }
        devices.push((id, identity));
    }
    if !reader.0.is_empty() || version < 1 {
        return None;
    }
    Some(ParsedList {
        account_identity,
        version,
        devices,
    })
}

/// Запрос связывания — то, что серверу нужно из него знать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedRequest {
    /// Ящик.
    pub nonce: Uuid,
    /// Новое устройство.
    pub device_id: Uuid,
    /// Его identity-ключ.
    pub identity: [u8; 32],
}

/// Разбирает запрос связывания. `None` — не тот формат.
#[must_use]
pub fn parse_link_request(bytes: &[u8]) -> Option<ParsedRequest> {
    if bytes.len() != LINK_REQUEST_LEN {
        return None;
    }
    let mut reader = Reader(bytes);
    if reader.take(4)? != b"GLR1" || reader.take(1)? != [1] {
        return None;
    }
    let nonce = Uuid::from_bytes(reader.array()?);
    reader.take(8)?;
    let device_id = Uuid::from_bytes(reader.array()?);
    let identity = reader.array()?;
    if device_id.is_nil() {
        return None;
    }
    Some(ParsedRequest {
        nonce,
        device_id,
        identity,
    })
}

/// Открывает ящик с запросом нового устройства.
///
/// # Errors
///
/// * [`RepoError::Conflict`] — ящик с таким nonce уже есть;
/// * [`RepoError::QuotaExceeded`] — открыто слишком много ящиков;
/// * [`RepoError::Database`] — сбой базы.
pub async fn open_box(pool: &PgPool, nonce: Uuid, request: &[u8]) -> Result<(), RepoError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM link_boxes WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await?;
    let open: i64 = sqlx::query_scalar("SELECT count(*) FROM link_boxes")
        .fetch_one(&mut *tx)
        .await?;
    if open >= MAX_OPEN_BOXES {
        return Err(RepoError::QuotaExceeded);
    }
    let inserted = sqlx::query(
        "INSERT INTO link_boxes (nonce, request, expires_at)
         VALUES ($1, $2, now() + $3 * interval '1 second')
         ON CONFLICT DO NOTHING",
    )
    .bind(nonce)
    .bind(request)
    .bind(LINK_TTL_SECS)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(RepoError::Conflict);
    }
    tx.commit().await?;
    Ok(())
}

/// Сколько ящиков открыто сейчас — по нему API назначает цену открытия
/// следующего (`pow::link_difficulty`).
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn open_boxes(pool: &PgPool) -> Result<i64, RepoError> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM link_boxes WHERE expires_at > now()")
            .fetch_one(pool)
            .await?,
    )
}

/// Удаляет просроченные ящики связывания.
///
/// Вызывается расписанием сроков хранения (`retention`): прежде ящики
/// удалялись только при открытии следующего, и последние из них — с
/// открытыми ключами нового устройства и грантом — лежали, пока кто-нибудь
/// не открыл новый (аудит 2026-11-28).
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn purge_expired_boxes(pool: &PgPool) -> Result<u64, RepoError> {
    Ok(
        sqlx::query("DELETE FROM link_boxes WHERE expires_at <= now()")
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

/// Запрос из ящика — основному устройству, сканирующему QR.
///
/// # Errors
///
/// [`RepoError::NotFound`] — ящика нет или срок вышел.
pub async fn box_request(pool: &PgPool, nonce: Uuid) -> Result<Vec<u8>, RepoError> {
    sqlx::query_scalar("SELECT request FROM link_boxes WHERE nonce = $1 AND expires_at > now()")
        .bind(nonce)
        .fetch_optional(pool)
        .await?
        .ok_or(RepoError::NotFound)
}

/// Аккаунт основного устройства и текущая версия его списка.
/// `None` — устройство не основное (его ключ — не ключ аккаунта).
async fn primary_account(
    tx: &mut Transaction<'_, Postgres>,
    device_id: Uuid,
) -> Result<Option<(Uuid, Vec<u8>, i64)>, RepoError> {
    let row: Option<(Uuid, Vec<u8>, Option<i64>)> = sqlx::query_as(
        "SELECT a.account_id, a.identity_key, l.version
           FROM devices d
           JOIN accounts a ON a.account_id = d.account_id AND a.identity_key = d.identity_key
           LEFT JOIN device_lists l ON l.account_id = a.account_id
          WHERE d.device_id = $1
          FOR UPDATE OF a",
    )
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|(account, identity, version)| (account, identity, version.unwrap_or(0))))
}

/// Устройства аккаунта.
async fn account_devices(
    tx: &mut Transaction<'_, Postgres>,
    account: Uuid,
) -> Result<Vec<(Uuid, Vec<u8>)>, RepoError> {
    Ok(
        sqlx::query_as("SELECT device_id, identity_key FROM devices WHERE account_id = $1")
            .bind(account)
            .fetch_all(&mut **tx)
            .await?,
    )
}

/// Есть ли у аккаунта устройство с таким идентификатором.
fn has_device(known: &[(Uuid, Vec<u8>)], device: Uuid) -> bool {
    known.iter().any(|(id, _)| *id == device)
}

/// Проверяет новый список основного устройства: ключ аккаунта, версия
/// больше текущей, только известные устройства (и `extra`).
fn list_fits(
    list: &ParsedList,
    identity: &[u8],
    current_version: i64,
    known: &[(Uuid, Vec<u8>)],
    extra: Option<Uuid>,
) -> bool {
    // Устройство в списке — с тем же ключом, с каким оно зарегистрировано:
    // иначе список назвал бы «своим» чужой ключ под своим идентификатором.
    list.account_identity.as_slice() == identity
        && list.version > current_version
        && list.devices.iter().all(|(id, key)| {
            known
                .iter()
                .any(|(known_id, known_key)| known_id == id && known_key.as_slice() == key)
                || Some(*id) == extra
        })
}

/// Основное устройство выдаёт грант: шифротекст для нового устройства и
/// список устройств с ним.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — ящика нет, срок вышел или грант уже выдан;
/// * [`RepoError::Conflict`] — устройство не основное, список не того
///   аккаунта, не новее текущего, без нового устройства или с чужими;
/// * [`RepoError::QuotaExceeded`] — у аккаунта уже
///   [`MAX_PENDING_GRANTS`] незавершённых грантов;
/// * [`RepoError::Database`] — сбой базы.
pub async fn put_grant(
    pool: &PgPool,
    nonce: Uuid,
    primary_device: Uuid,
    grant: &[u8],
    device_list: &[u8],
) -> Result<(), RepoError> {
    let mut tx = pool.begin().await?;
    let request: Vec<u8> = sqlx::query_scalar(
        "SELECT request FROM link_boxes
          WHERE nonce = $1 AND expires_at > now() AND grant_blob IS NULL
          FOR UPDATE",
    )
    .bind(nonce)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(RepoError::NotFound)?;
    let request = parse_link_request(&request).ok_or(RepoError::NotFound)?;

    let (account, identity, version) = primary_account(&mut tx, primary_device)
        .await?
        .ok_or(RepoError::Conflict)?;
    // Строка аккаунта заперта выше (`FOR UPDATE`): два гранта одного
    // аккаунта предел не обойдут.
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM link_boxes
          WHERE account_id = $1 AND expires_at > now() AND grant_blob IS NOT NULL",
    )
    .bind(account)
    .fetch_one(&mut *tx)
    .await?;
    if pending >= MAX_PENDING_GRANTS {
        return Err(RepoError::QuotaExceeded);
    }
    let list = parse_device_list(device_list).ok_or(RepoError::Conflict)?;
    let known = account_devices(&mut tx, account).await?;
    let new_listed = list
        .devices
        .iter()
        .any(|(id, key)| *id == request.device_id && *key == request.identity);
    if !new_listed
        || has_device(&known, request.device_id)
        || !list_fits(&list, &identity, version, &known, Some(request.device_id))
    {
        return Err(RepoError::Conflict);
    }

    sqlx::query(
        "UPDATE link_boxes SET account_id = $2, grant_blob = $3, device_list = $4, list_version = $5
          WHERE nonce = $1",
    )
    .bind(nonce)
    .bind(account)
    .bind(grant)
    .bind(device_list)
    .bind(list.version)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Грант — новому устройству, по nonce из своего QR.
///
/// # Errors
///
/// [`RepoError::NotFound`] — гранта ещё нет (или ящика уже нет).
pub async fn take_grant(pool: &PgPool, nonce: Uuid) -> Result<Vec<u8>, RepoError> {
    sqlx::query_scalar(
        "SELECT grant_blob FROM link_boxes
          WHERE nonce = $1 AND expires_at > now() AND grant_blob IS NOT NULL",
    )
    .bind(nonce)
    .fetch_optional(pool)
    .await?
    .flatten()
    .ok_or(RepoError::NotFound)
}

/// Запрос ящика, у которого уже есть грант, — для проверки подписи
/// нового устройства перед [`complete_link`].
///
/// # Errors
///
/// [`RepoError::NotFound`] — ящика нет, гранта нет или срок вышел.
pub async fn granted_request(
    pool: &PgPool,
    nonce: Uuid,
) -> Result<(ParsedRequest, Vec<u8>), RepoError> {
    let (request, account_identity): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT b.request, a.identity_key
           FROM link_boxes b
           JOIN accounts a ON a.account_id = b.account_id
          WHERE b.nonce = $1 AND b.expires_at > now() AND b.grant_blob IS NOT NULL",
    )
    .bind(nonce)
    .fetch_optional(pool)
    .await?
    .ok_or(RepoError::NotFound)?;
    Ok((
        parse_link_request(&request).ok_or(RepoError::NotFound)?,
        account_identity,
    ))
}

/// Подпись членства подключённого устройства. `None` — основное (ему
/// подпись не нужна) либо устройства нет.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn membership_of(pool: &PgPool, device_id: Uuid) -> Result<Option<Vec<u8>>, RepoError> {
    Ok(
        sqlx::query_scalar("SELECT membership FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(pool)
            .await?
            .flatten(),
    )
}

/// Ящик с грантом: запрос, аккаунт, список, его версия.
type GrantedBox = (Vec<u8>, Option<Uuid>, Option<Vec<u8>>, Option<i64>);

/// Новое устройство завершает связывание: устройство появляется у
/// аккаунта, список устройств — новый, ящик удаляется.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — ящика или гранта нет, срок вышел;
/// * [`RepoError::Conflict`] — пока ждали, список сменился, или
///   устройств уже предел;
/// * [`RepoError::Database`] — сбой базы.
pub async fn complete_link(
    pool: &PgPool,
    nonce: Uuid,
    membership: &[u8],
) -> Result<(Uuid, Uuid), RepoError> {
    let mut tx = pool.begin().await?;
    let row: Option<GrantedBox> = sqlx::query_as(
        "SELECT request, account_id, device_list, list_version FROM link_boxes
          WHERE nonce = $1 AND expires_at > now() AND grant_blob IS NOT NULL
          FOR UPDATE",
    )
    .bind(nonce)
    .fetch_optional(&mut *tx)
    .await?;
    let (request, Some(account), Some(list), Some(version)) = row.ok_or(RepoError::NotFound)?
    else {
        return Err(RepoError::NotFound);
    };
    let request = parse_link_request(&request).ok_or(RepoError::NotFound)?;

    // Список не сменился, пока новое устройство открывало грант.
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT l.version FROM accounts a LEFT JOIN device_lists l ON l.account_id = a.account_id
          WHERE a.account_id = $1 FOR UPDATE OF a",
    )
    .bind(account)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let known = account_devices(&mut tx, account).await?;
    if current.unwrap_or(0) >= version || known.len() >= MAX_DEVICES {
        return Err(RepoError::Conflict);
    }

    sqlx::query(
        "INSERT INTO devices (device_id, account_id, identity_key, membership)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(request.device_id)
    .bind(account)
    .bind(request.identity.as_slice())
    .bind(membership)
    .execute(&mut *tx)
    .await?;
    store_list(&mut tx, account, version, &list).await?;
    sqlx::query("DELETE FROM link_boxes WHERE nonce = $1")
        .bind(nonce)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((account, request.device_id))
}

/// Основное устройство переподписывает свой список без изменений состава:
/// новая версия, новое время. Так список не стареет — клиенты не доверяют
/// списку старше 30 дней (иначе сервер мог бы бесконечно отдавать старую
/// версию с давно отключённым устройством).
///
/// # Errors
///
/// * [`RepoError::NotFound`] — у аккаунта ещё нет списка;
/// * [`RepoError::Conflict`] — устройство не основное, версия не новее,
///   состав другой или ключи не те;
/// * [`RepoError::Database`] — сбой базы.
pub async fn refresh_device_list(
    pool: &PgPool,
    primary_device: Uuid,
    device_list: &[u8],
) -> Result<(), RepoError> {
    let mut tx = pool.begin().await?;
    let (account, identity, version) = primary_account(&mut tx, primary_device)
        .await?
        .ok_or(RepoError::Conflict)?;
    if version == 0 {
        return Err(RepoError::NotFound);
    }
    let known = account_devices(&mut tx, account).await?;
    let list = parse_device_list(device_list).ok_or(RepoError::Conflict)?;
    // Состав — тот же: переподпись не подключает и не отключает.
    let same = list.devices.len() == known.len()
        && known
            .iter()
            .all(|(id, _)| list.devices.iter().any(|(listed, _)| listed == id));
    if !same || !list_fits(&list, &identity, version, &known, None) {
        return Err(RepoError::Conflict);
    }
    store_list(&mut tx, account, list.version, device_list).await?;
    tx.commit().await?;
    Ok(())
}

/// Основное устройство отключает устройство `target`: новый список без
/// него, устройство и его очередь и ключи удаляются.
///
/// # Errors
///
/// * [`RepoError::NotFound`] — такого устройства у аккаунта нет (или это
///   само основное);
/// * [`RepoError::Conflict`] — устройство не основное, список не новее,
///   с отключаемым или с чужими устройствами;
/// * [`RepoError::Database`] — сбой базы.
pub async fn unlink_device(
    pool: &PgPool,
    primary_device: Uuid,
    target: Uuid,
    device_list: &[u8],
) -> Result<(), RepoError> {
    let mut tx = pool.begin().await?;
    let (account, identity, version) = primary_account(&mut tx, primary_device)
        .await?
        .ok_or(RepoError::Conflict)?;
    let known = account_devices(&mut tx, account).await?;
    if target == primary_device || !has_device(&known, target) {
        return Err(RepoError::NotFound);
    }
    let list = parse_device_list(device_list).ok_or(RepoError::Conflict)?;
    if list.devices.iter().any(|(id, _)| *id == target)
        || !list_fits(&list, &identity, version, &known, None)
    {
        return Err(RepoError::Conflict);
    }
    sqlx::query("DELETE FROM devices WHERE device_id = $1 AND account_id = $2")
        .bind(target)
        .bind(account)
        .execute(&mut *tx)
        .await?;
    store_list(&mut tx, account, list.version, device_list).await?;
    tx.commit().await?;
    Ok(())
}

async fn store_list(
    tx: &mut Transaction<'_, Postgres>,
    account: Uuid,
    version: i64,
    signed: &[u8],
) -> Result<(), RepoError> {
    sqlx::query(
        "INSERT INTO device_lists (account_id, version, signed) VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO UPDATE
            SET version = EXCLUDED.version, signed = EXCLUDED.signed, updated_at = date_trunc('hour', now())",
    )
    .bind(account)
    .bind(version)
    .bind(signed)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Основное ли устройство: его identity — ключ аккаунта.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn is_primary(pool: &PgPool, device_id: Uuid) -> Result<bool, RepoError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM devices d JOIN accounts a
                          ON a.account_id = d.account_id AND a.identity_key = d.identity_key
                         WHERE d.device_id = $1)",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await?)
}

/// Подключено ли устройство по QR (`complete_link`), а не заведено
/// регистрацией или восстановлением аккаунта.
///
/// 🔐 По нему API отказывает подключённому устройству в действиях над
/// аккаунтом целиком — удалить аккаунт, вести свои каналы, заводить и
/// удалять ботов (аудит 2026-11-28, `MULTI-DEVICE.md` §2): второй телефон,
/// потерянный или украденный, не должен уносить аккаунт.
///
/// Признак — подпись членства: она есть только у подключённых. Не
/// [`is_primary`]: у ботов (и у аккаунтов тестов) ключ устройства не
/// совпадает с ключом аккаунта, а подключёнными они от этого не
/// становятся.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn is_linked(pool: &PgPool, device_id: Uuid) -> Result<bool, RepoError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE device_id = $1 AND membership IS NOT NULL)",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await?)
}

/// Устройства аккаунта и его ботов — те, чьи сокеты закрываются, когда
/// аккаунт удаляют (боты уходят вместе с владельцем).
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn account_and_bot_devices(pool: &PgPool, account: Uuid) -> Result<Vec<Uuid>, RepoError> {
    Ok(sqlx::query_scalar(
        "SELECT d.device_id FROM devices d
          WHERE d.account_id = $1
             OR d.account_id IN (SELECT b.account_id FROM bots b WHERE b.owner_id = $1)",
    )
    .bind(account)
    .fetch_all(pool)
    .await?)
}

/// Записывает пост-квантовую половину подключённого устройства.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn set_device_pq(
    pool: &PgPool,
    device_id: Uuid,
    public: &[u8],
    binding: &[u8],
) -> Result<(), RepoError> {
    sqlx::query(
        "UPDATE devices SET pq_identity_key = $2, identity_binding = $3 WHERE device_id = $1",
    )
    .bind(device_id)
    .bind(public)
    .bind(binding)
    .execute(pool)
    .await?;
    Ok(())
}

/// Пост-квантовая половина подключённого устройства, если есть.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn device_pq(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, RepoError> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT pq_identity_key, identity_binding FROM devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((Some(public), Some(binding))) => Some((public, binding)),
        _ => None,
    })
}

/// Подписанный список устройств аккаунта; `None` — у аккаунта одно
/// устройство и списка ещё не было.
///
/// # Errors
///
/// [`RepoError::Database`] — сбой базы.
pub async fn device_list(pool: &PgPool, account: Uuid) -> Result<Option<Vec<u8>>, RepoError> {
    Ok(
        sqlx::query_scalar("SELECT signed FROM device_lists WHERE account_id = $1")
            .bind(account)
            .fetch_optional(pool)
            .await?,
    )
}

/// Читатель байтов без индексации.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_bytes(identity: [u8; 32], version: u64, devices: &[(u8, [u8; 32])]) -> Vec<u8> {
        let mut out = b"GDL1".to_vec();
        out.extend_from_slice(&identity);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&0i64.to_be_bytes());
        out.push(u8::try_from(devices.len()).unwrap());
        for (id, key) in devices {
            out.extend_from_slice(&[*id; 16]);
            out.extend_from_slice(key);
            out.extend_from_slice(&[0u8; 1952]);
        }
        out.extend_from_slice(&[0u8; LIST_SIGNATURE_LEN]);
        out
    }

    #[test]
    fn device_lists_are_parsed_strictly() {
        let list =
            parse_device_list(&list_bytes([1; 32], 3, &[(1, [1; 32]), (2, [2; 32])])).unwrap();
        assert_eq!(list.version, 3);
        assert_eq!(list.devices.len(), 2);
        assert_eq!(list.devices[1].0, Uuid::from_bytes([2; 16]));

        let mut extra = list_bytes([1; 32], 3, &[(1, [1; 32])]);
        extra.insert(10, 0);
        assert!(parse_device_list(&extra).is_none());
        assert!(parse_device_list(&list_bytes([1; 32], 0, &[(1, [1; 32])])).is_none());
        assert!(
            parse_device_list(&list_bytes([1; 32], 1, &[(1, [1; 32]), (1, [2; 32])])).is_none()
        );
        let six: Vec<(u8, [u8; 32])> = (1..=6).map(|i| (i, [i; 32])).collect();
        assert!(parse_device_list(&list_bytes([1; 32], 1, &six)).is_none());
    }

    #[test]
    fn link_requests_are_parsed_strictly() {
        let mut request = b"GLR1".to_vec();
        request.push(1);
        request.extend_from_slice(&[7; 16]);
        request.extend_from_slice(&0i64.to_be_bytes());
        request.extend_from_slice(&[9; 16]);
        request.extend_from_slice(&[3; 32]);
        request.resize(LINK_REQUEST_LEN, 0);
        let parsed = parse_link_request(&request).unwrap();
        assert_eq!(parsed.nonce, Uuid::from_bytes([7; 16]));
        assert_eq!(parsed.device_id, Uuid::from_bytes([9; 16]));
        assert_eq!(parsed.identity, [3; 32]);

        request.push(0);
        assert!(parse_link_request(&request).is_none());
    }
}
