// SPDX-License-Identifier: AGPL-3.0-only

//! Премиум и каналы.
//!
//! # Что такое канал
//!
//! Лента записей одного автора для многих читателей — как канал
//! в Telegram: записи с текстом и медиа, правка и удаление, закреп,
//! реакции, счётчики просмотров и подписчиков, публичное `@имя` и
//! поиск. Отличия следуют из устройства GasApp:
//!
//! * **закрытый канал сервер не читает.** Название, описание, записи
//!   и медиа приходят шифротекстом на ключе канала. Ключ лежит в
//!   ссылке-приглашении и на сервер не попадает;
//! * **публичный канал сервер прочитать может.** Чтобы канал находился
//!   по `@имени`, автор отдаёт серверу ссылку-приглашение. Это цена
//!   публичности, и приложение говорит о ней до включения;
//! * **читателя сервер не знает, подписчика — знает.** Записи
//!   забираются без подписи запроса: по ссылке канал читается
//!   анонимно. Подписка, отметка «дочитал» и реакция — за подписью
//!   устройства: один аккаунт — один подписчик, иначе счётчик
//!   накручивался бы циклом (ADR-035).
//!
//! # Кто может создать канал
//!
//! Только аккаунт с премиумом (`accounts.premium`). Премиум выдаёт
//! оператор вручную — админ-центр или `gasapp-server-admin premium`.
//! Читать каналы может любой.
//!
//! # 🔐 Что проверяет сервер и чего нет
//!
//! Сервер проверяет, что публикует владелец канала (подпись устройства
//! и принадлежность канала аккаунту). Подпись **записи** он не
//! проверяет — её проверяют читатели ключом из ссылки. Поэтому
//! взломанный сервер может не отдать запись, но не может подделать её
//! или выдать правку за авторскую. Счётчики — подписчики, просмотры,
//! реакции — ничем не подписаны: это статистика сервера.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use gasapp_server_db::channels::{
    self, Channel, Post, MAX_LINK_LEN, MAX_META_BYTES, MAX_POSTS_PER_PAGE, MAX_POST_BYTES,
    REACTIONS,
};
use gasapp_server_db::repo::RepoError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::AuthenticatedDevice;
use crate::rate_limit;
use crate::routes::{decode_hex, now_millis, ApiError, AppState};

/// Сколько записей и правок в минуту принимает один канал.
pub const POSTS_PER_MINUTE: u32 = 30;

/// Сколько действий читателя (отметка о прочтении, реакция) в минуту
/// принимается от одного жетона.
pub const READER_ACTIONS_PER_MINUTE: u32 = 60;

/// Длина публичного ключа подписи записей.
const VERIFY_KEY_LEN: usize = 32;

/// Состояние аккаунта — то, что приложению нужно знать о себе.
#[derive(Debug, Serialize)]
pub struct AccountStatusResponse {
    /// Есть ли у аккаунта премиум.
    pub premium: bool,
    /// Ограничение оператором, если действует.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restriction: Option<RestrictionResponse>,
}

/// Заморозка либо блокировка — то, что приложение показывает человеку.
#[derive(Debug, Serialize)]
pub struct RestrictionResponse {
    /// `frozen` либо `blocked`.
    pub kind: &'static str,
    /// Конец заморозки, секунды Unix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Причина: `spam`, `harassment`, `csae`, `impersonation`,
    /// `illegal`, `other`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ограничен владелец этого бота, а не сам бот.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub owner: bool,
}

/// Запрос создания канала.
#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    /// Идентификатор канала — его выбирает клиент: он входит в ссылку
    /// и в данные, под которыми шифруются записи.
    pub channel_id: Uuid,
    /// Публичный ключ подписи записей, hex.
    pub verify_key: String,
    /// Зашифрованное описание канала, hex.
    pub meta: String,
}

/// Запрос изменения канала: описание и/или публичность.
#[derive(Debug, Deserialize)]
pub struct UpdateChannelRequest {
    /// Новое зашифрованное описание, hex. Нет — описание не меняется.
    #[serde(default)]
    pub meta: Option<String>,
    /// Менять ли публичность. Без этого флага `handle` и `public_link`
    /// не читаются: так «не трогать» отличается от «сделать закрытым».
    #[serde(default)]
    pub set_public: bool,
    /// Публичное имя; `None` при `set_public` — сделать канал закрытым.
    #[serde(default)]
    pub handle: Option<String>,
    /// Ссылка-приглашение, которую сервер будет отдавать по имени.
    #[serde(default)]
    pub public_link: Option<String>,
    /// Сделать канал закрытым (`true`) либо открытым (`false`); нет —
    /// не менять.
    #[serde(default)]
    pub closed: Option<bool>,
}

/// Ссылка-приглашение закрытого канала: хеш её метки.
#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    /// SHA-256 метки из ссылки, hex. Саму метку сервер видит только
    /// в заявке — от того, кому ссылку дали.
    pub invite_hash: String,
}

/// Заявка на вход в закрытый канал.
#[derive(Debug, Deserialize)]
pub struct JoinRequestBody {
    /// Метка из ссылки-приглашения, hex.
    pub invite: String,
    /// Открытый ключ заявителя с подписью его аккаунта, hex. Сервер
    /// его не разбирает: под него одобривший зашифрует ключ чтения.
    pub request: String,
}

/// Состояние заявки.
#[derive(Debug, Serialize)]
pub struct JoinStatusResponse {
    /// `none`, `pending` либо `approved`.
    pub status: &'static str,
    /// Ответ на одобренную заявку: зашифрованный ключ чтения, hex.
    pub grant: Option<String>,
}

/// Заявка глазами владельца и администраторов.
#[derive(Debug, Serialize)]
pub struct JoinRequestResponse {
    /// Аккаунт заявителя.
    pub account_id: Uuid,
    /// Его имя.
    pub username: String,
    /// Открытый ключ с подписью, hex.
    pub request: String,
}

/// Ответ на заявку.
#[derive(Debug, Deserialize)]
pub struct AnswerRequest {
    /// Чья заявка.
    pub account_id: Uuid,
    /// Ключ чтения, зашифрованный под заявку, hex; нет — отклонить.
    #[serde(default)]
    pub grant: Option<String>,
    /// Удостоверение участника, hex (миграция 0027).
    #[serde(default)]
    pub approval: Option<String>,
}

/// Подписчик глазами владельца и администраторов.
#[derive(Debug, Serialize)]
pub struct MemberResponse {
    /// Аккаунт.
    pub account_id: Uuid,
    /// Имя.
    pub username: String,
}

/// Откуда продолжать список подписчиков.
#[derive(Debug, Deserialize)]
pub struct MembersQuery {
    /// Последний аккаунт прошлой страницы.
    #[serde(default)]
    pub after: Option<Uuid>,
}

/// Запрос об одном подписчике: удалить либо снять запрет.
#[derive(Debug, Deserialize)]
pub struct MemberRequest {
    /// Аккаунт.
    pub account_id: Uuid,
}

/// Запрос публикации.
#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    /// Шифротекст записи, hex.
    pub body: String,
    /// Номер, под которым автор ждёт запись, — он же лежит внутри
    /// шифротекста. Не совпал со следующим номером канала — `409`,
    /// и запись не сохраняется.
    #[serde(default)]
    pub seq: Option<i64>,
}

/// Запрос назначения администратора.
#[derive(Debug, Deserialize)]
pub struct AddAdminRequest {
    /// Устройство будущего администратора — из его заявки.
    pub device_id: Uuid,
    /// Публичный ключ, которым он подписывает записи, hex.
    pub verify_key: String,
}

/// Запрос снятия администратора.
#[derive(Debug, Deserialize)]
pub struct RemoveAdminRequest {
    /// Его публичный ключ подписи, hex.
    pub verify_key: String,
}

/// Ответ на публикацию и правку.
#[derive(Debug, Serialize)]
pub struct PublishResponse {
    /// Номер записи в канале.
    pub seq: i64,
    /// Номер изменения канала.
    pub rev: i64,
}

/// Запрос правки или удаления записи.
#[derive(Debug, Deserialize)]
pub struct ReplaceRequest {
    /// Номер записи.
    pub seq: i64,
    /// Новый шифротекст либо подписанная отметка об удалении, hex.
    pub body: String,
    /// Удаление, а не правка.
    #[serde(default)]
    pub deleted: bool,
}

/// Ответ на загрузку медиа.
#[derive(Debug, Serialize)]
pub struct MediaResponse {
    /// Адрес блоба в канале.
    pub media_id: Uuid,
}

/// Запрос удаления медиа.
#[derive(Debug, Deserialize)]
pub struct DeleteMediaRequest {
    /// Адрес блоба в канале.
    pub media_id: Uuid,
}

/// Канал глазами читателя.
#[derive(Debug, Serialize)]
pub struct ChannelResponse {
    /// Идентификатор.
    pub channel_id: Uuid,
    /// Публичный ключ подписи записей, hex.
    pub verify_key: String,
    /// Зашифрованное описание, hex.
    pub meta: String,
    /// Номер последней записи.
    pub last_seq: i64,
    /// Номер последнего изменения.
    pub last_rev: i64,
    /// Публичное имя, если канал публичный.
    pub handle: Option<String>,
    /// Ссылка-приглашение публичного канала.
    pub public_link: Option<String>,
    /// Число подписчиков.
    pub subscribers: i64,
    /// Закрытый ли канал.
    pub closed: bool,
    /// Номер действующего ключа чтения.
    pub key_epoch: i32,
}

impl From<Channel> for ChannelResponse {
    fn from(channel: Channel) -> Self {
        Self {
            channel_id: channel.channel_id,
            verify_key: hex::encode(channel.verify_key),
            meta: hex::encode(channel.meta),
            last_seq: channel.last_seq,
            last_rev: channel.last_rev,
            handle: channel.handle,
            public_link: channel.public_link,
            subscribers: channel.subscribers,
            closed: channel.closed,
            key_epoch: channel.key_epoch,
        }
    }
}

/// Запись канала.
#[derive(Debug, Serialize)]
pub struct PostResponse {
    /// Номер записи.
    pub seq: i64,
    /// Номер изменения.
    pub rev: i64,
    /// Шифротекст либо отметка об удалении, hex.
    pub body: String,
    /// Удалена ли запись.
    pub deleted: bool,
    /// Час публикации, миллисекунды эпохи.
    pub posted_at: i64,
    /// Сколько подписчиков дочитали до записи.
    pub views: i64,
    /// Реакции: `эмодзи:число,…`.
    pub reactions: String,
}

impl From<Post> for PostResponse {
    fn from(post: Post) -> Self {
        Self {
            seq: post.seq,
            rev: post.rev,
            body: hex::encode(post.body),
            deleted: post.deleted,
            posted_at: post.posted_at_millis,
            views: post.views,
            reactions: post.reactions,
        }
    }
}

/// Параметры выборки записей.
///
/// Два режима. С `after_rev` — изменения после ревизии, по возрастанию:
/// так читатель догоняет канал. Без него — страница ленты от новых
/// к старым, начиная перед `before_seq`: так листают историю.
#[derive(Debug, Deserialize)]
pub struct PostsQuery {
    /// Отдать изменения после этой ревизии.
    #[serde(default)]
    pub after_rev: Option<i64>,
    /// Отдать записи старше этого номера.
    #[serde(default)]
    pub before_seq: Option<i64>,
    /// Сколько записей отдать (не больше ста).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Параметры поиска.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// Начало публичного имени.
    #[serde(default)]
    pub q: String,
}

/// Отметка «дочитал до записи».
#[derive(Debug, Deserialize)]
pub struct SeenRequest {
    /// Номер записи.
    pub seq: i64,
}

/// Реакция на запись.
#[derive(Debug, Deserialize)]
pub struct ReactRequest {
    /// Номер записи.
    pub seq: i64,
    /// Эмодзи из [`REACTIONS`]; `None` — снять реакцию.
    #[serde(default)]
    pub emoji: Option<String>,
}

/// Аккаунт подписавшего устройства — и только если оно названо в пути.
pub(crate) async fn owner_of(
    state: &AppState,
    device: AuthenticatedDevice,
    device_id: Uuid,
) -> Result<(Uuid, bool), ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    channels::account_status(&state.pool, device_id)
        .await
        .map_err(|_| ApiError::Unauthorized)
}

/// Декодирует hex-поле с пределом длины.
/// Разбирает удостоверение участника: ровно
/// [`channels::MEMBER_APPROVAL_BYTES`] байт либо ничего.
fn decode_approval(hex_text: Option<&str>) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(hex_text) = hex_text else {
        return Ok(None);
    };
    let approval = decode_bounded(hex_text, channels::MEMBER_APPROVAL_BYTES)?;

    if approval.len() == channels::MEMBER_APPROVAL_BYTES {
        Ok(Some(approval))
    } else {
        Err(ApiError::BadRequest)
    }
}

fn decode_bounded(hex_text: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    // Длина проверяется до декодирования: hex вдвое длиннее байтов.
    if hex_text.len() > max_bytes.saturating_mul(2) {
        return Err(ApiError::PayloadTooLarge);
    }

    let bytes = decode_hex(hex_text)?;

    if bytes.is_empty() {
        return Err(ApiError::BadRequest);
    }

    Ok(bytes)
}

/// Ссылка-приглашение именно этого канала: `gasapp://channel/`, его
/// идентификатор в hex и две части из знаков base32.
///
/// 🔐 Сервер отдаёт эту строку всем, кто спросит канал по имени.
/// Прежде принималась любая строка ASCII до 512 знаков: владелец канала
/// мог раздавать под своим именем ссылку на чужой канал или вовсе
/// не ссылку. Приложение такую ссылку отвергает, но раздавать её
/// сервер не должен.
fn is_link_to(link: &str, channel_id: Uuid) -> bool {
    let Some(rest) = link.strip_prefix("gasapp://channel/") else {
        return false;
    };

    let mut parts = rest.split('.');
    let (Some(id), Some(secret), Some(verify), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    let base32 = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    };

    link.len() <= MAX_LINK_LEN
        && id == channel_id.simple().to_string()
        && base32(secret)
        && base32(verify)
}

/// Ограничитель публикаций канала: запись, правка, удаление, медиа.
fn limit_channel(state: &AppState, channel_id: Uuid) -> Result<(), ApiError> {
    let key = rate_limit::key_from_addr(&state.limiter_salt, &channel_id.to_string());
    let mut limiter = state
        .channel_post_limiter
        .lock()
        .map_err(|_| ApiError::Internal)?;

    if limiter.allow(key, now_millis()) {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests)
    }
}

/// Ограничитель действий подписчика — по аккаунту.
fn limit_reader(state: &AppState, account_id: Uuid) -> Result<(), ApiError> {
    let key = rate_limit::key_from_addr(&state.limiter_salt, &account_id.to_string());
    let mut limiter = state
        .channel_reader_limiter
        .lock()
        .map_err(|_| ApiError::Internal)?;

    if limiter.allow(key, now_millis()) {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests)
    }
}

/// Состояние своего аккаунта: есть ли премиум.
///
/// Нужен приложению, чтобы показать или скрыть «Создать канал».
/// Право всё равно проверяется при создании — этот ответ ничего
/// не разрешает.
pub(crate) async fn account_status(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<Json<AccountStatusResponse>, ApiError> {
    let (_, premium) = owner_of(&state, device, device_id).await?;

    let restriction = gasapp_server_db::repo::device_for_auth(&state.pool, device_id)
        .await?
        .restriction
        .map(|r| RestrictionResponse {
            kind: if r.blocked { "blocked" } else { "frozen" },
            until: r.until_secs,
            reason: r.reason,
            owner: r.via_owner,
        });

    Ok(Json(AccountStatusResponse {
        premium,
        restriction,
    }))
}

/// Создаёт канал. Только для премиум-аккаунта: иначе `403`.
pub(crate) async fn create(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<CreateChannelRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, premium) = owner_of(&state, device, device_id).await?;

    if !premium {
        return Err(ApiError::Forbidden);
    }

    let verify_key = decode_hex(&request.verify_key)?;

    if verify_key.len() != VERIFY_KEY_LEN {
        return Err(ApiError::BadRequest);
    }

    let meta = decode_bounded(&request.meta, MAX_META_BYTES)?;

    channels::create_channel(
        &state.pool,
        account_id,
        request.channel_id,
        &verify_key,
        &meta,
    )
    .await
    .map_err(|error| match error {
        // Занятый идентификатор — «конфликт», а не отказ авторизации,
        // как у перепривязки: клиент выберет другой.
        RepoError::Conflict => ApiError::Conflict,
        other => other.into(),
    })?;

    Ok(StatusCode::CREATED)
}

/// Меняет описание своего канала и/или его публичность.
///
/// Занятое публичное имя — `409`.
pub(crate) async fn update(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateChannelRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    if let Some(meta) = &request.meta {
        let meta = decode_bounded(meta, MAX_META_BYTES)?;

        channels::update_meta(&state.pool, account_id, channel_id, &meta).await?;
    }

    if let Some(closed) = request.closed {
        channels::set_closed(&state.pool, account_id, channel_id, closed)
            .await
            .map_err(|error| match error {
                // Канал с публичным именем закрытым не бывает, а канал,
                // у которого меняли ключ, — открытым.
                RepoError::Conflict => ApiError::BadRequest,
                other => other.into(),
            })?;
    }

    if request.set_public {
        // Закрытому каналу имя не дать: по имени раздаётся ссылка с ключом.
        if request.handle.is_some()
            && channels::find_channel(&state.pool, channel_id)
                .await?
                .closed
        {
            return Err(ApiError::BadRequest);
        }

        let public = match (&request.handle, &request.public_link) {
            (None, _) => None,
            (Some(handle), Some(link)) => {
                // 🔐 Только каноничное имя — то же правило, что у имён
                // аккаунтов: двойник с кириллической буквой не пройдёт.
                if !gasapp_server_db::is_canonical_username(handle) || !is_link_to(link, channel_id)
                {
                    return Err(ApiError::BadRequest);
                }

                Some((handle.as_str(), link.as_str()))
            }
            // Имя без ссылки: по имени было бы нечего отдать.
            (Some(_), None) => return Err(ApiError::BadRequest),
        };

        channels::set_handle(&state.pool, account_id, channel_id, public).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Удаляет свой канал вместе с записями.
pub(crate) async fn delete(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::delete_channel(&state.pool, account_id, channel_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Публикует запись в своём канале.
///
/// Премиум здесь не проверяется: канал, созданный с премиумом,
/// остаётся у владельца и после снятия премиума — снятие запрещает
/// создавать новые, а не отнимает существующий.
pub(crate) async fn publish(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let body = decode_bounded(&request.body, MAX_POST_BYTES)?;

    // Ограничитель — после проверки подписи: чужой запрос бюджет
    // канала не тратит.
    limit_channel(&state, channel_id)?;
    require_current_epoch(&state, channel_id, &body).await?;

    let (seq, rev) =
        channels::publish_post(&state.pool, account_id, channel_id, &body, request.seq)
            .await
            .map_err(|error| match error {
                // «Номер занят» — не отказ авторизации: автор возьмёт
                // следующий номер и повторит.
                RepoError::Conflict => ApiError::Conflict,
                other => other.into(),
            })?;

    Ok(Json(PublishResponse { seq, rev }))
}

/// Первый байт записи под ключом эпохи старше нулевой; за ним — номер
/// эпохи. Остальное сервер не разбирает.
const EPOCH_WIRE_VERSION: u8 = 3;

/// Номер эпохи, под которой сделана запись.
fn wire_epoch(body: &[u8]) -> i64 {
    match body {
        [EPOCH_WIRE_VERSION, a, b, c, d, ..] => i64::from(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => 0,
    }
}

/// 🔐 Запись принимается только под действующим ключом канала: автор,
/// не узнавший о смене ключа, иначе писал бы ключом, который есть у
/// удалённого подписчика. `409` — автор заберёт новый ключ и повторит.
async fn require_current_epoch(
    state: &AppState,
    channel_id: Uuid,
    body: &[u8],
) -> Result<(), ApiError> {
    let channel = channels::find_channel(&state.pool, channel_id).await?;

    if wire_epoch(body) == i64::from(channel.key_epoch) {
        Ok(())
    } else {
        Err(ApiError::Conflict)
    }
}

/// Жалоба на канал.
#[derive(Debug, Deserialize)]
pub struct ReportChannelRequest {
    /// Причина: 1 спам, 2 незаконное, 3 безопасность детей, 4 насилие
    /// и ненависть, 5 другое.
    pub reason: i16,
    /// Номер записи, на которую жалуются; нет — на канал целиком.
    #[serde(default)]
    pub seq: Option<i64>,
    /// Ссылка канала — если жалобщик решил дать оператору прочитать
    /// записи.
    #[serde(default)]
    pub link: Option<String>,
}

/// Ведёт ли ссылка именно в этот канал.
///
/// 🔐 Иначе к жалобе на один канал приложили бы ссылку другого, и
/// оператор судил бы о канале по чужим записям.
fn links_to(link: &str, channel_id: Uuid) -> bool {
    link.strip_prefix("gasapp://channel/")
        .and_then(|rest| rest.split('.').next())
        .is_some_and(|id| id.eq_ignore_ascii_case(&channel_id.simple().to_string()))
}

/// Принимает жалобу на канал — от любого аккаунта, за подписью.
///
/// 🔐 Что в канале, сервер не знает и по жалобе: ссылку (ключ чтения)
/// жалобщик прикладывает сам, если хочет.
pub(crate) async fn report(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<ReportChannelRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    if !(1..=channels::CHANNEL_REPORT_REASONS).contains(&request.reason)
        || request.seq.is_some_and(|seq| seq < 1)
        || request
            .link
            .as_deref()
            .is_some_and(|link| link.len() > MAX_LINK_LEN || !links_to(link, channel_id))
    {
        return Err(ApiError::BadRequest);
    }

    limit_reader(&state, account_id)?;

    channels::report_channel(
        &state.pool,
        channel_id,
        account_id,
        request.reason,
        request.seq,
        request.link.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Ключ доставки участника закрытого канала.
#[derive(Debug, Deserialize)]
pub struct MemberKeyRequest {
    /// Открытый ключ за подписью аккаунта, hex.
    pub member_key: String,
    /// Удостоверение — его выписывает себе тот, кто ведёт канал, hex.
    #[serde(default)]
    pub approval: Option<String>,
}

/// Ключ доставки участника — тому, кто ведёт канал.
#[derive(Debug, Serialize)]
pub struct MemberKeyResponse {
    /// Аккаунт участника.
    pub account_id: Uuid,
    /// Ключ доставки, hex.
    pub member_key: String,
    /// Удостоверение участника, hex.
    pub approval: Option<String>,
}

/// Какие ключи доставки нужны.
#[derive(Debug, Deserialize)]
pub struct MemberKeysQuery {
    /// Только тех, у кого нет ключа действующей эпохи.
    #[serde(default)]
    pub missing: bool,
    /// Последний аккаунт прошлой страницы.
    #[serde(default)]
    pub after: Option<Uuid>,
}

/// Ключ эпохи одному участнику.
#[derive(Debug, Deserialize)]
pub struct EpochGrant {
    /// Кому.
    pub account_id: Uuid,
    /// Ключ эпохи шифротекстом под ключ доставки участника, hex.
    pub grant: String,
    /// Удостоверение на эту эпоху, hex; нет — прежнее остаётся.
    #[serde(default)]
    pub approval: Option<String>,
}

/// Смена ключа канала либо досылка ключей действующей эпохи.
#[derive(Debug, Deserialize)]
pub struct RekeyRequest {
    /// Эпоха: следующая — при смене ключа, действующая — при досылке.
    pub epoch: i32,
    /// Звено цепочки к новой эпохе, hex; нет — досылка.
    #[serde(default)]
    pub record: Option<String>,
    /// Ключи участникам.
    #[serde(default)]
    pub grants: Vec<EpochGrant>,
}

/// Звено цепочки ключей.
#[derive(Debug, Serialize)]
pub struct EpochResponse {
    /// Номер эпохи.
    pub epoch: i32,
    /// Прежний ключ, зашифрованный новым, за подписью сменившего, hex.
    pub record: String,
}

/// С какой эпохи нужны звенья.
#[derive(Debug, Deserialize)]
pub struct EpochsQuery {
    /// Номер последней известной эпохи.
    #[serde(default)]
    pub after: i32,
}

/// Участник закрытого канала называет ключ доставки.
pub(crate) async fn set_member_key(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<MemberKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let member_key = decode_bounded(&request.member_key, channels::MAX_JOIN_BLOB_BYTES)?;
    let approval = decode_approval(request.approval.as_deref())?;

    limit_reader(&state, account_id)?;
    channels::set_member_key(
        &state.pool,
        channel_id,
        account_id,
        &member_key,
        approval.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Ключи доставки участников — тому, кто ведёт канал.
pub(crate) async fn member_keys(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<MemberKeysQuery>,
) -> Result<Json<Vec<MemberKeyResponse>>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        channels::member_keys(
            &state.pool,
            account_id,
            channel_id,
            query.missing,
            query.after,
        )
        .await?
        .into_iter()
        .map(|key| MemberKeyResponse {
            account_id: key.account_id,
            member_key: hex::encode(key.member_key),
            approval: key.approval.map(hex::encode),
        })
        .collect(),
    ))
}

/// Меняет ключ канала либо досылает ключи действующей эпохи.
///
/// 🔐 Сервер не знает, что внутри: и звено, и ответы — шифротекст.
/// Он следит только за номером эпохи. Не та эпоха — `409`.
pub(crate) async fn rekey(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RekeyRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    if request.grants.len() > usize::try_from(channels::MAX_MEMBER_KEYS_PER_PAGE).unwrap_or(0) {
        return Err(ApiError::PayloadTooLarge);
    }

    let record = request
        .record
        .as_deref()
        .map(|record| decode_bounded(record, channels::MAX_EPOCH_RECORD_BYTES))
        .transpose()?;
    let grants = request
        .grants
        .iter()
        .map(|grant| {
            Ok(channels::EpochGrant {
                account_id: grant.account_id,
                grant: decode_bounded(&grant.grant, channels::MAX_JOIN_BLOB_BYTES)?,
                approval: decode_approval(grant.approval.as_deref())?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    channels::rekey(
        &state.pool,
        account_id,
        channel_id,
        request.epoch,
        record.as_deref(),
        &grants,
    )
    .await
    .map_err(|error| match error {
        RepoError::Conflict => ApiError::Conflict,
        other => other.into(),
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Звенья цепочки ключей — участнику.
pub(crate) async fn epochs(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<EpochsQuery>,
) -> Result<Json<Vec<EpochResponse>>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        channels::epochs(&state.pool, channel_id, account_id, query.after)
            .await
            .map_err(|error| match error {
                // Не участнику канала нет — как и на чтении.
                RepoError::NotFound => ApiError::NotFound,
                other => other.into(),
            })?
            .into_iter()
            .map(|(epoch, record)| EpochResponse {
                epoch,
                record: hex::encode(record),
            })
            .collect(),
    ))
}

/// Ключ подписи администратора из hex.
fn admin_key(hex_text: &str) -> Result<[u8; VERIFY_KEY_LEN], ApiError> {
    decode_hex(hex_text)?
        .try_into()
        .map_err(|_| ApiError::BadRequest)
}

/// Назначает администратора своего канала.
///
/// 🔐 Это право сервера принять запись, а не право записи быть
/// подлинной: читатели верят списку из описания канала, которое
/// подписывает владелец (миграция 0020).
pub(crate) async fn add_admin(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<AddAdminRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let verify_key = admin_key(&request.verify_key)?;

    channels::add_admin(
        &state.pool,
        account_id,
        channel_id,
        request.device_id,
        &verify_key,
    )
    .await
    .map_err(|error| match error {
        // Владелец не назначает администратором себя.
        RepoError::Conflict => ApiError::BadRequest,
        other => other.into(),
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Снимает администратора своего канала.
pub(crate) async fn remove_admin(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RemoveAdminRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let verify_key = admin_key(&request.verify_key)?;

    channels::remove_admin(&state.pool, account_id, channel_id, &verify_key).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Исправляет или удаляет запись своего канала.
///
/// Что именно лежит в `body` — исправленная запись или отметка об
/// удалении, — сервер не знает: и то и другое подписано автором
/// и проверяется читателями.
pub(crate) async fn replace(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<ReplaceRequest>,
) -> Result<Json<PublishResponse>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let body = decode_bounded(&request.body, MAX_POST_BYTES)?;

    limit_channel(&state, channel_id)?;
    require_current_epoch(&state, channel_id, &body).await?;

    let rev = channels::replace_post(
        &state.pool,
        account_id,
        channel_id,
        request.seq,
        &body,
        request.deleted,
    )
    .await?;

    Ok(Json(PublishResponse {
        seq: request.seq,
        rev,
    }))
}

/// Загружает медиаблоб своего канала: зашифрованное фото, файл, аватар.
///
/// Тело — сырые байты: hex удвоил бы объём.
pub(crate) async fn upload_media(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    blob: Bytes,
) -> Result<Json<MediaResponse>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    limit_channel(&state, channel_id)?;

    let media_id = channels::store_media(&state.pool, account_id, channel_id, &blob).await?;

    Ok(Json(MediaResponse { media_id }))
}

/// Удаляет медиаблоб своего канала.
pub(crate) async fn delete_media(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DeleteMediaRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::delete_media(&state.pool, account_id, channel_id, request.media_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Канал по идентификатору — без подписи.
pub(crate) async fn info(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelResponse>, ApiError> {
    Ok(Json(open_channel(&state, channel_id).await?.into()))
}

/// Канал, если он открытый. Закрытый для запроса без подписи не
/// существует: его отдают только участникам (`member_*`).
async fn open_channel(state: &AppState, channel_id: Uuid) -> Result<Channel, ApiError> {
    let channel = channels::find_channel(&state.pool, channel_id).await?;

    if channel.closed {
        return Err(ApiError::NotFound);
    }

    Ok(channel)
}

/// Записи по параметрам выборки — общая часть открытого и закрытого
/// чтения.
async fn select_posts(
    state: &AppState,
    channel_id: Uuid,
    query: &PostsQuery,
) -> Result<Vec<PostResponse>, ApiError> {
    let limit = query.limit.unwrap_or(MAX_POSTS_PER_PAGE);

    let posts = match query.after_rev {
        Some(after) => {
            channels::changes_since(&state.pool, channel_id, after.max(0), limit).await?
        }
        None => channels::page_before(&state.pool, channel_id, query.before_seq, limit).await?,
    };

    Ok(posts.into_iter().map(PostResponse::from).collect())
}

/// Записи канала — без подписи. Режимы — см. [`PostsQuery`].
///
/// Несуществующий канал даёт пустой список, а не `404`: читателю
/// удалённого канала нечего показать в обоих случаях, а существование
/// канала сообщает [`info`].
pub(crate) async fn posts(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
    Query(query): Query<PostsQuery>,
) -> Result<Json<Vec<PostResponse>>, ApiError> {
    // Закрытый канал без подписи неотличим от несуществующего.
    if open_channel(&state, channel_id).await.is_err() {
        return Ok(Json(Vec::new()));
    }

    Ok(Json(select_posts(&state, channel_id, &query).await?))
}

/// Медиаблоб канала — без подписи.
pub(crate) async fn media(
    State(state): State<Arc<AppState>>,
    Path((channel_id, media_id)): Path<(Uuid, Uuid)>,
) -> Result<Vec<u8>, ApiError> {
    open_channel(&state, channel_id).await?;

    Ok(channels::fetch_media(&state.pool, channel_id, media_id).await?)
}

/// Публичный канал по точному имени — без подписи.
pub(crate) async fn by_handle(
    State(state): State<Arc<AppState>>,
    Path(handle): Path<String>,
) -> Result<Json<ChannelResponse>, ApiError> {
    if !gasapp_server_db::is_canonical_username(&handle) {
        return Err(ApiError::NotFound);
    }

    Ok(Json(
        channels::find_by_handle(&state.pool, &handle).await?.into(),
    ))
}

/// Поиск публичных каналов по началу имени — без подписи.
///
/// Ищет только по `@имени`: названий сервер не знает. Пустой или
/// негодный запрос даёт пустой список.
pub(crate) async fn search(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<ChannelResponse>>, ApiError> {
    let prefix = query.q.trim().trim_start_matches('@').to_ascii_lowercase();

    let acceptable = (2..=32).contains(&prefix.len())
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');

    if !acceptable {
        return Ok(Json(Vec::new()));
    }

    Ok(Json(
        channels::search_public(&state.pool, &prefix)
            .await?
            .into_iter()
            .map(ChannelResponse::from)
            .collect(),
    ))
}

/// Подписывает аккаунт на канал.
///
/// 🔐 За подписью устройства: один аккаунт — один подписчик. Анонимную
/// подписку нечем было ограничить — счётчик накручивался циклом. Цена:
/// сервер знает, на какие каналы подписан аккаунт. Читать канал по
/// ссылке можно и без подписки — тогда сервер не знает ничего.
pub(crate) async fn subscribe(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::subscribe(&state.pool, channel_id, account_id)
        .await
        .map_err(|error| match error {
            // В закрытый канал входят по одобренной заявке.
            RepoError::Conflict => ApiError::Forbidden,
            other => other.into(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Отписывает аккаунт: подписка и его реакции исчезают.
pub(crate) async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::unsubscribe(&state.pool, channel_id, account_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Отметка «дочитал до записи» — из неё складываются просмотры.
pub(crate) async fn seen(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<SeenRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    limit_reader(&state, account_id)?;
    channels::mark_seen(&state.pool, channel_id, account_id, request.seq.max(0)).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Реакция подписчика на запись: поставить, сменить или снять.
pub(crate) async fn react(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<ReactRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    // Набор закрыт: произвольная строка была бы способом писать в
    // чужой канал.
    if let Some(emoji) = &request.emoji {
        if !REACTIONS.contains(&emoji.as_str()) {
            return Err(ApiError::BadRequest);
        }
    }

    limit_reader(&state, account_id)?;
    channels::react(
        &state.pool,
        channel_id,
        account_id,
        request.seq,
        request.emoji.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Хеш метки ссылки-приглашения из hex.
fn invite_hash(hex_text: &str) -> Result<[u8; 32], ApiError> {
    decode_hex(hex_text)?
        .try_into()
        .map_err(|_| ApiError::BadRequest)
}

/// Заводит ссылку-приглашение закрытого канала.
pub(crate) async fn add_invite(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<InviteRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::add_invite(
        &state.pool,
        account_id,
        channel_id,
        &invite_hash(&request.invite_hash)?,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Отзывает ссылку-приглашение.
pub(crate) async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<InviteRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::revoke_invite(
        &state.pool,
        account_id,
        channel_id,
        &invite_hash(&request.invite_hash)?,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Подаёт заявку на вход в закрытый канал.
///
/// Удалённому из канала — `403`; по недействующей ссылке — `404`,
/// как на несуществующий канал.
pub(crate) async fn request_join(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<JoinRequestBody>,
) -> Result<StatusCode, ApiError> {
    use sha2::{Digest as _, Sha256};

    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let invite = decode_hex(&request.invite)?;
    let blob = decode_bounded(&request.request, channels::MAX_JOIN_BLOB_BYTES)?;

    limit_reader(&state, account_id)?;

    channels::request_join(
        &state.pool,
        channel_id,
        account_id,
        &Sha256::digest(&invite).into(),
        &blob,
    )
    .await
    .map_err(|error| match error {
        RepoError::Conflict => ApiError::Forbidden,
        other => other.into(),
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Что с заявкой: ждёт, одобрена (тогда — ответ с ключом) либо её нет.
pub(crate) async fn join_status(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<JoinStatusResponse>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        match channels::join_status(&state.pool, channel_id, account_id).await? {
            channels::JoinStatus::None => JoinStatusResponse {
                status: "none",
                grant: None,
            },
            channels::JoinStatus::Pending => JoinStatusResponse {
                status: "pending",
                grant: None,
            },
            channels::JoinStatus::Approved(grant) => JoinStatusResponse {
                status: "approved",
                grant: Some(hex::encode(grant)),
            },
        },
    ))
}

/// Заявки, ждущие ответа, — тем, кто ведёт канал.
pub(crate) async fn list_requests(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<JoinRequestResponse>>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        channels::list_requests(&state.pool, account_id, channel_id)
            .await?
            .into_iter()
            .map(|request| JoinRequestResponse {
                account_id: request.account_id,
                username: request.username,
                request: hex::encode(request.request),
            })
            .collect(),
    ))
}

/// Одобряет заявку (с ключом чтения, зашифрованным под неё) либо
/// отклоняет.
///
/// 🔐 Что лежит в `grant`, сервер не знает и не проверяет: это
/// шифротекст под ключ заявителя.
pub(crate) async fn answer_request(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<AnswerRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let grant = request
        .grant
        .as_deref()
        .map(|grant| decode_bounded(grant, channels::MAX_JOIN_BLOB_BYTES))
        .transpose()?;
    let approval = decode_approval(request.approval.as_deref())?;

    channels::answer_request(
        &state.pool,
        account_id,
        channel_id,
        request.account_id,
        grant.as_deref(),
        approval.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Подписчики канала — тем, кто его ведёт.
pub(crate) async fn list_subscribers(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<MembersQuery>,
) -> Result<Json<Vec<MemberResponse>>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        channels::list_subscribers(&state.pool, account_id, channel_id, query.after)
            .await?
            .into_iter()
            .map(|member| MemberResponse {
                account_id: member.account_id,
                username: member.username,
            })
            .collect(),
    ))
}

/// Удаляет подписчика из канала; новую заявку от него сервер не примет.
pub(crate) async fn remove_subscriber(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<MemberRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::remove_subscriber(&state.pool, account_id, channel_id, request.account_id)
        .await
        .map_err(|error| match error {
            // Того, кто ведёт канал, так не удалить.
            RepoError::Conflict => ApiError::BadRequest,
            other => other.into(),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Удалённые из канала — тем, кто его ведёт.
pub(crate) async fn list_bans(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<MemberResponse>>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        channels::list_bans(&state.pool, account_id, channel_id)
            .await?
            .into_iter()
            .map(|member| MemberResponse {
                account_id: member.account_id,
                username: member.username,
            })
            .collect(),
    ))
}

/// Снимает запрет: удалённый снова может подать заявку.
pub(crate) async fn unban(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<MemberRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    channels::unban(&state.pool, account_id, channel_id, request.account_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Аккаунт участника канала — либо `404`, как на несуществующий канал.
async fn member_of(
    state: &AppState,
    device: AuthenticatedDevice,
    device_id: Uuid,
    channel_id: Uuid,
) -> Result<Uuid, ApiError> {
    let (account_id, _) = owner_of(state, device, device_id).await?;

    if channels::is_member(&state.pool, channel_id, account_id).await? {
        Ok(account_id)
    } else {
        Err(ApiError::NotFound)
    }
}

/// Канал — участнику, за подписью. Так читается закрытый канал.
pub(crate) async fn member_info(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ChannelResponse>, ApiError> {
    member_of(&state, device, device_id, channel_id).await?;

    Ok(Json(
        channels::find_channel(&state.pool, channel_id)
            .await?
            .into(),
    ))
}

/// Записи канала — участнику, за подписью.
pub(crate) async fn member_posts(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<PostsQuery>,
) -> Result<Json<Vec<PostResponse>>, ApiError> {
    member_of(&state, device, device_id, channel_id).await?;

    Ok(Json(select_posts(&state, channel_id, &query).await?))
}

/// Медиаблоб канала — участнику, за подписью.
pub(crate) async fn member_media(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id, media_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Vec<u8>, ApiError> {
    member_of(&state, device, device_id, channel_id).await?;

    Ok(channels::fetch_media(&state.pool, channel_id, media_id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 По имени сервер раздаёт только ссылку на этот самый канал.
    #[test]
    fn a_public_link_must_point_at_its_channel() {
        let channel = Uuid::from_u128(0x1234_5678_9abc_def0_0123_4567_89ab_cdef);
        let good = "gasapp://channel/123456789abcdef00123456789abcdef.ABCDEF234567.ZYXWVU765432";

        assert!(is_link_to(good, channel));
        assert!(!is_link_to(good, Uuid::from_u128(7)));

        for bad in [
            "",
            "https://example.org/",
            "gasapp://contact/123456789abcdef00123456789abcdef.ABC.DEF",
            "gasapp://channel/123456789abcdef00123456789abcdef.ABC",
            "gasapp://channel/123456789abcdef00123456789abcdef.ABC.DEF.GHI",
            "gasapp://channel/123456789abcdef00123456789abcdef.abc.DEF",
            "gasapp://channel/123456789abcdef00123456789abcdef..DEF",
            "gasapp://channel/123456789ABCDEF00123456789ABCDEF.ABC.DEF",
        ] {
            assert!(!is_link_to(bad, channel), "{bad:?}");
        }
    }
}
