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
//! * **сервер не знает читателей.** Читатель забирает записи без
//!   подписи запроса. Подписчик для сервера — случайный жетон, по
//!   которому считаются подписчики, просмотры и реакции; чей он,
//!   в базе не записано.
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
use sha2::{Digest as _, Sha256};
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

/// Длина жетона подписчика.
const TOKEN_LEN: usize = 32;

/// Состояние аккаунта — то, что приложению нужно знать о себе.
#[derive(Debug, Serialize)]
pub struct AccountStatusResponse {
    /// Есть ли у аккаунта премиум.
    pub premium: bool,
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

/// Запрос подписки.
#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    /// Жетон подписчика, hex.
    pub token: String,
    /// Зерно пропуска, hex.
    pub pass_seed: String,
    /// Код траты пропуска на эту подписку, hex
    /// (см. [`crate::pass::subscribe_binding`]).
    pub pass_mac: String,
}

/// Запрос пропусков: замаскированные точки, hex.
#[derive(Debug, Deserialize)]
pub struct IssuePassesRequest {
    /// Точки на подпись.
    pub blinded: Vec<String>,
}

/// Подписанная точка с доказательством.
#[derive(Debug, Serialize)]
pub struct SignedPass {
    /// Подписанная точка, hex.
    pub point: String,
    /// Доказательство DLEQ, hex.
    pub proof: String,
}

/// Ответ на запрос пропусков.
#[derive(Debug, Serialize)]
pub struct IssuePassesResponse {
    /// Публичный ключ пропусков узла, hex: с ним сверяются доказательства.
    pub key: String,
    /// Подписанные точки — в порядке запроса.
    pub signed: Vec<SignedPass>,
}

/// Запрос с жетоном подписчика: отписка.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// Жетон подписчика, hex.
    pub token: String,
}

/// Отметка «дочитал до записи».
#[derive(Debug, Deserialize)]
pub struct SeenRequest {
    /// Жетон подписчика, hex.
    pub token: String,
    /// Номер записи.
    pub seq: i64,
}

/// Реакция на запись.
#[derive(Debug, Deserialize)]
pub struct ReactRequest {
    /// Жетон подписчика, hex.
    pub token: String,
    /// Номер записи.
    pub seq: i64,
    /// Эмодзи из [`REACTIONS`]; `None` — снять реакцию.
    #[serde(default)]
    pub emoji: Option<String>,
}

/// Аккаунт подписавшего устройства — и только если оно названо в пути.
async fn owner_of(
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

/// Хеш жетона подписчика: в базе лежит он, а не сам жетон.
fn token_hash(token_hex: &str) -> Result<([u8; TOKEN_LEN], [u8; 32]), ApiError> {
    let token: [u8; TOKEN_LEN] = decode_hex(token_hex)?
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;

    Ok((token, Sha256::digest(token).into()))
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

/// Ограничитель действий читателя — по жетону.
fn limit_reader(state: &AppState, hash: &[u8; 32]) -> Result<(), ApiError> {
    let key = rate_limit::key_from_addr(&state.limiter_salt, &hex::encode(hash));
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

    Ok(Json(AccountStatusResponse { premium }))
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

    if request.set_public {
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
    Ok(Json(
        channels::find_channel(&state.pool, channel_id)
            .await?
            .into(),
    ))
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
    let limit = query.limit.unwrap_or(MAX_POSTS_PER_PAGE);

    let posts = match query.after_rev {
        Some(after) => {
            channels::changes_since(&state.pool, channel_id, after.max(0), limit).await?
        }
        None => channels::page_before(&state.pool, channel_id, query.before_seq, limit).await?,
    };

    Ok(Json(posts.into_iter().map(PostResponse::from).collect()))
}

/// Медиаблоб канала — без подписи.
pub(crate) async fn media(
    State(state): State<Arc<AppState>>,
    Path((channel_id, media_id)): Path<(Uuid, Uuid)>,
) -> Result<Vec<u8>, ApiError> {
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

/// Выдаёт аккаунту пропуска — подписывает присланные замаскированные
/// точки.
///
/// 🔐 За подписью устройства: сколько пропусков взял аккаунт, сервер
/// знает и ограничивает. На что они пойдут — не знает: точки
/// замаскированы, и при трате сервер увидит уже другое (см. `pass`).
///
/// Сверх суточного предела — `429`.
pub(crate) async fn issue_passes(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<IssuePassesRequest>,
) -> Result<Json<IssuePassesResponse>, ApiError> {
    use gasapp_server_db::passes;

    let (account_id, _) = owner_of(&state, device, device_id).await?;

    if request.blinded.is_empty() || request.blinded.len() > passes::MAX_PASSES_PER_REQUEST {
        return Err(ApiError::BadRequest);
    }

    // Сначала разбор и подпись, потом счёт: негодный запрос предел
    // аккаунта не тратит.
    let mut signed = Vec::with_capacity(request.blinded.len());
    for blinded in &request.blinded {
        let point: [u8; crate::pass::LEN] = decode_hex(blinded)?
            .try_into()
            .map_err(|_| ApiError::BadRequest)?;
        let (point, proof) = state.pass_key.sign(&point).ok_or(ApiError::BadRequest)?;

        signed.push(SignedPass {
            point: hex::encode(point),
            proof: hex::encode(proof),
        });
    }

    let wanted = i32::try_from(signed.len()).map_err(|_| ApiError::BadRequest)?;
    passes::reserve(&state.pool, account_id, wanted)
        .await
        .map_err(|error| match error {
            RepoError::QuotaExceeded => ApiError::TooManyRequests,
            other => other.into(),
        })?;

    Ok(Json(IssuePassesResponse {
        key: hex::encode(state.pass_key.public()),
        signed,
    }))
}

/// Подписка: жетон читателя попадает в счётчик подписчиков.
///
/// 🔐 Без подписи устройства: сервер не узнаёт, кто подписался.
/// Цена — пропуск: одноразовое право, которое сервер выдал какому-то
/// аккаунту вслепую и теперь не может связать с ним. Без неё счётчик
/// накручивался бы циклом; с ней — не быстрее, чем аккаунты берут
/// пропуска.
pub(crate) async fn subscribe(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
    Json(request): Json<SubscribeRequest>,
) -> Result<StatusCode, ApiError> {
    let (token, hash) = token_hash(&request.token)?;
    let seed: [u8; crate::pass::LEN] = decode_hex(&request.pass_seed)?
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;
    let mac: [u8; crate::pass::LEN] = decode_hex(&request.pass_mac)?
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;

    // Подлинность — до базы: поддельный пропуск не стоит ей запроса.
    let binding = crate::pass::subscribe_binding(&channel_id.to_string(), &token);
    if !state.pass_key.accepts(&seed, &binding, &mac) {
        return Err(ApiError::Unauthorized);
    }

    // Канал — до траты: пропуск не сгорает на канале, которого нет.
    channels::find_channel(&state.pool, channel_id).await?;

    if !gasapp_server_db::passes::spend(&state.pool, &Sha256::digest(seed).into()).await? {
        return Err(ApiError::Unauthorized);
    }

    channels::subscribe(&state.pool, channel_id, &hash).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Отписка: жетон и его реакции исчезают.
pub(crate) async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
    Json(request): Json<TokenRequest>,
) -> Result<StatusCode, ApiError> {
    let (_, hash) = token_hash(&request.token)?;

    channels::unsubscribe(&state.pool, channel_id, &hash).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Отметка «дочитал до записи» — из неё складываются просмотры.
pub(crate) async fn seen(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
    Json(request): Json<SeenRequest>,
) -> Result<StatusCode, ApiError> {
    let (_, hash) = token_hash(&request.token)?;

    limit_reader(&state, &hash)?;
    channels::mark_seen(&state.pool, channel_id, &hash, request.seq.max(0)).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Реакция подписчика на запись: поставить, сменить или снять.
pub(crate) async fn react(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
    Json(request): Json<ReactRequest>,
) -> Result<StatusCode, ApiError> {
    let (_, hash) = token_hash(&request.token)?;

    // Набор закрыт: произвольная строка была бы способом писать в
    // чужой канал.
    if let Some(emoji) = &request.emoji {
        if !REACTIONS.contains(&emoji.as_str()) {
            return Err(ApiError::BadRequest);
        }
    }

    limit_reader(&state, &hash)?;
    channels::react(
        &state.pool,
        channel_id,
        &hash,
        request.seq,
        request.emoji.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
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
