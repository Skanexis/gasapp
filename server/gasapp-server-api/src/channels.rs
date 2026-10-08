// SPDX-License-Identifier: AGPL-3.0-only

//! Премиум и каналы.
//!
//! # Что такое канал
//!
//! Лента записей одного автора для многих читателей — как канал
//! в Telegram, с двумя отличиями, которые следуют из устройства GasApp:
//!
//! * **сервер не читает канал.** Название, описание и записи приходят
//!   шифротекстом на ключе канала. Ключ лежит в ссылке-приглашении
//!   (`gasapp://channel/…`) и на сервер не попадает;
//! * **сервер не знает читателей.** Подписки нет как серверного
//!   понятия: читатель забирает записи без подписи запроса, зная
//!   идентификатор канала. Список каналов человека живёт на его
//!   устройстве.
//!
//! Отсюда прямое следствие: каталога каналов и поиска по ним нет —
//! канал находят по ссылке или QR-коду.
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
//! взломанный сервер может не отдать запись или отдать не все, но не
//! может подделать запись от имени автора.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use gasapp_server_db::channels::{self, MAX_META_BYTES, MAX_POSTS_PER_PAGE, MAX_POST_BYTES};
use gasapp_server_db::repo::RepoError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::AuthenticatedDevice;
use crate::rate_limit;
use crate::routes::{decode_hex, now_millis, ApiError, AppState};

/// Сколько записей в минуту принимает один канал.
pub const POSTS_PER_MINUTE: u32 = 30;

/// Длина публичного ключа подписи записей.
const VERIFY_KEY_LEN: usize = 32;

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

/// Запрос замены описания канала.
#[derive(Debug, Deserialize)]
pub struct UpdateMetaRequest {
    /// Зашифрованное описание канала, hex.
    pub meta: String,
}

/// Запрос публикации.
#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    /// Шифротекст записи, hex.
    pub body: String,
}

/// Ответ на публикацию.
#[derive(Debug, Serialize)]
pub struct PublishResponse {
    /// Номер записи в канале.
    pub seq: i64,
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
}

/// Запись канала.
#[derive(Debug, Serialize)]
pub struct PostResponse {
    /// Номер записи.
    pub seq: i64,
    /// Шифротекст, hex.
    pub body: String,
    /// Час публикации, миллисекунды эпохи.
    pub posted_at: i64,
}

/// Параметры выборки записей.
#[derive(Debug, Deserialize)]
pub struct PostsQuery {
    /// Отдать записи с номером больше этого.
    #[serde(default)]
    pub after: i64,
    /// Сколько записей отдать (не больше ста).
    #[serde(default)]
    pub limit: Option<i64>,
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

/// Заменяет описание своего канала.
pub(crate) async fn update_meta(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, channel_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMetaRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;
    let meta = decode_bounded(&request.meta, MAX_META_BYTES)?;

    channels::update_meta(&state.pool, account_id, channel_id, &meta).await?;

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
    {
        let key = rate_limit::key_from_addr(&state.limiter_salt, &channel_id.to_string());
        let mut limiter = state
            .channel_post_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        if !limiter.allow(key, now_millis()) {
            return Err(ApiError::TooManyRequests);
        }
    }

    let seq = channels::publish_post(&state.pool, account_id, channel_id, &body).await?;

    Ok(Json(PublishResponse { seq }))
}

/// Канал по идентификатору — без подписи.
pub(crate) async fn info(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelResponse>, ApiError> {
    let channel = channels::find_channel(&state.pool, channel_id).await?;

    Ok(Json(ChannelResponse {
        channel_id: channel.channel_id,
        verify_key: hex::encode(channel.verify_key),
        meta: hex::encode(channel.meta),
        last_seq: channel.last_seq,
    }))
}

/// Записи канала после номера `after` — без подписи.
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
    let posts = channels::list_posts(&state.pool, channel_id, query.after.max(0), limit).await?;

    Ok(Json(
        posts
            .into_iter()
            .map(|post| PostResponse {
                seq: post.seq,
                body: hex::encode(post.body),
                posted_at: post.posted_at_millis,
            })
            .collect(),
    ))
}
