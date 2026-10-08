// SPDX-License-Identifier: AGPL-3.0-only

//! Боты: аккаунты, которые ведёт программа владельца.
//!
//! Владелец с премиумом берёт одноразовый токен под имя на `bot`;
//! программа бота по токену регистрируется со своими ключами. Дальше
//! бот — обычный аккаунт: ему пишут, его назначают администратором
//! канала, и всё, что он делает, делает его программа теми же
//! запросами, что и приложение. Сервер за бота ничего не делает.
//!
//! 🔐 Токен сервер хранит хешем и отдаёт владельцу один раз. Ключей
//! бота сервер не видит, как и ключей любого аккаунта.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use gasapp_server_db::bots;
use gasapp_server_db::repo::RepoError;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::authz::AuthenticatedDevice;
use crate::channels::owner_of;
use crate::pow;
use crate::routes::{decode_hex, decode_pq_identity, ApiError, AppState, RegisterResponse};

/// Длина токена бота.
const TOKEN_LEN: usize = 32;

/// Запрос токена под имя будущего бота либо удаления бота.
#[derive(Debug, Deserialize)]
pub struct BotNameRequest {
    /// Имя бота: каноничное и на `bot`.
    pub username: String,
}

/// Токен, по которому программа бота зарегистрируется.
#[derive(Debug, Serialize)]
pub struct BotTokenResponse {
    /// Токен, hex. Отдаётся один раз: сервер хранит только его хеш.
    pub token: String,
    /// Сколько секунд токен действует.
    pub expires_in: i64,
}

/// Бот глазами владельца.
#[derive(Debug, Serialize)]
pub struct BotResponse {
    /// Аккаунт бота.
    pub account_id: Uuid,
    /// Имя бота.
    pub username: String,
}

/// Регистрация бота его программой.
#[derive(Debug, Deserialize)]
pub struct RegisterBotRequest {
    /// Токен от владельца, hex.
    pub token: String,
    /// Имя, под которое токен выдан.
    pub username: String,
    /// Публичный identity-ключ аккаунта, hex.
    pub identity_key: String,
    /// Публичный identity-ключ устройства, hex.
    pub device_identity_key: String,
    /// Пост-квантовая половина identity — ключ ML-DSA-65, hex.
    pub pq_identity_key: String,
    /// Гибридная привязка половин identity, hex.
    pub identity_binding: String,
    /// Челлендж proof-of-work, hex.
    pub pow_challenge: String,
    /// Решение proof-of-work.
    pub pow_nonce: u64,
}

fn token_hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

/// Выдаёт владельцу токен под имя будущего бота. Только с премиумом.
///
/// Занятое имя — `409`, предел ботов — `507`, нет премиума — `403`.
pub(crate) async fn create(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<BotNameRequest>,
) -> Result<Json<BotTokenResponse>, ApiError> {
    let (account_id, premium) = owner_of(&state, device, device_id).await?;

    if !premium {
        return Err(ApiError::Forbidden);
    }

    if !bots::is_bot_username(&request.username) {
        return Err(ApiError::BadRequest);
    }

    let mut token = [0u8; TOKEN_LEN];
    rand::rngs::OsRng.fill_bytes(&mut token);

    bots::issue_token(
        &state.pool,
        account_id,
        &request.username,
        &token_hash(&token),
    )
    .await
    .map_err(|error| match error {
        // Премиум сняли между проверкой и записью.
        RepoError::Conflict => ApiError::Forbidden,
        other => other.into(),
    })?;

    Ok(Json(BotTokenResponse {
        token: hex::encode(token),
        expires_in: bots::BOT_TOKEN_TTL_SECS,
    }))
}

/// Боты владельца.
pub(crate) async fn list(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<Json<Vec<BotResponse>>, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    Ok(Json(
        bots::list_bots(&state.pool, account_id)
            .await?
            .into_iter()
            .map(|bot| BotResponse {
                account_id: bot.account_id,
                username: bot.username,
            })
            .collect(),
    ))
}

/// Удаляет бота владельца вместе с его аккаунтом.
pub(crate) async fn delete(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<BotNameRequest>,
) -> Result<StatusCode, ApiError> {
    let (account_id, _) = owner_of(&state, device, device_id).await?;

    bots::delete_bot(&state.pool, account_id, &request.username).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Регистрирует бота по токену владельца — без подписи: аккаунта у
/// программы бота ещё нет.
///
/// Работа (proof-of-work) та же, что при обычной регистрации, и
/// проверяется до базы. Негодный, истёкший и чужой токен дают один и
/// тот же `403`.
pub(crate) async fn register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterBotRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let challenge = decode_hex(&request.pow_challenge)?;
    let identity = decode_hex(&request.identity_key)?;
    let device_identity = decode_hex(&request.device_identity_key)?;
    let token = decode_hex(&request.token)?;

    if identity.len() != 32 || device_identity.len() != 32 || token.len() != TOKEN_LEN {
        return Err(ApiError::BadRequest);
    }

    if challenge != pow::registration_challenge(&request.username, &identity, &device_identity) {
        return Err(ApiError::Unauthorized);
    }

    pow::verify(&challenge, request.pow_nonce, state.pow_difficulty)
        .map_err(|_| ApiError::Unauthorized)?;

    if !bots::is_bot_username(&request.username) {
        return Err(ApiError::BadRequest);
    }

    let (pq_public, binding) = decode_pq_identity(
        Some(&request.pq_identity_key),
        Some(&request.identity_binding),
    )?
    .ok_or(ApiError::BadRequest)?;

    // 🔐 Токен годится только под то имя, над которым посчитана работа.
    let (account_id, device_id) = bots::register_bot(
        &state.pool,
        &token_hash(&token),
        &request.username,
        &identity,
        &device_identity,
        &pq_public,
        &binding,
    )
    .await
    .map_err(|error| match error {
        RepoError::NotFound => ApiError::Forbidden,
        other => other.into(),
    })?;

    Ok(Json(RegisterResponse {
        account_id,
        device_id,
    }))
}
