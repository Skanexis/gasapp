// SPDX-License-Identifier: AGPL-3.0-only

//! Связывание и отключение устройств (`docs/protocol/MULTI-DEVICE.md`, §3, §5).
//!
//! ```text
//! B (новое):   POST /v1/link/{nonce}            запрос — открытые ключи
//! A (основное): GET  /v1/link/{nonce}/request    по nonce из QR
//!              PUT  /v1/devices/{A}/link/{nonce} грант и список с B (подпись A)
//! B:           GET  /v1/link/{nonce}/grant       шифротекст для B
//!              POST /v1/link/{nonce}/complete    подпись B — устройство создано
//! A:           DELETE /v1/devices/{A}/linked/{X} список без X (подпись A)
//! ```
//!
//! 🔐 Без подписи — только ящик: его nonce (16 случайных байт) знают лишь
//! два экрана рядом. Создать устройство без гранта основного нельзя, а
//! грант принимается только за подписью основного устройства. Завершает
//! связывание тот, кто владеет ключом из запроса: подпись nonce.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use gasapp_server_db::devices;
use gasapp_server_db::repo::RepoError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::AuthenticatedDevice;
use crate::routes::{decode_hex, ApiError, AppState};

/// Предел гранта: конверт с данными приложения (1 МиБ) и списком.
const MAX_GRANT_BYTES: usize = 1_200_000;
/// Предел списка устройств: 5 устройств по 2000 байт и подпись.
const MAX_LIST_BYTES: usize = 20_000;
/// Что подписывает новое устройство, завершая связывание.
const COMPLETE_DOMAIN: &[u8] = b"GASAPP_LINK_COMPLETE_v1";

/// Запрос нового устройства.
#[derive(Debug, Deserialize)]
pub struct LinkRequestBody {
    /// `LinkRequest`, hex.
    pub request: String,
}

/// Запрос из ящика.
#[derive(Debug, Serialize, Deserialize)]
pub struct LinkRequestResponse {
    /// `LinkRequest`, hex.
    pub request: String,
}

/// Грант основного устройства.
#[derive(Debug, Deserialize)]
pub struct GrantBody {
    /// Конверт для нового устройства, hex.
    pub grant: String,
    /// Подписанный список устройств с новым, hex.
    pub device_list: String,
}

/// Грант для нового устройства.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantResponse {
    /// Конверт, hex.
    pub grant: String,
}

/// Завершение связывания.
#[derive(Debug, Deserialize)]
pub struct CompleteBody {
    /// Подпись `GASAPP_LINK_COMPLETE_v1 ‖ nonce` ключом нового устройства, hex.
    pub signature: String,
}

/// Новое устройство создано.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteResponse {
    /// Аккаунт.
    pub account_id: Uuid,
    /// Новое устройство.
    pub device_id: Uuid,
}

/// Список устройств аккаунта.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceListResponse {
    /// Подписанный список, hex.
    pub device_list: String,
}

/// Отключение устройства.
#[derive(Debug, Deserialize)]
pub struct UnlinkBody {
    /// Подписанный список без отключаемого, hex.
    pub device_list: String,
}

fn bounded_hex(text: &str, limit: usize) -> Result<Vec<u8>, ApiError> {
    if text.len() > limit.saturating_mul(2) {
        return Err(ApiError::PayloadTooLarge);
    }
    decode_hex(text)
}

/// Новое устройство открывает ящик с запросом.
pub(crate) async fn open(
    State(state): State<Arc<AppState>>,
    Path(nonce): Path<Uuid>,
    Json(body): Json<LinkRequestBody>,
) -> Result<StatusCode, ApiError> {
    let request = bounded_hex(&body.request, devices::LINK_REQUEST_LEN)?;
    let parsed = devices::parse_link_request(&request).ok_or(ApiError::BadRequest)?;
    if parsed.nonce != nonce {
        return Err(ApiError::BadRequest);
    }
    devices::open_box(&state.pool, nonce, &request)
        .await
        .map_err(|error| match error {
            RepoError::Conflict => ApiError::Conflict,
            other => other.into(),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// Основное устройство берёт запрос по nonce из QR.
pub(crate) async fn request(
    State(state): State<Arc<AppState>>,
    Path(nonce): Path<Uuid>,
) -> Result<Json<LinkRequestResponse>, ApiError> {
    let request = devices::box_request(&state.pool, nonce).await?;
    Ok(Json(LinkRequestResponse {
        request: hex::encode(request),
    }))
}

/// Основное устройство выдаёт грант.
pub(crate) async fn grant(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, nonce)): Path<(Uuid, Uuid)>,
    Json(body): Json<GrantBody>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }
    let grant = bounded_hex(&body.grant, MAX_GRANT_BYTES)?;
    let list = bounded_hex(&body.device_list, MAX_LIST_BYTES)?;
    if grant.is_empty() {
        return Err(ApiError::BadRequest);
    }
    devices::put_grant(&state.pool, nonce, device_id, &grant, &list)
        .await
        .map_err(|error| match error {
            // Не основное устройство, чужие устройства, старая версия.
            RepoError::Conflict => ApiError::Forbidden,
            other => other.into(),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// Новое устройство забирает грант; пока его нет — `404`.
pub(crate) async fn take_grant(
    State(state): State<Arc<AppState>>,
    Path(nonce): Path<Uuid>,
) -> Result<Json<GrantResponse>, ApiError> {
    let grant = devices::take_grant(&state.pool, nonce).await?;
    Ok(Json(GrantResponse {
        grant: hex::encode(grant),
    }))
}

/// Новое устройство завершает связывание подписью своего ключа.
pub(crate) async fn complete(
    State(state): State<Arc<AppState>>,
    Path(nonce): Path<Uuid>,
    Json(body): Json<CompleteBody>,
) -> Result<Json<CompleteResponse>, ApiError> {
    let signature = bounded_hex(&body.signature, 64)?;
    let request = devices::granted_request(&state.pool, nonce).await?;

    let mut message = COMPLETE_DOMAIN.to_vec();
    message.extend_from_slice(nonce.as_bytes());
    crate::auth::verify_challenge_signature(&request.identity, &message, &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    let (account_id, device_id) =
        devices::complete_link(&state.pool, nonce)
            .await
            .map_err(|error| match error {
                RepoError::Conflict => ApiError::Conflict,
                other => other.into(),
            })?;
    Ok(Json(CompleteResponse {
        account_id,
        device_id,
    }))
}

/// Подписанный список устройств аккаунта — без подписи запроса: в нём
/// только открытые ключи, а аккаунт получатель знает из сертификата
/// отправителя. Нет списка — `404` (у аккаунта одно устройство).
pub(crate) async fn device_list_of(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<Uuid>,
) -> Result<Json<DeviceListResponse>, ApiError> {
    let list = devices::device_list(&state.pool, account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(DeviceListResponse {
        device_list: hex::encode(list),
    }))
}

/// Основное устройство отключает другое.
pub(crate) async fn unlink(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path((device_id, target)): Path<(Uuid, Uuid)>,
    Json(body): Json<UnlinkBody>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }
    let list = bounded_hex(&body.device_list, MAX_LIST_BYTES)?;
    devices::unlink_device(&state.pool, device_id, target, &list)
        .await
        .map_err(|error| match error {
            RepoError::Conflict => ApiError::Forbidden,
            other => other.into(),
        })?;
    Ok(StatusCode::NO_CONTENT)
}
