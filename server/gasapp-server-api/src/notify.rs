// SPDX-License-Identifier: AGPL-3.0-only

//! Уведомления без провайдера: «есть ли новое» по токену (ADR-040).
//!
//! # Зачем
//!
//! Приложение в фоне заперто PIN: ключ устройства в зашифрованной базе,
//! и подписать запрос ему нечем. Доставка через Firebase решила бы это
//! ценой метаданных у третьей стороны и не работает в сборке без Google.
//! Здесь устройство само, раз в несколько минут, спрашивает сервер одно:
//! непуста ли его очередь.
//!
//! # Что даёт токен
//!
//! Только ответ «да» или «нет». Ни прочитать очередь, ни забрать её, ни
//! сделать что-либо от имени устройства по токену нельзя — всё это
//! по-прежнему требует подписи. Сервер хранит SHA-256 токена.
//!
//! ⚠️ Честно о цене: по этим запросам сервер видит, что телефон включён
//! и в сети, — как видел бы по открытому сокету. Времени обращений он не
//! записывает. При прямом соединении он видит и адрес.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::authz::AuthenticatedDevice;
use crate::rate_limit;
use crate::routes::{decode_hex, now_millis, ApiError, AppState};

/// Длина токена уведомлений.
const TOKEN_LEN: usize = 32;

/// Сколько проверок очереди устройство делает в минуту.
///
/// Приложение спрашивает раз в четверть часа; запас — на повторы после
/// сбоя сети. Предел не даёт превратить проверку в частый опрос, по
/// которому время прихода сообщения читалось бы с точностью до секунд.
pub const NOTIFY_CHECKS_PER_MINUTE: u32 = 4;

/// Запрос на регистрацию токена.
#[derive(Debug, Deserialize)]
pub struct NotifyTokenRequest {
    /// SHA-256 токена, hex.
    pub token_hash: String,
}

/// Проверка очереди.
#[derive(Debug, Deserialize)]
pub struct NotifyCheckRequest {
    /// Устройство.
    pub device_id: Uuid,
    /// Токен уведомлений, hex.
    pub token: String,
}

/// Ответ проверки.
#[derive(Debug, Serialize)]
pub struct NotifyCheckResponse {
    /// Есть ли в очереди недоставленное.
    pub pending: bool,
}

/// Запоминает токен уведомлений устройства. За подписью устройства.
pub(crate) async fn register(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
    Json(request): Json<NotifyTokenRequest>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    let hash: [u8; 32] = decode_hex(&request.token_hash)?
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;

    gasapp_server_db::notify::set_token(&state.pool, device_id, &hash).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Забывает токен: уведомления выключены. За подписью устройства.
pub(crate) async fn unregister(
    State(state): State<Arc<AppState>>,
    device: AuthenticatedDevice,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if device.device_id != device_id {
        return Err(ApiError::Unauthorized);
    }

    gasapp_server_db::notify::delete_token(&state.pool, device_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Отвечает, непуста ли очередь, — предъявившему токен.
///
/// 🔐 Без подписи: в фоне подписывать нечем. Неизвестное устройство и
/// неверный токен дают один и тот же отказ.
pub(crate) async fn check(
    State(state): State<Arc<AppState>>,
    Json(request): Json<NotifyCheckRequest>,
) -> Result<Json<NotifyCheckResponse>, ApiError> {
    let token = decode_hex(&request.token)?;

    if token.len() != TOKEN_LEN {
        return Err(ApiError::BadRequest);
    }

    // Предел — до обращения к базе: перебор токена не должен стоить
    // серверу запроса на каждую попытку.
    {
        let key = rate_limit::key_from_addr(&state.limiter_salt, &request.device_id.to_string());
        let mut limiter = state
            .notify_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        if !limiter.allow(key, now_millis()) {
            return Err(ApiError::TooManyRequests);
        }
    }

    let hash: [u8; 32] = Sha256::digest(&token).into();

    gasapp_server_db::notify::pending(&state.pool, request.device_id, &hash)
        .await?
        .map(|pending| Json(NotifyCheckResponse { pending }))
        .ok_or(ApiError::Unauthorized)
}
