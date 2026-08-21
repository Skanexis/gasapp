// SPDX-License-Identifier: AGPL-3.0-only

//! Аутентификация запросов подписью устройства.
//!
//! # Что защищается
//!
//! Три маршрута, где отсутствие проверки означало прямую атаку:
//!
//! * `PUT /v1/keys/{device}` — без подписи любой мог заменить чужие
//!   предключи своими и получать сообщения, адресованные другому;
//! * `GET /v1/messages/{device}` — без подписи любой мог вычитать
//!   чужую очередь. Конверты зашифрованы, но их получение удаляет
//!   их с сервера, то есть лишает адресата переписки;
//! * `DELETE /v1/messages/{device}/{envelope}` — без подписи любой
//!   мог удалять чужие неполученные сообщения.
//!
//! # Что подписывается
//!
//! Не произвольный челлендж, а **сам запрос**: метод, путь и время
//! выпуска. Подпись под свободным челленджем годилась бы для любого
//! действия — перехватив её у запроса на чтение очереди, атакующий
//! предъявил бы её при подмене предключей.
//!
//! ```text
//! AEGIS_AUTH_v1 ‖ METHOD ‖ '\n' ‖ PATH ‖ '\n' ‖ issued_at
//! ```
//!
//! Домен-разделитель в начале не даёт засчитать здесь подпись,
//! сделанную в другом контексте — например, подпись предключа.
//!
//! # Защита от повтора
//!
//! Окно свежести — пять минут ([`crate::auth::CHALLENGE_TTL_MILLIS`]).
//! Внутри него подпись можно предъявить повторно, и это осознанный
//! размен: список использованных подписей означал бы состояние,
//! которое сервер обязан хранить для каждого гостя, то есть мишень
//! для исчерпания памяти. Повтор запроса на чтение собственной
//! очереди ничего атакующему не даёт — он всё равно не расшифрует
//! конверты, а окно в пять минут закрывает перехват «на потом».

use std::sync::Arc;

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use uuid::Uuid;

use crate::auth;
use crate::routes::{ApiError, AppState};

/// Домен-разделитель подписи запроса.
const AUTH_DOMAIN: &[u8] = b"AEGIS_AUTH_v1";

/// Заголовок с подписью, hex.
const SIGNATURE_HEADER: &str = "x-aegis-signature";

/// Заголовок с временем выпуска подписи, миллисекунды.
const ISSUED_AT_HEADER: &str = "x-aegis-issued-at";

/// Устройство, чья подпись проверена.
///
/// Наличие этого типа в аргументах обработчика означает, что запрос
/// пришёл от владельца устройства. Тип пустой снаружи: единственное,
/// что он несёт, — сам факт проверки и идентификатор.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedDevice {
    /// Устройство, подпись которого проверена.
    pub device_id: Uuid,
}

/// Извлекатель привязан к конкретному состоянию `Arc<AppState>`.
///
/// Обобщение по `S` выглядит аккуратнее, но требует, чтобы состояние
/// умело отдавать `Arc<AppState>` — а это ровно то же самое, только
/// выраженное через границу типа, которую компилятор не может вывести
/// для роутера. Конкретный тип честнее: у сервера одно состояние.
#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for AuthenticatedDevice {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Устройство берётся из пути: подписывающий обязан быть тем,
        // о чьих данных идёт речь. Идентификатор из заголовка позволил
        // бы подписать своим ключом запрос к чужой очереди.
        //
        // Путь бывает двух форм — `/…/{device}` и `/…/{device}/{envelope}`,
        // поэтому сначала пробуется одиночный параметр, затем пара.
        // Брать «первый параметр» вслепую нельзя: порядок в кортеже
        // задаётся маршрутом, и молчаливая опора на него сломалась бы
        // при добавлении маршрута с другим порядком.
        let device_id = if let Ok(Path(id)) =
            Path::<Uuid>::from_request_parts(parts, state).await
        {
            id
        } else {
            let Path((id, _)) = Path::<(Uuid, Uuid)>::from_request_parts(parts, state)
                .await
                .map_err(|_| ApiError::Unauthorized)?;

            id
        };


        let signature = header_bytes(parts, SIGNATURE_HEADER)?;
        let issued_at = header_i64(parts, ISSUED_AT_HEADER)?;

        auth::check_freshness(issued_at, crate::routes::now_millis())
            .map_err(|_| ApiError::Unauthorized)?;

        // Публичный ключ берётся из базы, а не из запроса: иначе
        // клиент подсунул бы свой и подписал что угодно.
        let device = aegis_server_db::repo::list_devices_by_id(&state.pool, device_id)
            .await
            .map_err(|_| ApiError::Unauthorized)?;

        let identity: [u8; 32] = device
            .identity_key
            .try_into()
            .map_err(|_| ApiError::Unauthorized)?;

        let message = signed_message(parts.method.as_str(), parts.uri.path(), issued_at);

        auth::verify_challenge_signature(&identity, &message, &signature)
            .map_err(|_| ApiError::Unauthorized)?;

        Ok(Self { device_id })
    }
}

/// Собирает сообщение, которое подписывает клиент.
///
/// Публична, потому что её обязан воспроизвести клиент: расхождение
/// хотя бы в одном байте отвергнет все запросы, и причину такого
/// отказа искать долго.
#[must_use]
pub fn signed_message(method: &str, path: &str, issued_at: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        AUTH_DOMAIN
            .len()
            .saturating_add(method.len())
            .saturating_add(path.len())
            .saturating_add(32),
    );

    message.extend_from_slice(AUTH_DOMAIN);
    message.push(b'\n');
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(path.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(issued_at.to_string().as_bytes());

    message
}

/// Читает заголовок с hex-значением.
fn header_bytes(parts: &Parts, name: &str) -> Result<Vec<u8>, ApiError> {
    let raw = parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    crate::routes::decode_hex(raw).map_err(|_| ApiError::Unauthorized)
}

/// Читает числовой заголовок.
fn header_i64(parts: &Parts, name: &str) -> Result<i64, ApiError> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse().ok())
        .ok_or(ApiError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Подпись привязана к методу.
    ///
    /// Иначе подпись запроса на чтение очереди годилась бы для замены
    /// предключей — а это подмена личности.
    #[test]
    fn message_depends_on_method() {
        let read = signed_message("GET", "/v1/messages/abc", 1);
        let write = signed_message("PUT", "/v1/messages/abc", 1);

        assert_ne!(read, write);
    }

    /// Подпись привязана к пути.
    ///
    /// Иначе подпись запроса к своей очереди годилась бы для чужой.
    #[test]
    fn message_depends_on_path() {
        let mine = signed_message("GET", "/v1/messages/mine", 1);
        let theirs = signed_message("GET", "/v1/messages/theirs", 1);

        assert_ne!(mine, theirs);
    }

    /// Подпись привязана ко времени выпуска.
    #[test]
    fn message_depends_on_time() {
        let first = signed_message("GET", "/v1/messages/abc", 1);
        let second = signed_message("GET", "/v1/messages/abc", 2);

        assert_ne!(first, second);
    }

    /// Домен-разделитель стоит первым.
    ///
    /// Без него подпись, сделанную в другом контексте — например,
    /// подпись предключа, — можно было бы предъявить здесь.
    #[test]
    fn message_starts_with_domain() {
        let message = signed_message("GET", "/v1/messages/abc", 1);

        assert!(message.starts_with(AUTH_DOMAIN));
    }

    /// Разделители не дают склеить поля.
    ///
    /// Без них путь `/a` с методом `bc` и путь `/abc` с пустым методом
    /// давали бы одну и ту же подпись.
    #[test]
    fn fields_cannot_be_confused() {
        let first = signed_message("GET", "/ab", 1);
        let second = signed_message("GETA", "/b", 1);

        assert_ne!(first, second);
    }
}
