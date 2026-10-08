// SPDX-License-Identifier: Apache-2.0

//! Сообщение, которое подписывает клиент для аутентификации запроса.
//!
//! # Что подписывается
//!
//! Метод, путь, время выпуска и SHA-256 тела — то есть **конкретный
//! запрос**, а не свободный челлендж. Подпись под челленджем годилась бы
//! для любого действия: перехватив её у запроса на чтение очереди,
//! атакующий предъявил бы её при подмене предключей, а это уже подмена
//! личности.
//!
//! ```text
//! GASAPP_AUTH_v2 ‖ '\n' ‖ METHOD ‖ '\n' ‖ PATH ‖ '\n' ‖ issued_at
//!               ‖ '\n' ‖ hex(SHA-256(body))
//! ```
//!
//! # 🔐 Почему тело — часть подписи
//!
//! В v1 тела в подписи не было. Кто видел запрос открытым — прокси,
//! завершающий TLS перед сервером, его журнал, — пять минут
//! подписи мог предъявлять её с **другим** телом: к `PUT` предключей
//! подложить свои ключи, а это подмена личности. Хеш тела едет ещё
//! и заголовком ([`BODY_SHA256_HEADER`]): так сервер проверяет подпись
//! до чтения тела и не буферизует тела тех, кто не доказал, кто он.
//!
//! # Почему код продублирован с сервером
//!
//! Клиент под Apache-2.0, сервер под AGPL-3.0: общий крейт связал бы
//! лицензии. Расхождение ловит вектор в тесте на совместимость —
//! иначе оно проявилось бы как отказ **всех** запросов без внятной
//! причины.
//!
//! # Чего здесь нет
//!
//! Самой подписи: она требует приватного ключа, который живёт в ядре
//! и в сетевой слой не передаётся.

/// Домен-разделитель подписи запроса.
///
/// Не даёт засчитать здесь подпись, сделанную в другом контексте —
/// например, подпись предключа.
const AUTH_DOMAIN: &[u8] = b"GASAPP_AUTH_v2";

/// Имя заголовка с подписью, hex.
pub const SIGNATURE_HEADER: &str = "x-gasapp-signature";

/// Имя заголовка с временем выпуска, миллисекунды.
pub const ISSUED_AT_HEADER: &str = "x-gasapp-issued-at";

/// Имя заголовка с SHA-256 тела запроса, hex.
pub const BODY_SHA256_HEADER: &str = "x-gasapp-body-sha256";

/// Подписывающая сторона: ядро, у которого приватный ключ устройства.
///
/// Сетевой слой ключа не видит и видеть не должен — он отдаёт сообщение
/// на подпись и получает подпись обратно. Сообщение собирается здесь,
/// из того, что уйдёт в сеть: метод, путь и тело подписываются ровно
/// те, что отправляются. Прежде ядро собирало заголовки само и повторяло
/// путь, который потом отдельно собирал сетевой клиент, — два места,
/// которые обязаны совпадать байт в байт.
pub trait RequestSigner {
    /// Время выпуска подписи, миллисекунды.
    fn issued_at(&self) -> i64;

    /// Подписывает сообщение [`signed_message`].
    ///
    /// # Errors
    ///
    /// [`gasapp_types::GasAppError::Crypto`] — подпись не построилась.
    fn sign(&self, message: &[u8]) -> gasapp_types::Result<Vec<u8>>;
}

/// SHA-256 тела запроса.
#[must_use]
pub fn body_sha256(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(body).into()
}

/// Заголовки подписи запроса: подпись, время выпуска и хеш тела.
///
/// # Errors
///
/// [`gasapp_types::GasAppError::Crypto`] — подпись не построилась.
pub fn signature_headers(
    signer: &dyn RequestSigner,
    method: &str,
    path: &str,
    body: &[u8],
) -> gasapp_types::Result<Vec<(String, String)>> {
    let digest = body_sha256(body);
    let issued_at = signer.issued_at();
    let signature = signer.sign(&signed_message(method, path, issued_at, &digest))?;

    Ok(vec![
        (SIGNATURE_HEADER.to_owned(), to_hex(&signature)),
        (ISSUED_AT_HEADER.to_owned(), issued_at.to_string()),
        (BODY_SHA256_HEADER.to_owned(), to_hex(&digest)),
    ])
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

/// Собирает сообщение для подписи.
///
/// Разделители обязательны: без них метод `GET` с путём `/ab` и метод
/// `GETA` с путём `/b` дали бы одно и то же сообщение, а значит одна
/// подпись подошла бы к двум разным запросам.
#[must_use]
pub fn signed_message(method: &str, path: &str, issued_at: i64, body_sha256: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        AUTH_DOMAIN
            .len()
            .saturating_add(method.len())
            .saturating_add(path.len())
            .saturating_add(32 + 64),
    );

    message.extend_from_slice(AUTH_DOMAIN);
    message.push(b'\n');
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(path.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(issued_at.to_string().as_bytes());
    message.push(b'\n');
    message.extend_from_slice(to_hex(body_sha256).as_bytes());

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 пустого тела — у GET и DELETE.
    const EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    /// 🔐 Подпись привязана к телу: подпись одного тела не подойдёт
    /// к другому. В v1 тела в подписи не было.
    #[test]
    fn message_depends_on_body() {
        assert_ne!(
            signed_message("PUT", "/v1/keys/abc", 1, &body_sha256(b"{\"keys\":1}")),
            signed_message("PUT", "/v1/keys/abc", 1, &body_sha256(b"{\"keys\":2}"))
        );
    }

    /// Хеш пустого тела — известный вектор SHA-256.
    #[test]
    fn empty_body_hash_is_the_sha256_of_nothing() {
        assert_eq!(body_sha256(b""), EMPTY);
    }

    /// 🔐 Вектор совместимости с сервером.
    ///
    /// Байты зафиксированы и продублированы в тесте сервера
    /// (`client_contract.rs`). Расхождение реализаций проявилось бы
    /// как отказ всех запросов, и причину такого отказа искать долго:
    /// сервер отвечает 401 без объяснений — намеренно, чтобы не
    /// подсказывать атакующему.
    #[test]
    fn message_matches_fixed_vector() {
        let message = signed_message("GET", "/v1/messages/abc", 1_700_000_000_000, &EMPTY);

        assert_eq!(
            message,
            b"GASAPP_AUTH_v2\nGET\n/v1/messages/abc\n1700000000000\n\
              e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_vec()
        );
    }

    /// Подпись привязана к методу.
    #[test]
    fn message_depends_on_method() {
        assert_ne!(
            signed_message("GET", "/v1/messages/abc", 1, &EMPTY),
            signed_message("PUT", "/v1/messages/abc", 1, &EMPTY)
        );
    }

    /// Подпись привязана к пути: подпись к своей очереди не подойдёт
    /// к чужой.
    #[test]
    fn message_depends_on_path() {
        assert_ne!(
            signed_message("GET", "/v1/messages/mine", 1, &EMPTY),
            signed_message("GET", "/v1/messages/theirs", 1, &EMPTY)
        );
    }

    /// Подпись привязана ко времени выпуска.
    #[test]
    fn message_depends_on_time() {
        assert_ne!(
            signed_message("GET", "/v1/messages/abc", 1, &EMPTY),
            signed_message("GET", "/v1/messages/abc", 2, &EMPTY)
        );
    }

    /// Разделители не дают склеить поля.
    #[test]
    fn fields_cannot_be_confused() {
        assert_ne!(
            signed_message("GET", "/ab", 1, &EMPTY),
            signed_message("GETA", "/b", 1, &EMPTY)
        );
    }
}
