// SPDX-License-Identifier: Apache-2.0

//! Сообщение, которое подписывает клиент для аутентификации запроса.
//!
//! # Что подписывается
//!
//! Метод, путь и время выпуска — то есть **конкретный запрос**,
//! а не свободный челлендж. Подпись под челленджем годилась бы для
//! любого действия: перехватив её у запроса на чтение очереди,
//! атакующий предъявил бы её при подмене предключей, а это уже
//! подмена личности.
//!
//! ```text
//! AEGIS_AUTH_v1 ‖ '\n' ‖ METHOD ‖ '\n' ‖ PATH ‖ '\n' ‖ issued_at
//! ```
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
const AUTH_DOMAIN: &[u8] = b"AEGIS_AUTH_v1";

/// Имя заголовка с подписью, hex.
pub const SIGNATURE_HEADER: &str = "x-aegis-signature";

/// Имя заголовка с временем выпуска, миллисекунды.
pub const ISSUED_AT_HEADER: &str = "x-aegis-issued-at";

/// Собирает сообщение для подписи.
///
/// Разделители обязательны: без них метод `GET` с путём `/ab` и метод
/// `GETA` с путём `/b` дали бы одно и то же сообщение, а значит одна
/// подпись подошла бы к двум разным запросам.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔐 Вектор совместимости с сервером.
    ///
    /// Байты зафиксированы и продублированы в тесте сервера
    /// (`client_contract.rs`). Расхождение реализаций проявилось бы
    /// как отказ всех запросов, и причину такого отказа искать долго:
    /// сервер отвечает 401 без объяснений — намеренно, чтобы не
    /// подсказывать атакующему.
    #[test]
    fn message_matches_fixed_vector() {
        let message = signed_message("GET", "/v1/messages/abc", 1_700_000_000_000);

        assert_eq!(
            message,
            b"AEGIS_AUTH_v1\nGET\n/v1/messages/abc\n1700000000000".to_vec()
        );
    }

    /// Подпись привязана к методу.
    #[test]
    fn message_depends_on_method() {
        assert_ne!(
            signed_message("GET", "/v1/messages/abc", 1),
            signed_message("PUT", "/v1/messages/abc", 1)
        );
    }

    /// Подпись привязана к пути: подпись к своей очереди не подойдёт
    /// к чужой.
    #[test]
    fn message_depends_on_path() {
        assert_ne!(
            signed_message("GET", "/v1/messages/mine", 1),
            signed_message("GET", "/v1/messages/theirs", 1)
        );
    }

    /// Подпись привязана ко времени выпуска.
    #[test]
    fn message_depends_on_time() {
        assert_ne!(
            signed_message("GET", "/v1/messages/abc", 1),
            signed_message("GET", "/v1/messages/abc", 2)
        );
    }

    /// Разделители не дают склеить поля.
    #[test]
    fn fields_cannot_be_confused() {
        assert_ne!(
            signed_message("GET", "/ab", 1),
            signed_message("GETA", "/b", 1)
        );
    }
}
