// SPDX-License-Identifier: Apache-2.0

//! Адрес почты для регистрации — каноничный вид.
//!
//! Сервер подтверждает адрес кодом из письма и хранит только его хеш
//! (`server/gasapp-server-api/src/email.rs`). Клиенту каноничный вид
//! нужен по одной причине: над ним считается proof-of-work запроса
//! кода, и обе стороны обязаны привести адрес одинаково.
//!
//! ⚠️ Правила продублированы на сервере (разные лицензии, общий крейт
//! невозможен). Расхождение проявилось бы как отказ в письме: работа
//! посчитана не над тем адресом.

/// Предел длины адреса (RFC 5321).
pub const MAX_EMAIL_LEN: usize = 254;

/// Приводит адрес к каноничному виду или отвергает его.
///
/// Без пробелов по краям, строчными буквами. Форма проверяется просто:
/// одна `@`, непустые части, точка в домене, печатные ASCII-знаки.
/// Настоящая проверка адреса — письмо с кодом.
#[must_use]
pub fn normalize(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();

    if email.is_empty() || email.len() > MAX_EMAIL_LEN {
        return None;
    }

    if !email
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b',' | b';' | b'<' | b'>' | b'"'))
    {
        return None;
    }

    let (local, domain) = email.split_once('@')?;

    if local.is_empty() || local.len() > 64 || domain.contains('@') {
        return None;
    }

    let labels_ok = domain.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });

    if !labels_ok || !domain.contains('.') {
        return None;
    }

    Some(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_trimmed_and_lowercased() {
        assert_eq!(
            normalize("  Alice@Example.ORG ").as_deref(),
            Some("alice@example.org")
        );
    }

    /// Тот же список, что отвергает сервер.
    #[test]
    fn malformed_addresses_are_rejected() {
        for bad in [
            "",
            "alice",
            "@example.org",
            "alice@",
            "alice@localhost",
            "alice@@example.org",
            "alice@exa mple.org",
            "alice@example..org",
            "alice@-example.org",
            "a,b@example.org",
            "alice@example.org\nbcc:eve@example.org",
            "алиса@example.org",
        ] {
            assert_eq!(normalize(bad), None, "{bad:?} не должен приниматься");
        }
    }
}
