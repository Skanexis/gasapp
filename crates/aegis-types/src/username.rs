// SPDX-License-Identifier: Apache-2.0

//! Каноничная форма имени пользователя.
//!
//! # 🔐 Зачем
//!
//! Имя — то, по чему человека находят, и то, что показывается в чате.
//! Если два разных имени выглядят одинаково, самозванец регистрирует
//! двойника: «alice» и «аlice» с кириллической «а», «Alice», «alice»
//! с невидимым символом в конце. Прежде сервер сравнивал имена
//! побайтно, и все четыре были разными аккаунтами.
//!
//! Правило: строчные латинские буквы, цифры и подчёркивание, первая —
//! буква, от 3 до 32 символов. В таком алфавите нет двух символов,
//! которые путаются при чтении, кроме пар вроде `l`/`1` и `o`/`0`,
//! а их различает любой шрифт интерфейса. То же правило — на сервере
//! и в схеме его базы.

use crate::{AegisError, Result};

/// Наименьшая длина имени.
pub const MIN_USERNAME_LEN: usize = 3;

/// Наибольшая длина имени.
pub const MAX_USERNAME_LEN: usize = 32;

/// Приводит введённое имя к каноничной форме.
///
/// Прощается то, что человек делает, не задумываясь: пробелы по краям,
/// `@` в начале, заглавные латинские буквы. Всё остальное — отказ,
/// а не молчаливая чистка: убрать из имени кириллическую «а» значило бы
/// найти другого человека.
///
/// # Errors
///
/// [`AegisError::InvalidUsername`] — имя не приводится к каноничной форме.
///
/// # Примеры
///
/// ```
/// use aegis_types::canonical_username;
///
/// assert_eq!(canonical_username(" @Alice_1 ").unwrap(), "alice_1");
/// assert!(canonical_username("\u{430}lice").is_err());
/// ```
pub fn canonical_username(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let bare = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let lowered = bare.to_ascii_lowercase();

    if is_canonical_username(&lowered) {
        Ok(lowered)
    } else {
        Err(AegisError::InvalidUsername)
    }
}

/// Каноничное ли имя — ровно в том виде, в каком передано.
#[must_use]
pub fn is_canonical_username(name: &str) -> bool {
    let bytes = name.as_bytes();

    (MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_input_is_forgiven() {
        assert_eq!(canonical_username("bob").unwrap(), "bob");
        assert_eq!(canonical_username("  Bob ").unwrap(), "bob");
        assert_eq!(canonical_username("@ALICE_2").unwrap(), "alice_2");
    }

    /// 🔐 Двойники не приводятся к оригиналу — они отвергаются.
    #[test]
    fn lookalikes_are_refused() {
        for raw in [
            "\u{430}lice",   // кириллическая «а»
            "alice\u{200b}", // пробел нулевой ширины
            "al\u{0131}ce",  // турецкая «ı» без точки
            "\u{202e}ecila", // смена направления текста
            "alice\u{301}",  // комбинирующий акцент
        ] {
            assert!(canonical_username(raw).is_err(), "{raw:?} принято");
        }
    }

    #[test]
    fn junk_is_refused() {
        for raw in [
            "", "ab", "1alice", "_alice", "al ice", "al-ice", "al.ice", "@@alice",
        ] {
            assert!(canonical_username(raw).is_err(), "{raw:?} принято");
        }

        let longest = "a".repeat(MAX_USERNAME_LEN);
        assert!(canonical_username(&longest).is_ok());
        assert!(canonical_username(&format!("{longest}a")).is_err());
    }
}
