// SPDX-License-Identifier: AGPL-3.0-only

//! Вход оператора в админ-центр.
//!
//! # Токен
//!
//! Оператор входит длинным случайным токеном. В окружении сервера лежит
//! только его SHA-256 (`AEGIS_ADMIN_TOKEN_SHA256`,
//! `aegis-server-admin hash-token`): утёкшее окружение не даёт войти.
//! Сравнение — за постоянное время.
//!
//! # Сессия
//!
//! После входа — случайный идентификатор сессии в cookie (`HttpOnly`,
//! `SameSite=Strict`) и свой токен CSRF для каждой формы. Сессии живут
//! только в памяти процесса: перезапуск выходит из всех, и на диске
//! нечего красть. Простой — 30 минут.
//!
//! # Перебор
//!
//! Пять неверных токенов подряд закрывают вход на десять минут для всех:
//! админ-центр слушает только петлю, и неверный токен там — не опечатка
//! пользователя, а повод остановиться.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Имя cookie сессии.
pub const SESSION_COOKIE: &str = "aegis_admin";

/// Сколько сессия живёт без действий.
const IDLE_TIMEOUT: Duration = Duration::from_mins(30);

/// Сколько неверных токенов закрывают вход.
const MAX_FAILURES: u32 = 5;

/// На сколько закрывается вход.
const LOCKOUT: Duration = Duration::from_mins(10);

/// Сессия оператора.
#[derive(Debug, Clone)]
struct Session {
    csrf: String,
    last_seen: Instant,
}

/// Вход и сессии.
#[derive(Debug)]
pub struct Auth {
    token_hash: [u8; 32],
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<(u32, Option<Instant>)>,
}

/// Почему вход не состоялся.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    /// Токен неверен.
    Wrong,
    /// Вход закрыт после серии неверных токенов.
    Locked,
}

/// SHA-256 токена в hex — то, что кладут в `AEGIS_ADMIN_TOKEN_SHA256`.
#[must_use]
pub fn token_hash_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

/// Случайная строка: 32 байта в hex.
fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl Auth {
    /// Разбирает хеш токена из окружения.
    ///
    /// `None` — не 64 шестнадцатеричных знака: запускать админ-центр без
    /// годного хеша нельзя.
    #[must_use]
    pub fn from_hash_hex(text: &str) -> Option<Self> {
        let bytes = hex::decode(text.trim()).ok()?;
        let token_hash = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;

        Some(Self {
            token_hash,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new((0, None)),
        })
    }

    /// Проверяет токен и открывает сессию. Возвращает её идентификатор.
    ///
    /// # Errors
    ///
    /// [`LoginError`] — токен неверен или вход закрыт.
    pub fn login(&self, token: &str) -> Result<String, LoginError> {
        let mut failures = self.failures.lock().map_err(|_| LoginError::Locked)?;

        if let Some(since) = failures.1 {
            if since.elapsed() < LOCKOUT {
                return Err(LoginError::Locked);
            }
            *failures = (0, None);
        }

        let presented: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        if !bool::from(presented.ct_eq(&self.token_hash)) {
            failures.0 = failures.0.saturating_add(1);
            if failures.0 >= MAX_FAILURES {
                failures.1 = Some(Instant::now());
                tracing::warn!("админ-центр: вход закрыт после серии неверных токенов");
            }
            return Err(LoginError::Wrong);
        }
        *failures = (0, None);
        drop(failures);

        let id = random_hex();
        let mut sessions = self.sessions.lock().map_err(|_| LoginError::Locked)?;
        sessions.retain(|_, session| session.last_seen.elapsed() < IDLE_TIMEOUT);
        sessions.insert(
            id.clone(),
            Session {
                csrf: random_hex(),
                last_seen: Instant::now(),
            },
        );

        Ok(id)
    }

    /// Действующая сессия — продлевается; возвращает её токен CSRF.
    #[must_use]
    pub fn touch(&self, id: &str) -> Option<String> {
        let mut sessions = self.sessions.lock().ok()?;
        let session = sessions.get_mut(id)?;

        if session.last_seen.elapsed() >= IDLE_TIMEOUT {
            sessions.remove(id);
            return None;
        }
        session.last_seen = Instant::now();

        Some(session.csrf.clone())
    }

    /// Сверяет токен CSRF формы с токеном сессии — за постоянное время.
    #[must_use]
    pub fn csrf_matches(&self, id: &str, presented: &str) -> bool {
        self.touch(id)
            .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(presented.as_bytes())))
    }

    /// Закрывает сессию.
    pub fn logout(&self, id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(id);
        }
    }
}

/// Идентификатор сессии из заголовка `Cookie`.
#[must_use]
pub fn session_from_cookies(header: &str) -> Option<&str> {
    header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == SESSION_COOKIE).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(token: &str) -> Auth {
        Auth::from_hash_hex(&token_hash_hex(token)).expect("хеш")
    }

    #[test]
    fn the_right_token_opens_a_session_with_csrf() {
        let auth = auth("correct horse");
        let id = auth.login("correct horse").expect("вход");
        let csrf = auth.touch(&id).expect("сессия");

        assert!(auth.csrf_matches(&id, &csrf));
        assert!(!auth.csrf_matches(&id, "forged"));
        assert!(!auth.csrf_matches("unknown", &csrf));

        auth.logout(&id);
        assert!(auth.touch(&id).is_none());
    }

    /// 🔐 Пять неверных токенов закрывают вход — и для верного тоже.
    #[test]
    fn guessing_locks_the_door() {
        let auth = auth("correct horse");

        for _ in 0..MAX_FAILURES {
            assert_eq!(auth.login("guess"), Err(LoginError::Wrong));
        }
        assert_eq!(auth.login("correct horse"), Err(LoginError::Locked));
    }

    #[test]
    fn a_bad_hash_is_refused() {
        assert!(Auth::from_hash_hex("").is_none());
        assert!(Auth::from_hash_hex("abcd").is_none());
        assert!(Auth::from_hash_hex(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn the_session_is_read_from_cookies() {
        assert_eq!(
            session_from_cookies("theme=dark; aegis_admin=abc123; x=y"),
            Some("abc123")
        );
        assert_eq!(session_from_cookies("theme=dark"), None);
    }
}
