// SPDX-License-Identifier: AGPL-3.0-only

//! Подтверждение адреса почты при регистрации.
//!
//! # Что это и зачем
//!
//! Аккаунт создаётся только после того, как человек ввёл код из письма
//! (решение владельца, 2026-10-07; миграция 0017). Один адрес — один
//! аккаунт.
//!
//! # 🔐 Что сервер делает с адресом
//!
//! 1. Приводит к каноничному виду ([`normalize`]).
//! 2. Считает `email_hash` — HMAC-SHA-256 на ключе узла ([`hash_email`]).
//! 3. Отдаёт адрес и код отправителю писем ([`Mailer`]).
//! 4. Забывает адрес. В базе остаётся только `email_hash`.
//!
//! ⚠️ Чего это **не** даёт — честно:
//!
//! * оператор с ключом узла проверит, зарегистрирован ли **известный**
//!   ему адрес: посчитает тот же HMAC и сравнит;
//! * почтовая служба, через которую уходит письмо, видит адрес и время.
//!   Её журналы — вне сервера;
//! * адрес в запросе виден узлу в момент запроса, как и всё остальное
//!   в запросе.
//!
//! # Почему отправка — внешняя команда
//!
//! Почтовый клиент внутри сервера — это SMTP, TLS до чужого узла,
//! учётные данные и десяток зависимостей в процессе, который держит
//! ключ подписи сертификатов. Сервер вместо этого запускает программу
//! оператора (`GASAPP_EMAIL_CMD`) и передаёт ей адрес и код через
//! stdin. Чем она отправляет — `msmtp`, `curl` к почтовой службе —
//! решает оператор; готовый пример лежит в `server/deploy/mail/`.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use gasapp_server_db::email::CodeIssue;
use hmac::{Hmac, Mac as _};
use rand::Rng as _;
use sha2::{Digest as _, Sha256};

use crate::routes::{ApiError, AppState};

/// Переменная с программой отправки писем.
pub const EMAIL_CMD: &str = "GASAPP_EMAIL_CMD";

/// Переменная (или `…_FILE`) с ключом хеширования адресов, 32 байта hex.
pub const EMAIL_KEY: &str = "GASAPP_EMAIL_KEY";

/// Предел длины адреса (RFC 5321: 254 знака).
pub const MAX_EMAIL_LEN: usize = 254;

/// Число цифр в коде.
pub const CODE_DIGITS: usize = 6;

/// Сколько ждать программу отправки.
const SEND_DEADLINE: Duration = Duration::from_secs(30);

/// Сколько писем с кодом узел отправляет в минуту — всего, на всех.
///
/// 🔐 Работа (proof-of-work) и предел на адрес не мешают просить коды
/// на тысячу **разных** чужих адресов: сервер стал бы рассыльщиком
/// спама, а его почтовый домен попал бы в чёрные списки. Общий предел
/// ограничивает это сверху. Цена — тот, кто готов тратить работу,
/// может на время занять весь бюджет; регистрация тогда отвечает `429`
/// и проходит позже.
pub const CODES_PER_MINUTE: u32 = 60;

/// Домен-разделитель хеша кода.
const CODE_DOMAIN: &[u8] = b"GASAPP_EMAIL_CODE_v1";

/// Приводит адрес к каноничному виду или отвергает его.
///
/// Каноничный вид — без пробелов по краям, строчными буквами. Больше
/// ничего не делается: точки и `+метка` у разных почтовых служб значат
/// разное, и угадывать их правила значило бы склеить чужие адреса.
///
/// Проверка формы намеренно простая: одна `@`, непустые части, точка
/// в домене, только печатные ASCII-знаки без пробелов. Настоящая
/// проверка адреса — письмо с кодом.
#[must_use]
pub fn normalize(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();

    if email.is_empty() || email.len() > MAX_EMAIL_LEN {
        return None;
    }

    // Печатные ASCII без пробела и без знаков, которыми в заголовок
    // письма подставляют второго получателя.
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

/// `email_hash` — HMAC-SHA-256 каноничного адреса на ключе узла.
#[must_use]
pub fn hash_email(key: &[u8; 32], normalized: &str) -> [u8; 32] {
    // `new_from_slice` не отказывает ни для какой длины ключа HMAC.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return [0u8; 32];
    };
    mac.update(normalized.as_bytes());

    mac.finalize().into_bytes().into()
}

/// Хеш кода, привязанный к адресу.
#[must_use]
pub fn hash_code(email_hash: &[u8; 32], code: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CODE_DOMAIN);
    hasher.update(email_hash);
    hasher.update(code.trim().as_bytes());

    hasher.finalize().into()
}

/// Случайный код из [`CODE_DIGITS`] цифр.
#[must_use]
pub fn generate_code() -> String {
    let number: u32 = rand::rngs::OsRng.gen_range(0..1_000_000);

    format!("{number:0CODE_DIGITS$}")
}

/// Переменная с постоянным кодом для тестов (см. [`dev_code_from_env`]).
pub const DEV_EMAIL_CODE: &str = "GASAPP_DEV_EMAIL_CODE";

/// Постоянный код подтверждения из окружения — шесть цифр.
///
/// ⚠️ Вызывающий обязан применять его только при явно небезопасном
/// запуске (`GASAPP_ALLOW_INSECURE`): с постоянным кодом адрес почты
/// не подтверждается вовсе.
#[must_use]
pub fn dev_code_from_env() -> Option<String> {
    let code = std::env::var(DEV_EMAIL_CODE).ok()?;
    let code = code.trim();

    (code.len() == CODE_DIGITS && code.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| code.to_owned())
}

/// Ключ хеширования адресов из окружения.
///
/// `None` — не задан или не 32 байта hex. Сервер без него не стартует
/// (см. `config`), кроме явно небезопасного запуска.
#[must_use]
pub fn key_from_env() -> Option<[u8; 32]> {
    let encoded = gasapp_server_db::runtime::secret(EMAIL_KEY)?;
    let bytes = hex::decode(encoded.trim()).ok()?;
    let key: [u8; 32] = bytes.try_into().ok()?;

    key.iter().any(|byte| *byte != 0).then_some(key)
}

/// Отправитель писем с кодом.
///
/// Трейт нужен по той же причине, что и `PushProvider`: маршруты не
/// зависят от того, чем письмо уходит, а тесты читают код из памяти.
pub trait Mailer: Send + Sync {
    /// Отправляет код на адрес. `false` — письмо не ушло.
    ///
    /// Вызывается из блокирующего пула: реализация может ждать.
    fn send_code(&self, email: &str, code: &str) -> bool;
}

/// Отправка внешней программой.
///
/// Программа получает на stdin две строки: адрес и код. Через stdin,
/// а не аргументами: аргументы видны всем пользователям машины в
/// списке процессов. Код возврата `0` — письмо принято к отправке.
#[derive(Debug, Clone)]
pub struct CommandMailer {
    program: String,
}

impl CommandMailer {
    /// Отправитель с программой из `GASAPP_EMAIL_CMD`, если она задана.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let program = std::env::var(EMAIL_CMD).ok()?;
        let program = program.trim();

        (!program.is_empty()).then(|| Self {
            program: program.to_owned(),
        })
    }
}

impl Mailer for CommandMailer {
    fn send_code(&self, email: &str, code: &str) -> bool {
        let spawned = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn();

        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                // Без адреса: журнал сервера не должен становиться
                // списком тех, кто регистрировался.
                tracing::error!(%error, "программа отправки писем не запустилась");
                return false;
            }
        };

        let written = child
            .stdin
            .take()
            .is_some_and(|mut stdin| writeln!(stdin, "{email}\n{code}").is_ok());

        // Зависшая программа не держит поток вечно: по истечении срока
        // она снимается, и письмо считается неотправленным.
        let started = Instant::now();
        let finished = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if started.elapsed() < SEND_DEADLINE => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
            }
        };

        if !(written && finished) {
            tracing::warn!("программа отправки писем завершилась с ошибкой");
        }

        written && finished
    }
}

/// Отправитель для локальной проверки: пишет код в журнал сервера.
///
/// ⚠️ Только при `GASAPP_ALLOW_INSECURE`: код в журнале означает, что
/// почту никто не подтверждал. Адрес в журнал не пишется и здесь.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogMailer;

impl Mailer for LogMailer {
    fn send_code(&self, _email: &str, code: &str) -> bool {
        tracing::warn!(
            code,
            "ПИСЬМО НЕ ОТПРАВЛЕНО — код подтверждения (только для тестов)"
        );
        true
    }
}

/// Запрос письма с кодом.
#[derive(Debug, serde::Deserialize)]
pub struct CodeRequest {
    /// Адрес почты.
    pub email: String,
    /// Решение proof-of-work над [`crate::pow::email_code_challenge`].
    pub pow_nonce: u64,
    /// Окно времени, для которого найдено решение (см. `challenge`).
    pub window: u64,
}

/// Условия запроса письма: что решать и насколько это сейчас дорого.
#[derive(Debug, serde::Serialize)]
pub struct ChallengeResponse {
    /// Сколько ведущих нулевых бит требует узел прямо сейчас.
    pub difficulty: u32,
    /// Текущее окно времени.
    pub window: u64,
}

/// Сколько писем узел уже отправил за последнюю минуту.
fn letters_sent(state: &AppState) -> Result<(crate::rate_limit::LimitKey, u32, u32), ApiError> {
    // Один ключ на всех: предел общий (см. `CODES_PER_MINUTE`).
    let key = crate::rate_limit::key_from_addr(&state.limiter_salt, "email-codes");
    let limiter = state
        .email_code_limiter
        .lock()
        .map_err(|_| ApiError::Internal)?;
    let limit = limiter.limit();
    let remaining = limiter.remaining(&key, crate::routes::now_millis());

    Ok((key, limit.saturating_sub(remaining), limit))
}

/// Отдаёт условия запроса письма — без подписи: аккаунта ещё нет.
///
/// Цена растёт с нагрузкой узла (см. [`crate::pow::email_difficulty`]).
pub(crate) async fn challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let (_, used, limit) = letters_sent(&state)?;

    Ok(Json(ChallengeResponse {
        difficulty: crate::pow::email_difficulty(state.pow_difficulty, used, limit),
        window: crate::pow::email_window(crate::routes::now_millis()),
    }))
}

/// Отправляет письмо с кодом подтверждения — шаг перед регистрацией.
///
/// # 🔐 Чего ответ не сообщает
///
/// Занят ли адрес. Код уходит и на адрес, у которого уже есть аккаунт:
/// отказ здесь был бы оракулом «этот человек пользуется GasApp» для
/// любого, кто знает адрес. О занятом адресе узнаёт только тот, кто
/// ввёл код из письма, — то есть владелец ящика (`422` при регистрации).
///
/// # Порядок проверок
///
/// Форма адреса → окно → работа по текущей цене → общий предел узла →
/// предел на адрес (в базе) → отправка. Дешёвое раньше дорогого,
/// и письмо — последним.
pub(crate) async fn request_code(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CodeRequest>,
) -> Result<StatusCode, ApiError> {
    let email = normalize(&request.email).ok_or(ApiError::BadRequest)?;

    // 🔐 Решение годится в своём окне и в следующем: заготовленные
    // впрок решения нельзя выложить разом через неделю.
    let now_window = crate::pow::email_window(crate::routes::now_millis());
    if request.window > now_window || now_window.saturating_sub(request.window) > 1 {
        return Err(ApiError::Unauthorized);
    }

    // Цена — та, что действует сейчас, а не та, что была, когда клиент
    // спрашивал: если узел успели нагрузить, клиент спросит ещё раз.
    let (key, used, limit) = letters_sent(&state)?;
    let challenge = crate::pow::email_code_challenge(&email, request.window);
    crate::pow::verify(
        &challenge,
        request.pow_nonce,
        crate::pow::email_difficulty(state.pow_difficulty, used, limit),
    )
    .map_err(|_| ApiError::Unauthorized)?;

    {
        let mut limiter = state
            .email_code_limiter
            .lock()
            .map_err(|_| ApiError::Internal)?;

        if !limiter.allow(key, crate::routes::now_millis()) {
            return Err(ApiError::TooManyRequests);
        }
    }

    let email_hash = hash_email(&state.email_key, &email);
    let code = state.fixed_email_code.clone().unwrap_or_else(generate_code);
    let code_hash = hash_code(&email_hash, &code);

    match gasapp_server_db::email::store_code(&state.pool, &email_hash, &code_hash).await? {
        CodeIssue::Stored => {}
        CodeIssue::Throttled => return Err(ApiError::TooManyRequests),
    }

    // Программа отправки блокирует поток — ей место в блокирующем пуле.
    let mailer = Arc::clone(&state.mailer);
    let sent = tokio::task::spawn_blocking(move || mailer.send_code(&email, &code))
        .await
        .unwrap_or(false);

    if sent {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Unavailable)
    }
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

    #[test]
    fn overlong_address_is_rejected() {
        let long = format!("{}@example.org", "a".repeat(MAX_EMAIL_LEN));

        assert_eq!(normalize(&long), None);
    }

    /// Хеш зависит от ключа: дамп базы без ключа адреса не выдаёт.
    #[test]
    fn hash_depends_on_key_and_address() {
        let first = hash_email(&[1; 32], "alice@example.org");

        assert_ne!(first, hash_email(&[2; 32], "alice@example.org"));
        assert_ne!(first, hash_email(&[1; 32], "bob@example.org"));
        assert_eq!(first, hash_email(&[1; 32], "alice@example.org"));
    }

    /// Код одного адреса не подходит другому.
    #[test]
    fn code_hash_is_bound_to_address() {
        assert_ne!(hash_code(&[1; 32], "123456"), hash_code(&[2; 32], "123456"));
        assert_eq!(
            hash_code(&[1; 32], " 123456 "),
            hash_code(&[1; 32], "123456")
        );
    }

    #[test]
    fn code_is_six_digits() {
        for _ in 0..64 {
            let code = generate_code();

            assert_eq!(code.len(), CODE_DIGITS);
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }
}
