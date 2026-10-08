// SPDX-License-Identifier: AGPL-3.0-only

//! Подпись запросов так, как её делает настоящий клиент.
//!
//! # Зачем отдельный модуль
//!
//! Подписывать умеют оба набора интеграционных тестов — и `http.rs`,
//! и `client_contract.rs`. Две копии XEdDSA разошлись бы: достаточно
//! поправить домен-разделитель в одной, и второй набор продолжил бы
//! проверять протокол, которого больше нет.
//!
//! # ⚠️ Почему не `ed25519_dalek::Signer`
//!
//! Прежде в обоих наборах стоял именно он, и каждый подписанный
//! запрос получал `401`. Причина — не в подписи, а в **ключе**:
//! у устройства один ключ, X25519, и он же подписывает (ADR-009,
//! XEdDSA). Сервер принимает его как точку Монтгомери и переводит
//! в форму Эдвардса ([`gasapp_server_api::auth`]), а тесты
//! регистрировали ed25519-ключ и подписывали по-ed25519 — то есть
//! проверяли связку, которой в продукте нет.
//!
//! Обнаружилось это только тогда, когда наборы впервые запустили
//! против живой базы: без `GASAPP_TEST_DATABASE_URL` они молча
//! пропускались целиком, и красные тесты годами считались зелёными.
//!
//! Реализация повторяет клиентскую побайтово: расхождение означало бы,
//! что тест говорит не на том протоколе, что клиент.

// Арифметика ниже — групповая, на скалярах и точках Curve25519:
// `+`, `*` и унарный минус реализуют операции конечного поля
// и переполниться не могут. Лимит `arithmetic_side_effects`
// рассчитан на целочисленное переполнение. Тот же допуск стоит
// над `client_sign` в `src/auth.rs`, по той же причине.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use axum::body::Body;
use axum::http::Request;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest as _, Sha512};

/// Приватный ключ устройства — 32 байта X25519, как на клиенте.
pub type DeviceKey = [u8; 32];

/// Подписывает сообщение по XEdDSA.
#[must_use]
pub fn client_sign(private: &DeviceKey, message: &[u8]) -> [u8; 64] {
    let scalar = clamp(private);
    let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;

    // XEdDSA фиксирует знак точки нулём: у точки Монтгомери знака нет,
    // и обе стороны обязаны выбрать его одинаково.
    let sign_bit = point.compress().to_bytes()[31] & 0x80;

    let (scalar, point) = if sign_bit == 0 {
        (scalar, point)
    } else {
        let negated = -scalar;
        let negated_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &negated;

        (negated, negated_point)
    };

    let public_bytes = point.compress().to_bytes();

    let mut nonce_hash = Sha512::new();
    nonce_hash.update([0xFEu8; 32]);
    nonce_hash.update(scalar.to_bytes());
    nonce_hash.update(message);
    let nonce = Scalar::from_hash(nonce_hash);

    let r_point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &nonce;
    let r_bytes = r_point.compress().to_bytes();

    let mut challenge_hash = Sha512::new();
    challenge_hash.update(r_bytes);
    challenge_hash.update(public_bytes);
    challenge_hash.update(message);
    let challenge_scalar = Scalar::from_hash(challenge_hash);

    let s = nonce + challenge_scalar * scalar;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(&s.to_bytes());

    signature
}

/// Приводит приватный ключ к скаляру по правилам Curve25519.
fn clamp(private: &DeviceKey) -> Scalar {
    let mut bytes = *private;
    bytes[0] &= 0xF8;
    bytes[31] &= 0x7F;
    bytes[31] |= 0x40;

    Scalar::from_bytes_mod_order(bytes)
}

/// Публичный ключ X25519 — то, что уходит на сервер при регистрации.
///
/// Считается из того же скаляра, которым подписывает [`client_sign`]:
/// иначе сервер сверял бы подпись с чужим ключом.
#[must_use]
pub fn public_key(private: &DeviceKey) -> [u8; 32] {
    let scalar = clamp(private);
    let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;

    point.to_montgomery().to_bytes()
}

/// Текущее время в миллисекундах — так же, как его берёт сервер.
///
/// Внутренняя `now_millis` намеренно `pub(crate)`: расширять публичный
/// API ради теста значило бы делать частью контракта то, что им
/// не является.
#[must_use]
pub fn now_millis() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("часы после 1970")
            .as_millis(),
    )
    .expect("время помещается в i64")
}

/// Собирает подписанный запрос.
///
/// Подписывается **путь**, а не весь URI: сервер видит
/// `parts.uri.path()`, и строка запроса в подпись не входит.
#[must_use]
pub fn signed_request(
    private: &DeviceKey,
    method: &str,
    uri: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Request<Body> {
    use sha2::{Digest as _, Sha256};

    let issued_at = now_millis();
    let path = uri.split('?').next().unwrap_or(uri);
    let body_sha256: [u8; 32] = Sha256::digest(&body).into();
    let message = gasapp_server_api::authz::signed_message(method, path, issued_at, &body_sha256);
    let signature = client_sign(private, &message);

    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-gasapp-signature", hex::encode(signature))
        .header("x-gasapp-issued-at", issued_at.to_string())
        .header("x-gasapp-body-sha256", hex::encode(body_sha256))
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap()
}

// ---------------------------------------------------------------------------
//  Подготовка базы
// ---------------------------------------------------------------------------

// Общий с `gasapp-server-db` файл: схема тестовой базы одна, и готовить
// её по-разному из разных наборов тестов означало гонку — подробности
// в самом файле.
#[path = "../../../test-support/schema.rs"]
pub mod schema;

pub use schema::TEST_DIFFICULTY;

/// Поднимает состояние сервера поверх тестовой базы.
///
/// Возвращает `None`, если `GASAPP_TEST_DATABASE_URL` не задан —
/// кроме случая, когда выставлен `GASAPP_REQUIRE_DATABASE`
/// (см. [`schema::database_url`]).
pub async fn state() -> Option<std::sync::Arc<gasapp_server_api::routes::AppState>> {
    let url = schema::database_url()?;
    let pool = sqlx::PgPool::connect(&url).await.ok()?;

    schema::bootstrap(&pool).await;

    let mut state = gasapp_server_api::routes::AppState::new(pool, [0x5Au8; 32]);
    state.pow_difficulty = TEST_DIFFICULTY;
    state.subscribe_difficulty = TEST_DIFFICULTY;

    Some(std::sync::Arc::new(state))
}

// ---------------------------------------------------------------------------
//  Подтверждённый адрес почты
// ---------------------------------------------------------------------------

/// Код, который тесты кладут в базу вместо письма.
pub const TEST_EMAIL_CODE: &str = "424242";

/// Заводит свежий адрес с уже выданным кодом [`TEST_EMAIL_CODE`].
///
/// Регистрация требует кода из письма (миграция 0017). Тестам, которые
/// проверяют не почту, письмо ни к чему: код кладётся в базу тем же
/// путём, каким его кладёт обработчик, — хешем на ключе узла.
pub async fn confirmed_email(state: &gasapp_server_api::routes::AppState) -> String {
    use gasapp_server_api::email;

    let address = format!("{}@test.example", uuid::Uuid::new_v4().simple());
    let email_hash = email::hash_email(&state.email_key, &address);
    let code_hash = email::hash_code(&email_hash, TEST_EMAIL_CODE);

    gasapp_server_db::email::store_code(&state.pool, &email_hash, &code_hash)
        .await
        .expect("код подтверждения записывается");

    address
}

/// Поля `email` и `email_code` для тела регистрации, собранного строкой.
pub async fn email_fields(state: &gasapp_server_api::routes::AppState) -> String {
    format!(
        r#""email":"{}","email_code":"{}","#,
        confirmed_email(state).await,
        TEST_EMAIL_CODE,
    )
}

/// Отправитель, который складывает письма в память — вместо почты.
#[derive(Default)]
pub struct CapturingMailer {
    letters: std::sync::Mutex<Vec<(String, String)>>,
}

impl CapturingMailer {
    /// Последний код, отправленный на адрес.
    pub fn code_for(&self, email: &str) -> Option<String> {
        let letters = self.letters.lock().unwrap();

        letters
            .iter()
            .rev()
            .find(|(to, _)| to == email)
            .map(|(_, code)| code.clone())
    }

    /// Сколько писем ушло на адрес.
    pub fn letters_to(&self, email: &str) -> usize {
        let letters = self.letters.lock().unwrap();

        letters.iter().filter(|(to, _)| to == email).count()
    }
}

impl gasapp_server_api::email::Mailer for CapturingMailer {
    fn send_code(&self, email: &str, code: &str) -> bool {
        self.letters
            .lock()
            .unwrap()
            .push((email.to_owned(), code.to_owned()));

        true
    }
}

/// Состояние сервера с отправителем писем, который можно прочитать.
pub async fn state_with_mailer() -> Option<(
    std::sync::Arc<gasapp_server_api::routes::AppState>,
    std::sync::Arc<CapturingMailer>,
)> {
    let url = schema::database_url()?;
    let pool = sqlx::PgPool::connect(&url).await.ok()?;

    schema::bootstrap(&pool).await;

    let mailer = std::sync::Arc::new(CapturingMailer::default());
    let mut state = gasapp_server_api::routes::AppState::new(pool, [0x5Au8; 32]);
    state.pow_difficulty = TEST_DIFFICULTY;
    state.subscribe_difficulty = TEST_DIFFICULTY;
    state.mailer = mailer.clone();

    Some((std::sync::Arc::new(state), mailer))
}
