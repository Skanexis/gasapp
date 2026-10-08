// SPDX-License-Identifier: AGPL-3.0-only

//! Аутентификация подписью identity-ключа.
//!
//! # Почему подпись, а не пароль
//!
//! Пароль пришлось бы хранить — пусть и в виде хеша, — то есть заводить
//! на сервере данные, кража которых компрометирует пользователей.
//! Публичный identity-ключ красть бессмысленно: он и так публичен.
//!
//! Схема на деле: клиент подписывает **каждый запрос** — метод, путь,
//! время выпуска и хеш тела (`GASAPP_AUTH_v2`), — а сервер проверяет
//! подпись ключом из базы ([`crate::authz`]). Здесь — проверка подписи
//! XEdDSA и свежести времени, общая для всех маршрутов.
//!
//! ⚠️ Прежде здесь была описана челлендж-схема: «сервер выдаёт случайный
//! челлендж». Выдачи челленджа нет; от той схемы остался маршрут
//! `/v1/auth/verify`, который клиент не вызывает и который ничего
//! не выдаёт — только отвечает, верна ли подпись. Он оставлен ради
//! проверок на нём: одинаковый 401 для неизвестного устройства
//! и неверной подписи, отказ по сроку.
//!
//! # Почему время выпуска, а не просто подпись пути
//!
//! Без времени подпись стала бы многоразовым паролем: перехватив её
//! однажды, атакующий предъявлял бы её вечно. Время ограничивает
//! её жизнь окном свежести ([`check_freshness`]).
//!
//! # Про XEdDSA
//!
//! `IK` — ключ **X25519**, а не Ed25519. Проверить его подпись обычным
//! Ed25519 нельзя: кодировки разные, и попытка приводит к тому, что
//! проверка не проходит никогда. Сервер повторяет ту же схему, что
//! и клиент (`gasapp-protocol::xeddsa::montgomery`): переносит точку
//! из формы Монтгомери в форму Эдвардса и проверяет там.
//!
//! Дублирование намеренно: серверный workspace под AGPL-3.0, клиентский
//! под Apache-2.0, и связывать их зависимостью нельзя (ADR-006). Тридцать
//! строк повторённой математики дешевле лицензионного конфликта, но
//! расхождение между ними сломало бы аутентификацию — поэтому оно
//! закреплено тестом на совместимость векторов.

use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint};
use ed25519_dalek::{Signature, VerifyingKey};

/// Длина челленджа в байтах.
pub const CHALLENGE_LEN: usize = 32;

/// Сколько миллисекунд челлендж считается свежим.
///
/// Пять минут: достаточно, чтобы клиент успел подписать даже на плохой
/// сети, и мало, чтобы перехваченный челлендж успел пригодиться.
pub const CHALLENGE_TTL_MILLIS: i64 = 5 * 60 * 1000;

/// Ошибка аутентификации.
///
/// # Про единообразие
///
/// Варианты намеренно не различают «такого аккаунта нет» и «подпись
/// неверна». Разница между ними — оракул, по которому перебором
/// выясняется, какие аккаунты существуют.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// Аутентификация не прошла.
    #[error("authentication failed")]
    Failed,
    /// Челлендж просрочен.
    #[error("challenge expired")]
    Expired,
}

/// Проверяет подпись челленджа ключом X25519.
///
/// # Errors
///
/// [`AuthError::Failed`] — ключ не является точкой кривой, подпись
/// неверной длины либо не сходится.
pub fn verify_challenge_signature(
    identity_key: &[u8; 32],
    challenge: &[u8],
    signature: &[u8],
) -> Result<(), AuthError> {
    let verifying = to_edwards(identity_key).ok_or(AuthError::Failed)?;
    let bytes: [u8; 64] = signature.try_into().map_err(|_| AuthError::Failed)?;

    verifying
        .verify_strict(challenge, &Signature::from_bytes(&bytes))
        .map_err(|_| AuthError::Failed)
}

/// Проверяет, что челлендж ещё не просрочен.
///
/// # Errors
///
/// [`AuthError::Expired`] — с момента выпуска прошло больше
/// [`CHALLENGE_TTL_MILLIS`], либо челлендж выпущен «в будущем»
/// (рассогласование часов или подделка метки).
pub fn check_freshness(issued_at_millis: i64, now_millis: i64) -> Result<(), AuthError> {
    let age = now_millis.saturating_sub(issued_at_millis);

    if (0..=CHALLENGE_TTL_MILLIS).contains(&age) {
        Ok(())
    } else {
        Err(AuthError::Expired)
    }
}

/// Переносит публичный ключ X25519 в форму Эдвардса.
///
/// Знак точки фиксируется нулём — то же соглашение, что и на клиенте.
fn to_edwards(public: &[u8; 32]) -> Option<VerifyingKey> {
    let point = MontgomeryPoint(*public).to_edwards(0)?;
    let compressed: CompressedEdwardsY = point.compress();

    VerifyingKey::from_bytes(&compressed.to_bytes()).ok()
}

#[cfg(test)]
// Арифметика ниже — групповая, на скалярах и точках Curve25519:
// `+` и `*` реализуют операции конечного поля и переполниться не могут.
// Лимит `arithmetic_side_effects` рассчитан на целочисленное переполнение.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    /// Повторяет клиентскую подпись XEdDSA — для проверки совместимости.
    ///
    /// Функция живёт в тестах, потому что сервер только **проверяет**
    /// подписи и никогда их не создаёт. Но без неё нельзя убедиться,
    /// что серверная проверка принимает то, что клиент производит.
    fn client_sign(private: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let scalar = clamp(private);
        let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;
        let compressed = point.compress();
        let sign_bit = compressed.to_bytes().get(31).copied().unwrap_or(0) & 0x80;

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
        let (r_half, s_half) = signature.split_at_mut(32);
        r_half.copy_from_slice(&r_bytes);
        s_half.copy_from_slice(&s.to_bytes());

        signature
    }

    fn clamp(private: &[u8; 32]) -> Scalar {
        let mut bytes = *private;
        if let Some(first) = bytes.first_mut() {
            *first &= 0xF8;
        }
        if let Some(last) = bytes.last_mut() {
            *last &= 0x7F;
            *last |= 0x40;
        }

        Scalar::from_bytes_mod_order(bytes)
    }

    fn public_key(private: &[u8; 32]) -> [u8; 32] {
        let scalar = clamp(private);
        let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;

        point.to_montgomery().to_bytes()
    }

    /// 🔐 Подпись, созданная клиентской схемой, принимается сервером.
    ///
    /// Главный тест модуля: он ловит расхождение между дублированной
    /// математикой сервера и клиента. Разойдись они — аутентификация
    /// перестала бы работать у всех сразу.
    #[test]
    fn client_signature_is_accepted() {
        let private = [0x11u8; 32];
        let public = public_key(&private);
        let challenge = [0x42u8; CHALLENGE_LEN];

        let signature = client_sign(&private, &challenge);

        assert!(verify_challenge_signature(&public, &challenge, &signature).is_ok());
    }

    /// 🔐 Подпись чужого челленджа не проходит.
    ///
    /// Это и есть защита от повторного использования перехваченной подписи.
    #[test]
    fn signature_of_another_challenge_is_rejected() {
        let private = [0x11u8; 32];
        let public = public_key(&private);

        let signature = client_sign(&private, &[0x42u8; CHALLENGE_LEN]);

        assert_eq!(
            verify_challenge_signature(&public, &[0x43u8; CHALLENGE_LEN], &signature),
            Err(AuthError::Failed)
        );
    }

    /// 🔐 Чужой ключ не проходит.
    #[test]
    fn signature_under_another_key_is_rejected() {
        let challenge = [0x42u8; CHALLENGE_LEN];
        let signature = client_sign(&[0x11u8; 32], &challenge);
        let impostor = public_key(&[0x22u8; 32]);

        assert_eq!(
            verify_challenge_signature(&impostor, &challenge, &signature),
            Err(AuthError::Failed)
        );
    }

    /// Испорченная подпись отвергается.
    #[test]
    fn corrupted_signature_is_rejected() {
        let private = [0x11u8; 32];
        let public = public_key(&private);
        let challenge = [0x42u8; CHALLENGE_LEN];

        let mut signature = client_sign(&private, &challenge);
        if let Some(byte) = signature.last_mut() {
            *byte ^= 0x01;
        }

        assert_eq!(
            verify_challenge_signature(&public, &challenge, &signature),
            Err(AuthError::Failed)
        );
    }

    /// Подпись неверной длины отвергается, а не паникует.
    #[test]
    fn malformed_signature_length_is_rejected() {
        let public = public_key(&[0x11u8; 32]);

        assert_eq!(
            verify_challenge_signature(&public, b"challenge", b"short"),
            Err(AuthError::Failed)
        );
    }

    /// Свежий челлендж принимается, просроченный — нет.
    #[test]
    fn freshness_window_is_enforced() {
        assert!(check_freshness(1_000, 1_000).is_ok());
        assert!(check_freshness(1_000, 1_000 + CHALLENGE_TTL_MILLIS).is_ok());
        assert_eq!(
            check_freshness(1_000, 1_000 + CHALLENGE_TTL_MILLIS + 1),
            Err(AuthError::Expired)
        );
    }

    /// 🔐 Челлендж «из будущего» отвергается.
    ///
    /// Иначе подделанная метка времени давала бы бесконечно свежий
    /// челлендж.
    #[test]
    fn future_challenge_is_rejected() {
        assert_eq!(check_freshness(2_000, 1_000), Err(AuthError::Expired));
    }
}
