// SPDX-License-Identifier: AGPL-3.0-only

//! Перепривязка аккаунта к новой identity — имя остаётся за человеком
//! после переустановки.
//!
//! Приватный identity-ключ между устройствами не копируется (раздел
//! 13.1 плана), поэтому новая установка приходит с новой identity.
//! Право на имя доказывает **ключ восстановления аккаунта**: его
//! открытые половины сервер получил при регистрации, секрет лежит
//! в зашифрованной резервной копии владельца.
//!
//! Подпись гибридная — XEdDSA ‖ ML-DSA-65: квантовый противник,
//! подделав одну классическую, увёл бы чужое имя.
//!
//! ⚠️ Сообщение строится так же, как в клиенте
//! (`gasapp-protocol::account_recovery::RecoverRequest::message`).
//! Код продублирован (лицензии клиента и сервера разные), расхождение
//! ловит тест с эталонными байтами в обоих крейтах.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

/// Домен подписи запроса перепривязки.
pub const RECOVER_DOMAIN: &[u8] = b"GASAPP_ACCOUNT_RECOVER_v1";

/// Допустимое расхождение часов клиента и сервера.
pub const MAX_SKEW_MILLIS: i64 = 5 * 60 * 1000;

/// Длина классической подписи XEdDSA.
const CLASSICAL_SIGNATURE_LEN: usize = 64;

/// Каноническое сообщение запроса: домен и поля с длинами
/// (u32, big-endian), затем момент подписи (i64, big-endian).
#[must_use]
pub fn message(
    username: &str,
    identity_key: &[u8],
    device_identity_key: &[u8],
    pq_identity_key: &[u8],
    identity_binding: &[u8],
    issued_at_millis: i64,
) -> Vec<u8> {
    let mut out = RECOVER_DOMAIN.to_vec();

    for field in [
        username.as_bytes(),
        identity_key,
        device_identity_key,
        pq_identity_key,
        identity_binding,
    ] {
        out.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(field);
    }

    out.extend_from_slice(&issued_at_millis.to_be_bytes());
    out
}

/// Проверяет гибридную подпись ключа восстановления: обе половины
/// обязаны сойтись.
#[must_use]
pub fn verify(
    recovery_key: &[u8; 32],
    recovery_pq_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Some((classical, post_quantum)) = signature.split_at_checked(CLASSICAL_SIGNATURE_LEN)
    else {
        return false;
    };

    if crate::auth::verify_challenge_signature(recovery_key, message, classical).is_err() {
        return false;
    }

    let (Ok(public), Ok(encoded)) = (
        EncodedVerifyingKey::<MlDsa65>::try_from(recovery_pq_key),
        EncodedSignature::<MlDsa65>::try_from(post_quantum),
    ) else {
        return false;
    };

    let Some(signature) = Signature::<MlDsa65>::decode(&encoded) else {
        return false;
    };

    VerifyingKey::<MlDsa65>::decode(&public).verify_with_context(
        message,
        RECOVER_DOMAIN,
        &signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⚠️ Эталон совпадает с `gasapp-protocol::account_recovery`
    /// (`message_matches_the_server_reference`). Разойдись они —
    /// восстановление перестало бы работать у всех.
    #[test]
    fn message_matches_the_client_reference() {
        let bytes = message("alice", &[1; 2], &[2; 2], &[3; 1], &[4; 1], 7);

        assert_eq!(
            hex::encode(bytes),
            "4741534150505f4143434f554e545f5245434f5645525f7631\
             00000005616c696365\
             000000020101\
             000000020202\
             0000000103\
             0000000104\
             0000000000000007"
        );
    }

    #[test]
    fn garbage_does_not_verify() {
        assert!(!verify(&[9; 32], &[0; 1952], b"m", &[0; 3373]));
        assert!(!verify(&[9; 32], &[0; 1952], b"m", &[0; 10]));
    }
}
