// SPDX-License-Identifier: AGPL-3.0-only

//! Сертификаты отправителя для sealed sender (раздел 15.2).
//!
//! # Что сервер здесь утверждает
//!
//! «Этот identity-ключ принадлежит этому аккаунту и устройству, и это
//! верно до такого-то момента.» Сертификат выдаётся **аутентифицированному**
//! клиенту и кладётся им внутрь запечатанного конверта, куда сервер
//! заглянуть не может.
//!
//! # Зачем это нужно, если сервер и так знает отправителя
//!
//! Он знает его только в момент выдачи сертификата — раз в сутки.
//! При доставке сообщения отправитель не аутентифицируется вовсе:
//! запечатанный конверт приходит без подписи и без имени. Сертификат
//! переносит утверждение сервера о личности **внутрь шифрования**,
//! чтобы получатель мог его прочитать, а сервер при доставке — нет.
//!
//! ```text
//!   раз в сутки:  клиент ──подпись IK──▶ сервер ──сертификат──▶ клиент
//!   при отправке: клиент ──[запечатанный конверт]──▶ сервер
//!                          └─ сертификат внутри, сервер его не видит
//! ```
//!
//! # Про ротацию
//!
//! Срок — сутки. Украденный сертификат перестаёт действовать назавтра,
//! а клиент обновляет его в фоне. Бессрочный сертификат означал бы, что
//! однажды утёкший файл вечно позволяет выдавать себя за владельца
//! перед его собеседниками.
//!
//! # ⚠️ Чего сертификат не даёт
//!
//! Подписывает его сервер, значит сервер может выписать поддельный
//! и выдать чужое сообщение за ваше. Это не дыра в реализации,
//! а граница модели: защита от недобросовестного сервера — safety
//! number, который считается по identity-ключам и подписи сервера
//! не касается. Сертификат отвечает на вопрос «какому аккаунту
//! принадлежит ключ», а не «можно ли доверять серверу».
//!
//! # Почему подпись повторена здесь, а не взята из `gasapp-protocol`
//!
//! Серверный workspace под AGPL-3.0, клиентский под Apache-2.0, и
//! связывать их зависимостью нельзя (ADR-006). Та же причина, по
//! которой в `auth` повторена проверка подписи. Расхождение между
//! двумя половинами сломало бы sealed sender молча, поэтому оно
//! закреплено тестом на совместимость векторов.

// Арифметика здесь — групповая, на скалярах и точках Curve25519,
// а не на машинных целых: `+` и `*` реализуют операции конечного
// поля и переполниться не могут. Лимит `arithmetic_side_effects`
// рассчитан на целочисленное переполнение и к этим типам неприменим,
// поэтому снят точечно — на одном модуле, а не на крейте.
//
// Тот же приём и по той же причине применён в клиентском
// `gasapp-protocol::xeddsa::montgomery`.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, montgomery::MontgomeryPoint,
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

/// Длина подписи XEdDSA.
pub const SIGNATURE_LEN: usize = 64;

/// Длина ключа.
pub const KEY_LEN: usize = 32;

/// Длина идентификатора: UUID.
pub const ID_LEN: usize = 16;

/// Версия формата сертификата.
///
/// Обязана совпадать с `CERTIFICATE_VERSION` в
/// `gasapp-protocol::sealed_sender`: версия входит в подпись, и
/// расхождение означало бы, что ни один сертификат не проверяется.
pub const CERTIFICATE_VERSION: u8 = 1;

/// Сколько сертификат действителен: сутки (раздел 15.2).
pub const VALIDITY_MILLIS: i64 = 24 * 60 * 60 * 1000;

/// Собирает подписываемые байты сертификата.
///
/// Раскладка обязана совпадать с `SenderCertificate::signed_payload`
/// на клиенте байт в байт.
#[must_use]
pub fn signed_payload(
    account_id: &[u8; ID_LEN],
    device_id: &[u8; ID_LEN],
    identity_key: &[u8; KEY_LEN],
    expires_at_millis: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + ID_LEN + ID_LEN + KEY_LEN + 8);

    out.push(CERTIFICATE_VERSION);
    out.extend_from_slice(account_id);
    out.extend_from_slice(device_id);
    out.extend_from_slice(identity_key);
    out.extend_from_slice(&expires_at_millis.to_be_bytes());

    out
}

/// Собирает готовый сертификат: подписываемая часть плюс подпись.
#[must_use]
pub fn encode(payload: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(SIGNATURE_LEN));
    out.extend_from_slice(payload);
    out.extend_from_slice(signature);

    out
}

/// Приводит байты приватного ключа к скаляру X25519.
///
/// Клампинг по RFC 7748 §5 — тот же, что применяет сама операция DH.
/// Подпись обязана использовать ровно этот скаляр, иначе выведенный
/// публичный ключ не совпадёт с тем, который знает клиент.
fn clamp(private: &[u8; KEY_LEN]) -> Scalar {
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

/// Подписывает сообщение приватным ключом X25519 по схеме XEdDSA.
///
/// # Про детерминированность
///
/// Nonce выводится из скаляра и сообщения, как в Ed25519 (RFC 8032).
/// Отдельный источник случайности не нужен, а его отсутствие исключает
/// целый класс отказов: повтор nonce при плохой энтропии раскрывает
/// приватный ключ.
#[must_use]
pub fn sign(private: &[u8; KEY_LEN], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let scalar = clamp(private);

    let point = ED25519_BASEPOINT_TABLE * &scalar;
    let compressed = point.compress();
    let sign_bit = compressed.to_bytes().get(31).copied().unwrap_or(0) & 0x80;

    // Соглашение «знак = 0»: проверяющий восстанавливает точку
    // из формы Монтгомери именно с нулевым знаком.
    let (scalar, point) = if sign_bit == 0 {
        (scalar, point)
    } else {
        let negated = -scalar;
        let negated_point = ED25519_BASEPOINT_TABLE * &negated;
        (negated, negated_point)
    };
    let public_bytes = point.compress().to_bytes();

    let mut nonce_hash = Sha512::new();
    nonce_hash.update([0xFEu8; 32]);
    nonce_hash.update(scalar.to_bytes());
    nonce_hash.update(message);
    let nonce = Scalar::from_hash(nonce_hash);

    let r_point = ED25519_BASEPOINT_TABLE * &nonce;
    let r_bytes = r_point.compress().to_bytes();

    let mut challenge_hash = Sha512::new();
    challenge_hash.update(r_bytes);
    challenge_hash.update(public_bytes);
    challenge_hash.update(message);
    let challenge = Scalar::from_hash(challenge_hash);

    let s = nonce + challenge * scalar;

    let mut signature = [0u8; SIGNATURE_LEN];
    let (r_half, s_half) = signature.split_at_mut(32);
    r_half.copy_from_slice(&r_bytes);
    s_half.copy_from_slice(&s.to_bytes());

    signature
}

/// Публичный ключ X25519, соответствующий приватному.
///
/// Клиенту он нужен, чтобы проверять подписи сервера, поэтому
/// отдаётся в ответе на регистрацию и по отдельному маршруту.
#[must_use]
pub fn public_key(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let scalar = clamp(private);
    let point = ED25519_BASEPOINT_TABLE * &scalar;

    point.to_montgomery().to_bytes()
}

/// Проверяет подпись — нужна тестам совместимости и жалобам на спам.
///
/// # Errors
///
/// Возвращает `false`, если ключ не является точкой кривой либо
/// подпись не сходится. Причина не различается: разница между
/// «плохой ключ» и «плохая подпись» — оракул.
#[must_use]
pub fn verify(public: &[u8; KEY_LEN], message: &[u8], signature: &[u8]) -> bool {
    let Some(point) = MontgomeryPoint(*public).to_edwards(0) else {
        return false;
    };

    let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&point.compress().to_bytes())
    else {
        return false;
    };

    let Ok(bytes) = <[u8; SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };

    verifying
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&bytes))
        .is_ok()
}

/// Разбирает подписываемую часть из готового сертификата.
///
/// Нужен разбору жалобы: получатель присылает сертификат целиком,
/// а сервер обязан проверить подпись над той же частью, которую
/// подписывал.
///
/// Возвращает `None`, если длина не та или версия незнакомая.
#[must_use]
pub fn split(raw: &[u8]) -> Option<(&[u8], [u8; SIGNATURE_LEN])> {
    let expected = 1 + ID_LEN + ID_LEN + KEY_LEN + 8 + SIGNATURE_LEN;

    if raw.len() != expected {
        return None;
    }

    if raw.first() != Some(&CERTIFICATE_VERSION) {
        return None;
    }

    let boundary = expected.saturating_sub(SIGNATURE_LEN);
    let payload = raw.get(..boundary)?;
    let signature = <[u8; SIGNATURE_LEN]>::try_from(raw.get(boundary..)?).ok()?;

    Some((payload, signature))
}

/// Достаёт аккаунт и устройство из подписываемой части.
///
/// Вызывается **после** проверки подписи: до неё содержимое —
/// это то, что прислал жалобщик, а не то, что утверждал сервер.
#[must_use]
pub fn subject(payload: &[u8]) -> Option<([u8; ID_LEN], [u8; ID_LEN])> {
    let account = <[u8; ID_LEN]>::try_from(payload.get(1..1 + ID_LEN)?).ok()?;
    let device = <[u8; ID_LEN]>::try_from(payload.get(1 + ID_LEN..1 + ID_LEN + ID_LEN)?).ok()?;

    Some((account, device))
}

/// Разбирает компактную запись точки — нужна проверке ключа сервера.
#[must_use]
pub fn is_valid_public_key(public: &[u8; KEY_LEN]) -> bool {
    MontgomeryPoint(*public).to_edwards(0).is_some()
        && CompressedEdwardsY(
            MontgomeryPoint(*public)
                .to_edwards(0)
                .map(|point| point.compress().to_bytes())
                .unwrap_or_default(),
        )
        .decompress()
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; KEY_LEN] {
        [0x42u8; KEY_LEN]
    }

    /// Сообщение вектора совместимости с клиентом.
    const COMPAT_MESSAGE: &[u8] = b"GASAPP-XEDDSA-COMPAT-VECTOR";

    /// Публичный ключ вектора: X25519 от приватного `[0x42; 32]`.
    const COMPAT_PUBLIC: &str = "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472";

    /// Подпись вектора, посчитанная клиентской реализацией.
    const COMPAT_SIGNATURE: &str = concat!(
        "7d084061db5bcd0e16a22fb1ebd6ae377b8ef921759f04b85c51549a5c94dd56",
        "ad111bea5a8526252729d7baaf578a2c30e11797e58431b49131aebe8b19ff0b",
    );

    fn hex_to_array<const N: usize>(text: &str) -> Option<[u8; N]> {
        let bytes = hex::decode(text).ok()?;

        <[u8; N]>::try_from(bytes.as_slice()).ok()
    }

    /// 🔐 Клиентский вектор совпадает с тем, что считает сервер.
    ///
    /// Клиент проверяет сертификаты собственной реализацией XEdDSA:
    /// связать workspace зависимостью нельзя (ADR-006). Расхождение
    /// двух реализаций означало бы, что ни один сертификат
    /// не проверяется, то есть sealed sender не работает целиком.
    ///
    /// Тот же вектор закреплён на клиенте
    /// (`sealed_sender::tests::server_compatibility_vector_verifies`).
    #[test]
    fn client_vector_verifies() {
        let expected_public = hex_to_array::<KEY_LEN>(COMPAT_PUBLIC).expect("вектор ключа");
        let expected_signature =
            hex_to_array::<SIGNATURE_LEN>(COMPAT_SIGNATURE).expect("вектор подписи");

        assert_eq!(
            public_key(&key()),
            expected_public,
            "серверный вывод публичного ключа разошёлся с клиентским"
        );
        assert_eq!(
            sign(&key(), COMPAT_MESSAGE),
            expected_signature,
            "серверная подпись разошлась с клиентской"
        );
        assert!(verify(
            &expected_public,
            COMPAT_MESSAGE,
            &expected_signature
        ));
    }

    /// Своя подпись проверяется своим же публичным ключом.
    #[test]
    fn signature_verifies() {
        let public = public_key(&key());
        let signature = sign(&key(), b"payload");

        assert!(verify(&public, b"payload", &signature));
    }

    /// 🔐 Подпись не проходит по другому сообщению.
    #[test]
    fn signature_does_not_transfer_to_another_message() {
        let public = public_key(&key());
        let signature = sign(&key(), b"payload");

        assert!(!verify(&public, b"another payload", &signature));
    }

    /// 🔐 Чужой ключ подпись не проверяет.
    #[test]
    fn foreign_key_does_not_verify() {
        let signature = sign(&key(), b"payload");
        let other = public_key(&[0x11u8; KEY_LEN]);

        assert!(!verify(&other, b"payload", &signature));
    }

    /// Подпись детерминирована: один ключ и одно сообщение — одна подпись.
    #[test]
    fn signing_is_deterministic() {
        assert_eq!(sign(&key(), b"payload"), sign(&key(), b"payload"));
    }

    /// 🔐 Порча подписи обнаруживается.
    #[test]
    fn damaged_signature_is_rejected() {
        let public = public_key(&key());
        let signature = sign(&key(), b"payload");

        for position in 0..SIGNATURE_LEN {
            let mut damaged = signature;
            if let Some(byte) = damaged.get_mut(position) {
                *byte ^= 0xFF;
            }

            assert!(
                !verify(&public, b"payload", &damaged),
                "порча байта {position} прошла проверку"
            );
        }
    }

    /// Сертификат разбирается обратно на части.
    #[test]
    fn certificate_splits_back() {
        let payload = signed_payload(&[1u8; ID_LEN], &[2u8; ID_LEN], &[3u8; KEY_LEN], 12345);
        let signature = sign(&key(), &payload);
        let encoded = encode(&payload, &signature);

        let (split_payload, split_signature) = split(&encoded).expect("разбор");

        assert_eq!(split_payload, payload.as_slice());
        assert_eq!(split_signature, signature);
        assert_eq!(subject(split_payload), Some(([1u8; ID_LEN], [2u8; ID_LEN])));
    }

    /// Сертификат неверной длины не разбирается.
    #[test]
    fn wrong_length_does_not_split() {
        assert!(split(&[]).is_none());
        assert!(split(&[0u8; 10]).is_none());
    }

    /// Незнакомая версия не разбирается.
    #[test]
    fn unknown_version_does_not_split() {
        let payload = signed_payload(&[1u8; ID_LEN], &[2u8; ID_LEN], &[3u8; KEY_LEN], 1);
        let mut encoded = encode(&payload, &sign(&key(), &payload));

        if let Some(version) = encoded.first_mut() {
            *version = 99;
        }

        assert!(split(&encoded).is_none());
    }

    /// Подписываемая часть имеет ожидаемую длину.
    ///
    /// Длина входит в разбор на клиенте, и расхождение сломало бы
    /// проверку каждого сертификата.
    #[test]
    fn payload_length_matches_the_client_format() {
        let payload = signed_payload(&[0u8; ID_LEN], &[0u8; ID_LEN], &[0u8; KEY_LEN], 0);

        assert_eq!(payload.len(), 1 + ID_LEN + ID_LEN + KEY_LEN + 8);
    }
}
