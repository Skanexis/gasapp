// SPDX-License-Identifier: Apache-2.0

//! Заворачивание ключей: шифрование ключа другим ключом.
//!
//! # Зачем это нужно
//!
//! У каждого файла File Vault свой ключ шифрования. Хранить эти ключи
//! в базе открытыми нельзя: расшифрованная база тогда отдавала бы
//! содержимое vault без второго фактора, то есть второй фактор
//! защищал бы только кнопку в интерфейсе. Поэтому ключ файла лежит
//! в базе **завёрнутым** в `K_vault`, который появляется в памяти
//! только после повторной аутентификации и исчезает вместе
//! с закрытием vault.
//!
//! # Почему nonce случайный и лежит рядом
//!
//! Одним `K_vault` заворачиваются ключи всех файлов. Вывести nonce
//! из заворачиваемого ключа нельзя — тогда два одинаковых ключа дали
//! бы одинаковый nonce; вывести из счётчика тоже нельзя — счётчик
//! пришлось бы где-то хранить и синхронизировать. Остаётся случайный,
//! а у XChaCha20 он длиной 192 бита, и при такой длине случайный
//! выбор безопасен без подсчёта числа использований.
//!
//! # Что защищает тег
//!
//! AAD — постоянная метка назначения. Она не даёт подставить в поле
//! ключа vault что-то, завёрнутое тем же ключом для другой цели,
//! если такая цель когда-нибудь появится.

use aegis_types::{AegisError, Result, Secret};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};

use crate::KEY_SIZE;

/// Длина nonce XChaCha20 в байтах.
pub const NONCE_LEN: usize = 24;

/// Длина завёрнутого ключа: nonce + шифротекст + тег.
pub const WRAPPED_LEN: usize = NONCE_LEN + KEY_SIZE + 16;

/// Метка назначения, входящая в тег.
const WRAP_AAD: &[u8] = b"AEGIS_KEY_WRAP_v1";

/// Заворачивает ключ в ключ-обёртку.
///
/// Возвращает `nonce || ciphertext || tag`.
///
/// # Errors
///
/// [`AegisError::Crypto`] — сбой AEAD.
pub fn wrap_key<R: RngCore + CryptoRng>(
    wrapping_key: &[u8; KEY_SIZE],
    key: &[u8; KEY_SIZE],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key).map_err(|_| AegisError::Crypto)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    let mut out = Vec::with_capacity(WRAPPED_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Разворачивает ключ.
///
/// # Errors
///
/// [`AegisError::Malformed`] — завёрнутый ключ не той длины;
/// [`AegisError::Crypto`] — тег не сходится: не тот ключ-обёртка
/// либо запись изменена.
pub fn unwrap_key(wrapping_key: &[u8; KEY_SIZE], wrapped: &[u8]) -> Result<Secret<[u8; KEY_SIZE]>> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(AegisError::Malformed);
    }

    let nonce = wrapped.get(..NONCE_LEN).ok_or(AegisError::Malformed)?;
    let ciphertext = wrapped.get(NONCE_LEN..).ok_or(AegisError::Malformed)?;

    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key).map_err(|_| AegisError::Crypto)?;

    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| AegisError::Crypto)?;

    let key: [u8; KEY_SIZE] = plain
        .as_slice()
        .try_into()
        .map_err(|_| AegisError::Malformed)?;

    Ok(Secret::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Ключ разворачивается обратно тем же ключом-обёрткой.
    #[test]
    fn wrap_round_trips() {
        let wrapping = [0x11u8; KEY_SIZE];
        let key = [0x22u8; KEY_SIZE];

        let wrapped = wrap_key(&wrapping, &key, &mut OsRng).expect("заворачивание");
        let unwrapped = unwrap_key(&wrapping, &wrapped).expect("разворачивание");

        assert_eq!(unwrapped.expose_secret(), &key);
        assert_eq!(wrapped.len(), WRAPPED_LEN);
    }

    /// 🔐 Чужой ключ-обёртка не разворачивает.
    #[test]
    fn foreign_wrapping_key_is_rejected() {
        let wrapped =
            wrap_key(&[0x11u8; KEY_SIZE], &[0x22u8; KEY_SIZE], &mut OsRng).expect("заворачивание");

        assert!(matches!(
            unwrap_key(&[0x33u8; KEY_SIZE], &wrapped),
            Err(AegisError::Crypto)
        ));
    }

    /// 🔐 Завёрнутый ключ не содержит исходного открытым текстом.
    #[test]
    fn wrapped_key_hides_the_original() {
        let key = [0x5Au8; KEY_SIZE];
        let wrapped = wrap_key(&[0x11u8; KEY_SIZE], &key, &mut OsRng).expect("заворачивание");

        assert!(
            !wrapped.windows(KEY_SIZE).any(|window| window == key),
            "исходный ключ виден в завёрнутом"
        );
    }

    /// 🔐 Один ключ, завёрнутый дважды, даёт разные записи.
    ///
    /// Иначе одинаковые файлы опознавались бы по совпадению
    /// завёрнутых ключей — а совпадение nonce означало бы ещё и
    /// повтор пары «ключ, nonce».
    #[test]
    fn wrapping_twice_gives_different_records() {
        let wrapping = [0x11u8; KEY_SIZE];
        let key = [0x22u8; KEY_SIZE];

        let first = wrap_key(&wrapping, &key, &mut OsRng).expect("заворачивание");
        let second = wrap_key(&wrapping, &key, &mut OsRng).expect("заворачивание");

        assert_ne!(first, second, "nonce не случаен");
    }

    /// 🔐 Порча любого байта обнаруживается.
    #[test]
    fn any_flipped_byte_is_detected() {
        let wrapping = [0x11u8; KEY_SIZE];
        let wrapped = wrap_key(&wrapping, &[0x22u8; KEY_SIZE], &mut OsRng).expect("заворачивание");

        for position in 0..wrapped.len() {
            let mut damaged = wrapped.clone();
            if let Some(byte) = damaged.get_mut(position) {
                *byte ^= 0xFF;
            }

            assert!(
                unwrap_key(&wrapping, &damaged).is_err(),
                "порча байта {position} осталась незамеченной"
            );
        }
    }

    /// Запись неверной длины отвергается до расшифровки.
    #[test]
    fn wrong_length_is_rejected() {
        assert!(matches!(
            unwrap_key(&[0u8; KEY_SIZE], &[0u8; 8]),
            Err(AegisError::Malformed)
        ));
    }
}
