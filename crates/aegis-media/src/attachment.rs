// SPDX-License-Identifier: Apache-2.0

//! Шифрование вложений чанками.
//!
//! # Зачем чанки
//!
//! Конверт сообщения ограничен 256 КБ — файл в него не поместится.
//! Вложения идут отдельным каналом: клиент шифрует файл, загружает
//! шифроблоб в хранилище, а в сообщении передаёт только ключ и адрес.
//!
//! Чанки нужны не ради размера, а ради потоковой обработки: телефон
//! не должен держать в памяти видео целиком, чтобы его зашифровать.
//!
//! # Почему XChaCha20-Poly1305, а не AES-GCM
//!
//! Ключ вложения используется многократно — по разу на чанк. У AES-GCM
//! 96-битный nonce, и при случайном выборе вероятность повторения
//! становится ощутимой после 2³² сообщений; повторение nonce в GCM
//! раскрывает открытый текст обоих сообщений и позволяет подделывать
//! теги.
//!
//! У XChaCha20 nonce 192-битный: даже случайные значения не повторятся
//! за всё время существования человечества. Здесь nonce всё равно
//! выводится из счётчика — это надёжнее случайности, — но запас
//! разрядности убирает целый класс ошибок.
//!
//! # Про лимит числа чанков
//!
//! Счётчик 32-битный (раздел 10 плана: жёсткий лимит 2³² на ключ).
//! При чанке в 64 КБ это 256 ТБ — граница недостижима практически,
//! но проверяется явно: молчаливое переполнение счётчика вернуло бы
//! nonce к началу и повторило бы их.
//!
//! # Что не шифруется
//!
//! Ничего. Имя файла, тип и размер идут внутри сообщения, то есть
//! под сквозным шифрованием. Хранилище видит только шифроблоб
//! и его длину — по ней можно судить о размере файла, и это
//! неустранимо без паддинга, который для видео стоил бы слишком
//! дорого.

use aegis_types::{AegisError, Result, Secret};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};

/// Длина ключа вложения.
pub const KEY_LEN: usize = 32;

/// Длина nonce XChaCha20.
pub const NONCE_LEN: usize = 24;

/// Длина тега аутентификации.
pub const TAG_LEN: usize = 16;

/// Размер чанка открытого текста.
///
/// 64 КБ — компромисс: меньше означает больше тегов аутентификации
/// (по 16 байт на чанк) и больше обращений к диску; больше означает,
/// что бюджетный телефон держит в памяти лишнее при загрузке
/// нескольких файлов одновременно.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Размер зашифрованного чанка.
pub const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_LEN;

/// Предел числа чанков на один ключ.
///
/// 🔐 Раздел 10 плана: жёсткий лимит 2³² сообщений на ключ. Достижение
/// предела означает ошибку в вызывающем коде — при 64 КБ на чанк это
/// 256 терабайт одним файлом.
pub const MAX_CHUNKS: u32 = u32::MAX;

/// Ключ вложения.
///
/// Живёт ровно столько, сколько нужно для шифрования или расшифровки
/// одного файла. Передаётся получателю внутри сообщения, то есть
/// под сквозным шифрованием.
pub struct AttachmentKey(Secret<[u8; KEY_LEN]>);

impl AttachmentKey {
    /// Генерирует ключ для нового вложения.
    ///
    /// 🔐 Ключ на каждое вложение свой. Общий ключ на все файлы
    /// пользователя означал бы, что компрометация одного раскрывает
    /// все — включая уже отправленные и «удалённые».
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = [0u8; KEY_LEN];
        rng.fill_bytes(&mut key);

        Self(Secret::new(key))
    }

    /// Восстанавливает ключ из байтов, полученных в сообщении.
    #[must_use]
    pub fn from_bytes(key: [u8; KEY_LEN]) -> Self {
        Self(Secret::new(key))
    }

    /// Отдаёт байты ключа для передачи в сообщении.
    ///
    /// 🔐 Единственное место, где ключ покидает тип. Вызывается при
    /// сборке сообщения — то есть перед тем, как ключ уйдёт под
    /// сквозным шифрованием.
    #[must_use]
    pub const fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

/// Шифрует один чанк.
///
/// # Про порядковый номер
///
/// Номер чанка входит в nonce и в аутентифицируемые данные. Первое
/// не даёт повторить nonce, второе — переставить чанки местами:
/// без привязки к номеру атакующий поменял бы куски видео местами,
/// и получатель не заметил бы подмены, потому что каждый чанк
/// по отдельности остался бы подлинным.
///
/// # Errors
///
/// [`AegisError::Malformed`] — номер чанка достиг предела;
/// [`AegisError::Crypto`] — сбой шифрования.
pub fn seal_chunk(key: &AttachmentKey, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    if index == MAX_CHUNKS {
        return Err(AegisError::Malformed);
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| AegisError::Crypto)?;

    cipher
        .encrypt(
            XNonce::from_slice(&nonce_for(index)),
            Payload {
                msg: plaintext,
                aad: &index.to_be_bytes(),
            },
        )
        .map_err(|_| AegisError::Crypto)
}

/// Расшифровывает один чанк.
///
/// # Errors
///
/// [`AegisError::Crypto`] — тег не сходится. Это означает либо
/// повреждение, либо подмену, включая перестановку чанков местами;
/// различать их для пользователя смысла нет.
pub fn open_chunk(key: &AttachmentKey, index: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| AegisError::Crypto)?;

    cipher
        .decrypt(
            XNonce::from_slice(&nonce_for(index)),
            Payload {
                msg: ciphertext,
                aad: &index.to_be_bytes(),
            },
        )
        .map_err(|_| AegisError::Crypto)
}

/// Сколько чанков потребуется для файла заданного размера.
///
/// # Errors
///
/// [`AegisError::Malformed`] — файл не помещается в лимит чанков.
pub fn chunk_count(size: usize) -> Result<u32> {
    if size == 0 {
        return Ok(0);
    }

    let count = size.div_ceil(CHUNK_SIZE);

    u32::try_from(count).map_err(|_| AegisError::Malformed)
}

/// 🔐 Длина, до которой дополняется файл перед шифрованием (Padmé).
///
/// Сервер видит длину шифроблоба, а точная длина файла узнаваема:
/// одна и та же пересланная фотография весит одинаково у всех, кому
/// её переслали, и по размеру блоба видно, что десять человек
/// получили один файл. Длина округляется вверх до сетки, шаг которой
/// растёт с размером (Nikitin et al., «Reducing Metadata Leakage from
/// Encrypted Files and Communication with PURBs», 2019): накладные
/// расходы не больше 12 %, а о файле остаётся известен лишь порядок
/// величины — O(log log n) бит вместо O(log n).
///
/// Дополнение — нули перед шифрованием: под AEAD они неотличимы
/// от данных, а настоящая длина едет внутри описания вложения,
/// зашифрованного вместе с сообщением.
///
/// # Errors
///
/// [`AegisError::Malformed`] — длина не представима.
pub fn padded_len(size: usize) -> Result<usize> {
    if size < 2 {
        return Ok(size);
    }

    let size64 = u64::try_from(size).map_err(|_| AegisError::Malformed)?;

    // E = ⌊log2 L⌋, S = ⌊log2 E⌋ + 1, обнуляется E − S младших бит.
    let exponent = 63u32
        .checked_sub(size64.leading_zeros())
        .ok_or(AegisError::Malformed)?;
    let bits_of_exponent = 32u32
        .checked_sub(exponent.leading_zeros())
        .ok_or(AegisError::Malformed)?;
    let low_bits = exponent.saturating_sub(bits_of_exponent);
    let mask = 1u64
        .checked_shl(low_bits)
        .and_then(|bit| bit.checked_sub(1))
        .ok_or(AegisError::Malformed)?;

    let padded = size64.checked_add(mask).ok_or(AegisError::Malformed)? & !mask;

    usize::try_from(padded).map_err(|_| AegisError::Malformed)
}

/// Выводит nonce для чанка.
///
/// Счётчик в старших байтах, остальное — нули. Случайная часть здесь
/// не нужна: ключ уникален для вложения, и пара «ключ + счётчик»
/// не повторяется по построению. Добавление случайности создало бы
/// иллюзию защиты там, где она обеспечена детерминированно.
fn nonce_for(index: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce
        .get_mut(..4)
        .unwrap_or(&mut [])
        .copy_from_slice(&index.to_be_bytes());

    nonce
}

#[cfg(test)]
mod tests {

    /// Padmé: не меньше исходного, не больше +12 %, на сетке.
    #[test]
    fn padding_is_bounded_and_coarse() {
        for size in [2usize, 3, 100, 1_000, 4_096, 65_537, 1_000_000, 104_857_600] {
            let padded = padded_len(size).expect("длина");

            assert!(padded >= size);
            assert!(
                (padded - size) * 100 <= size * 12,
                "{size} → {padded}: больше 12 %"
            );
        }

        // Близкие размеры неразличимы после дополнения.
        assert_eq!(
            padded_len(1_000_001).expect("длина"),
            padded_len(1_010_000).expect("длина")
        );
        // 100 МиБ лежит на сетке: предел сервера не превышается.
        assert_eq!(padded_len(104_857_600).expect("длина"), 104_857_600);
    }
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn chunk_round_trips() {
        let key = AttachmentKey::generate(&mut OsRng);
        let data = b"attachment payload".to_vec();

        let sealed = seal_chunk(&key, 0, &data).expect("шифрование");
        let opened = open_chunk(&key, 0, &sealed).expect("расшифровка");

        assert_eq!(opened, data);
    }

    /// 🔐 Чанки нельзя переставить местами.
    ///
    /// Без привязки к номеру атакующий поменял бы куски видео
    /// местами, и получатель не заметил бы: каждый чанк по отдельности
    /// остался бы подлинным.
    #[test]
    fn chunks_cannot_be_reordered() {
        let key = AttachmentKey::generate(&mut OsRng);

        let first = seal_chunk(&key, 0, b"first").expect("шифрование");

        // Тот же шифротекст, предъявленный как другой чанк.
        assert!(open_chunk(&key, 1, &first).is_err());
    }

    /// 🔐 Одинаковые чанки дают разные шифротексты.
    ///
    /// Иначе наблюдатель хранилища видел бы повторяющиеся блоки —
    /// например, одинаковые кадры видео или заполненные нулями
    /// участки файла.
    #[test]
    fn identical_chunks_differ_in_ciphertext() {
        let key = AttachmentKey::generate(&mut OsRng);
        let data = vec![0u8; 1024];

        let first = seal_chunk(&key, 0, &data).expect("шифрование");
        let second = seal_chunk(&key, 1, &data).expect("шифрование");

        assert_ne!(first, second);
    }

    /// 🔐 Чужой ключ не расшифровывает.
    #[test]
    fn wrong_key_is_rejected() {
        let key = AttachmentKey::generate(&mut OsRng);
        let other = AttachmentKey::generate(&mut OsRng);

        let sealed = seal_chunk(&key, 0, b"secret").expect("шифрование");

        assert!(open_chunk(&other, 0, &sealed).is_err());
    }

    /// Повреждение хотя бы одного байта отвергается.
    #[test]
    fn tampering_is_detected() {
        let key = AttachmentKey::generate(&mut OsRng);
        let mut sealed = seal_chunk(&key, 0, b"payload").expect("шифрование");

        sealed[0] ^= 0x01;

        assert!(open_chunk(&key, 0, &sealed).is_err());
    }

    /// Каждое вложение получает свой ключ.
    #[test]
    fn generated_keys_differ() {
        let first = AttachmentKey::generate(&mut OsRng);
        let second = AttachmentKey::generate(&mut OsRng);

        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn chunk_count_rounds_up() {
        assert_eq!(chunk_count(0).expect("ноль"), 0);
        assert_eq!(chunk_count(1).expect("один байт"), 1);
        assert_eq!(chunk_count(CHUNK_SIZE).expect("ровно чанк"), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1).expect("чанк и байт"), 2);
    }

    /// Nonce различаются для разных чанков.
    ///
    /// Проверка самого механизма: повторение nonce при одном ключе —
    /// это раскрытие открытого текста, и полагаться здесь на «оно
    /// наверняка работает» нельзя.
    #[test]
    fn nonces_are_unique_per_chunk() {
        let mut seen = std::collections::HashSet::new();

        for index in [0u32, 1, 2, 1000, u32::MAX - 1] {
            assert!(seen.insert(nonce_for(index)), "nonce повторился");
        }
    }
}
