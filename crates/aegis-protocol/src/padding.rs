// SPDX-License-Identifier: Apache-2.0

//! Бакетированный padding: сокрытие длины сообщения (раздел 15.3).
//!
//! # Что утекает без padding
//!
//! Размер шифротекста примерно равен размеру открытого текста.
//! Сервер, не читая ни слова, отличает «ок» от «я не приду, потому
//! что…» и видит, когда человек отправил документ, а когда — короткий
//! ответ. По одной длине строится ритм разговора: кто задаёт вопросы,
//! кто отвечает односложно, когда разговор оживился.
//!
//! # Схема
//!
//! Все сообщения приводятся к ближайшему бакету сверху:
//!
//! ```text
//! 512 · 1024 · 2048 · 4096 · 8192 · 16384 · 32768 · 65536 · 131072 · 262144
//!
//! 37 байт   → 512
//! 700 байт  → 1024
//! 5000 байт → 8192
//! ```
//!
//! 🔐 Padding кладётся **внутрь** шифротекста, поэтому сервер видит
//! только размер бакета. Класть его снаружи бессмысленно: там он
//! отделяется от содержимого простым вычитанием.
//!
//! # Почему нет опции «экономия трафика»
//!
//! ✅ Решение раздела 15.3: минимальный бакет 512 байт, всегда.
//! Настройка, снижающая приватность ради трафика, была бы включена
//! частью пользователей — и именно они стали бы отличимы по размеру
//! пакетов от остальных. То есть настройка сама превратилась бы
//! в различающий признак, и хуже всего пришлось бы тем, кто её
//! не трогал. Единый бакет для всех надёжнее любой экономии.
//!
//! # Формат
//!
//! ```text
//! ┌────────────┬──────────────────┬─────────────────┐
//! │ длина: u32 │ содержимое       │ нули до бакета  │
//! └────────────┴──────────────────┴─────────────────┘
//! ```
//!
//! Длина хранится явно, а не выводится из позиции последнего
//! ненулевого байта: содержимое имеет право заканчиваться нулём,
//! и «искать конец с хвоста» отрезало бы его молча.

use aegis_types::{AegisError, Result};

/// Длина поля размера.
const LENGTH_PREFIX: usize = 4;

/// Границы бакетов в байтах (раздел 15.3).
///
/// Список отсортирован по возрастанию — [`bucket_for`] полагается
/// на это при поиске.
pub const BUCKETS: &[usize] = &[
    512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536, 131_072, 262_144,
];

/// Наименьший бакет.
///
/// 🔐 512 байт даже на «ок». Это цена приватности, названная
/// в разделе 15.3 явно, а не побочный эффект.
pub const MIN_BUCKET: usize = 512;

/// Наибольший бакет.
pub const MAX_BUCKET: usize = 262_144;

/// Наибольшее содержимое, помещающееся в бакеты.
pub const MAX_CONTENT: usize = MAX_BUCKET - LENGTH_PREFIX;

/// Подбирает бакет для содержимого указанной длины.
///
/// # Errors
///
/// [`AegisError::Malformed`] — содержимое не помещается в наибольший
/// бакет. Отказ, а не отправка без padding: сообщение, выбившееся
/// из бакетов, отличимо по размеру, и молча отправить его значило бы
/// нарушить обещание раздела 15.3 ровно там, где оно важнее всего.
pub fn bucket_for(content_len: usize) -> Result<usize> {
    let needed = content_len
        .checked_add(LENGTH_PREFIX)
        .ok_or(AegisError::Malformed)?;

    BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= needed)
        .ok_or(AegisError::Malformed)
}

/// Дополняет содержимое до границы бакета.
///
/// # Errors
///
/// [`AegisError::Malformed`] — содержимое длиннее [`MAX_CONTENT`].
pub fn pad(content: &[u8]) -> Result<Vec<u8>> {
    let bucket = bucket_for(content.len())?;
    let length = u32::try_from(content.len()).map_err(|_| AegisError::Malformed)?;

    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(content);
    // Нулями, а не случайными байтами: под шифрованием и то, и другое
    // неразличимо, а нули не требуют источника случайности и делают
    // тесты воспроизводимыми.
    out.resize(bucket, 0);

    Ok(out)
}

/// Снимает padding.
///
/// # 🔐 Про доверие к длине
///
/// Значение длины приходит из расшифрованного сообщения, то есть
/// от владельца ключа сессии, — но не обязательно от добросовестного
/// собеседника. Поэтому длина сверяется с размером буфера до того,
/// как по ней что-то читается.
///
/// # Errors
///
/// [`AegisError::Malformed`] — буфер короче префикса, размер буфера
/// не совпадает ни с одним бакетом либо объявленная длина выходит
/// за его границы.
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    // Размер обязан совпадать с бакетом: сообщение произвольной
    // длины означает либо сбой, либо отправителя, который padding
    // не применил, — и принимать такое молча значит поощрять его.
    if !BUCKETS.contains(&padded.len()) {
        return Err(AegisError::Malformed);
    }

    let header = padded.get(..LENGTH_PREFIX).ok_or(AegisError::Malformed)?;
    let length = usize::try_from(u32::from_be_bytes(
        header.try_into().map_err(|_| AegisError::Malformed)?,
    ))
    .map_err(|_| AegisError::Malformed)?;

    let end = LENGTH_PREFIX
        .checked_add(length)
        .ok_or(AegisError::Malformed)?;

    padded.get(LENGTH_PREFIX..end).ok_or(AegisError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Содержимое переживает padding без изменений.
    #[test]
    fn padding_round_trips() {
        for length in [0usize, 1, 37, 511, 512, 700, 5000, 65_000] {
            let content = vec![0xABu8; length];
            let padded = pad(&content).expect("padding");

            assert_eq!(unpad(&padded).expect("снятие"), content.as_slice());
        }
    }

    /// 🧪 Задача раздела 15.3: любой шифротекст имеет размер из списка.
    #[test]
    fn every_padded_size_is_a_bucket() {
        for length in [0usize, 1, 37, 100, 511, 512, 513, 700, 5000, 65_000, 200_000] {
            let padded = pad(&vec![0u8; length]).expect("padding");

            assert!(
                BUCKETS.contains(&padded.len()),
                "длина {length} дала размер {}, которого нет в списке бакетов",
                padded.len()
            );
        }
    }

    /// Примеры из плана считаются ровно так, как там записано.
    #[test]
    fn plan_examples_match() {
        assert_eq!(bucket_for(37).expect("бакет"), 512);
        assert_eq!(bucket_for(700).expect("бакет"), 1024);
        assert_eq!(bucket_for(5000).expect("бакет"), 8192);
    }

    /// 🔐 Даже пустое содержимое занимает минимальный бакет.
    ///
    /// Иначе «прочитано» и «ок» отличались бы от текста по размеру.
    #[test]
    fn empty_content_still_fills_the_minimum_bucket() {
        assert_eq!(pad(&[]).expect("padding").len(), MIN_BUCKET);
    }

    /// 🔐 Сообщения разной длины в одном бакете неразличимы по размеру.
    ///
    /// Это и есть проверяемое свойство: «ок» и абзац на четыреста
    /// символов дают шифротекст одного размера.
    #[test]
    fn different_lengths_share_a_bucket() {
        let short = pad(b"ok").expect("padding");
        let long = pad(&vec![0x41u8; 400]).expect("padding");

        assert_eq!(short.len(), long.len());
    }

    /// Граница бакета переключает на следующий ровно вовремя.
    #[test]
    fn bucket_boundary_is_exact() {
        // 508 = 512 - 4 байта префикса: последняя длина, влезающая
        // в наименьший бакет.
        assert_eq!(bucket_for(508).expect("бакет"), 512);
        assert_eq!(bucket_for(509).expect("бакет"), 1024);
    }

    /// Слишком длинное содержимое отвергается, а не отправляется голым.
    #[test]
    fn oversized_content_is_rejected() {
        assert!(matches!(
            pad(&vec![0u8; MAX_CONTENT + 1]),
            Err(AegisError::Malformed)
        ));
        assert!(pad(&vec![0u8; MAX_CONTENT]).is_ok());
    }

    /// Буфер не из списка бакетов отвергается.
    #[test]
    fn non_bucket_length_is_rejected() {
        assert!(matches!(unpad(&[0u8; 500]), Err(AegisError::Malformed)));
        assert!(matches!(unpad(&[]), Err(AegisError::Malformed)));
    }

    /// 🔐 Длина, выходящая за буфер, отвергается до чтения.
    #[test]
    fn length_beyond_the_buffer_is_rejected() {
        let mut padded = pad(b"hello").expect("padding");

        // Объявляем содержимое длиннее самого бакета.
        if let Some(header) = padded.get_mut(..LENGTH_PREFIX) {
            header.copy_from_slice(&u32::MAX.to_be_bytes());
        }

        assert!(matches!(unpad(&padded), Err(AegisError::Malformed)));
    }

    /// Содержимое, заканчивающееся нулями, не обрезается.
    ///
    /// Ровно ради этого длина хранится явно: поиск конца по последнему
    /// ненулевому байту съел бы такой хвост молча.
    #[test]
    fn trailing_zeros_in_content_survive() {
        let content = vec![0u8; 100];
        let padded = pad(&content).expect("padding");

        assert_eq!(unpad(&padded).expect("снятие").len(), 100);
    }

    /// Бакеты идут по возрастанию: на этом держится поиск.
    #[test]
    fn buckets_are_sorted() {
        assert!(BUCKETS.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(BUCKETS.first().copied(), Some(MIN_BUCKET));
        assert_eq!(BUCKETS.last().copied(), Some(MAX_BUCKET));
    }

    /// Любой обрубок не приводит к панике.
    #[test]
    fn truncation_never_panics() {
        let padded = pad(b"hello").expect("padding");

        for length in 0..padded.len() {
            let slice = padded.get(..length).expect("срез");

            // Все обрубки короче бакета, поэтому обязаны отвергаться.
            assert!(unpad(slice).is_err());
        }
    }
}
