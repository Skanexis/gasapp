// SPDX-License-Identifier: Apache-2.0

//! Превью вложений.
//!
//! # Почему превью генерируется локально
//!
//! Сервер, делающий превью, обязан видеть оригинал — то есть сквозного
//! шифрования больше нет. Превью строит отправитель на своём
//! устройстве, шифрует и загружает как отдельный файл.
//!
//! # Почему у превью отдельный ключ
//!
//! 🔐 Превью показывается сразу, оригинал — по нажатию. Если бы они
//! шифровались одним ключом, получатель, открывший список сообщений,
//! уже имел бы доступ к полному файлу; при отзыве сообщения отозвать
//! осталось бы нечего.
//!
//! Отдельный ключ позволяет передать превью, не передавая оригинал —
//! это понадобится для «удаления для всех» и для чатов с исчезающими
//! сообщениями.
//!
//! # Чего этот модуль не делает
//!
//! Не масштабирует картинки и не декодирует видео. Это работа
//! платформы: у Android и iOS есть аппаратные кодеки, а тянуть
//! декодер изображений в Rust значит добавить к поверхности атаки
//! разбор недоверенных форматов — исторически самый богатый источник
//! уязвимостей.
//!
//! Здесь только шифрование готового изображения и проверка его
//! размера.

use aegis_types::{AegisError, Result};
use rand_core::{CryptoRng, RngCore};

use crate::attachment::{self, AttachmentKey};

/// Предел размера превью.
///
/// 🔐 Не только про экономию трафика. Превью показывается
/// автоматически, без действия пользователя, — значит его разбор
/// происходит для каждого входящего сообщения. Чем меньше данных
/// попадает в декодер платформы, тем меньше поверхность атаки.
///
/// 16 КБ достаточно для картинки 512×512 в JPEG приемлемого качества
/// и вчетверо меньше размера чанка — превью гарантированно
/// помещается в один чанк, и логика сборки для него не нужна.
pub const MAX_PREVIEW_BYTES: usize = 16 * 1024;

/// Максимальная сторона превью в пикселях.
///
/// Ограничение проверяется вызывающей стороной при генерации:
/// здесь оно объявлено, чтобы платформы не расходились в значении.
pub const MAX_PREVIEW_SIDE: u32 = 512;

/// Предел превью заметно меньше размера чанка.
///
/// Проверка на этапе компиляции, а не в тесте: сравнение констант
/// вычисляется компилятором, и тест из него получился бы всегда
/// истинным или всегда ложным — то есть бесполезным.
///
/// Если чанк уменьшат, превью перестанет помещаться в один чанк,
/// и `seal_preview` начнёт молча обрезать данные. Сборка должна
/// упасть раньше.
const _: () = assert!(MAX_PREVIEW_BYTES < attachment::CHUNK_SIZE);

/// Зашифрованное превью, готовое к загрузке.
pub struct SealedPreview {
    /// Шифроблоб.
    pub ciphertext: Vec<u8>,

    /// Ключ превью.
    ///
    /// 🔐 Уходит получателю внутри сообщения. Отдельный от ключа
    /// оригинала — см. пояснение в модуле.
    pub key: AttachmentKey,
}

/// Шифрует готовое изображение превью.
///
/// Изображение уже уменьшено платформой: этот модуль не декодирует
/// картинки (см. пояснение модуля).
///
/// # Errors
///
/// [`AegisError::Malformed`] — превью больше [`MAX_PREVIEW_BYTES`];
/// [`AegisError::Crypto`] — сбой шифрования.
pub fn seal_preview<R: RngCore + CryptoRng>(
    image: &[u8],
    rng: &mut R,
) -> Result<SealedPreview> {
    if image.len() > MAX_PREVIEW_BYTES {
        return Err(AegisError::Malformed);
    }

    let key = AttachmentKey::generate(rng);

    // Превью помещается в один чанк по построению: его предел вчетверо
    // меньше размера чанка. Отдельной логики сборки не нужно.
    let ciphertext = attachment::seal_chunk(&key, 0, image)?;

    Ok(SealedPreview { ciphertext, key })
}

/// Расшифровывает превью.
///
/// # Errors
///
/// [`AegisError::Crypto`] — тег не сходится: повреждение или подмена;
/// [`AegisError::Malformed`] — расшифрованное превью больше предела.
pub fn open_preview(key: &AttachmentKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let image = attachment::open_chunk(key, 0, ciphertext)?;

    // 🔐 Проверка после расшифровки, а не только до шифрования:
    // размер приходит от отправителя, то есть потенциально
    // от атакующего. Превью на десять мегабайт скормило бы декодеру
    // платформы ровно то, чего предел и должен избежать.
    if image.len() > MAX_PREVIEW_BYTES {
        return Err(AegisError::Malformed);
    }

    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn preview_round_trips() {
        let image = vec![0x42u8; 4096];

        let sealed = seal_preview(&image, &mut OsRng).expect("шифрование");
        let opened = open_preview(&sealed.key, &sealed.ciphertext).expect("расшифровка");

        assert_eq!(opened, image);
    }

    /// 🔐 Ключ превью отличается от ключа оригинала.
    ///
    /// Иначе получатель, увидевший превью в списке, уже имел бы доступ
    /// к полному файлу — и отзывать сообщение было бы поздно.
    #[test]
    fn preview_key_is_independent() {
        let original = AttachmentKey::generate(&mut OsRng);
        let sealed = seal_preview(b"thumbnail", &mut OsRng).expect("шифрование");

        assert_ne!(sealed.key.expose(), original.expose());
    }

    /// Слишком большое превью отвергается при шифровании.
    #[test]
    fn oversized_preview_is_rejected() {
        let image = vec![0u8; MAX_PREVIEW_BYTES + 1];

        assert!(matches!(
            seal_preview(&image, &mut OsRng),
            Err(AegisError::Malformed)
        ));
    }

    /// 🔐 Слишком большое превью отвергается и при расшифровке.
    ///
    /// Размер приходит от отправителя: проверка только на своей
    /// стороне не защитила бы от того, кто собрал сообщение вручную.
    #[test]
    fn oversized_preview_is_rejected_on_open() {
        let key = AttachmentKey::generate(&mut OsRng);
        let oversized = vec![0u8; MAX_PREVIEW_BYTES + 1];

        // Шифруем в обход проверки — так поступил бы атакующий,
        // собравший сообщение своей реализацией.
        let ciphertext =
            attachment::seal_chunk(&key, 0, &oversized).expect("шифрование");

        assert!(matches!(
            open_preview(&key, &ciphertext),
            Err(AegisError::Malformed)
        ));
    }

    #[test]
    fn tampered_preview_is_detected() {
        let mut sealed = seal_preview(b"thumbnail", &mut OsRng).expect("шифрование");
        sealed.ciphertext[0] ^= 0x01;

        assert!(open_preview(&sealed.key, &sealed.ciphertext).is_err());
    }

}
