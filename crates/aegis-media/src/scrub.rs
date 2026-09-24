// SPDX-License-Identifier: Apache-2.0

//! 🔐 Удаление метаданных из вложений до шифрования.
//!
//! # Что здесь закрывается
//!
//! Фотография с телефона несёт больше, чем изображение: координаты GPS
//! места съёмки, модель и серийный номер камеры, точное время, программу
//! обработки, миниатюру исходного кадра (иногда — до кадрирования).
//! Видео — геометку, модель телефона и дату. Сквозное шифрование прячет
//! всё это от сервера, но не от собеседника, а собеседник пересылает
//! дальше. «Фото кота» с координатами подъезда — классическая утечка
//! домашнего адреса.
//!
//! # Как
//!
//! Без перекодирования: изображение и звук не пересжимаются, качество
//! не теряется. Разбирается только контейнер, и из него выбрасывается
//! всё, что не нужно для показа.
//!
//! | Формат | Что остаётся | Что удаляется |
//! |---|---|---|
//! | JPEG | кадр, таблицы, JFIF, ICC, Adobe; поворот — отдельным минимальным EXIF | EXIF, GPS, XMP, миниатюры, комментарии, сегменты производителей, всё после конца кадра («живое фото») |
//! | PNG | IHDR, PLTE, IDAT, IEND, прозрачность, цвет, анимация | текст, EXIF, время, прочее |
//! | WebP | кадры, прозрачность, анимация, ICC | EXIF, XMP |
//! | GIF | кадры, палитры, управление, повтор анимации | комментарии, XMP и прочие расширения |
//! | MP4 / MOV / M4A / 3GP | дорожки и данные | `udta`, `meta`, `uuid`, `XMP_` затираются на месте; время в заголовках обнуляется |
//! | MP3 | звук | `ID3v2`, `ID3v1`, `APEv2` |
//!
//! # Почему MP4 затирается на месте, а не вырезается
//!
//! Данные дорожек адресуются абсолютными смещениями (`stco`/`co64`).
//! Вырезанный блок перед `mdat` сдвинул бы их все, и видео перестало бы
//! играть. Блок метаданных переименовывается в `free` — «пустое место»
//! стандарта — и забивается нулями: размер и смещения прежние,
//! содержимого нет.
//!
//! # Чего здесь нет
//!
//! ⚠️ HEIC и AVIF: их метаданные — элементы внутри структуры самого
//! изображения, и вырезать их на месте без пересборки нельзя. Такие
//! файлы отвергаются ([`AegisError::Malformed`]); платформа перед
//! отправкой перекодирует их в JPEG.
//!
//! ⚠️ Документы (PDF, Word и прочее) не разбираются: в них метаданные
//! — часть формата, и «удалить автора» из PDF без его переписывания
//! нельзя. Такие файлы проходят как есть ([`Format::Unknown`]), и
//! интерфейс об этом предупреждает.
//!
//! ⚠️ Содержимое кадра не трогается: лица, номера, отражения,
//! водяные знаки и шум конкретной матрицы камеры остаются. Это
//! метаданные только в переносном смысле, и удалить их нельзя
//! без изменения самого изображения.
//!
//! # 🔐 Отказ закрытым
//!
//! Файл известного формата, который не разбирается, — ошибка, а не
//! «отправить как есть». Иначе испорченный на один байт JPEG уходил бы
//! со всем EXIF, и именно такой файл подсунул бы тот, кто хочет
//! утечки.

use aegis_types::{AegisError, Result};

/// Распознанный формат вложения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// JPEG.
    Jpeg,
    /// PNG, в том числе анимированный.
    Png,
    /// WebP.
    WebP,
    /// GIF.
    Gif,
    /// Контейнер ISO BMFF: MP4, MOV, M4A, 3GP.
    IsoMedia,
    /// MP3.
    Mp3,
    /// Формат не распознан — содержимое не изменено.
    Unknown,
}

impl Format {
    /// Изображение, видео или звук — то, у чего имя файла сообщает
    /// только время съёмки и устройство.
    #[must_use]
    pub const fn is_media(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Очищенное вложение.
#[derive(Debug, Clone)]
pub struct Scrubbed {
    /// Содержимое без метаданных.
    pub bytes: Vec<u8>,
    /// Что было распознано.
    pub format: Format,
}

/// Распознаёт формат по первым байтам.
///
/// По содержимому, а не по имени или MIME: их выбирает отправитель,
/// и «отчёт.pdf», который на деле JPEG, обязан очиститься как JPEG.
#[must_use]
pub fn detect(bytes: &[u8]) -> Format {
    let starts = |prefix: &[u8]| bytes.starts_with(prefix);

    if starts(&[0xFF, 0xD8, 0xFF]) {
        Format::Jpeg
    } else if starts(b"\x89PNG\r\n\x1a\n") {
        Format::Png
    } else if starts(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Format::WebP
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        Format::Gif
    } else if bytes.get(4..8) == Some(b"ftyp") {
        Format::IsoMedia
    } else if starts(b"ID3") || is_mpeg_audio_sync(bytes) {
        Format::Mp3
    } else {
        Format::Unknown
    }
}

/// Удаляет метаданные.
///
/// # Errors
///
/// [`AegisError::Malformed`] — файл распознанного формата не разбирается
/// или это HEIC/AVIF (см. описание модуля). Отправлять такой файл
/// как есть нельзя: метаданные ушли бы вместе с ним.
pub fn scrub(bytes: &[u8]) -> Result<Scrubbed> {
    let format = detect(bytes);

    let cleaned = match format {
        Format::Jpeg => jpeg(bytes)?,
        Format::Png => png(bytes)?,
        Format::WebP => webp(bytes)?,
        Format::Gif => gif(bytes)?,
        Format::IsoMedia => iso_media(bytes)?,
        Format::Mp3 => mp3(bytes)?,
        Format::Unknown => bytes.to_vec(),
    };

    Ok(Scrubbed {
        bytes: cleaned,
        format,
    })
}

// ---------------------------------------------------------------------------
//  Общие помощники: всё чтение — с проверкой границ.
// ---------------------------------------------------------------------------

fn slice(bytes: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start.checked_add(len).ok_or(AegisError::Malformed)?;
    bytes.get(start..end).ok_or(AegisError::Malformed)
}

fn byte(bytes: &[u8], at: usize) -> Result<u8> {
    bytes.get(at).copied().ok_or(AegisError::Malformed)
}

fn u16_be(bytes: &[u8], at: usize) -> Result<u16> {
    let raw = slice(bytes, at, 2)?;
    Ok(u16::from_be_bytes([byte(raw, 0)?, byte(raw, 1)?]))
}

fn u32_be(bytes: &[u8], at: usize) -> Result<u32> {
    let raw: [u8; 4] = slice(bytes, at, 4)?
        .try_into()
        .map_err(|_| AegisError::Malformed)?;
    Ok(u32::from_be_bytes(raw))
}

fn u32_le(bytes: &[u8], at: usize) -> Result<u32> {
    let raw: [u8; 4] = slice(bytes, at, 4)?
        .try_into()
        .map_err(|_| AegisError::Malformed)?;
    Ok(u32::from_le_bytes(raw))
}

fn u64_be(bytes: &[u8], at: usize) -> Result<u64> {
    let raw: [u8; 8] = slice(bytes, at, 8)?
        .try_into()
        .map_err(|_| AegisError::Malformed)?;
    Ok(u64::from_be_bytes(raw))
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(AegisError::Malformed)
}

fn to_usize(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| AegisError::Malformed)
}

// ---------------------------------------------------------------------------
//  JPEG
// ---------------------------------------------------------------------------

const JPEG_SOI: u8 = 0xD8;
const JPEG_EOI: u8 = 0xD9;
const JPEG_SOS: u8 = 0xDA;
const JPEG_APP0: u8 = 0xE0;
const JPEG_APP1: u8 = 0xE1;
const JPEG_APP2: u8 = 0xE2;
const JPEG_APP14: u8 = 0xEE;
const JPEG_COM: u8 = 0xFE;

/// Сегмент JPEG, который остаётся.
///
/// Все `APPn`, кроме трёх нужных для показа, и комментарии удаляются.
/// JFIF — плотность пикселей, ICC — цветовой профиль (без него цвета
/// широкого охвата поблёкнут), Adobe — признак преобразования цвета
/// (без него CMYK-файл покажется негативом).
fn jpeg_keeps(marker: u8, payload: &[u8]) -> bool {
    match marker {
        JPEG_APP0 => payload.starts_with(b"JFIF\0"),
        JPEG_APP2 => payload.starts_with(b"ICC_PROFILE\0"),
        JPEG_APP14 => payload.starts_with(b"Adobe"),
        0xE1..=0xEF | JPEG_COM => false,
        _ => true,
    }
}

fn jpeg(bytes: &[u8]) -> Result<Vec<u8>> {
    if slice(bytes, 0, 2)? != [0xFF, JPEG_SOI] {
        return Err(AegisError::Malformed);
    }

    let mut head: Vec<u8> = vec![0xFF, JPEG_SOI];
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut orientation: Option<u16> = None;
    let mut pos = 2usize;

    loop {
        if byte(bytes, pos)? != 0xFF {
            return Err(AegisError::Malformed);
        }

        // Байты-заполнители 0xFF перед маркером допустимы стандартом.
        while byte(bytes, pos)? == 0xFF {
            pos = add(pos, 1)?;
        }

        let marker = byte(bytes, pos)?;
        pos = add(pos, 1)?;

        match marker {
            JPEG_EOI => {
                body.extend_from_slice(&[0xFF, JPEG_EOI]);

                // 🔐 Всё после конца кадра отбрасывается: туда телефоны
                // дописывают видео «живого фото» и служебные хвосты.
                break;
            }
            0x01 | 0xD0..=0xD7 => {
                body.extend_from_slice(&[0xFF, marker]);
            }
            _ => {
                let len = usize::from(u16_be(bytes, pos)?);

                if len < 2 {
                    return Err(AegisError::Malformed);
                }

                let payload = slice(
                    bytes,
                    add(pos, 2)?,
                    len.checked_sub(2).ok_or(AegisError::Malformed)?,
                )?;
                let end = add(pos, len)?;

                if marker == JPEG_APP1 && orientation.is_none() {
                    orientation = exif_orientation(payload);
                }

                let keep = jpeg_keeps(marker, payload);

                if keep && marker == JPEG_APP0 && body.is_empty() {
                    // JFIF обязан идти сразу после SOI — впереди
                    // минимального EXIF с поворотом.
                    head.extend_from_slice(&[0xFF, marker]);
                    head.extend_from_slice(slice(bytes, pos, len)?);
                } else if keep {
                    body.extend_from_slice(&[0xFF, marker]);
                    body.extend_from_slice(slice(bytes, pos, len)?);
                }

                pos = end;

                if marker == JPEG_SOS {
                    let scan_end = jpeg_scan_end(bytes, pos)?;
                    body.extend_from_slice(slice(
                        bytes,
                        pos,
                        scan_end.checked_sub(pos).ok_or(AegisError::Malformed)?,
                    )?);
                    pos = scan_end;
                }
            }
        }
    }

    if let Some(value) = orientation.filter(|value| (2..=8).contains(value)) {
        head.extend_from_slice(&orientation_segment(value));
    }

    head.extend_from_slice(&body);

    Ok(head)
}

/// Конец энтропийно закодированных данных после SOS: первый маркер,
/// который не является экранированным `FF 00` и не маркером рестарта.
fn jpeg_scan_end(bytes: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;

    loop {
        if byte(bytes, pos)? == 0xFF {
            let next = byte(bytes, add(pos, 1)?)?;

            match next {
                0x00 | 0xD0..=0xD7 => pos = add(pos, 2)?,
                0xFF => pos = add(pos, 1)?,
                _ => return Ok(pos),
            }
        } else {
            pos = add(pos, 1)?;
        }
    }
}

/// Ориентация из EXIF (тег 0x0112 в IFD0), если она там есть.
///
/// Любая ошибка разбора — «ориентации нет»: сам EXIF удаляется
/// в любом случае, а неверный поворот лучше пропавшего кадра.
fn exif_orientation(payload: &[u8]) -> Option<u16> {
    let tiff = payload.strip_prefix(b"Exif\0\0")?;
    let big_endian = match tiff.get(0..2)? {
        b"MM" => true,
        b"II" => false,
        _ => return None,
    };

    let read16 = |at: usize| -> Option<u16> {
        let raw = [*tiff.get(at)?, *tiff.get(at.checked_add(1)?)?];
        Some(if big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    };
    let read32 = |at: usize| -> Option<u32> {
        let raw: [u8; 4] = tiff.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    };

    let ifd = usize::try_from(read32(4)?).ok()?;
    let count = usize::from(read16(ifd)?);

    (0..count).find_map(|index| {
        let entry = ifd.checked_add(2)?.checked_add(index.checked_mul(12)?)?;
        (read16(entry)? == 0x0112).then(|| read16(entry.checked_add(8)?))?
    })
}

/// Минимальный сегмент APP1: EXIF с единственным тегом — ориентацией.
///
/// Без него повёрнутый при съёмке кадр пришёл бы лёжа на боку:
/// телефоны не поворачивают пиксели, а записывают поворот в EXIF.
fn orientation_segment(orientation: u16) -> Vec<u8> {
    let mut tiff: Vec<u8> = Vec::with_capacity(26);
    tiff.extend_from_slice(b"MM\0\x2A");
    tiff.extend_from_slice(&8u32.to_be_bytes()); // IFD0 сразу за заголовком
    tiff.extend_from_slice(&1u16.to_be_bytes()); // одна запись
    tiff.extend_from_slice(&0x0112u16.to_be_bytes()); // Orientation
    tiff.extend_from_slice(&3u16.to_be_bytes()); // SHORT
    tiff.extend_from_slice(&1u32.to_be_bytes()); // одно значение
    tiff.extend_from_slice(&orientation.to_be_bytes());
    tiff.extend_from_slice(&[0, 0]); // дополнение значения до 4 байт
    tiff.extend_from_slice(&0u32.to_be_bytes()); // следующего IFD нет

    // Длина сегмента: 2 (само поле) + 6 ("Exif\0\0") + TIFF — 34 байта.
    let len: u16 = 34;

    let mut segment = vec![0xFF, JPEG_APP1];
    segment.extend_from_slice(&len.to_be_bytes());
    segment.extend_from_slice(b"Exif\0\0");
    segment.extend_from_slice(&tiff);
    segment
}

// ---------------------------------------------------------------------------
//  PNG
// ---------------------------------------------------------------------------

/// Чанки PNG, нужные для показа. Всё остальное — текст (`tEXt`,
/// `zTXt`, `iTXt`), `eXIf`, время (`tIME`), данные программ — удаляется.
const PNG_KEEP: [&[u8; 4]; 13] = [
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT",
    b"acTL", b"fcTL", b"fdAT",
];

fn png(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = slice(bytes, 0, 8)?.to_vec();
    let mut pos = 8usize;
    let mut first = true;

    loop {
        let len = to_usize(u64::from(u32_be(bytes, pos)?))?;
        let kind = slice(bytes, add(pos, 4)?, 4)?;
        // длина + тип + данные + CRC
        let total = add(len, 12)?;
        let chunk = slice(bytes, pos, total)?;

        if first && kind != b"IHDR" {
            return Err(AegisError::Malformed);
        }
        first = false;

        if PNG_KEEP.iter().any(|keep| keep.as_slice() == kind) {
            out.extend_from_slice(chunk);
        }

        pos = add(pos, total)?;

        if kind == b"IEND" {
            // Хвост после IEND отбрасывается.
            return Ok(out);
        }
    }
}

// ---------------------------------------------------------------------------
//  WebP
// ---------------------------------------------------------------------------

const WEBP_KEEP: [&[u8; 4]; 7] = [
    b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF", b"ICCP",
];

/// Биты «есть EXIF» и «есть XMP» в флагах VP8X.
const VP8X_EXIF_AND_XMP: u8 = 0x08 | 0x04;

fn webp(bytes: &[u8]) -> Result<Vec<u8>> {
    let riff_len = to_usize(u64::from(u32_le(bytes, 4)?))?;
    let end = add(riff_len, 8)?;

    if end > bytes.len() {
        return Err(AegisError::Malformed);
    }

    let mut chunks: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut pos = 12usize;

    while pos < end {
        let kind = slice(bytes, pos, 4)?;
        let len = to_usize(u64::from(u32_le(bytes, add(pos, 4)?)?))?;
        let padded = add(len, len & 1)?;
        let total = add(padded, 8)?;
        let chunk = slice(bytes, pos, total)?;

        if WEBP_KEEP.iter().any(|keep| keep.as_slice() == kind) {
            let start = chunks.len();
            chunks.extend_from_slice(chunk);

            if kind == b"VP8X" {
                let flags = chunks
                    .get_mut(add(start, 8)?)
                    .ok_or(AegisError::Malformed)?;
                *flags &= !VP8X_EXIF_AND_XMP;
            }
        }

        pos = add(pos, total)?;
    }

    let riff = u32::try_from(add(chunks.len(), 4)?).map_err(|_| AegisError::Malformed)?;

    let mut out = Vec::with_capacity(add(chunks.len(), 12)?);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&riff.to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend_from_slice(&chunks);

    Ok(out)
}

// ---------------------------------------------------------------------------
//  GIF
// ---------------------------------------------------------------------------

/// Длина цепочки подблоков GIF, начиная с `start`, включая завершающий ноль.
fn gif_sub_blocks(bytes: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;

    loop {
        let size = usize::from(byte(bytes, pos)?);
        pos = add(pos, 1)?;

        if size == 0 {
            return pos.checked_sub(start).ok_or(AegisError::Malformed);
        }

        pos = add(pos, size)?;
    }
}

/// Размер таблицы цветов по полю упакованных флагов, если она есть.
fn gif_color_table(packed: u8) -> usize {
    if packed & 0x80 == 0 {
        0
    } else {
        3usize << (usize::from(packed & 0x07) + 1)
    }
}

fn gif(bytes: &[u8]) -> Result<Vec<u8>> {
    // Заголовок (6) + дескриптор экрана (7) + глобальная палитра.
    let packed = byte(bytes, 10)?;
    let head = add(13, gif_color_table(packed))?;
    let mut out = slice(bytes, 0, head)?.to_vec();
    let mut pos = head;

    loop {
        match byte(bytes, pos)? {
            0x3B => {
                out.push(0x3B);
                // Хвост после завершающего байта отбрасывается.
                return Ok(out);
            }
            0x2C => {
                // Кадр: дескриптор (10), локальная палитра, минимальный
                // размер кода LZW (1), подблоки данных.
                let local = gif_color_table(byte(bytes, add(pos, 9)?)?);
                let data = add(add(pos, 10)?, add(local, 1)?)?;
                let end = add(data, gif_sub_blocks(bytes, data)?)?;
                out.extend_from_slice(slice(
                    bytes,
                    pos,
                    end.checked_sub(pos).ok_or(AegisError::Malformed)?,
                )?);
                pos = end;
            }
            0x21 => {
                let label = byte(bytes, add(pos, 1)?)?;
                let blocks = add(pos, 2)?;
                let end = add(blocks, gif_sub_blocks(bytes, blocks)?)?;

                let keep = match label {
                    // Управление кадром и текст — часть изображения.
                    0xF9 | 0x01 => true,
                    // Приложения: только повтор анимации.
                    0xFF => {
                        let name = slice(bytes, add(blocks, 1)?, 11).unwrap_or_default();
                        name == b"NETSCAPE2.0" || name == b"ANIMEXTS1.0"
                    }
                    // Комментарии (0xFE) и всё прочее.
                    _ => false,
                };

                if keep {
                    out.extend_from_slice(slice(
                        bytes,
                        pos,
                        end.checked_sub(pos).ok_or(AegisError::Malformed)?,
                    )?);
                }

                pos = end;
            }
            _ => return Err(AegisError::Malformed),
        }
    }
}

// ---------------------------------------------------------------------------
//  ISO BMFF: MP4, MOV, M4A, 3GP
// ---------------------------------------------------------------------------

/// Бренды HEIF/AVIF: изображения, чьи метаданные — элементы структуры.
const HEIF_BRANDS: [&[u8; 4]; 9] = [
    b"heic", b"heix", b"hevc", b"heim", b"heis", b"hevm", b"mif1", b"msf1", b"avif",
];

/// Контейнеры, внутрь которых нужно заходить.
const ISO_CONTAINERS: [&[u8; 4]; 9] = [
    b"moov", b"trak", b"mdia", b"minf", b"edts", b"dinf", b"moof", b"traf", b"mvex",
];

/// Блоки метаданных: затираются целиком.
const ISO_METADATA: [&[u8; 4]; 4] = [b"udta", b"meta", b"uuid", b"XMP_"];

/// Заголовки со временем создания и изменения.
const ISO_TIMED: [&[u8; 4]; 3] = [b"mvhd", b"tkhd", b"mdhd"];

fn iso_media(bytes: &[u8]) -> Result<Vec<u8>> {
    if is_heif(bytes)? {
        return Err(AegisError::Malformed);
    }

    let mut out = bytes.to_vec();
    iso_walk(&mut out, 0, bytes.len(), 0)?;

    Ok(out)
}

/// Бренды из `ftyp`: основной и совместимые.
fn is_heif(bytes: &[u8]) -> Result<bool> {
    let size = to_usize(u64::from(u32_be(bytes, 0)?))?;
    let ftyp = slice(bytes, 0, size)?;

    // основной бренд (8..12), версия (12..16), совместимые (16..)
    let mut brands = vec![slice(ftyp, 8, 4)?];
    let mut at = 16usize;

    while at < ftyp.len() {
        brands.push(slice(ftyp, at, 4)?);
        at = add(at, 4)?;
    }

    Ok(brands
        .iter()
        .any(|brand| HEIF_BRANDS.iter().any(|heif| heif.as_slice() == *brand)))
}

/// Глубина вложенности, после которой файл считается испорченным:
/// настоящие файлы укладываются в десяток уровней, а бесконечная
/// вложенность — способ уронить разбор переполнением стека.
const ISO_MAX_DEPTH: usize = 16;

fn iso_walk(bytes: &mut [u8], start: usize, end: usize, depth: usize) -> Result<()> {
    if depth > ISO_MAX_DEPTH {
        return Err(AegisError::Malformed);
    }

    let mut pos = start;

    while pos < end {
        let size32 = u32_be(bytes, pos)?;
        let kind: [u8; 4] = slice(bytes, add(pos, 4)?, 4)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?;

        let (header, size) = match size32 {
            0 => (8usize, end.checked_sub(pos).ok_or(AegisError::Malformed)?),
            1 => (16usize, to_usize(u64_be(bytes, add(pos, 8)?)?)?),
            other => (8usize, to_usize(u64::from(other))?),
        };

        let box_end = add(pos, size)?;

        if size < header || box_end > end {
            return Err(AegisError::Malformed);
        }

        let payload = add(pos, header)?;

        if ISO_METADATA.iter().any(|meta| **meta == kind) {
            // Переименовать в `free` и забить нулями: размер прежний,
            // смещения данных не сдвигаются.
            let name = bytes
                .get_mut(add(pos, 4)?..add(pos, 8)?)
                .ok_or(AegisError::Malformed)?;
            name.copy_from_slice(b"free");

            bytes
                .get_mut(payload..box_end)
                .ok_or(AegisError::Malformed)?
                .fill(0);
        } else if ISO_TIMED.iter().any(|timed| **timed == kind) {
            iso_zero_times(bytes, payload, box_end)?;
        } else if ISO_CONTAINERS.iter().any(|container| **container == kind) {
            iso_walk(bytes, payload, box_end, add(depth, 1)?)?;
        }

        pos = box_end;
    }

    Ok(())
}

/// Обнуляет время создания и изменения в `mvhd`/`tkhd`/`mdhd`.
///
/// Полный блок: версия (1 байт), флаги (3), затем два времени —
/// по 4 байта в версии 0, по 8 в версии 1.
fn iso_zero_times(bytes: &mut [u8], payload: usize, end: usize) -> Result<()> {
    let width = match byte(bytes, payload)? {
        0 => 8usize,
        1 => 16usize,
        _ => return Err(AegisError::Malformed),
    };

    let from = add(payload, 4)?;
    let to = add(from, width)?;

    if to > end {
        return Err(AegisError::Malformed);
    }

    bytes
        .get_mut(from..to)
        .ok_or(AegisError::Malformed)?
        .fill(0);

    Ok(())
}

// ---------------------------------------------------------------------------
//  MP3
// ---------------------------------------------------------------------------

fn is_mpeg_audio_sync(bytes: &[u8]) -> bool {
    matches!(bytes, [0xFF, second, ..] if second & 0xE0 == 0xE0)
}

fn mp3(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut start = 0usize;

    // ID3v2 в начале; тегов может быть несколько подряд.
    while slice(bytes, start, 3).is_ok_and(|tag| tag == b"ID3") {
        let flags = byte(bytes, add(start, 5)?)?;
        let size_bytes = slice(bytes, add(start, 6)?, 4)?;

        // Размер — «syncsafe»: по семь значащих бит в байте.
        let mut size = 0usize;
        for part in size_bytes {
            if part & 0x80 != 0 {
                return Err(AegisError::Malformed);
            }
            size = size
                .checked_mul(128)
                .and_then(|value| value.checked_add(usize::from(*part)))
                .ok_or(AegisError::Malformed)?;
        }

        let footer = if flags & 0x10 == 0 { 0 } else { 10 };
        start = add(add(start, 10)?, add(size, footer)?)?;

        if start > bytes.len() {
            return Err(AegisError::Malformed);
        }
    }

    let mut end = bytes.len();

    // ID3v1 — последние 128 байт, начинаются с "TAG".
    if end >= add(start, 128)?
        && slice(bytes, end.checked_sub(128).ok_or(AegisError::Malformed)?, 3)? == b"TAG"
    {
        end = end.checked_sub(128).ok_or(AegisError::Malformed)?;
    }

    // APEv2 — подвал из 32 байт "APETAGEX"; размер в нём включает
    // элементы и подвал, но не заголовок (+32, если он есть).
    if end >= add(start, 32)? {
        let footer = end.checked_sub(32).ok_or(AegisError::Malformed)?;

        if slice(bytes, footer, 8)? == b"APETAGEX" {
            let size = to_usize(u64::from(u32_le(bytes, add(footer, 12)?)?))?;
            let flags = u32_le(bytes, add(footer, 20)?)?;
            let header = if flags & 0x8000_0000 == 0 { 0 } else { 32 };
            let total = add(size, header)?;

            end = end.checked_sub(total).ok_or(AegisError::Malformed)?;

            if end < start {
                return Err(AegisError::Malformed);
            }
        }
    }

    Ok(slice(
        bytes,
        start,
        end.checked_sub(start).ok_or(AegisError::Malformed)?,
    )?
    .to_vec())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len() + 2).expect("длина");
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// EXIF с GPS-строкой и поворотом 6 (90° по часовой).
    fn exif_with_gps() -> Vec<u8> {
        let mut tiff = b"MM\0\x2A".to_vec();
        tiff.extend_from_slice(&8u32.to_be_bytes());
        tiff.extend_from_slice(&1u16.to_be_bytes());
        tiff.extend_from_slice(&0x0112u16.to_be_bytes());
        tiff.extend_from_slice(&3u16.to_be_bytes());
        tiff.extend_from_slice(&1u32.to_be_bytes());
        tiff.extend_from_slice(&6u16.to_be_bytes());
        tiff.extend_from_slice(&[0, 0]);
        tiff.extend_from_slice(&0u32.to_be_bytes());
        tiff.extend_from_slice(b"GPS 55.7558N 37.6173E Pixel 8 Pro SN-12345");

        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&tiff);
        payload
    }

    fn sample_jpeg() -> Vec<u8> {
        let mut jpeg = vec![0xFF, 0xD8];
        jpeg.extend(segment(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
        jpeg.extend(segment(0xE1, &exif_with_gps()));
        jpeg.extend(segment(
            0xE1,
            b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>Moscow</x:xmpmeta>",
        ));
        jpeg.extend(segment(0xE2, b"ICC_PROFILE\0\x01\x01profile"));
        jpeg.extend(segment(0xED, b"Photoshop 3.0\0IPTC author Ivanov"));
        jpeg.extend(segment(0xFE, b"comment: shot at home"));
        jpeg.extend(segment(0xDB, &[0u8; 65])); // DQT
        jpeg.extend(segment(0xC0, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0])); // SOF0
        jpeg.extend(segment(0xC4, &[0u8; 20])); // DHT
        jpeg.extend(segment(0xDA, &[1, 1, 0, 0, 63, 0])); // SOS
        jpeg.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]); // скан
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI
        jpeg.extend_from_slice(b"ftypmp42 motion photo video with GPS");
        jpeg
    }

    #[test]
    fn jpeg_loses_exif_gps_xmp_iptc_comments_and_trailer() {
        let original = sample_jpeg();
        let cleaned = scrub(&original).expect("очищено");

        assert_eq!(cleaned.format, Format::Jpeg);

        for leak in [
            &b"GPS 55.7558N"[..],
            b"SN-12345",
            b"xmpmeta",
            b"IPTC",
            b"shot at home",
            b"motion photo",
        ] {
            assert!(
                !contains(&cleaned.bytes, leak),
                "осталось: {}",
                String::from_utf8_lossy(leak)
            );
        }
    }

    #[test]
    fn jpeg_keeps_the_image_and_rendering_segments() {
        let cleaned = scrub(&sample_jpeg()).expect("очищено").bytes;

        assert!(
            cleaned.starts_with(&[0xFF, 0xD8, 0xFF, 0xE0]),
            "JFIF не первым"
        );
        assert!(cleaned.ends_with(&[0xFF, 0xD9]), "нет конца кадра");
        assert!(
            contains(&cleaned, b"ICC_PROFILE"),
            "цветовой профиль потерян"
        );
        assert!(
            contains(&cleaned, &[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]),
            "данные кадра изменены"
        );
    }

    /// Поворот переносится: без него кадр пришёл бы на боку.
    #[test]
    fn jpeg_keeps_orientation_only() {
        let cleaned = scrub(&sample_jpeg()).expect("очищено").bytes;

        let exif_at = cleaned
            .windows(6)
            .position(|window| window == b"Exif\0\0")
            .expect("поворот не перенесён");

        assert_eq!(exif_orientation(&cleaned[exif_at..]), Some(6));
        assert_eq!(
            scrub(&cleaned).expect("повторно").bytes,
            cleaned,
            "очистка не идемпотентна"
        );
    }

    #[test]
    fn truncated_jpeg_is_refused_not_sent_as_is() {
        let original = sample_jpeg();
        let cut = &original[..original.len() >> 1];

        assert!(scrub(cut).is_err());
    }

    fn png_chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(data.len())
            .expect("длина")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(&kind);
        out.extend_from_slice(data);
        out.extend_from_slice(&[0, 0, 0, 0]); // CRC не проверяется
        out
    }

    #[test]
    fn png_loses_text_exif_and_time() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(png_chunk(*b"IHDR", &[0; 13]));
        png.extend(png_chunk(*b"tEXt", b"Author\0Ivanov"));
        png.extend(png_chunk(*b"eXIf", b"MM\0*GPS"));
        png.extend(png_chunk(*b"tIME", &[7, 234, 9, 24, 12, 0, 0]));
        png.extend(png_chunk(*b"IDAT", b"pixels"));
        png.extend(png_chunk(*b"IEND", &[]));
        png.extend_from_slice(b"trailer");

        let cleaned = scrub(&png).expect("очищено").bytes;

        for leak in [&b"Ivanov"[..], b"eXIf", b"tIME", b"trailer"] {
            assert!(!contains(&cleaned, leak));
        }
        assert!(contains(&cleaned, b"pixels"));
        assert!(cleaned.ends_with(&png_chunk(*b"IEND", &[])));
    }

    #[test]
    fn webp_loses_exif_and_xmp_and_clears_flags() {
        let mut chunks = Vec::new();
        chunks.extend_from_slice(b"VP8X");
        chunks.extend_from_slice(&10u32.to_le_bytes());
        chunks.extend_from_slice(&[0x0C | 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        chunks.extend_from_slice(b"VP8 ");
        chunks.extend_from_slice(&4u32.to_le_bytes());
        chunks.extend_from_slice(b"data");
        chunks.extend_from_slice(b"EXIF");
        chunks.extend_from_slice(&3u32.to_le_bytes());
        chunks.extend_from_slice(b"GPS\0");
        chunks.extend_from_slice(b"XMP ");
        chunks.extend_from_slice(&2u32.to_le_bytes());
        chunks.extend_from_slice(b"xm");

        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(
            &u32::try_from(chunks.len() + 4)
                .expect("длина")
                .to_le_bytes(),
        );
        webp.extend_from_slice(b"WEBP");
        webp.extend(chunks);

        let cleaned = scrub(&webp).expect("очищено").bytes;

        assert!(!contains(&cleaned, b"GPS"));
        assert!(!contains(&cleaned, b"XMP "));
        assert!(contains(&cleaned, b"data"));
        assert_eq!(
            cleaned[20] & VP8X_EXIF_AND_XMP,
            0,
            "флаги EXIF/XMP не сняты"
        );
        assert_eq!(cleaned[20] & 0x10, 0x10, "прочие флаги задеты");
        assert_eq!(
            u32_le(&cleaned, 4).expect("размер") as usize,
            cleaned.len() - 8,
            "размер RIFF не пересчитан"
        );
    }

    #[test]
    fn gif_loses_comments_and_xmp_but_keeps_animation() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]); // экран, палитра 2 цвета
        gif.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
        gif.extend_from_slice(&[0x21, 0xFF, 11]);
        gif.extend_from_slice(b"NETSCAPE2.0");
        gif.extend_from_slice(&[3, 1, 0, 0, 0]);
        gif.extend_from_slice(&[0x21, 0xFE, 7]);
        gif.extend_from_slice(b"Ivanov!");
        gif.push(0);
        gif.extend_from_slice(&[0x21, 0xFF, 11]);
        gif.extend_from_slice(b"XMP DataXMP");
        gif.extend_from_slice(&[4, b'G', b'P', b'S', b'!', 0]);
        gif.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x4C, 0x01, 0]);
        gif.push(0x3B);

        let cleaned = scrub(&gif).expect("очищено").bytes;

        assert!(!contains(&cleaned, b"Ivanov"));
        assert!(!contains(&cleaned, b"GPS"));
        assert!(
            contains(&cleaned, b"NETSCAPE2.0"),
            "повтор анимации потерян"
        );
        assert!(contains(&cleaned, &[0x4C, 0x01]), "кадр потерян");
        assert_eq!(cleaned.last(), Some(&0x3B));
    }

    fn iso_box(kind: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(payload.len() + 8)
            .expect("длина")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(&kind);
        out.extend_from_slice(payload);
        out
    }

    fn sample_mp4() -> Vec<u8> {
        let mut mvhd = vec![0, 0, 0, 0];
        mvhd.extend_from_slice(&0xE123_4567u32.to_be_bytes()); // создание
        mvhd.extend_from_slice(&0xE123_4568u32.to_be_bytes()); // изменение
        mvhd.extend_from_slice(&[0u8; 88]);

        let udta = iso_box(*b"udta", &iso_box(*b"\xA9xyz", b"+55.7558+037.6173/"));
        let meta = iso_box(*b"meta", b"com.apple.quicktime.model Pixel 8 Pro");
        let trak = iso_box(
            *b"trak",
            &iso_box(*b"tkhd", &{
                let mut tkhd = vec![1, 0, 0, 0];
                tkhd.extend_from_slice(&0x0000_00E1_2345_6789u64.to_be_bytes());
                tkhd.extend_from_slice(&0x0000_00E1_2345_678Au64.to_be_bytes());
                tkhd.extend_from_slice(&[0u8; 60]);
                tkhd
            }),
        );

        let mut moov_payload = iso_box(*b"mvhd", &mvhd);
        moov_payload.extend(trak);
        moov_payload.extend(udta);
        moov_payload.extend(meta);

        let mut mp4 = iso_box(*b"ftyp", b"isom\0\0\0\x01isommp42");
        mp4.extend(iso_box(*b"moov", &moov_payload));
        mp4.extend(iso_box(*b"mdat", b"FRAMES"));
        mp4
    }

    #[test]
    fn mp4_loses_location_model_and_times_in_place() {
        let original = sample_mp4();
        let cleaned = scrub(&original).expect("очищено");

        assert_eq!(cleaned.format, Format::IsoMedia);
        assert_eq!(
            cleaned.bytes.len(),
            original.len(),
            "размер изменился — смещения сдвинутся"
        );

        for leak in [
            &b"+55.7558"[..],
            b"Pixel 8 Pro",
            b"udta",
            b"\xE1\x23\x45\x67",
        ] {
            assert!(!contains(&cleaned.bytes, leak), "осталось {leak:?}");
        }

        // Данные дорожек на том же месте.
        let at = original
            .windows(6)
            .position(|w| w == b"FRAMES")
            .expect("данные");
        assert_eq!(&cleaned.bytes[at..at + 6], b"FRAMES");
    }

    #[test]
    fn heif_is_refused_for_platform_conversion() {
        let heic = iso_box(*b"ftyp", b"heic\0\0\0\0mif1heic");

        assert!(scrub(&heic).is_err());
    }

    #[test]
    fn mp3_loses_id3_and_ape_tags() {
        let mut mp3 = b"ID3\x04\0\0\0\0\0\x0A".to_vec();
        mp3.extend_from_slice(b"TPE1Ivanov");
        mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        mp3.extend_from_slice(b"AUDIO");

        let mut ape = b"APETAGEX".to_vec();
        ape.extend_from_slice(&2000u32.to_le_bytes());
        ape.extend_from_slice(&32u32.to_le_bytes());
        ape.extend_from_slice(&0u32.to_le_bytes());
        ape.extend_from_slice(&0u32.to_le_bytes());
        ape.extend_from_slice(&[0u8; 8]);
        mp3.extend(ape);

        let mut v1 = b"TAG".to_vec();
        v1.extend_from_slice(b"Home recording");
        v1.resize(128, 0);
        mp3.extend(v1);

        let cleaned = scrub(&mp3).expect("очищено").bytes;

        assert_eq!(
            cleaned,
            [0xFF, 0xFB, 0x90, 0x00, b'A', b'U', b'D', b'I', b'O']
        );
    }

    #[test]
    fn unknown_formats_pass_unchanged() {
        let pdf = b"%PDF-1.7 /Author (Ivanov)".to_vec();
        let cleaned = scrub(&pdf).expect("как есть");

        assert_eq!(cleaned.format, Format::Unknown);
        assert_eq!(cleaned.bytes, pdf);
        assert!(!cleaned.format.is_media());
    }

    /// 🔐 Любая порча — ошибка или корректный вывод, но не паника
    /// и не бесконечный цикл.
    #[test]
    fn corrupted_inputs_never_panic() {
        let samples = [sample_jpeg(), sample_mp4()];
        let mut state = 0x5EED_u64;

        for sample in &samples {
            for _ in 0..5_000 {
                let mut data = sample.clone();
                for _ in 0..3 {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let at = (state as usize) % data.len();
                    data[at] = (state >> 32) as u8;
                }
                if state.is_multiple_of(5) {
                    data.truncate((state as usize >> 8) % data.len());
                }

                // Очищенное очищается повторно без изменений: иначе
                // «очищенный» файл нёс бы что-то, что очистка ещё видит.
                if let Ok(cleaned) = scrub(&data) {
                    if cleaned.format != Format::Unknown {
                        let again = scrub(&cleaned.bytes).expect("очищенное разбирается");
                        assert_eq!(again.bytes, cleaned.bytes, "очистка не идемпотентна");
                    }
                }
            }
        }
    }
}
