// SPDX-License-Identifier: Apache-2.0

//! Описание вложения внутри сообщения.
//!
//! # Что здесь передаётся
//!
//! Всё, что нужно получателю, чтобы найти файл в хранилище и
//! расшифровать его: адрес, ключ, размер, тип, имя, превью.
//!
//! 🔐 Описание целиком уходит **внутри** сообщения, то есть под
//! сквозным шифрованием. Хранилище видит только шифроблоб и его
//! длину; имя файла, его тип и длительность голосового сообщения
//! оно не узнаёт.
//!
//! # Почему имя файла шифруется
//!
//! Имя — это содержимое. «Договор аренды.pdf», «результаты
//! анализов.jpg», «паспорт.png» говорят о человеке больше, чем сам
//! факт отправки файла. Хранилище, знающее имена, знает переписку
//! почти целиком.
//!
//! # Про waveform голосовых
//!
//! Огибающая громкости передаётся вместе с описанием: она нужна
//! для отрисовки до загрузки файла. Это те же данные, что и звук,
//! только с меньшим разрешением, поэтому она тоже под шифрованием
//! и тоже ограничена по размеру — её разбирает получатель, не спросив
//! пользователя.

use aegis_types::{AegisError, Result};

use crate::attachment::KEY_LEN;

/// Тип вложения.
///
/// Различается на уровне протокола, потому что от типа зависит
/// поведение получателя: голосовое проигрывается, картинка
/// показывается, документ сохраняется. Определять тип по расширению
/// имени нельзя — имя выбирает отправитель, и «отчёт.jpg», который
/// на деле исполняемый файл, не должен открываться как картинка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    /// Изображение.
    Image,
    /// Видео.
    Video,
    /// Голосовое сообщение.
    Voice,
    /// Произвольный файл.
    Document,
}

impl AttachmentKind {
    /// Числовое представление для хранения и передачи.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Image => 1,
            Self::Video => 2,
            Self::Voice => 3,
            Self::Document => 4,
        }
    }

    /// Разбирает тип из числа.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — неизвестный тип. Отказ, а не
    /// подстановка `Document`: неизвестный тип означает сообщение
    /// от более новой версии, и обращаться с ним как с файлом
    /// значит угадывать.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Image),
            2 => Ok(Self::Video),
            3 => Ok(Self::Voice),
            4 => Ok(Self::Document),
            _ => Err(AegisError::Malformed),
        }
    }
}

/// Предел длины имени файла.
///
/// 🔐 Имя приходит от отправителя и попадает в интерфейс. Без предела
/// имя на мегабайт растянуло бы разметку и заняло память при разборе
/// каждого входящего сообщения.
pub const MAX_NAME_LEN: usize = 255;

/// Предел размера вложения.
///
/// 100 МБ. Ограничение не техническое: чанки позволяют файл любого
/// размера. Оно про то, сколько трафика и места разумно тратить
/// на одно сообщение — и про то, сколько чужих данных сервер обязан
/// хранить до доставки.
pub const MAX_ATTACHMENT_BYTES: u64 = 100 * 1024 * 1024;

/// Предел числа точек огибающей.
///
/// Столько помещается на экране телефона; больше не даёт ничего,
/// кроме размера сообщения.
pub const MAX_WAVEFORM_POINTS: usize = 256;

/// Описание вложения.
/// 🔐 `Debug` написан вручную и ключа файла не печатает: прежде он был
/// выведен и отдавал ключ расшифровки вложения байт за байтом.
#[derive(Clone)]
pub struct AttachmentDescriptor {
    /// Тип вложения.
    pub kind: AttachmentKind,

    /// Адрес шифроблоба в хранилище.
    pub location: String,

    /// Ключ расшифровки.
    ///
    /// 🔐 Уходит внутри сообщения — то есть под сквозным шифрованием.
    /// Хранилище, отдающее файл, ключа не знает и расшифровать его
    /// не может.
    pub key: [u8; KEY_LEN],

    /// Размер открытого файла в байтах.
    pub size: u64,

    /// Имя файла.
    ///
    /// 🔐 Шифруется вместе с остальным описанием: «результаты
    /// анализов.jpg» говорит о человеке больше, чем факт отправки.
    pub name: Option<String>,

    /// Описание для незрячих пользователей.
    pub description: Option<String>,

    /// Длительность в миллисекундах — для голосовых и видео.
    pub duration_millis: Option<u32>,

    /// Огибающая громкости для голосовых.
    ///
    /// Значения 0–255, одно на точку. Нужна, чтобы нарисовать волну
    /// до загрузки файла.
    pub waveform: Option<Vec<u8>>,

    /// Превью: адрес и ключ.
    ///
    /// 🔐 Ключ отдельный от ключа файла — см. модуль `preview`.
    pub preview: Option<PreviewRef>,
}

// Неполнота `Debug` — намеренная: ключ файла не печатается.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for AttachmentDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachmentDescriptor")
            .field("kind", &self.kind)
            .field("location", &self.location)
            .field("size", &self.size)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("duration_millis", &self.duration_millis)
            .field("waveform", &self.waveform)
            .field("preview", &self.preview)
            .finish()
    }
}

/// Ссылка на превью.
///
/// 🔐 `Debug` написан вручную и ключа превью не печатает. Прежде он был
/// выведен, и ручной `Debug` описания, скрывший ключ файла, печатал
/// ключ превью через поле `preview`.
#[derive(Clone)]
pub struct PreviewRef {
    /// Адрес шифроблоба превью.
    pub location: String,
    /// Ключ превью.
    pub key: [u8; KEY_LEN],
}

// Неполнота `Debug` — намеренная: ключ превью не печатается.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for PreviewRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreviewRef")
            .field("location", &self.location)
            .finish()
    }
}

impl AttachmentDescriptor {
    /// Проверяет описание, пришедшее от отправителя.
    ///
    /// # 🔐 Зачем проверять то, что уже расшифровано
    ///
    /// Расшифровка доказывает, что сообщение отправил владелец ключа
    /// сессии, — но не то, что он добросовестен. Собеседник может
    /// собрать описание своей реализацией: имя на мегабайт, размер
    /// в терабайтах, огибающая из миллиона точек. Всё это попадёт
    /// в разметку и в память до того, как пользователь что-то нажмёт.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — какое-либо поле вне допустимых
    /// границ.
    pub fn validate(&self) -> Result<()> {
        if self.size > MAX_ATTACHMENT_BYTES {
            return Err(AegisError::Malformed);
        }

        if self.location.is_empty() {
            return Err(AegisError::Malformed);
        }

        if let Some(name) = &self.name {
            // Считаются символы, а не байты: предел в байтах отсекал бы
            // имена на кириллице вдвое короче латинских.
            if name.chars().count() > MAX_NAME_LEN {
                return Err(AegisError::Malformed);
            }

            // 🔐 Разделители пути и NUL отвергаются: имя попадает
            // в файловую систему получателя, и «../../etc/passwd»
            // записал бы файл не туда, куда предполагает пользователь.
            if name.contains(['/', '\\', '\0']) {
                return Err(AegisError::Malformed);
            }

            // 🔐 Управляющие символы и смена направления текста — тоже:
            // «счёт\u{202E}fdp.exe» показался бы в переписке как
            // «счётexe.pdf», то есть документом, а сохранился бы
            // исполняемым. Та же проверка, что у имени в ссылке контакта.
            if name.chars().any(|character| {
                character.is_control()
                    || matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            }) {
                return Err(AegisError::Malformed);
            }
        }

        if let Some(description) = &self.description {
            if description.chars().count() > MAX_NAME_LEN {
                return Err(AegisError::Malformed);
            }
        }

        if let Some(waveform) = &self.waveform {
            if waveform.len() > MAX_WAVEFORM_POINTS {
                return Err(AegisError::Malformed);
            }

            // Огибающая имеет смысл только у голосовых: у документа
            // она означает, что описание собрано не нашим клиентом.
            if self.kind != AttachmentKind::Voice {
                return Err(AegisError::Malformed);
            }
        }

        // Длительность имеет смысл у голосовых и видео.
        if self.duration_millis.is_some()
            && !matches!(self.kind, AttachmentKind::Voice | AttachmentKind::Video)
        {
            return Err(AegisError::Malformed);
        }

        Ok(())
    }
}

/// Версия формата описания.
///
/// Меняется при любом изменении раскладки полей. Получатель, увидев
/// незнакомую версию, отказывается разбирать: угадывать раскладку
/// значило бы прочитать ключ или размер не оттуда.
const DESCRIPTOR_VERSION: u8 = 1;

/// Метка присутствия необязательного поля.
const PRESENT: u8 = 1;

/// Метка отсутствия.
const ABSENT: u8 = 0;

impl AttachmentDescriptor {
    /// Сериализует описание для отправки внутри сообщения.
    ///
    /// # Формат
    ///
    /// Ручная раскладка, а не `serde`: описание пересекает границу
    /// версий, и молчаливое добавление поля сериализатором сломало бы
    /// разбор у старого клиента. Явные длины и метки присутствия
    /// делают несовместимость видимой сразу.
    ///
    /// Все длины — `u32` в сетевом порядке. Строки — UTF-8.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — описание не проходит [`Self::validate`]
    /// либо какое-то поле не помещается в `u32`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // Проверка перед отправкой, а не только при приёме: описание,
        // собранное с ошибкой, лучше отвергнуть у себя, чем отправить
        // собеседнику то, что он обязан будет отвергнуть.
        self.validate()?;

        let mut out = Vec::new();

        out.push(DESCRIPTOR_VERSION);
        out.push(self.kind.as_u8());

        write_bytes(&mut out, self.location.as_bytes())?;
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.size.to_be_bytes());

        write_optional_str(&mut out, self.name.as_deref())?;
        write_optional_str(&mut out, self.description.as_deref())?;

        match self.duration_millis {
            None => out.push(ABSENT),
            Some(duration) => {
                out.push(PRESENT);
                out.extend_from_slice(&duration.to_be_bytes());
            }
        }

        match &self.waveform {
            None => out.push(ABSENT),
            Some(waveform) => {
                out.push(PRESENT);
                write_bytes(&mut out, waveform)?;
            }
        }

        match &self.preview {
            None => out.push(ABSENT),
            Some(preview) => {
                out.push(PRESENT);
                write_bytes(&mut out, preview.location.as_bytes())?;
                out.extend_from_slice(&preview.key);
            }
        }

        Ok(out)
    }

    /// Разбирает описание, пришедшее от собеседника.
    ///
    /// 🔐 Разбор придирчив по той же причине, что и [`Self::validate`]:
    /// расшифровка доказывает, что сообщение прислал владелец ключа
    /// сессии, но не то, что он добросовестен. Каждая длина сверяется
    /// с остатком буфера до того, как по ней что-то читается.
    ///
    /// Лишние байты в хвосте — ошибка, а не мусор: они означают, что
    /// отправитель имел в виду что-то ещё, чего этот разбор не понял.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — незнакомая версия, обрыв буфера,
    /// лишний хвост либо поле вне допустимых границ.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let mut cursor = Cursor { raw, offset: 0 };

        if cursor.take_u8()? != DESCRIPTOR_VERSION {
            return Err(AegisError::Malformed);
        }

        let kind = AttachmentKind::from_u8(cursor.take_u8()?)?;
        let location =
            String::from_utf8(cursor.take_bytes()?.to_vec()).map_err(|_| AegisError::Malformed)?;

        let key: [u8; KEY_LEN] = cursor
            .take_exact(KEY_LEN)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?;

        let size = u64::from_be_bytes(
            cursor
                .take_exact(8)?
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
        );

        let name = cursor.take_optional_str()?;
        let description = cursor.take_optional_str()?;

        let duration_millis = match cursor.take_u8()? {
            ABSENT => None,
            PRESENT => Some(u32::from_be_bytes(
                cursor
                    .take_exact(4)?
                    .try_into()
                    .map_err(|_| AegisError::Malformed)?,
            )),
            _ => return Err(AegisError::Malformed),
        };

        let waveform = match cursor.take_u8()? {
            ABSENT => None,
            PRESENT => Some(cursor.take_bytes()?.to_vec()),
            _ => return Err(AegisError::Malformed),
        };

        let preview = match cursor.take_u8()? {
            ABSENT => None,
            PRESENT => {
                let location = String::from_utf8(cursor.take_bytes()?.to_vec())
                    .map_err(|_| AegisError::Malformed)?;
                let key: [u8; KEY_LEN] = cursor
                    .take_exact(KEY_LEN)?
                    .try_into()
                    .map_err(|_| AegisError::Malformed)?;

                Some(PreviewRef { location, key })
            }
            _ => return Err(AegisError::Malformed),
        };

        // Хвост означает, что отправитель имел в виду что-то ещё.
        if !cursor.is_empty() {
            return Err(AegisError::Malformed);
        }

        let descriptor = Self {
            kind,
            location,
            key,
            size,
            name,
            description,
            duration_millis,
            waveform,
            preview,
        };

        // 🔐 Границы проверяются после разбора: разбор отвечает
        // за форму, validate — за смысл.
        descriptor.validate()?;

        Ok(descriptor)
    }
}

/// Дописывает блок с длиной впереди.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| AegisError::Malformed)?;

    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);

    Ok(())
}

/// Дописывает необязательную строку.
fn write_optional_str(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => {
            out.push(ABSENT);

            Ok(())
        }
        Some(text) => {
            out.push(PRESENT);

            write_bytes(out, text.as_bytes())
        }
    }
}

/// Чтение по буферу с проверкой границ на каждом шаге.
///
/// 🔐 Существует ради того, чтобы ни одно чтение не полагалось
/// на длину, пришедшую от собеседника, без сверки с остатком буфера.
struct Cursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    /// Остались ли непрочитанные байты.
    fn is_empty(&self) -> bool {
        self.offset >= self.raw.len()
    }

    /// Читает один байт.
    fn take_u8(&mut self) -> Result<u8> {
        let byte = *self.raw.get(self.offset).ok_or(AegisError::Malformed)?;
        self.offset = self.offset.saturating_add(1);

        Ok(byte)
    }

    /// Читает ровно `count` байт.
    fn take_exact(&mut self, count: usize) -> Result<&[u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AegisError::Malformed)?;

        let slice = self
            .raw
            .get(self.offset..end)
            .ok_or(AegisError::Malformed)?;

        self.offset = end;

        Ok(slice)
    }

    /// Читает блок с длиной впереди.
    fn take_bytes(&mut self) -> Result<&[u8]> {
        let length = u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| AegisError::Malformed)?,
        );

        let count = usize::try_from(length).map_err(|_| AegisError::Malformed)?;

        self.take_exact(count)
    }

    /// Читает необязательную строку.
    fn take_optional_str(&mut self) -> Result<Option<String>> {
        match self.take_u8()? {
            ABSENT => Ok(None),
            PRESENT => {
                let text = String::from_utf8(self.take_bytes()?.to_vec())
                    .map_err(|_| AegisError::Malformed)?;

                Ok(Some(text))
            }
            _ => Err(AegisError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> AttachmentDescriptor {
        AttachmentDescriptor {
            kind: AttachmentKind::Document,
            location: "blob-1".to_owned(),
            key: [0x11; KEY_LEN],
            size: 1024,
            name: Some("отчёт.pdf".to_owned()),
            description: None,
            duration_millis: None,
            waveform: None,
            preview: None,
        }
    }

    /// Описание переживает круг сериализации.
    /// 🔐 Ключ файла не печатается в `Debug`.
    ///
    /// Прежде `Debug` был выведен и отдавал ключ расшифровки вложения.
    #[test]
    fn debug_does_not_print_the_file_key() {
        let mut descriptor = document();
        descriptor.key = [0xE7; KEY_LEN];
        // С превью: его ключ печатался через поле `preview`, и прежний
        // тест этого не видел — в его описании превью не было.
        descriptor.preview = Some(PreviewRef {
            location: "blob-preview".to_owned(),
            key: [0xD3; KEY_LEN],
        });

        let rendered = format!("{descriptor:?}");

        assert!(
            !rendered.contains("231, 231, 231"),
            "ключ файла напечатан: {rendered}"
        );
        assert!(
            !rendered.contains("211, 211, 211"),
            "ключ превью напечатан: {rendered}"
        );
        assert!(
            rendered.contains("AttachmentDescriptor"),
            "заготовка теста: Debug пуст"
        );
    }

    #[test]
    fn descriptor_round_trips() {
        let mut original = document();
        original.description = Some("скан договора".to_owned());
        original.preview = Some(PreviewRef {
            location: "blob-preview".to_owned(),
            key: [0x99; KEY_LEN],
        });

        let restored =
            AttachmentDescriptor::from_bytes(&original.to_bytes().expect("сериализация"))
                .expect("разбор");

        assert_eq!(restored.kind, original.kind);
        assert_eq!(restored.location, original.location);
        assert_eq!(restored.key, original.key);
        assert_eq!(restored.size, original.size);
        assert_eq!(restored.name, original.name);
        assert_eq!(restored.description, original.description);
        assert_eq!(
            restored.preview.map(|preview| preview.location),
            Some("blob-preview".to_owned())
        );
    }

    /// Голосовое с огибающей и длительностью переживает круг.
    #[test]
    fn voice_descriptor_round_trips() {
        let mut original = document();
        original.kind = AttachmentKind::Voice;
        original.name = None;
        original.duration_millis = Some(7_500);
        original.waveform = Some((0..64u8).collect());

        let restored =
            AttachmentDescriptor::from_bytes(&original.to_bytes().expect("сериализация"))
                .expect("разбор");

        assert_eq!(restored.duration_millis, Some(7_500));
        assert_eq!(restored.waveform, original.waveform);
        assert!(restored.name.is_none());
    }

    /// 🔐 Обрыв на любом байте отвергается, а не читается частично.
    ///
    /// Обрезанное описание приходит по сети от собеседника; чтение
    /// «сколько получится» дало бы ключ или размер, взятые не оттуда.
    #[test]
    fn truncation_at_every_offset_is_rejected() {
        let encoded = document().to_bytes().expect("сериализация");

        for length in 0..encoded.len() {
            assert!(
                AttachmentDescriptor::from_bytes(&encoded[..length]).is_err(),
                "обрезка до {length} байт прошла разбор"
            );
        }
    }

    /// 🔐 Лишний хвост отвергается.
    ///
    /// Он означает, что отправитель имел в виду что-то ещё, чего
    /// этот разбор не понял.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = document().to_bytes().expect("сериализация");
        encoded.push(0);

        assert!(AttachmentDescriptor::from_bytes(&encoded).is_err());
    }

    /// 🔐 Незнакомая версия отвергается.
    ///
    /// Угадывать раскладку значило бы прочитать ключ не оттуда.
    #[test]
    fn unknown_version_is_rejected() {
        let mut encoded = document().to_bytes().expect("сериализация");
        encoded[0] = DESCRIPTOR_VERSION.saturating_add(1);

        assert!(AttachmentDescriptor::from_bytes(&encoded).is_err());
    }

    /// 🔐 Длина, обещающая больше, чем есть, отвергается.
    ///
    /// Иначе разбор попытался бы прочитать за пределами буфера
    /// по числу, которое назвал собеседник.
    #[test]
    fn oversized_length_prefix_is_rejected() {
        let mut encoded = document().to_bytes().expect("сериализация");

        // Длина адреса блоба лежит сразу после версии и типа.
        encoded[2] = 0xFF;
        encoded[3] = 0xFF;

        assert!(AttachmentDescriptor::from_bytes(&encoded).is_err());
    }

    /// 🔐 Описание, нарушающее границы, не сериализуется.
    ///
    /// Отправить то, что собеседник обязан отвергнуть, — значит
    /// показать пользователю доставленное сообщение, которого
    /// на той стороне нет.
    #[test]
    fn invalid_descriptor_is_not_serialized() {
        let mut descriptor = document();
        descriptor.name = Some("../../etc/passwd".to_owned());

        assert!(descriptor.to_bytes().is_err());
    }

    #[test]
    fn valid_descriptor_passes() {
        assert!(document().validate().is_ok());
    }

    /// 🔐 Имя с разделителем пути отвергается.
    ///
    /// Оно попадает в файловую систему получателя, и «../../etc/passwd»
    /// записал бы файл не туда, куда предполагает пользователь.
    #[test]
    fn path_traversal_in_name_is_rejected() {
        for name in ["../../etc/passwd", "dir/file.txt", "dir\\file.txt"] {
            let mut descriptor = document();
            descriptor.name = Some(name.to_owned());

            assert!(
                descriptor.validate().is_err(),
                "имя «{name}» прошло проверку"
            );
        }
    }

    /// 🔐 NUL в имени отвергается.
    ///
    /// Он обрывает строку в системных вызовах C: «безобидное.txt\0.exe»
    /// показалось бы текстовым файлом, а сохранилось исполняемым.
    #[test]
    fn nul_in_name_is_rejected() {
        let mut descriptor = document();
        descriptor.name = Some("file\0.exe".to_owned());

        assert!(descriptor.validate().is_err());
    }

    /// 🔐 Смена направления текста и управляющие символы в имени
    /// отвергаются: «счёт\u{202E}fdp.exe» выглядел бы документом.
    #[test]
    fn bidi_and_control_characters_in_name_are_rejected() {
        for name in [
            "счёт\u{202E}fdp.exe",
            "a\u{2066}b.txt",
            "две\nстроки.txt",
            "таб\tуляция",
        ] {
            let mut descriptor = document();
            descriptor.name = Some(name.to_owned());

            assert!(descriptor.validate().is_err(), "имя {name:?} прошло проверку");
        }
    }

    #[test]
    fn oversized_name_is_rejected() {
        let mut descriptor = document();
        descriptor.name = Some("a".repeat(MAX_NAME_LEN + 1));

        assert!(descriptor.validate().is_err());
    }

    /// Длина имени считается в символах, а не байтах.
    ///
    /// Иначе кириллические имена отсекались бы вдвое короче латинских.
    #[test]
    fn cyrillic_name_of_allowed_length_passes() {
        let mut descriptor = document();
        descriptor.name = Some("я".repeat(MAX_NAME_LEN));

        assert!(descriptor.validate().is_ok());
    }

    #[test]
    fn oversized_attachment_is_rejected() {
        let mut descriptor = document();
        descriptor.size = MAX_ATTACHMENT_BYTES + 1;

        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn empty_location_is_rejected() {
        let mut descriptor = document();
        descriptor.location = String::new();

        assert!(descriptor.validate().is_err());
    }

    /// Огибающая у документа означает чужую реализацию.
    #[test]
    fn waveform_on_document_is_rejected() {
        let mut descriptor = document();
        descriptor.waveform = Some(vec![0; 32]);

        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn oversized_waveform_is_rejected() {
        let mut descriptor = document();
        descriptor.kind = AttachmentKind::Voice;
        descriptor.waveform = Some(vec![0; MAX_WAVEFORM_POINTS + 1]);

        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn voice_with_waveform_passes() {
        let mut descriptor = document();
        descriptor.kind = AttachmentKind::Voice;
        descriptor.waveform = Some(vec![128; 64]);
        descriptor.duration_millis = Some(5_000);

        assert!(descriptor.validate().is_ok());
    }

    #[test]
    fn duration_on_document_is_rejected() {
        let mut descriptor = document();
        descriptor.duration_millis = Some(1_000);

        assert!(descriptor.validate().is_err());
    }

    /// Неизвестный тип отвергается, а не подставляется как документ.
    ///
    /// Он означает сообщение от более новой версии, и обращаться
    /// с ним как с файлом значит угадывать.
    #[test]
    fn unknown_kind_is_rejected() {
        assert!(AttachmentKind::from_u8(0).is_err());
        assert!(AttachmentKind::from_u8(99).is_err());
    }

    #[test]
    fn kind_round_trips() {
        for kind in [
            AttachmentKind::Image,
            AttachmentKind::Video,
            AttachmentKind::Voice,
            AttachmentKind::Document,
        ] {
            assert_eq!(
                AttachmentKind::from_u8(kind.as_u8()).expect("тип известен"),
                kind
            );
        }
    }
}
