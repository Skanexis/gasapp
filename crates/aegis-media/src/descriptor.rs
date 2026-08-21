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
#[derive(Debug, Clone)]
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

/// Ссылка на превью.
#[derive(Debug, Clone)]
pub struct PreviewRef {
    /// Адрес шифроблоба превью.
    pub location: String,
    /// Ключ превью.
    pub key: [u8; KEY_LEN],
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
