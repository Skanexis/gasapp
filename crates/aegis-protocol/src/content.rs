// SPDX-License-Identifier: Apache-2.0

//! Содержимое сообщения.
//!
//! # Зачем формат, если раньше хватало текста
//!
//! Текст — только один вид сообщения. Вложения, ответы, реакции,
//! правки и удаления должны отличаться друг от друга, и отличие
//! обязано быть **внутри** шифрования: сервер, знающий, что вот это
//! реакция, а вот это удаление, восстанавливает структуру разговора,
//! не читая ни слова.
//!
//! # Почему ручной формат, а не serde
//!
//! Разбор идёт над тем, что прислал собеседник. Он расшифровался —
//! значит отправлен владельцем ключа сессии, но это не делает его
//! добросовестным: он мог собрать сообщение своей реализацией.
//! Ручной разбор с явной проверкой каждой длины показывает границы
//! глазами и покрывается фаззингом.
//!
//! # Про совместимость
//!
//! Неизвестный тип содержимого отвергается, а не игнорируется.
//! Молчаливый пропуск означал бы, что сообщение от новой версии
//! выглядит доставленным и пустым — пользователь решил бы, что
//! собеседник прислал пустоту, хотя тот прислал, например, опрос.

use aegis_types::{AegisError, Result};

/// Версия формата содержимого.
pub const CONTENT_VERSION: u8 = 1;

/// Предел длины текста сообщения.
///
/// 🔐 Приходит от собеседника и попадает в разметку. Без предела
/// текст на десять мегабайт занял бы память при разборе каждого
/// входящего сообщения.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Предел числа вложений в одном сообщении.
pub const MAX_ATTACHMENTS: usize = 10;

/// Предел длины реакции.
///
/// Реакция — один-два эмодзи; четыре символа с запасом покрывают
/// составные последовательности вроде флагов и семей.
pub const MAX_REACTION_BYTES: usize = 32;

/// Тип содержимого: текст.
const KIND_TEXT: u8 = 1;

/// Тип: сообщение с вложениями.
const KIND_ATTACHMENTS: u8 = 2;

/// Тип: реакция на сообщение.
const KIND_REACTION: u8 = 3;

/// Тип: правка ранее отправленного.
const KIND_EDIT: u8 = 4;

/// Тип: удаление для всех.
const KIND_DELETE: u8 = 5;

/// Тип: индикатор набора текста.
const KIND_TYPING: u8 = 6;

/// Тип: квитанция о прочтении.
const KIND_READ_RECEIPT: u8 = 7;

/// Длина идентификатора сообщения.
const MESSAGE_ID_LEN: usize = 16;

/// Содержимое сообщения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Текст, возможно ответ на другое сообщение.
    Text {
        /// Сам текст.
        body: String,
        /// Сообщение, на которое отвечают.
        ///
        /// 🔐 Цитата не передаётся: получатель находит исходное
        /// сообщение у себя. Передача цитаты означала бы, что текст,
        /// который собеседник, возможно, уже удалил, возвращается
        /// к нему обратно.
        reply_to: Option<[u8; MESSAGE_ID_LEN]>,
    },

    /// Вложения с подписью.
    Attachments {
        /// Подпись к вложениям.
        body: String,
        /// Описания вложений в сериализованном виде.
        ///
        /// Байты, а не разобранные структуры: описание принадлежит
        /// `aegis-media`, и протокол не должен от него зависеть —
        /// иначе смена формата вложения тянула бы за собой изменение
        /// протокола сообщений.
        descriptors: Vec<Vec<u8>>,
        /// Ответ на сообщение.
        reply_to: Option<[u8; MESSAGE_ID_LEN]>,
    },

    /// Реакция на сообщение.
    Reaction {
        /// Сообщение, на которое реагируют.
        target: [u8; MESSAGE_ID_LEN],
        /// Символ реакции. Пустая строка снимает реакцию.
        emoji: String,
    },

    /// Правка ранее отправленного сообщения.
    Edit {
        /// Правимое сообщение.
        target: [u8; MESSAGE_ID_LEN],
        /// Новый текст.
        body: String,
    },

    /// Удаление сообщения у всех участников.
    ///
    /// 🔐 Это просьба, а не гарантия: получатель уже видел сообщение
    /// и мог сделать снимок экрана. Клиент обязан удалить, но
    /// обещать пользователю, что сообщение исчезло у собеседника,
    /// нельзя — интерфейс должен говорить «удалено у вас и запрошено
    /// удаление у собеседника».
    Delete {
        /// Удаляемое сообщение.
        target: [u8; MESSAGE_ID_LEN],
    },

    /// Индикатор набора текста.
    ///
    /// 🔐 Отправляется только при явно включённой настройке.
    /// Индикатор сообщает собеседнику, что человек сейчас у телефона
    /// и печатает, — то есть выдаёт присутствие с точностью до секунд.
    /// Для переписки, где важна анонимность, это существеннее
    /// содержимого: собеседник узнаёт распорядок дня.
    ///
    /// По умолчанию выключен: privacy-функция, требующая отключения,
    /// защищает только тех, кто нашёл настройку.
    Typing {
        /// Печатает ли пользователь сейчас.
        ///
        /// `false` отправляется при остановке: без него индикатор
        /// висел бы до таймаута, показывая активность, которой нет.
        active: bool,
    },

    /// Квитанция о прочтении.
    ///
    /// 🔐 Тоже opt-in и по той же причине: квитанция сообщает
    /// отправителю, что человек открыл переписку именно сейчас.
    ///
    /// Отправляется не за каждое сообщение, а с указанием последнего
    /// прочитанного: иначе открытие чата с сотней непрочитанных
    /// породило бы сто сообщений, и по их числу собеседник узнал бы,
    /// сколько всего накопилось.
    ReadReceipt {
        /// Последнее прочитанное сообщение.
        until: [u8; MESSAGE_ID_LEN],
    },
}

impl Content {
    /// Сериализует содержимое для отправки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — поле выходит за допустимые границы.
    /// Отказ на своей стороне лучше отправки сообщения, которое
    /// получатель обязан отвергнуть.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = vec![CONTENT_VERSION];

        match self {
            Self::Text { body, reply_to } => {
                out.push(KIND_TEXT);
                write_text(&mut out, body)?;
                write_optional_id(&mut out, reply_to.as_ref());
            }
            Self::Attachments {
                body,
                descriptors,
                reply_to,
            } => {
                if descriptors.len() > MAX_ATTACHMENTS {
                    return Err(AegisError::Malformed);
                }

                out.push(KIND_ATTACHMENTS);
                write_text(&mut out, body)?;
                write_optional_id(&mut out, reply_to.as_ref());

                out.push(u8::try_from(descriptors.len()).map_err(|_| AegisError::Malformed)?);

                for descriptor in descriptors {
                    write_bytes(&mut out, descriptor)?;
                }
            }
            Self::Reaction { target, emoji } => {
                if emoji.len() > MAX_REACTION_BYTES {
                    return Err(AegisError::Malformed);
                }

                out.push(KIND_REACTION);
                out.extend_from_slice(target);
                write_bytes(&mut out, emoji.as_bytes())?;
            }
            Self::Edit { target, body } => {
                out.push(KIND_EDIT);
                out.extend_from_slice(target);
                write_text(&mut out, body)?;
            }
            Self::Delete { target } => {
                out.push(KIND_DELETE);
                out.extend_from_slice(target);
            }
            Self::Typing { active } => {
                out.push(KIND_TYPING);
                out.push(u8::from(*active));
            }
            Self::ReadReceipt { until } => {
                out.push(KIND_READ_RECEIPT);
                out.extend_from_slice(until);
            }
        }

        Ok(out)
    }

    /// Разбирает содержимое, пришедшее от собеседника.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — неизвестная версия или тип, обрыв
    /// данных, превышение предела. Все случаи дают одну ошибку:
    /// подробный разбор причины подсказывал бы, как собрать
    /// сообщение, которое пройдёт.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);

        if reader.take_u8()? != CONTENT_VERSION {
            return Err(AegisError::Malformed);
        }

        let content = match reader.take_u8()? {
            KIND_TEXT => Self::Text {
                body: reader.take_text()?,
                reply_to: reader.take_optional_id()?,
            },
            KIND_ATTACHMENTS => {
                let body = reader.take_text()?;
                let reply_to = reader.take_optional_id()?;
                let count = reader.take_u8()? as usize;

                if count > MAX_ATTACHMENTS {
                    return Err(AegisError::Malformed);
                }

                let mut descriptors = Vec::with_capacity(count);
                for _ in 0..count {
                    descriptors.push(reader.take_blob()?);
                }

                Self::Attachments {
                    body,
                    descriptors,
                    reply_to,
                }
            }
            KIND_REACTION => {
                let target = reader.take_id()?;
                let emoji = reader.take_blob()?;

                if emoji.len() > MAX_REACTION_BYTES {
                    return Err(AegisError::Malformed);
                }

                Self::Reaction {
                    target,
                    emoji: String::from_utf8(emoji).map_err(|_| AegisError::Malformed)?,
                }
            }
            KIND_EDIT => Self::Edit {
                target: reader.take_id()?,
                body: reader.take_text()?,
            },
            KIND_DELETE => Self::Delete {
                target: reader.take_id()?,
            },
            KIND_TYPING => Self::Typing {
                active: match reader.take_u8()? {
                    0 => false,
                    1 => true,
                    // Иное значение означает чужую реализацию:
                    // булев флаг имеет ровно два состояния.
                    _ => return Err(AegisError::Malformed),
                },
            },
            KIND_READ_RECEIPT => Self::ReadReceipt {
                until: reader.take_id()?,
            },
            _ => return Err(AegisError::Malformed),
        };

        // Хвост означает, что сообщение собрано не нашим кодом.
        reader.expect_end()?;

        Ok(content)
    }
}

/// Записывает текст с проверкой предела.
fn write_text(out: &mut Vec<u8>, text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(AegisError::Malformed);
    }

    write_bytes(out, text.as_bytes())
}

/// Записывает блок с длиной.
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| AegisError::Malformed)?;

    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);

    Ok(())
}

/// Записывает необязательный идентификатор.
fn write_optional_id(out: &mut Vec<u8>, id: Option<&[u8; MESSAGE_ID_LEN]>) {
    match id {
        Some(value) => {
            // Признак наличия отдельным байтом: нулевой идентификатор
            // как «отсутствует» не годится, потому что он допустим.
            out.push(1);
            out.extend_from_slice(value);
        }
        None => out.push(0),
    }
}

/// Курсор с проверкой границ на каждом шаге.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or(AegisError::Malformed)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(AegisError::Malformed)?;

        self.offset = end;

        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take_slice(1)?
            .first()
            .copied()
            .ok_or(AegisError::Malformed)
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .take_slice(4)?
            .try_into()
            .map_err(|_| AegisError::Malformed)?;

        Ok(u32::from_be_bytes(bytes))
    }

    fn take_blob(&mut self) -> Result<Vec<u8>> {
        let length = self.take_u32()? as usize;

        // Длина сверяется с остатком до выделения памяти: объявленный
        // размер в четыре гигабайта не должен приводить к попытке
        // зарезервировать их.
        let remaining = self
            .bytes
            .len()
            .checked_sub(self.offset)
            .ok_or(AegisError::Malformed)?;

        if length > remaining {
            return Err(AegisError::Malformed);
        }

        Ok(self.take_slice(length)?.to_vec())
    }

    fn take_text(&mut self) -> Result<String> {
        let bytes = self.take_blob()?;

        if bytes.len() > MAX_TEXT_BYTES {
            return Err(AegisError::Malformed);
        }

        String::from_utf8(bytes).map_err(|_| AegisError::Malformed)
    }

    fn take_id(&mut self) -> Result<[u8; MESSAGE_ID_LEN]> {
        self.take_slice(MESSAGE_ID_LEN)?
            .try_into()
            .map_err(|_| AegisError::Malformed)
    }

    fn take_optional_id(&mut self) -> Result<Option<[u8; MESSAGE_ID_LEN]>> {
        match self.take_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.take_id()?)),
            _ => Err(AegisError::Malformed),
        }
    }

    fn expect_end(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AegisError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> [u8; MESSAGE_ID_LEN] {
        [value; MESSAGE_ID_LEN]
    }

    #[test]
    fn text_round_trips() {
        let content = Content::Text {
            body: "привет".to_owned(),
            reply_to: None,
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn reply_round_trips() {
        let content = Content::Text {
            body: "ответ".to_owned(),
            reply_to: Some(id(7)),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn attachments_round_trip() {
        let content = Content::Attachments {
            body: "смотри".to_owned(),
            descriptors: vec![vec![1, 2, 3], vec![4, 5]],
            reply_to: Some(id(9)),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn reaction_round_trips() {
        let content = Content::Reaction {
            target: id(3),
            emoji: "👍".to_owned(),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    /// Пустая реакция снимает предыдущую.
    #[test]
    fn empty_reaction_removes() {
        let content = Content::Reaction {
            target: id(3),
            emoji: String::new(),
        };

        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    #[test]
    fn edit_and_delete_round_trip() {
        for content in [
            Content::Edit {
                target: id(1),
                body: "исправлено".to_owned(),
            },
            Content::Delete { target: id(2) },
        ] {
            let bytes = content.to_bytes().expect("сериализация");

            assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
        }
    }

    /// 🔐 Неизвестный тип отвергается, а не игнорируется.
    ///
    /// Молчаливый пропуск означал бы, что сообщение от новой версии
    /// выглядит пустым: пользователь решил бы, что собеседник прислал
    /// пустоту, хотя тот прислал, например, опрос.
    #[test]
    fn unknown_kind_is_rejected() {
        let bytes = vec![CONTENT_VERSION, 99];

        assert!(matches!(
            Content::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut bytes = Content::Delete { target: id(1) }
            .to_bytes()
            .expect("сериализация");
        bytes[0] = CONTENT_VERSION.wrapping_add(1);

        assert!(Content::from_bytes(&bytes).is_err());
    }

    /// 🔐 Обрезка на любой позиции даёт ошибку, а не панику.
    ///
    /// Обрезанное сообщение может прислать кто угодно, а паника
    /// в разборе означает отказ в обслуживании.
    #[test]
    fn truncation_at_any_offset_is_an_error() {
        let full = Content::Attachments {
            body: "текст".to_owned(),
            descriptors: vec![vec![1, 2, 3]],
            reply_to: Some(id(5)),
        }
        .to_bytes()
        .expect("сериализация");

        for cut in 0..full.len() {
            let truncated = full.get(..cut).expect("срез в границах");

            assert!(
                Content::from_bytes(truncated).is_err(),
                "обрезка до {cut} байт разобралась"
            );
        }
    }

    /// Лишние байты в хвосте отвергаются.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = Content::Delete { target: id(1) }
            .to_bytes()
            .expect("сериализация");
        bytes.push(0);

        assert!(Content::from_bytes(&bytes).is_err());
    }

    /// Огромная объявленная длина отвергается без выделения памяти.
    #[test]
    fn absurd_length_is_rejected() {
        let mut bytes = vec![CONTENT_VERSION, KIND_TEXT];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());

        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn oversized_text_is_rejected() {
        let content = Content::Text {
            body: "a".repeat(MAX_TEXT_BYTES + 1),
            reply_to: None,
        };

        assert!(content.to_bytes().is_err());
    }

    #[test]
    fn too_many_attachments_are_rejected() {
        let content = Content::Attachments {
            body: String::new(),
            descriptors: vec![vec![1]; MAX_ATTACHMENTS + 1],
            reply_to: None,
        };

        assert!(content.to_bytes().is_err());
    }

    /// Некорректный UTF-8 отвергается.
    ///
    /// Иначе текст сообщения попал бы в интерфейс как последовательность
    /// байтов, и поведение отрисовки стало бы непредсказуемым.
    #[test]
    fn invalid_utf8_is_rejected() {
        let mut bytes = vec![CONTENT_VERSION, KIND_TEXT];
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        bytes.push(0);

        assert!(Content::from_bytes(&bytes).is_err());
    }

    #[test]
    fn typing_round_trips() {
        for active in [true, false] {
            let content = Content::Typing { active };
            let bytes = content.to_bytes().expect("сериализация");

            assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
        }
    }

    #[test]
    fn read_receipt_round_trips() {
        let content = Content::ReadReceipt { until: id(11) };
        let bytes = content.to_bytes().expect("сериализация");

        assert_eq!(Content::from_bytes(&bytes).expect("разбор"), content);
    }

    /// Булев флаг имеет ровно два состояния.
    ///
    /// Иное значение означает чужую реализацию, и принимать его
    /// как «истину» значило бы молча согласиться с чужим форматом.
    #[test]
    fn invalid_typing_flag_is_rejected() {
        let bytes = vec![CONTENT_VERSION, KIND_TYPING, 2];

        assert!(matches!(
            Content::from_bytes(&bytes),
            Err(AegisError::Malformed)
        ));
    }
}
