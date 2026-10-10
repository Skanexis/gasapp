// SPDX-License-Identifier: Apache-2.0

//! Кнопки под сообщением — то, что в Telegram зовётся inline-клавиатурой.
//!
//! Отправитель (обычно бот) прикладывает к своему сообщению ряды кнопок.
//! Кнопка бывает двух видов:
//!
//! * **с данными** — нажатие отправляет автору сообщения эти данные
//!   (до 64 байт) отдельным служебным сообщением; в переписке оно не
//!   показывается;
//! * **со ссылкой** — нажатие открывает ссылку у нажавшего. Автору
//!   сообщения ничего не уходит.
//!
//! Клавиатура едет внутри обычного сквозного шифрования переписки:
//! сервер не видит ни подписей кнопок, ни данных, ни нажатий.
//!
//! # 🔐 Что обязан помнить интерфейс
//!
//! * Подписи и ссылки пишет собеседник: показывать можно, доверять —
//!   нет. Ссылку перед открытием показывают человеку целиком.
//! * Нажатие кнопки с данными сообщает автору, что человек сейчас у
//!   телефона, — как и любой ответ.

use gasapp_types::{GasAppError, Result};

/// Сколько рядов кнопок под одним сообщением.
pub const MAX_ROWS: usize = 8;

/// Сколько кнопок в ряду.
pub const MAX_BUTTONS_PER_ROW: usize = 4;

/// Предел подписи кнопки, в знаках.
pub const MAX_LABEL_CHARS: usize = 40;

/// Предел данных кнопки, в байтах.
pub const MAX_DATA_BYTES: usize = 64;

/// Предел ссылки кнопки, в байтах.
pub const MAX_URL_BYTES: usize = 512;

/// Предел клавиатуры в закодированном виде.
pub const MAX_KEYBOARD_BYTES: usize = 8 * 1024;

const VERSION: u8 = 1;
const ACTION_CALLBACK: u8 = 1;
const ACTION_URL: u8 = 2;

/// Что делает нажатие.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ButtonAction {
    /// Отправить автору сообщения эти данные.
    Callback(Vec<u8>),
    /// Открыть ссылку (`https://…`) у нажавшего.
    Url(String),
}

/// Кнопка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    /// Подпись.
    pub label: String,
    /// Что делает нажатие.
    pub action: ButtonAction,
}

/// Ряды кнопок под сообщением. Пустая клавиатура — «убрать кнопки».
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyboard {
    /// Ряды, сверху вниз; в ряду — слева направо.
    pub rows: Vec<Vec<Button>>,
}

/// Знаки, которые меняют направление письма либо не видны.
///
/// 🔐 Ими подпись «Отмена» превращают в «анемтО», а в строку вставляют
/// невидимое: человек нажимает не то, что читает.
fn is_deceptive(symbol: char) -> bool {
    matches!(
        symbol,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

fn validate(button: &Button) -> Result<()> {
    let label_ok = !button.label.trim().is_empty()
        && button.label.chars().count() <= MAX_LABEL_CHARS
        && !button
            .label
            .chars()
            .any(|symbol| symbol.is_control() || is_deceptive(symbol));

    let action_ok = match &button.action {
        ButtonAction::Callback(data) => data.len() <= MAX_DATA_BYTES,
        // 🔐 Только https и только печатные знаки ASCII: иная схема
        // (`intent:`, `file:`, `javascript:`) открыла бы на телефоне
        // нажавшего то, что выбрал собеседник, а буквы других алфавитов
        // в адресе выдают чужой сайт за знакомый (`аpple.com` с
        // кириллической «а»). Международное имя пишется в виде `xn--…` —
        // так человек видит, что оно не латинское.
        ButtonAction::Url(url) => {
            url.len() <= MAX_URL_BYTES
                && url.starts_with("https://")
                && url.len() > "https://".len()
                && url.bytes().all(|byte| byte.is_ascii_graphic())
                // Данные входа в адресе (`https://bank.example@evil.example`)
                // прячут настоящий сайт за знакомым именем.
                && !url
                    .split(['/', '?', '#'])
                    .nth(2)
                    .unwrap_or_default()
                    .contains('@')
        }
    };

    if label_ok && action_ok {
        Ok(())
    } else {
        Err(GasAppError::Malformed)
    }
}

impl Keyboard {
    /// Кнопка в ряду `row` на месте `column`.
    #[must_use]
    pub fn button(&self, row: usize, column: usize) -> Option<&Button> {
        self.rows.get(row)?.get(column)
    }

    /// Есть ли в клавиатуре кнопка с такими данными.
    #[must_use]
    pub fn has_callback(&self, data: &[u8]) -> bool {
        self.rows
            .iter()
            .flatten()
            .any(|button| matches!(&button.action, ButtonAction::Callback(known) if known == data))
    }

    /// Кодирует клавиатуру.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — рядов, кнопок либо знаков больше
    /// предела, пустой ряд, пустая подпись, ссылка не `https://`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.rows.len() > MAX_ROWS {
            return Err(GasAppError::Malformed);
        }

        let mut out = vec![
            VERSION,
            u8::try_from(self.rows.len()).map_err(|_| GasAppError::Malformed)?,
        ];

        for row in &self.rows {
            if row.is_empty() || row.len() > MAX_BUTTONS_PER_ROW {
                return Err(GasAppError::Malformed);
            }

            out.push(u8::try_from(row.len()).map_err(|_| GasAppError::Malformed)?);

            for button in row {
                validate(button)?;

                let (kind, payload) = match &button.action {
                    ButtonAction::Callback(data) => (ACTION_CALLBACK, data.as_slice()),
                    ButtonAction::Url(url) => (ACTION_URL, url.as_bytes()),
                };

                put_block(&mut out, button.label.as_bytes())?;
                out.push(kind);
                put_block(&mut out, payload)?;
            }
        }

        Ok(out)
    }

    /// Разбирает клавиатуру, пришедшую от собеседника.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — формат не тот либо нарушен предел.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_KEYBOARD_BYTES {
            return Err(GasAppError::Malformed);
        }

        let mut rest = bytes;

        if take_u8(&mut rest)? != VERSION {
            return Err(GasAppError::Malformed);
        }

        let row_count = usize::from(take_u8(&mut rest)?);
        if row_count > MAX_ROWS {
            return Err(GasAppError::Malformed);
        }

        let mut rows = Vec::with_capacity(row_count);

        for _ in 0..row_count {
            let count = usize::from(take_u8(&mut rest)?);
            if count == 0 || count > MAX_BUTTONS_PER_ROW {
                return Err(GasAppError::Malformed);
            }

            let mut row = Vec::with_capacity(count);

            for _ in 0..count {
                let label = String::from_utf8(take_block(&mut rest)?.to_vec())
                    .map_err(|_| GasAppError::Malformed)?;
                let kind = take_u8(&mut rest)?;
                let payload = take_block(&mut rest)?.to_vec();

                let button = Button {
                    label,
                    action: match kind {
                        ACTION_CALLBACK => ButtonAction::Callback(payload),
                        ACTION_URL => ButtonAction::Url(
                            String::from_utf8(payload).map_err(|_| GasAppError::Malformed)?,
                        ),
                        _ => return Err(GasAppError::Malformed),
                    },
                };
                validate(&button)?;

                row.push(button);
            }

            rows.push(row);
        }

        // Хвост означает, что клавиатуру собрал не наш код.
        if !rest.is_empty() {
            return Err(GasAppError::Malformed);
        }

        Ok(Self { rows })
    }
}

fn put_block(out: &mut Vec<u8>, block: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u16::try_from(block.len())
            .map_err(|_| GasAppError::Malformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(block);

    Ok(())
}

fn take_u8(rest: &mut &[u8]) -> Result<u8> {
    let (first, tail) = rest.split_first().ok_or(GasAppError::Malformed)?;
    *rest = tail;

    Ok(*first)
}

fn take_block<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (length, tail) = rest.split_at_checked(2).ok_or(GasAppError::Malformed)?;
    let length = usize::from(u16::from_be_bytes(
        length.try_into().map_err(|_| GasAppError::Malformed)?,
    ));
    let (block, tail) = tail
        .split_at_checked(length)
        .ok_or(GasAppError::Malformed)?;
    *rest = tail;

    Ok(block)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn callback(label: &str, data: &[u8]) -> Button {
        Button {
            label: label.to_owned(),
            action: ButtonAction::Callback(data.to_vec()),
        }
    }

    fn link(label: &str, url: &str) -> Button {
        Button {
            label: label.to_owned(),
            action: ButtonAction::Url(url.to_owned()),
        }
    }

    #[test]
    fn a_keyboard_round_trips() {
        let keyboard = Keyboard {
            rows: vec![
                vec![callback("Да", b"yes"), callback("Нет", b"no")],
                vec![link("Сайт", "https://example.org/a?b=1")],
            ],
        };
        let bytes = keyboard.to_bytes().unwrap();

        assert_eq!(Keyboard::from_bytes(&bytes).unwrap(), keyboard);
        assert!(keyboard.has_callback(b"yes"));
        assert!(!keyboard.has_callback(b"maybe"));
        assert_eq!(keyboard.button(1, 0).unwrap().label, "Сайт");
        assert!(keyboard.button(2, 0).is_none());

        // Пустая клавиатура — «убрать кнопки».
        let empty = Keyboard::default().to_bytes().unwrap();
        assert!(Keyboard::from_bytes(&empty).unwrap().rows.is_empty());
    }

    #[test]
    fn limits_and_schemes_are_enforced() {
        let one = |button: Button| Keyboard {
            rows: vec![vec![button]],
        };

        for bad in [
            one(callback("", b"x")),
            one(callback("   ", b"x")),
            one(callback(&"я".repeat(MAX_LABEL_CHARS + 1), b"x")),
            one(callback("перевод\nстроки", b"x")),
            one(callback("много", &[0u8; MAX_DATA_BYTES + 1])),
            one(link("http", "http://example.org")),
            one(link("intent", "intent://scan/#Intent;end")),
            one(link("js", "javascript:alert(1)")),
            one(link("пусто", "https://")),
            one(link("пробел", "https://example.org/a b")),
            one(link("кириллица", "https://аpple.com/")),
            one(link("вход", "https://bank.example@evil.example/login")),
            one(callback("отмена\u{202E}", b"x")),
            one(callback("не\u{200B}видимое", b"x")),
            Keyboard {
                rows: vec![Vec::new()],
            },
            Keyboard {
                rows: vec![vec![callback("a", b"a"); MAX_BUTTONS_PER_ROW + 1]],
            },
            Keyboard {
                rows: vec![vec![callback("a", b"a")]; MAX_ROWS + 1],
            },
        ] {
            assert!(bad.to_bytes().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn malformed_bytes_are_refused() {
        let good = Keyboard {
            rows: vec![vec![callback("ok", b"1")]],
        }
        .to_bytes()
        .unwrap();

        assert!(Keyboard::from_bytes(&good[..good.len() - 1]).is_err());

        let mut tail = good.clone();
        tail.push(0);
        assert!(Keyboard::from_bytes(&tail).is_err());

        let mut version = good.clone();
        version[0] = 9;
        assert!(Keyboard::from_bytes(&version).is_err());

        // Вид действия, которого нет.
        let mut kind = good;
        let position = kind.len() - 4;
        kind[position] = 7;
        assert!(Keyboard::from_bytes(&kind).is_err());

        assert!(Keyboard::from_bytes(&[]).is_err());
        assert!(Keyboard::from_bytes(&vec![0u8; MAX_KEYBOARD_BYTES + 1]).is_err());
    }
}
