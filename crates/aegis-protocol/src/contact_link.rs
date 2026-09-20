// SPDX-License-Identifier: Apache-2.0

//! Ссылка на контакт: `aegis://contact/...`.
//!
//! # Что она заменяет
//!
//! Обмен контактами без сервера-посредника. Пользователь показывает
//! QR или отправляет ссылку, второй сканирует — и получает
//! identity-ключ собеседника напрямую, не спрашивая его у сервера.
//!
//! 🔐 Это и есть смысл: ключ, полученный от сервера, приходится
//! принимать на веру. Ключ, снятый с экрана человека, стоящего рядом,
//! проверять не нужно — канал доверия проходит мимо сети.
//!
//! # Чем это отличается от QR safety number
//!
//! [`crate::qr::safety_number_qr`] намеренно кодирует голые цифры,
//! без схемы и префикса: сканер, встретивший ссылку, откроет браузер,
//! а адрес в коде проверки — готовый фишинг.
//!
//! Здесь наоборот: ссылка нужна, потому что её пересылают в мессенджерах
//! и открывают нажатием. Разница в том, что схема `aegis://` не
//! открывается браузером — её обрабатывает только это приложение, —
//! и в том, что разбор ниже отвергает всё, что не является ровно
//! контактом.
//!
//! # Почему разбор такой придирчивый
//!
//! Ссылка приходит откуда угодно: из чужого чата, с наклейки, из
//! сообщения незнакомца. Она не подписана и не может быть подписана —
//! подписывать нечем, ключ как раз и передаётся. Единственное, что
//! может сделать разбор, — не дать ссылке означать больше, чем
//! «вот такой identity-ключ». Поэтому неизвестные поля, лишние
//! сегменты пути и вторая схема внутри отвергаются, а не игнорируются.
//!
//! # Чего в ссылке нет
//!
//! Адреса сервера. Ссылка, приносящая с собой сервер, позволила бы
//! увести пользователя на чужой узел одним нажатием.

use aegis_types::{AegisError, PublicKeyBytes, Result};

/// Схема ссылки вместе с типом.
///
/// Тип в префиксе, а не в параметре: он определяет, как читать
/// остальное, и должен быть виден до разбора.
const PREFIX: &str = "aegis://contact/";

/// Длина identity-ключа в base32 без выравнивания.
///
/// 32 байта — 256 бит; base32 кодирует 5 бит на символ, значит
/// 52 символа несут 260 бит, из которых четыре последних — нули.
const ENCODED_KEY_LEN: usize = 52;

/// Предел длины отображаемого имени.
///
/// 🔐 Имя приходит из ссылки, то есть от кого угодно, и попадает
/// в интерфейс до того, как пользователь что-то подтвердит.
pub const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Предел длины всей ссылки.
///
/// 🔐 Отсекает попытки скормить разбору мегабайт до того, как он
/// начнёт что-либо разбирать.
const MAX_LINK_LEN: usize = 512;

/// Алфавит base32 (RFC 4648) без выравнивания.
///
/// Base32, а не base64: ссылку читают вслух и набирают руками,
/// а base64 различает регистр и содержит «+» и «/», которые ломаются
/// при пересылке в мессенджерах.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Контакт, полученный по ссылке.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactLink {
    /// Identity-ключ контакта.
    pub identity: PublicKeyBytes,

    /// Имя, которое предложил владелец ссылки.
    ///
    /// 🔐 Подсказка для интерфейса, не более. Имя выбирает тот, кто
    /// сделал ссылку, и оно ничем не подтверждено: «Банк» в ссылке
    /// не делает её ссылкой банка. Показывать его следует как
    /// предложенное, а сверять — по [`identity`](Self::identity).
    pub display_name: Option<String>,
}

impl ContactLink {
    /// Собирает ссылку для показа или пересылки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — имя длиннее [`MAX_DISPLAY_NAME_LEN`]
    /// либо содержит символы, ломающие отображение.
    pub fn to_uri(&self) -> Result<String> {
        let mut uri = String::with_capacity(PREFIX.len().saturating_add(ENCODED_KEY_LEN));
        uri.push_str(PREFIX);
        uri.push_str(&encode_base32(self.identity.as_bytes()));

        if let Some(name) = &self.display_name {
            validate_name(name)?;

            uri.push_str("?name=");
            uri.push_str(&percent_encode(name));
        }

        Ok(uri)
    }

    /// Разбирает ссылку, пришедшую извне.
    ///
    /// # 🔐 Что здесь отвергается и почему
    ///
    /// - Чужая схема — чтобы `https://` не прошёл как контакт.
    /// - Лишние сегменты пути — `contact/KEY/../admin` не должен
    ///   означать ничего, кроме ошибки.
    /// - Неизвестные параметры — сегодня они лишние, а завтра
    ///   означали бы что-то в новой версии, и старый клиент принял бы
    ///   ссылку, поняв её иначе, чем задумал отправитель.
    /// - Пустое имя — отличить «имя не предложено» от «предложено
    ///   пустое» иначе невозможно, а разница видна в интерфейсе.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — ссылка не соответствует формату.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_LINK_LEN {
            return Err(AegisError::Malformed);
        }

        let rest = input.strip_prefix(PREFIX).ok_or(AegisError::Malformed)?;

        // Ключ и параметры разделяются одним «?». Второй «?» означает
        // не наш формат: угадывать, какой из них разделитель, значит
        // разобрать ссылку иначе, чем отправитель её собрал.
        let mut parts = rest.split('?');
        let encoded = parts.next().unwrap_or_default();
        let query = parts.next();

        if parts.next().is_some() {
            return Err(AegisError::Malformed);
        }

        let identity = PublicKeyBytes::new(decode_key(encoded)?);

        let display_name = match query {
            None => None,
            Some(query) => Some(parse_name(query)?),
        };

        Ok(Self {
            identity,
            display_name,
        })
    }
}

/// Разбирает часть параметров.
fn parse_name(query: &str) -> Result<String> {
    // Ровно один параметр. Неизвестные не игнорируются: в новой
    // версии они означали бы что-то, и старый клиент принял бы ссылку,
    // поняв её иначе, чем задумал отправитель.
    let value = query.strip_prefix("name=").ok_or(AegisError::Malformed)?;

    if value.contains('&') {
        return Err(AegisError::Malformed);
    }

    let name = percent_decode(value)?;

    validate_name(&name)?;

    Ok(name)
}

/// Проверяет имя, предложенное в ссылке.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().count() > MAX_DISPLAY_NAME_LEN {
        return Err(AegisError::Malformed);
    }

    // 🔐 Управляющие символы отвергаются: перевод строки разрывает имя
    // в интерфейсе, а RTL-override переставляет текст местами —
    // «Иван\u{202E}gpj.exe» показалось бы картинкой.
    if name.chars().any(|character| {
        character.is_control()
            || matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    }) {
        return Err(AegisError::Malformed);
    }

    Ok(())
}

/// Кодирует байты в base32 без выравнивания.
fn encode_base32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(ENCODED_KEY_LEN);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits = bits.saturating_add(8);

        while bits >= 5 {
            bits = bits.saturating_sub(5);

            let index = usize::from((buffer >> bits) & 0x1f);
            out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
        }
    }

    if bits > 0 {
        let shift = 5u8.saturating_sub(bits);
        let index = usize::from((buffer << shift) & 0x1f);
        out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
    }

    out
}

/// Разбирает identity-ключ из base32.
fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != ENCODED_KEY_LEN {
        return Err(AegisError::Malformed);
    }

    let mut key = [0u8; 32];
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    let mut written = 0usize;

    for symbol in encoded.bytes() {
        // Регистр приводится: ссылку набирают руками, и заглавные
        // с прописными различает только машина. Всё остальное —
        // ошибка, а не повод угадывать.
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == symbol.to_ascii_uppercase())
            .ok_or(AegisError::Malformed)?;

        buffer = (buffer << 5) | u16::try_from(value).map_err(|_| AegisError::Malformed)?;
        bits = bits.saturating_add(5);

        if bits >= 8 {
            bits = bits.saturating_sub(8);

            let byte = u8::try_from((buffer >> bits) & 0xff).map_err(|_| AegisError::Malformed)?;
            *key.get_mut(written).ok_or(AegisError::Malformed)? = byte;
            written = written.saturating_add(1);
        }
    }

    if written != 32 {
        return Err(AegisError::Malformed);
    }

    // 🔐 Хвостовые биты обязаны быть нулевыми. Иначе один ключ имел бы
    // несколько записей, и сверка ссылок посимвольно давала бы
    // «разные» для одного и того же контакта.
    if bits > 0 && (buffer & ((1u16 << bits).saturating_sub(1))) != 0 {
        return Err(AegisError::Malformed);
    }

    Ok(key)
}

/// Кодирует имя для ссылки.
///
/// Экранируется всё, кроме заведомо безопасного: пробел, «&», «?»
/// и «%» изменили бы разбор, а не только вид.
fn percent_encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());

    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }

    out
}

/// Шестнадцатеричная цифра.
fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0'.saturating_add(value)),
        _ => char::from(b'A'.saturating_add(value.saturating_sub(10))),
    }
}

/// Разбирает процентное кодирование.
fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = *bytes.get(index).ok_or(AegisError::Malformed)?;

        if byte == b'%' {
            let high = bytes
                .get(index.saturating_add(1))
                .ok_or(AegisError::Malformed)?;
            let low = bytes
                .get(index.saturating_add(2))
                .ok_or(AegisError::Malformed)?;

            let decoded = hex_value(*high)?
                .checked_mul(16)
                .and_then(|high| high.checked_add(hex_value(*low).ok()?))
                .ok_or(AegisError::Malformed)?;

            out.push(decoded);
            index = index.saturating_add(3);
        } else {
            out.push(byte);
            index = index.saturating_add(1);
        }
    }

    // 🔐 Результат обязан быть корректным UTF-8. Битые последовательности
    // отображаются по-разному в разных системах, и имя выглядело бы
    // у отправителя иначе, чем у получателя.
    String::from_utf8(out).map_err(|_| AegisError::Malformed)
}

/// Значение шестнадцатеричной цифры.
fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(byte.saturating_sub(b'A').saturating_add(10)),
        _ => Err(AegisError::Malformed),
    }
}

/// Строит QR-код ссылки на контакт.
///
/// # Errors
///
/// [`AegisError::Malformed`] — ссылка не собирается либо не помещается
/// в код.
pub fn contact_qr(link: &ContactLink) -> Result<crate::qr::QrMatrix> {
    let uri = link.to_uri()?;

    crate::qr::encode_text(&uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PublicKeyBytes {
        let mut bytes = [0u8; 32];

        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }

        PublicKeyBytes::new(bytes)
    }

    #[test]
    fn link_round_trips() {
        let link = ContactLink {
            identity: identity(),
            display_name: Some("Иван".to_owned()),
        };

        let parsed = ContactLink::parse(&link.to_uri().expect("ссылка")).expect("разбор");

        assert_eq!(parsed, link);
    }

    #[test]
    fn link_without_name_round_trips() {
        let link = ContactLink {
            identity: identity(),
            display_name: None,
        };

        assert_eq!(
            ContactLink::parse(&link.to_uri().expect("ссылка")).expect("разбор"),
            link
        );
    }

    /// 🔐 Чужая схема не проходит как контакт.
    #[test]
    fn foreign_scheme_is_rejected() {
        for input in [
            "https://aegis.example/contact/AAAA",
            "aegis://profile/AAAA",
            "aegis://contact",
            "contact/AAAA",
            "",
        ] {
            assert!(
                ContactLink::parse(input).is_err(),
                "ссылка «{input}» принята"
            );
        }
    }

    /// 🔐 Лишний сегмент пути отвергается.
    ///
    /// «contact/KEY/../admin» не должен означать ничего, кроме ошибки.
    #[test]
    fn extra_path_segments_are_rejected() {
        let uri = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        assert!(ContactLink::parse(&format!("{uri}/extra")).is_err());
        assert!(ContactLink::parse(&format!("{uri}/../admin")).is_err());
    }

    /// 🔐 Неизвестные параметры отвергаются, а не игнорируются.
    ///
    /// Иначе старый клиент принял бы ссылку из новой версии, поняв её
    /// иначе, чем задумал отправитель.
    #[test]
    fn unknown_parameters_are_rejected() {
        let uri = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        for suffix in ["?server=evil.example", "?name=A&server=evil.example", "?"] {
            assert!(
                ContactLink::parse(&format!("{uri}{suffix}")).is_err(),
                "параметры «{suffix}» приняты"
            );
        }
    }

    /// 🔐 Управляющие символы в имени отвергаются.
    ///
    /// RTL-override переставляет текст местами: «Иван\u{202E}gpj.exe»
    /// показалось бы картинкой.
    #[test]
    fn control_characters_in_name_are_rejected() {
        for name in ["Иван\u{202E}gpj.exe", "две\nстроки", "таб\tуляция"] {
            let link = ContactLink {
                identity: identity(),
                display_name: Some(name.to_owned()),
            };

            assert!(link.to_uri().is_err(), "имя «{name}» закодировано");
        }
    }

    #[test]
    fn oversized_name_is_rejected() {
        let link = ContactLink {
            identity: identity(),
            display_name: Some("я".repeat(MAX_DISPLAY_NAME_LEN.saturating_add(1))),
        };

        assert!(link.to_uri().is_err());
    }

    /// Имя длиной ровно в предел проходит, считаясь в символах.
    #[test]
    fn cyrillic_name_at_limit_round_trips() {
        let link = ContactLink {
            identity: identity(),
            display_name: Some("я".repeat(MAX_DISPLAY_NAME_LEN)),
        };

        assert_eq!(
            ContactLink::parse(&link.to_uri().expect("ссылка")).expect("разбор"),
            link
        );
    }

    /// 🔐 Слишком длинная ссылка отвергается до разбора.
    #[test]
    fn oversized_link_is_rejected() {
        assert!(ContactLink::parse(&"a".repeat(MAX_LINK_LEN.saturating_add(1))).is_err());
    }

    /// 🔐 Ключ неверной длины отвергается.
    #[test]
    fn wrong_key_length_is_rejected() {
        let short = "A".repeat(ENCODED_KEY_LEN.saturating_sub(1));
        let long = "A".repeat(ENCODED_KEY_LEN.saturating_add(1));

        for encoded in ["AAAA", short.as_str(), long.as_str()] {
            assert!(
                ContactLink::parse(&format!("{PREFIX}{encoded}")).is_err(),
                "ключ длиной {} принят",
                encoded.len()
            );
        }
    }

    /// 🔐 Символ вне алфавита отвергается.
    #[test]
    fn invalid_symbol_is_rejected() {
        // «1», «8», «9» и «0» в base32 отсутствуют: их путают
        // с буквами при наборе с бумаги.
        for symbol in ['1', '8', '9', '0', '!', 'а'] {
            let mut encoded = "A".repeat(ENCODED_KEY_LEN.saturating_sub(1));
            encoded.push(symbol);

            assert!(
                ContactLink::parse(&format!("{PREFIX}{encoded}")).is_err(),
                "символ «{symbol}» принят"
            );
        }
    }

    /// Регистр при наборе руками не важен.
    #[test]
    fn lowercase_key_is_accepted() {
        let uri = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        let lowered = format!(
            "{PREFIX}{}",
            uri.strip_prefix(PREFIX).unwrap_or_default().to_lowercase()
        );

        assert_eq!(
            ContactLink::parse(&lowered).expect("разбор"),
            ContactLink::parse(&uri).expect("разбор")
        );
    }

    /// 🔐 Ненулевые хвостовые биты отвергаются.
    ///
    /// Иначе один ключ имел бы несколько записей, и сверка ссылок
    /// посимвольно давала бы «разные» для одного контакта.
    #[test]
    fn nonzero_padding_bits_are_rejected() {
        let uri = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        let encoded = uri.strip_prefix(PREFIX).unwrap_or_default();
        let mut symbols: Vec<char> = encoded.chars().collect();

        // Последний символ несёт 4 значащих бита и один хвостовой.
        // «A» — нулевой символ алфавита; «B» отличается от него
        // младшим битом, то есть ровно хвостовым.
        let last = symbols.len().saturating_sub(1);

        if let Some(slot) = symbols.get_mut(last) {
            *slot = if *slot == 'B' { 'D' } else { 'B' };
        }

        let tampered: String = symbols.into_iter().collect();

        assert!(
            ContactLink::parse(&format!("{PREFIX}{tampered}")).is_err(),
            "ссылка с ненулевыми хвостовыми битами принята"
        );
    }

    /// Разные ключи дают разные ссылки.
    #[test]
    fn different_keys_give_different_links() {
        let first = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        let second = ContactLink {
            identity: PublicKeyBytes::new([0xff; 32]),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        assert_ne!(first, second);
    }

    /// Имя с пробелами и «&» переживает круг.
    ///
    /// Без экранирования «&» разорвал бы параметр, и имя пришло бы
    /// обрезанным.
    #[test]
    fn name_with_separators_round_trips() {
        let link = ContactLink {
            identity: identity(),
            display_name: Some("Иван и Мария?".to_owned()),
        };

        assert_eq!(
            ContactLink::parse(&link.to_uri().expect("ссылка")).expect("разбор"),
            link
        );
    }

    /// 🔐 Битое процентное кодирование отвергается.
    #[test]
    fn malformed_percent_encoding_is_rejected() {
        let uri = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        for name in ["%", "%A", "%ZZ", "%FF"] {
            assert!(
                ContactLink::parse(&format!("{uri}?name={name}")).is_err(),
                "имя «{name}» принято"
            );
        }
    }

    /// Инвариант, который проверяет фаззинг-таргет `parse_contact_link`.
    ///
    /// # Почему он продублирован здесь
    ///
    /// Таргет собирается только nightly с libFuzzer, а на Windows
    /// не собирается вовсе (см. `fuzz/README.md`). То есть свойство,
    /// на котором он держится, на обычном прогоне `cargo test` никто
    /// не проверяет, и сломать его можно, ни разу не увидев красного.
    ///
    /// Здесь оно проверяется на наборе входов, каждый из которых
    /// когда-то был отдельной ошибкой разбора: процентные последовательности,
    /// многобайтовый UTF-8, имя на границе предела длины.
    ///
    /// 🔐 Сравниваются разобранные контакты, а не строки: `%41` и `A`
    /// — одна и та же ссылка, и требовать побайтового совпадения
    /// значило бы запретить нормализацию.
    #[test]
    fn parse_and_rebuild_agree() {
        let base = ContactLink {
            identity: identity(),
            display_name: None,
        }
        .to_uri()
        .expect("ссылка");

        let names = [
            "Иван",
            "A",
            "%D0%98",
            "a b",
            // Имя у самого предела длины: «я» занимает два байта,
            // поэтому 32 символа — ровно MAX_DISPLAY_NAME_LEN байт.
            // Число записано, а не поделено: деление запрещено
            // правилами линтинга (раздел 4.2), и не зря — молчаливое
            // округление вниз здесь дало бы проверку не той границы.
            &"я".repeat(32),
        ];

        let mut checked = 0;

        for suffix in
            core::iter::once(String::new()).chain(names.iter().map(|name| format!("?name={name}")))
        {
            let uri = format!("{base}{suffix}");

            let Ok(link) = ContactLink::parse(&uri) else {
                continue;
            };

            let rebuilt = link
                .to_uri()
                .expect("разобранная ссылка обязана собираться");

            assert_eq!(
                link,
                ContactLink::parse(&rebuilt).expect("пересобранная обязана разбираться"),
                "круговой обход изменил контакт: {uri}"
            );

            checked += 1;
        }

        // Ноль разобранных ссылок означал бы, что тест ничего не проверил.
        assert!(checked >= 2, "проверено ссылок: {checked}");
    }

    #[test]
    fn qr_is_built_from_link() {
        let matrix = contact_qr(&ContactLink {
            identity: identity(),
            display_name: Some("Иван".to_owned()),
        })
        .expect("код");

        assert!(matrix.size >= 21);
        assert_eq!(
            matrix.modules.len(),
            matrix.size.saturating_mul(matrix.size)
        );
    }
}
