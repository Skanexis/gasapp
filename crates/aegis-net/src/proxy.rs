// SPDX-License-Identifier: Apache-2.0

//! Прокси и Tor: сокрытие IP-адреса от сервера (ADR-024).
//!
//! # Какую утечку это закрывает
//!
//! Раздел 15.5 честно признаёт: sealed sender прячет, **кто** пишет,
//! padding — **сколько**, но сервер по-прежнему видит IP-адрес.
//! По адресу восстанавливается и человек, и его местоположение,
//! и то, что два «разных» аккаунта сидят за одним роутером.
//! При требовании «максимально безопасно» это последняя крупная
//! утечка, и закрыть её можно относительно недорого.
//!
//! # Почему здесь только конфигурация, а сокет открывает платформа
//!
//! Rust в этом проекте не открывает соединений (см. модуль `client`):
//! собственный сетевой стек обошёл бы платформенный пиннинг. Поэтому
//! прокси устроен так же, как вся остальная сеть: этот модуль решает,
//! **что** считается допустимой настройкой, и проверяет её, а применяет
//! её платформенный транспорт. TLS при этом идёт сквозь туннель до
//! самого сервера, и пиннинг продолжает действовать — прокси видит
//! только шифротекст TLS.
//!
//! # 🔐 Обязательства платформенного транспорта
//!
//! Модуль не может проверить их сам, поэтому они записаны здесь
//! и повторены в транспорте:
//!
//! 1. **Отказ закрытым.** Если прокси недоступен, запрос обязан
//!    завершиться ошибкой, а не уйти напрямую. Тихий откат на прямое
//!    соединение выдал бы адрес ровно тогда, когда пользователь
//!    уверен, что он скрыт.
//! 2. **DNS через прокси.** Имя сервера передаётся прокси как имя,
//!    а не разрешается на устройстве. Иначе провайдер видит запрос
//!    DNS к серверу AEGIS даже при работающем Tor.
//! 3. **Все каналы.** Прокси применяется и к HTTP, и к сокету
//!    уведомлений. Сокет, идущий напрямую, выдаёт адрес так же,
//!    как и запрос.
//!
//! # Чего прокси НЕ скрывает (ADR-024)
//!
//! От самого прокси — факт использования AEGIS и время активности.
//! Tor прячет адрес от сервера, но не от входного узла Tor.
//! Обещание, понятое шире, чем оно есть, опаснее отсутствия обещания.
//!
//! # Почему без логина и пароля
//!
//! ADR-024 упоминает аутентификацию на прокси. Её здесь нет намеренно:
//! у платформенного транспорта нет проверенного на устройстве пути
//! передачи учётных данных SOCKS5, а поле «пароль», которое молча
//! не применяется, хуже его отсутствия — пользователь решит, что
//! подключён к своему прокси. Формы вида `user@host` поэтому
//! отвергаются, а не игнорируются.

use std::net::{Ipv4Addr, Ipv6Addr};

use aegis_types::{AegisError, Result};

/// Предел длины имени хоста (RFC 1035).
pub const MAX_HOST_LEN: usize = 253;

/// Предел длины одной метки имени (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

/// Запись настройки: напрямую.
const SETTING_DIRECT: &str = "direct";

/// Запись настройки: встроенный Tor.
const SETTING_TOR: &str = "tor";

/// Прежняя запись «Tor через Orbot» (до 2026-09-25). Читается как
/// встроенный Tor: человек выбирал Tor, и Tor он получает — без Orbot.
const SETTING_LEGACY_ORBOT: &str = "orbot";

/// Приставка записи настройки SOCKS5.
const SETTING_SOCKS5_PREFIX: &str = "socks5:";

/// Как клиент выходит в сеть.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ProxyMode {
    /// Напрямую: сервер видит IP-адрес.
    ///
    /// ⚠️ Прежде это было умолчанием — ради того, чтобы работало из
    /// коробки. С 2026-09-24 умолчание — Tor ([`ProxyMode::Tor`]):
    /// владелец продукта требует, чтобы сервер не знал адресов, а
    /// напрямую можно подключиться только явным выбором с
    /// предупреждением.
    Direct,

    /// Через SOCKS5-прокси по адресу.
    Socks5 {
        /// Имя хоста или IP-адрес прокси.
        host: String,
        /// Порт прокси.
        port: u16,
    },

    /// Через Tor, встроенный в приложение (`aegis-tor`, Arti).
    /// 🔐 Умолчание: адрес устройства сервер не видит.
    ///
    /// Порт моста случайный и известен только во время работы, поэтому
    /// [`ProxyMode::endpoint`] для этого режима пуст: адрес берёт
    /// платформа у запущенного моста.
    #[default]
    Tor,
}

impl ProxyMode {
    /// Проверяет, что настройка допустима.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — порт нулевой либо хост не является
    /// именем, IPv4 или IPv6: схема, путь, учётные данные, пробелы
    /// и пустые метки отвергаются.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Direct | Self::Tor => Ok(()),
            Self::Socks5 { host, port } => {
                if *port == 0 {
                    return Err(AegisError::Malformed);
                }

                validate_host(host)
            }
        }
    }

    /// Адрес внешнего прокси, если режим его задаёт.
    ///
    /// `None` — напрямую либо встроенный Tor (его порт знает только
    /// запущенный мост).
    #[must_use]
    pub fn endpoint(&self) -> Option<(&str, u16)> {
        match self {
            Self::Direct | Self::Tor => None,
            Self::Socks5 { host, port } => Some((host.as_str(), *port)),
        }
    }

    /// Скрывает ли режим IP-адрес от сервера.
    #[must_use]
    pub const fn hides_address(&self) -> bool {
        !matches!(self, Self::Direct)
    }

    /// Запись настройки для хранения.
    #[must_use]
    pub fn to_setting(&self) -> String {
        match self {
            Self::Direct => SETTING_DIRECT.to_owned(),
            Self::Tor => SETTING_TOR.to_owned(),
            Self::Socks5 { host, port } => format!("{SETTING_SOCKS5_PREFIX}{host}:{port}"),
        }
    }

    /// Разбирает запись настройки.
    ///
    /// # Errors
    ///
    /// [`AegisError::Malformed`] — незнакомый режим либо адрес не проходит
    /// [`ProxyMode::validate`]. 🔐 Отказ, а не откат на прямое
    /// соединение: повреждённая запись «Tor» не должна молча
    /// превращаться в «напрямую».
    pub fn from_setting(value: &str) -> Result<Self> {
        match value {
            SETTING_DIRECT => Ok(Self::Direct),
            SETTING_TOR | SETTING_LEGACY_ORBOT => Ok(Self::Tor),
            other => {
                let address = other
                    .strip_prefix(SETTING_SOCKS5_PREFIX)
                    .ok_or(AegisError::Malformed)?;

                // Порт — после последнего двоеточия: у IPv6 их несколько.
                let (host, port) = address.rsplit_once(':').ok_or(AegisError::Malformed)?;
                let port = port.parse::<u16>().map_err(|_| AegisError::Malformed)?;

                let mode = Self::Socks5 {
                    host: host.to_owned(),
                    port,
                };
                mode.validate()?;

                Ok(mode)
            }
        }
    }
}

/// Проверяет хост прокси.
///
/// 🔐 Придирчиво по той же причине, что и ссылка на контакт: строка
/// попадает в транспорт, и всё, что не является ровно адресом, могло
/// бы означать больше, чем задумано, — схему, путь или учётные данные.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(AegisError::Malformed);
    }

    // IPv6 — единственная допустимая запись с двоеточием.
    if host.contains(':') {
        return host
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| AegisError::Malformed);
    }

    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }

    let labels: Vec<&str> = host.split('.').collect();

    // Все метки из цифр, но это не IPv4: «1.2.3.999» — опечатка
    // в адресе, а не имя хоста, и угадывать, что имелось в виду, нельзя.
    if labels
        .iter()
        .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(AegisError::Malformed);
    }

    for label in labels {
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');

        if !valid {
            return Err(AegisError::Malformed);
        }
    }

    Ok(())
}

/// Предел числа мостов.
pub const MAX_BRIDGES: usize = 16;

/// Предел длины строки моста.
const MAX_BRIDGE_LINE: usize = 1024;

/// Транспорт `WebTunnel`.
const WEBTUNNEL: &str = "webtunnel";

/// Проверяет и нормализует строку моста Tor.
///
/// Принимаются мосты, которые встроенный Tor умеет использовать:
/// `WebTunnel` (свой клиент в `aegis-tor`) и обычные мосты без транспорта.
/// Приставка `Bridge` снимается. Результат — строка в виде, который
/// разбирает Arti.
///
/// 🔐 Отпечаток моста (40 шестнадцатеричных знаков) обязателен: он
/// закрепляет identity моста, и без него подставной мост на том же
/// адресе прошёл бы незамеченным. Адрес `url=` — только `https`: снаружи
/// соединение с мостом должно выглядеть как обычный HTTPS.
///
/// # Errors
///
/// [`AegisError::Malformed`] — формат нарушен, транспорт не
/// поддерживается (obfs4, Snowflake и прочим нужен сторонний клиент)
/// или нет отпечатка.
pub fn normalize_bridge_line(line: &str) -> Result<String> {
    let line = line.trim();
    let line = line.strip_prefix("Bridge ").unwrap_or(line).trim();

    if line.is_empty()
        || line.len() > MAX_BRIDGE_LINE
        || !line.is_ascii()
        || line.chars().any(char::is_control)
    {
        return Err(AegisError::Malformed);
    }

    let words: Vec<&str> = line.split_whitespace().collect();
    let (webtunnel, rest) = match words.split_first() {
        Some((first, rest)) if *first == WEBTUNNEL => (true, rest),
        Some(_) => (false, words.as_slice()),
        None => return Err(AegisError::Malformed),
    };

    let (address, rest) = rest.split_first().ok_or(AegisError::Malformed)?;
    address
        .parse::<std::net::SocketAddr>()
        .map_err(|_| AegisError::Malformed)?;

    let (fingerprint, args) = rest.split_first().ok_or(AegisError::Malformed)?;
    if fingerprint.len() != 40 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AegisError::Malformed);
    }

    let mut url = None;
    for arg in args {
        let (key, value) = arg.split_once('=').ok_or(AegisError::Malformed)?;
        if key.is_empty() || value.is_empty() {
            return Err(AegisError::Malformed);
        }
        if key == "url" {
            url = Some(value);
        }
    }

    if webtunnel {
        let host = url
            .and_then(|url| url.strip_prefix("https://"))
            .and_then(|rest| rest.split('/').next())
            .ok_or(AegisError::Malformed)?;
        if host.is_empty() || host.contains('@') {
            return Err(AegisError::Malformed);
        }
    } else if !args.is_empty() {
        // У обычного моста аргументов нет.
        return Err(AegisError::Malformed);
    }

    Ok(words.join(" "))
}

/// Разбирает список мостов: по строке на мост, пустые строки
/// пропускаются, повторы убираются.
///
/// # Errors
///
/// [`AegisError::Malformed`] — хотя бы одна строка негодна или мостов
/// больше [`MAX_BRIDGES`]. 🔐 Весь список отвергается целиком: молча
/// выброшенный мост — это мост, на который человек рассчитывает.
pub fn parse_bridges(text: &str) -> Result<Vec<String>> {
    let mut bridges: Vec<String> = Vec::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let bridge = normalize_bridge_line(line)?;
        if !bridges.contains(&bridge) {
            bridges.push(bridge);
        }
    }

    if bridges.len() > MAX_BRIDGES {
        return Err(AegisError::Malformed);
    }

    Ok(bridges)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FPR: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn webtunnel_and_plain_bridges_are_accepted() {
        let webtunnel = format!(
            "Bridge webtunnel [2001:db8::1]:443 {FPR} url=https://b.example.org/p ver=0.0.1"
        );
        assert_eq!(
            normalize_bridge_line(&webtunnel).expect("webtunnel"),
            format!("webtunnel [2001:db8::1]:443 {FPR} url=https://b.example.org/p ver=0.0.1")
        );
        assert_eq!(
            normalize_bridge_line(&format!("  192.0.2.7:9001   {FPR} ")).expect("обычный"),
            format!("192.0.2.7:9001 {FPR}")
        );
    }

    /// 🔐 Без отпечатка мост не принимается; чужие транспорты — тоже.
    #[test]
    fn unsafe_or_unsupported_bridges_are_rejected() {
        for line in [
            "webtunnel [2001:db8::1]:443 url=https://b.example.org/p".to_owned(),
            format!("webtunnel [2001:db8::1]:443 {FPR} url=http://b.example.org/p"),
            format!("webtunnel [2001:db8::1]:443 {FPR}"),
            format!("webtunnel [2001:db8::1]:443 {FPR} url=https://u@b.example.org/p"),
            format!("obfs4 192.0.2.1:443 {FPR} cert=abc iat-mode=0"),
            format!("snowflake 192.0.2.3:80 {FPR} url=https://x/"),
            format!("192.0.2.7:9001 {FPR} extra=1"),
            format!("webtunnel host.example:443 {FPR} url=https://b/p"),
            format!("webtunnel [2001:db8::1]:443 {FPR} url=https://b/p\u{7}"),
            // meek через CDN слишком медленен для каталога Arti (см. aegis-tor).
            format!("meek_lite 192.0.2.20:80 {FPR} url=https://c.example.net front=f.example.org"),
            "192.0.2.7:9001 NOTHEX0123456789ABCDEF0123456789ABCDEF01".to_owned(),
            String::new(),
        ] {
            assert!(normalize_bridge_line(&line).is_err(), "принят {line:?}");
        }
    }

    #[test]
    fn a_bridge_list_is_all_or_nothing() {
        let good = format!("192.0.2.7:9001 {FPR}");
        let list = format!("\n{good}\n\nBridge {good}\n");
        assert_eq!(parse_bridges(&list).expect("список"), vec![good.clone()]);

        assert!(parse_bridges(&format!("{good}\nobfs4 192.0.2.1:1 {FPR} cert=x")).is_err());

        let many = (0..=MAX_BRIDGES)
            .map(|i| format!("192.0.2.{i}:9001 {FPR}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_bridges(&many).is_err());
    }

    fn socks(host: &str, port: u16) -> ProxyMode {
        ProxyMode::Socks5 {
            host: host.to_owned(),
            port,
        }
    }

    /// 🔐 Умолчание — Tor: сервер не видит адреса устройства.
    #[test]
    fn default_is_tor() {
        assert_eq!(ProxyMode::default(), ProxyMode::Tor);
        assert!(ProxyMode::default().hides_address());
        assert!(!ProxyMode::Direct.hides_address());
        assert_eq!(ProxyMode::Direct.endpoint(), None);
    }

    /// Встроенный Tor скрывает адрес, а порт моста — дело платформы.
    #[test]
    fn embedded_tor_hides_the_address() {
        assert_eq!(ProxyMode::Tor.endpoint(), None);
        assert!(ProxyMode::Tor.hides_address());
    }

    /// Прежняя запись «Tor через Orbot» читается как встроенный Tor:
    /// обновление не превращает выбор Tor в прямое соединение.
    #[test]
    fn the_old_orbot_setting_means_embedded_tor() {
        assert_eq!(
            ProxyMode::from_setting("orbot").expect("запись"),
            ProxyMode::Tor
        );
        assert_eq!(ProxyMode::Tor.to_setting(), "tor");
    }

    /// Запись настройки переживает хранение для каждого режима.
    #[test]
    fn settings_round_trip() {
        for mode in [
            ProxyMode::Direct,
            ProxyMode::Tor,
            socks("proxy.example.org", 1080),
            socks("10.0.0.1", 9050),
            socks("::1", 1080),
            socks("abcdefghijklmnop.onion", 9050),
        ] {
            let text = mode.to_setting();

            assert_eq!(
                ProxyMode::from_setting(&text).expect("запись разбирается"),
                mode,
                "запись {text:?} разобралась в другой режим"
            );
        }
    }

    /// 🔐 Всё, что не является ровно адресом, отвергается.
    ///
    /// Схема, путь и учётные данные в поле хоста означали бы больше,
    /// чем «вот адрес прокси», а учётные данные — ещё и обещание
    /// аутентификации, которой нет.
    #[test]
    fn smuggled_forms_are_rejected() {
        for host in [
            "socks5://proxy.example.org",
            "proxy.example.org/path",
            "user:pass@proxy.example.org",
            "user@proxy.example.org",
            "proxy example.org",
            " proxy.example.org",
            "",
            "-proxy.example.org",
            "proxy-.example.org",
            "proxy..example.org",
            "proxy.example.org.",
            "1.2.3.999",
            "[::1]",
            "прокси.рф",
        ] {
            assert!(
                socks(host, 1080).validate().is_err(),
                "принят хост {host:?}"
            );
        }
    }

    /// Нулевой порт отвергается.
    #[test]
    fn zero_port_is_rejected() {
        assert!(socks("proxy.example.org", 0).validate().is_err());
    }

    /// Слишком длинное имя и слишком длинная метка отвергаются.
    #[test]
    fn overlong_host_is_rejected() {
        let label = "a".repeat(MAX_LABEL_LEN);
        let long_host = [label.as_str(); 5].join(".");
        let long_label = format!("{}.org", "a".repeat(MAX_LABEL_LEN + 1));

        assert!(long_host.len() > MAX_HOST_LEN);
        assert!(socks(&long_host, 1080).validate().is_err());
        assert!(socks(&long_label, 1080).validate().is_err());
    }

    /// 🔐 Повреждённая запись не превращается в прямое соединение.
    #[test]
    fn corrupted_setting_does_not_fall_back_to_direct() {
        for value in [
            "",
            "TOR",
            "DIRECT",
            "socks5:",
            "socks5:host",
            "socks5:host:0",
            "socks5:host:99999",
            "socks5:host:port",
            "socks5:user@host:1080",
        ] {
            assert!(
                ProxyMode::from_setting(value).is_err(),
                "запись {value:?} принята"
            );
        }
    }
}
