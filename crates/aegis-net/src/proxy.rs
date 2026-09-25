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

#[cfg(test)]
mod tests {
    use super::*;

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
