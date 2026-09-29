// SPDX-License-Identifier: Apache-2.0

//! Встроенный Tor на границе FFI (`aegis-tor`, раздел 23.18).
//!
//! Один экземпляр на процесс: мост и охранные узлы Tor — общие для
//! всех соединений приложения. Платформа запускает его до первого
//! сетевого запроса и направляет сеть на порт моста — как прежде на
//! Orbot, только без Orbot.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Mutex;

use aegis_tor::{Allowlist, EmbeddedTor, TorError, TorSettings, TorStatus};
use aegis_types::AegisError;

use crate::FfiError;

/// Запущенный Tor процесса.
static TOR: Mutex<Option<EmbeddedTor>> = Mutex::new(None);

/// Что нужно встроенному Tor от платформы.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiTorSettings {
    /// Каталог состояния (охранные узлы): должен переживать перезапуск.
    pub state_dir: String,
    /// Каталог кеша (консенсус Tor).
    pub cache_dir: String,
    /// Каталог, который вместе с предками проверка прав Arti пропускает:
    /// системные каталоги приложения на Android открыты группе
    /// приложения. Всё внутри него проверяется.
    pub trusted_prefix: Option<String>,
    /// 🔐 Хост сервера AEGIS — единственное назначение моста.
    pub server_host: String,
    /// Порт сервера AEGIS.
    pub server_port: u16,
    /// Мосты Tor (как их возвращает `Messenger::tor_bridges`); пусто —
    /// прямое подключение к сети Tor.
    pub bridges: Vec<String>,
    /// Onion-сервис сервера, `адрес.onion:порт`, если сборка его знает.
    ///
    /// Соединения к серверу мост ведёт туда, а не через выходной узел:
    /// TLS и пиннинг платформы — прежние (см. `Allowlist::via_onion`).
    /// 🔐 Задаётся сборкой приложения, не сервером.
    pub server_onion: Option<String>,
}

/// Состояние встроенного Tor.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiTorStatus {
    /// Запущен ли вообще.
    pub running: bool,
    /// Готов пропускать соединения.
    pub ready: bool,
    /// Готовность подключения, 0–100.
    pub percent: u8,
    /// Подключение застряло: нет сети, сбиты часы или Tor заблокирован.
    pub stalled: bool,
    /// Порт моста на 127.0.0.1; 0 — не запущен.
    pub port: u16,
    /// Порт для анонимных запросов: каждое соединение — своя цепочка
    /// Tor; 0 — не запущен.
    pub isolated_port: u16,
    /// Подключается через мосты.
    pub bridges: bool,
    /// 🔐 Логин SOCKS5 моста — случайный на запуск; без него мост
    /// не пускает (порт на 127.0.0.1 виден всем приложениям).
    pub socks_username: String,
    /// Пароль SOCKS5 моста.
    pub socks_password: String,
}

impl FfiTorStatus {
    const STOPPED: Self = Self {
        running: false,
        ready: false,
        percent: 0,
        stalled: false,
        port: 0,
        isolated_port: 0,
        bridges: false,
        socks_username: String::new(),
        socks_password: String::new(),
    };

    fn of(tor: &EmbeddedTor) -> Self {
        let (ready, percent, stalled) = match tor.status() {
            TorStatus::Ready => (true, 100, false),
            TorStatus::Starting { percent, stalled } => (false, percent, stalled),
        };

        Self {
            running: true,
            ready,
            percent,
            stalled,
            port: tor.port(),
            isolated_port: tor.isolated_port(),
            bridges: !tor.bridges().is_empty(),
            socks_username: tor.socks_credentials().0.to_owned(),
            socks_password: tor.socks_credentials().1.to_owned(),
        }
    }
}

/// Запускает встроенный Tor и возвращает порт моста на 127.0.0.1.
///
/// Повторный вызов с теми же мостами возвращает порт уже запущенного:
/// мост один на процесс. С другими мостами прежний Tor останавливается
/// и запускается заново — порт может смениться.
///
/// # Errors
///
/// * [`FfiError::InvalidArgument`] — пустой хост или нулевой порт;
/// * [`FfiError::Core`] — каталоги непригодны
///   ([`AegisError::Storage`]) либо не поднялся рантайм
///   ([`AegisError::Network`]).
#[uniffi::export]
pub fn start_embedded_tor(settings: FfiTorSettings) -> Result<u16, FfiError> {
    if settings.server_host.trim().is_empty() || settings.server_port == 0 {
        return Err(FfiError::InvalidArgument);
    }

    // Onion-сервис сервера — проверяется до запуска: опечатка в адресе
    // увела бы всё соединение в никуда.
    let mut destinations = Allowlist::new([(settings.server_host.as_str(), settings.server_port)]);
    if let Some(onion) = settings.server_onion.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
        let (host, port) = onion
            .rsplit_once(':')
            .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
            .ok_or(FfiError::InvalidArgument)?;

        destinations = destinations
            .via_onion(&settings.server_host, settings.server_port, host, port)
            .map_err(|_| FfiError::InvalidArgument)?;
    }

    // 🔐 Та же проверка, что при сохранении: отпечаток обязателен,
    // транспорт — только поддерживаемый.
    let bridges = settings
        .bridges
        .iter()
        .map(|line| aegis_net::proxy::normalize_bridge_line(line))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FfiError::InvalidArgument)?;

    catch_unwind(AssertUnwindSafe(|| {
        let mut slot = TOR.lock().map_err(|_| FfiError::Panic)?;

        if let Some(tor) = slot.as_ref() {
            if tor.bridges() == bridges.as_slice() {
                return Ok(tor.port());
            }
        }

        // Другие мосты — прежний Tor останавливается до запуска нового:
        // каталог состояния один, и Arti держит на нём блокировку.
        *slot = None;

        let tor = EmbeddedTor::start(TorSettings {
            state_dir: PathBuf::from(settings.state_dir),
            cache_dir: PathBuf::from(settings.cache_dir),
            trusted_prefix: settings.trusted_prefix.map(PathBuf::from),
            destinations,
            bridges,
            transports: Vec::new(),
            allow_private_bridges: false,
        })
        .map_err(|error| match error {
            TorError::NoDestinations => FfiError::InvalidArgument,
            TorError::Config => FfiError::Core(AegisError::Storage),
            TorError::Runtime => FfiError::Core(AegisError::Network),
        })?;

        let port = tor.port();
        *slot = Some(tor);

        Ok(port)
    }))
    .unwrap_or(Err(FfiError::Panic))
}

/// Останавливает встроенный Tor (например, при выборе прямого
/// соединения или SOCKS5): незачем держать цепочки, которыми никто
/// не пользуется.
#[uniffi::export]
pub fn stop_embedded_tor() {
    let _ = catch_unwind(|| {
        if let Ok(mut slot) = TOR.lock() {
            *slot = None;
        }
    });
}

/// Допустимы ли строки мостов (строка на мост) — для подсветки ошибки
/// до сохранения.
#[uniffi::export]
#[must_use]
pub fn validate_tor_bridges(text: String) -> bool {
    aegis_net::proxy::parse_bridges(&text).is_ok()
}

/// Состояние встроенного Tor — для индикатора подключения.
#[uniffi::export]
#[must_use]
pub fn embedded_tor_status() -> FfiTorStatus {
    TOR.lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(FfiTorStatus::of))
        .unwrap_or(FfiTorStatus::STOPPED)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(dir: &std::path::Path, host: &str, port: u16) -> FfiTorSettings {
        FfiTorSettings {
            state_dir: dir.join("state").to_string_lossy().into_owned(),
            cache_dir: dir.join("cache").to_string_lossy().into_owned(),
            trusted_prefix: None,
            server_host: host.to_owned(),
            server_port: port,
            bridges: Vec::new(),
            server_onion: None,
        }
    }

    /// 🔐 Без назначения мост не запускается.
    #[test]
    fn a_bridge_needs_a_server() {
        // Отказ — до любого обращения к каталогам.
        let dir = std::env::temp_dir();

        assert!(matches!(
            start_embedded_tor(settings(&dir, " ", 443)),
            Err(FfiError::InvalidArgument)
        ));
        assert!(matches!(
            start_embedded_tor(settings(&dir, "aegis.example.org", 0)),
            Err(FfiError::InvalidArgument)
        ));
    }

    /// 🔐 Опечатка в onion-адресе сервера — отказ до запуска, а не Tor,
    /// который ведёт все соединения в никуда.
    #[test]
    fn a_bad_server_onion_is_refused_before_start() {
        let dir = std::env::temp_dir();

        for onion in ["notanonion:443", "abc.onion", "abc.onion:x", "abc.onion:443"] {
            let mut bad = settings(&dir, "aegis.example.org", 443);
            bad.server_onion = Some(onion.to_owned());

            assert!(
                matches!(start_embedded_tor(bad), Err(FfiError::InvalidArgument)),
                "принят onion {onion:?}"
            );
        }
    }
}
