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
    /// Подключается через мосты.
    pub bridges: bool,
}

impl FfiTorStatus {
    const STOPPED: Self = Self {
        running: false,
        ready: false,
        percent: 0,
        stalled: false,
        port: 0,
        bridges: false,
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
            bridges: !tor.bridges().is_empty(),
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
            destinations: Allowlist::new([(settings.server_host, settings.server_port)]),
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
}
