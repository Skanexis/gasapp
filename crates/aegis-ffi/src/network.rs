// SPDX-License-Identifier: Apache-2.0

//! Граница FFI сетевых настроек и центра безопасности (M7).
//!
//! # Что здесь пересекает границу
//!
//! Режим выхода в сеть и результаты проверок. Прокси применяет
//! платформа (см. `aegis-net::proxy`): Rust сокетов не открывает,
//! и отдавать ему сеть значило бы обойти платформенный пиннинг.

use aegis_core::client::SecurityReport;
use aegis_net::proxy::ProxyMode;
use aegis_types::Timestamp;

use crate::messenger::Messenger;
use crate::{guard, FfiError};

/// Режим выхода в сеть.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiProxy {
    /// Напрямую: сервер видит IP-адрес.
    Direct,
    /// Через SOCKS5-прокси.
    Socks5 {
        /// Имя хоста или IP-адрес прокси.
        host: String,
        /// Порт прокси.
        port: u16,
    },
    /// Через Tor, встроенный в приложение.
    Tor,
}

impl From<ProxyMode> for FfiProxy {
    fn from(mode: ProxyMode) -> Self {
        match mode {
            ProxyMode::Direct => Self::Direct,
            ProxyMode::Socks5 { host, port } => Self::Socks5 { host, port },
            ProxyMode::Tor => Self::Tor,
        }
    }
}

impl From<FfiProxy> for ProxyMode {
    fn from(proxy: FfiProxy) -> Self {
        match proxy {
            FfiProxy::Direct => Self::Direct,
            FfiProxy::Socks5 { host, port } => Self::Socks5 { host, port },
            FfiProxy::Tor => Self::Tor,
        }
    }
}

/// Проверки центра безопасности, посчитанные ядром.
// Булевы поля — результаты независимых проверок, а не флаги одного
// состояния; см. `aegis_core::client::SecurityReport`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSecurityReport {
    /// Ключ восстановления создан.
    pub recovery_key_created: bool,
    /// Последняя резервная копия не старше недели.
    pub backup_recent: bool,
    /// Сколько контактов не сверены по safety number.
    pub unverified_contacts: u32,
    /// Sealed sender включён.
    pub sealed_sender_enabled: bool,
    /// IP-адрес скрыт прокси или Tor.
    pub address_hidden: bool,
    /// Сколько проверок ядра пройдено.
    pub passed: u32,
    /// Сколько проверок ядра всего.
    pub total: u32,
}

impl From<&SecurityReport> for FfiSecurityReport {
    fn from(report: &SecurityReport) -> Self {
        Self {
            recovery_key_created: report.recovery_key_created,
            backup_recent: report.backup_recent,
            unverified_contacts: report.unverified_contacts,
            sealed_sender_enabled: report.sealed_sender_enabled,
            address_hidden: report.address_hidden,
            passed: report.passed(),
            total: report.total(),
        }
    }
}

/// Допустим ли режим выхода в сеть.
///
/// Нужен экрану настройки: подсветить ошибку в адресе до сохранения,
/// а не после.
#[uniffi::export]
#[must_use]
pub fn validate_proxy(proxy: FfiProxy) -> bool {
    ProxyMode::from(proxy).validate().is_ok()
}

#[uniffi::export]
impl Messenger {
    /// Текущий режим выхода в сеть.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось либо запись повреждена.
    /// 🔐 Платформа при ошибке обязана закрыть сеть, а не открыть её:
    /// повреждённая запись «Tor» не должна превращаться в «напрямую».
    pub fn proxy(&self) -> Result<FfiProxy, FfiError> {
        let client = self.reader()?;

        guard(|| client.proxy_mode()).map(FfiProxy::from)
    }

    /// Сохраняет режим выхода в сеть.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — режим недопустим;
    /// [`FfiError::Core`] — запись не удалась.
    pub fn set_proxy(&self, proxy: FfiProxy) -> Result<(), FfiError> {
        let mode = ProxyMode::from(proxy);

        if mode.validate().is_err() {
            return Err(FfiError::InvalidArgument);
        }

        let client = self.client()?;

        guard(|| client.set_proxy_mode(&mode))
    }

    /// Мосты Tor; пусто — прямое подключение к сети Tor.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось либо запись повреждена.
    pub fn tor_bridges(&self) -> Result<Vec<String>, FfiError> {
        let client = self.reader()?;

        guard(|| client.tor_bridges())
    }

    /// Сохраняет мосты Tor (строка на мост) и возвращает их
    /// в нормальном виде. Пустой текст — без мостов.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidArgument`] — строка негодна (список
    /// отвергается целиком); [`FfiError::Core`] — запись не удалась.
    pub fn set_tor_bridges(&self, text: String) -> Result<Vec<String>, FfiError> {
        if aegis_net::proxy::parse_bridges(&text).is_err() {
            return Err(FfiError::InvalidArgument);
        }

        let client = self.client()?;

        guard(|| client.set_tor_bridges(&text))
    }

    /// Включён ли sealed sender.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось.
    pub fn sealed_sender_enabled(&self) -> Result<bool, FfiError> {
        let client = self.reader()?;

        guard(|| client.sealed_sender_enabled())
    }

    /// Проверки центра безопасности.
    ///
    /// # Errors
    ///
    /// [`FfiError::Core`] — чтение не удалось.
    pub fn security_report(&self, now_millis: i64) -> Result<FfiSecurityReport, FfiError> {
        let client = self.reader()?;

        let report = guard(|| client.security_report(Timestamp::from_millis(now_millis)))?;

        Ok(FfiSecurityReport::from(&report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Режим переживает переход через границу в обе стороны.
    #[test]
    fn proxy_crosses_the_boundary_unchanged() {
        for mode in [
            ProxyMode::Direct,
            ProxyMode::Tor,
            ProxyMode::Socks5 {
                host: "proxy.example.org".to_owned(),
                port: 1080,
            },
        ] {
            assert_eq!(ProxyMode::from(FfiProxy::from(mode.clone())), mode);
        }
    }

    /// Проверка режима повторяет проверку ядра.
    #[test]
    fn validation_matches_the_core() {
        assert!(validate_proxy(FfiProxy::Tor));
        assert!(validate_proxy(FfiProxy::Socks5 {
            host: "10.0.0.1".to_owned(),
            port: 9050,
        }));
        assert!(!validate_proxy(FfiProxy::Socks5 {
            host: "socks5://10.0.0.1".to_owned(),
            port: 9050,
        }));
        assert!(!validate_proxy(FfiProxy::Socks5 {
            host: "10.0.0.1".to_owned(),
            port: 0,
        }));
    }
}
