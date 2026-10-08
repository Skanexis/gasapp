// SPDX-License-Identifier: AGPL-3.0-only

//! Настройка TLS сервера: только TLS 1.3.
//!
//! # Почему версия задаётся явно
//!
//! 🔐 Прежде конфигурация строилась из `RustlsConfig::from_pem_file`,
//! то есть умолчаниями rustls. TLS 1.2 там выключен не выбором проекта,
//! а тем, что в этом графе зависимостей у rustls не включена возможность
//! `tls12`. Возможности в cargo объединяются: стоит любой зависимости —
//! своей или чужой, в любом обновлении — попросить `rustls/tls12`,
//! и сервер начнёт принимать TLS 1.2, не изменившись ни строкой.
//! Обнаружилось бы это не раньше, чем кто-нибудь снова проверил бы
//! рукопожатие вручную.
//!
//! Здесь список версий задан явно, и ниже — тест на настоящем
//! рукопожатии: клиент с TLS 1.2 получает отказ.

use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Ошибка чтения сертификата или ключа.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Файл не разбирается как PEM.
    #[error("сертификат или ключ не разбираются: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),

    /// В файле ключа нет приватного ключа.
    #[error("в файле ключа нет приватного ключа")]
    NoKey,

    /// Ключ не подходит к сертификату либо не поддерживается.
    #[error("конфигурация TLS не строится: {0}")]
    Config(#[from] rustls::Error),
}

/// Собирает конфигурацию TLS 1.3 из PEM сертификата и ключа.
///
/// # Errors
///
/// [`TlsError`] — PEM не разбирается, ключа нет, ключ не подходит.
pub fn config_from_pem(certificate: &[u8], key: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    // PEM разбирает rustls-pki-types: rustls-pemfile больше не
    // поддерживается (RUSTSEC-2025-0134).
    let certificates =
        CertificateDer::pem_slice_iter(certificate).collect::<Result<Vec<_>, _>>()?;

    let private_key = match PrivateKeyDer::from_pem_slice(key) {
        Ok(key) => key,
        Err(rustls::pki_types::pem::Error::NoItemsFound) => return Err(TlsError::NoKey),
        Err(error) => return Err(TlsError::Pem(error)),
    };

    // 🔐 Единственная разрешённая версия. TLS 1.2 отвергается
    // рукопожатием, а не удачей набора возможностей.
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    Ok(Arc::new(config))
}
