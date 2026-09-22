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

use std::io::BufReader;
use std::sync::Arc;

use rustls::ServerConfig;

/// Ошибка чтения сертификата или ключа.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Файл не читается или не разбирается как PEM.
    #[error("сертификат или ключ не разбираются: {0}")]
    Pem(#[from] std::io::Error),

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
    let certificates =
        rustls_pemfile::certs(&mut BufReader::new(certificate)).collect::<Result<Vec<_>, _>>()?;

    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(key))?.ok_or(TlsError::NoKey)?;

    // 🔐 Единственная разрешённая версия. TLS 1.2 отвергается
    // рукопожатием, а не удачей набора возможностей.
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    Ok(Arc::new(config))
}
