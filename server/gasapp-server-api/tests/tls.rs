// SPDX-License-Identifier: AGPL-3.0-only

//! 🔐 Сервер принимает только TLS 1.3 — проверено рукопожатием.
//!
//! Версия TLS задаётся в коде явно (`tls::config_from_pem`), но
//! утверждение «TLS 1.2 не принимается» проверяется не чтением
//! конфигурации, а настоящим рукопожатием: клиент с TLS 1.2 получает
//! отказ, клиент с TLS 1.3 — соединение.
//!
//! Прежде версия зависела от набора возможностей rustls в графе
//! зависимостей. Возможности в cargo объединяются: `rustls/tls12`,
//! включённая любой зависимостью, вернула бы TLS 1.2 молча.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Самоподписанный сертификат для проверки: PEM сертификата и ключа.
fn self_signed() -> (Vec<u8>, Vec<u8>) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("сертификат создаётся");

    (
        certificate.cert.pem().into_bytes(),
        certificate.key_pair.serialize_pem().into_bytes(),
    )
}

/// Клиент, доверяющий этому сертификату и говорящий только на `versions`.
fn client(
    certificate: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();

    for entry in
        <rustls::pki_types::CertificateDer<'_> as rustls::pki_types::pem::PemObject>::pem_slice_iter(
            certificate,
        )
    {
        roots
            .add(entry.expect("сертификат разбирается"))
            .expect("корень добавляется");
    }

    let config = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

/// Поднимает слушатель с серверной конфигурацией проекта и принимает
/// одно соединение.
async fn serve_once(certificate: Vec<u8>, key: Vec<u8>) -> u16 {
    let config = gasapp_server_api::tls::config_from_pem(&certificate, &key)
        .expect("конфигурация TLS строится");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("слушатель");
    let port = listener.local_addr().expect("адрес").port();
    let acceptor = TlsAcceptor::from(config);

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = tls.write_all(b"ok").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    port
}

async fn handshake(
    port: u16,
    connector: TlsConnector,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = ServerName::try_from("localhost")?.to_owned();

    connector.connect(name, stream).await?;

    Ok(())
}

#[tokio::test]
async fn tls13_connects_and_tls12_is_refused() {
    let (certificate, key) = self_signed();
    let port = serve_once(certificate.clone(), key).await;

    handshake(port, client(&certificate, &[&rustls::version::TLS13]))
        .await
        .expect("TLS 1.3 обязан соединяться");

    let refused = handshake(port, client(&certificate, &[&rustls::version::TLS12])).await;

    assert!(
        refused.is_err(),
        "сервер принял TLS 1.2: {:?}",
        refused.map(|()| "соединение установлено"),
    );
}
