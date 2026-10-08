// SPDX-License-Identifier: Apache-2.0

//! meek — канал через CDN: снаружи это HTTPS-запросы к крупному сайту.
//!
//! # Зачем
//!
//! Через meek приложение спрашивает свежие мосты у moat ([`crate::moat`])
//! там, где сам bridges.torproject.org закрыт. Соединение открывается
//! с фронтом (например, `www.phpmyadmin.net`), а внутри TLS заголовок
//! `Host` ведёт к серверу meek на том же CDN. Чтобы закрыть этот канал,
//! цензору пришлось бы закрыть сам фронт.
//!
//! # Почему не транспорт для Tor
//!
//! Tor Project держит и мост meek, но через CDN один обмен — 0,5–1,5 с
//! и до 64 КиБ, то есть около 60 КБ/с. Arti даёт скачиванию объекта
//! каталога (консенсус — около мегабайта) 10 секунд на всё, и бутстрап
//! через meek не проходит (проверено: C tor с тем же мостом ждёт три
//! минуты, Arti — никогда). Трафик Tor несёт `WebTunnel`
//! ([`crate::webtunnel`]), а meek — только короткий запрос к moat.
//!
//! # Протокол (как `meek_lite` в lyrebird)
//!
//! 1. TCP и TLS до фронта; SNI и проверка сертификата — по фронту.
//! 2. `POST <путь из url>` с `Host: <узел из url>` и
//!    `X-Session-Id: <случайный идентификатор сессии>`; тело — наши
//!    байты (до 64 КиБ).
//! 3. Ответ `200` несёт байты от сервера. Пришли байты — следующий запрос
//!    сразу (у сервера, вероятно, есть ещё); ушли только наши — через
//!    100 мс; ничего — пауза растёт в полтора раза до 5 с.
//!
//! Запросы идут строго по одному: порядок байтов держит сервер по
//! идентификатору сессии.
//!
//! # Почему свой клиент
//!
//! Как и с `WebTunnel`: эталон на Go, на Android — только в lyrebird под
//! GPL-3.0 (ADR-005). Протокол — HTTP/1.1 поверх rustls.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream,
};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::webtunnel::{connect_public, split_host_port, TunnelError};

/// Предел тела запроса — как в эталоне.
const MAX_PAYLOAD: usize = 0x10000;

/// Предел тела ответа.
const MAX_BODY: usize = 1024 * 1024;

/// Предел строки заголовка ответа и всех заголовков вместе.
const MAX_HEAD: usize = 16 * 1024;

/// Первая пауза опроса; растёт в полтора раза до [`POLL_MAX`].
const POLL_FIRST: Duration = Duration::from_millis(100);

/// Предел паузы опроса.
const POLL_MAX: Duration = Duration::from_secs(5);

/// Сколько ждать соединения с фронтом или одного обмена.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_mins(1);

/// Куда и как ходить: разобранные URL сервера meek и фронт.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    /// Заголовок `Host`: узел (и порт) из URL.
    host: String,
    /// Узел, с которым открывается соединение и чьё имя в SNI.
    dial_host: String,
    port: u16,
    /// Путь с ведущей косой чертой.
    path: String,
}

impl Endpoint {
    /// Точка из URL сервера meek (только `https`) и необязательного фронта.
    pub(crate) fn new(url: &str, front: Option<&str>) -> Result<Self, TunnelError> {
        let rest = url.strip_prefix("https://").ok_or(TunnelError::Protocol)?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_host_port(authority, 443)?;

        if host.is_empty() || !path.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(TunnelError::Protocol);
        }
        if let Some(front) = front {
            let name = front
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
            if front.is_empty() || !name {
                return Err(TunnelError::Protocol);
            }
        }

        Ok(Self {
            host: authority.to_owned(),
            dial_host: front.unwrap_or(&host).to_owned(),
            port,
            path: format!("/{path}"),
        })
    }
}

/// TLS по корням `WebPKI` (данные Mozilla), HTTP/1.1.
///
/// Снаружи проверяется сертификат фронта; внутри канала moat — свой TLS
/// до bridges.torproject.org, тоже по корням `WebPKI`.
pub(crate) fn tls_config() -> Result<Arc<ClientConfig>, TunnelError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TunnelError::Protocol)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Соединение с фронтом: HTTP/1.1 с keep-alive.
type Connection = BufReader<TlsStream<TcpStream>>;

async fn dial(endpoint: &Endpoint) -> Result<Connection, TunnelError> {
    let tcp = connect_public(&endpoint.dial_host, endpoint.port, false).await?;
    let name =
        ServerName::try_from(endpoint.dial_host.clone()).map_err(|_| TunnelError::Protocol)?;
    let tls = TlsConnector::from(tls_config()?).connect(name, tcp).await?;

    Ok(BufReader::new(tls))
}

/// Пишет запрос `POST`.
pub(crate) async fn write_post<S: AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    use std::fmt::Write as _;

    // Как у net/http в эталонном клиенте.
    let mut head =
        format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());

    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Ответ HTTP.
#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    /// Соединение можно использовать дальше.
    pub(crate) keep_alive: bool,
}

/// Строка до `\n` включительно, в пределах бюджета.
async fn read_line<S: AsyncBufRead + Unpin>(
    stream: &mut S,
    budget: &mut usize,
) -> Result<Vec<u8>, TunnelError> {
    let mut line = Vec::new();
    let limit = u64::try_from(*budget).unwrap_or(u64::MAX);
    let read = (&mut *stream)
        .take(limit)
        .read_until(b'\n', &mut line)
        .await?;

    if read == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    if line.last() != Some(&b'\n') {
        return Err(TunnelError::Protocol);
    }
    *budget = budget.saturating_sub(read);

    Ok(line)
}

/// Читает ответ HTTP/1.1: `Content-Length`, `chunked` или до конца.
pub(crate) async fn read_response<S: AsyncBufRead + Unpin>(
    stream: &mut S,
    max_body: usize,
) -> Result<Response, TunnelError> {
    let mut budget = MAX_HEAD;

    let status_line = read_line(stream, &mut budget).await?;
    let status_line = std::str::from_utf8(&status_line).map_err(|_| TunnelError::Protocol)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or(TunnelError::Protocol)?;
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or(TunnelError::Protocol)?;
    if !version.starts_with("HTTP/1.") {
        return Err(TunnelError::Protocol);
    }

    let mut length = None;
    let mut chunked = false;
    let mut keep_alive = version == "HTTP/1.1";

    loop {
        let line = read_line(stream, &mut budget).await?;
        let line = std::str::from_utf8(&line).map_err(|_| TunnelError::Protocol)?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        let (name, value) = line.split_once(':').ok_or(TunnelError::Protocol)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse::<usize>().map_err(|_| TunnelError::Protocol)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        } else if name.eq_ignore_ascii_case("connection") {
            keep_alive = !value.eq_ignore_ascii_case("close");
        }
    }

    let mut body = Vec::new();

    if chunked {
        loop {
            let mut line_budget = MAX_HEAD;
            let line = read_line(stream, &mut line_budget).await?;
            let line = std::str::from_utf8(&line).map_err(|_| TunnelError::Protocol)?;
            let size = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size, 16).map_err(|_| TunnelError::Protocol)?;

            if size == 0 {
                // Завершающие заголовки — до пустой строки.
                while read_line(stream, &mut line_budget).await? != b"\r\n" {}
                break;
            }
            if body.len().saturating_add(size) > max_body {
                return Err(TunnelError::Protocol);
            }

            let mut chunk = vec![0u8; size];
            stream.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
            if read_line(stream, &mut line_budget).await? != b"\r\n" {
                return Err(TunnelError::Protocol);
            }
        }
    } else if let Some(length) = length {
        if length > max_body {
            return Err(TunnelError::Protocol);
        }
        body.resize(length, 0);
        stream.read_exact(&mut body).await?;
    } else if status != 204 && status != 304 {
        // Ни длины, ни кусков — тело до закрытия соединения.
        let limit = u64::try_from(max_body)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        (&mut *stream).take(limit).read_to_end(&mut body).await?;
        if body.len() > max_body {
            return Err(TunnelError::Protocol);
        }
        keep_alive = false;
    }

    Ok(Response {
        status,
        body,
        keep_alive,
    })
}

/// Сбой, после которого запрос стоит повторить на новом соединении:
/// фронт закрыл простаивавшее соединение keep-alive.
fn is_stale(error: &TunnelError) -> bool {
    matches!(
        error,
        TunnelError::Io(io) if matches!(
            io.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
        )
    )
}

/// Один обмен сессии: байты туда, байты обратно.
async fn round_trip(
    connection: &mut Option<Connection>,
    endpoint: &Endpoint,
    session: &str,
    payload: &[u8],
) -> Result<Vec<u8>, TunnelError> {
    for attempt in 0..2 {
        let reused = connection.is_some();
        let mut stream = match connection.take() {
            Some(stream) => stream,
            None => timeout(ROUND_TRIP_TIMEOUT, dial(endpoint))
                .await
                .map_err(|_| TunnelError::Refused)??,
        };

        let exchange = async {
            write_post(
                &mut stream,
                &endpoint.host,
                &endpoint.path,
                &[
                    ("X-Session-Id", session),
                    ("Content-Type", "application/octet-stream"),
                ],
                payload,
            )
            .await?;
            read_response(&mut stream, MAX_BODY).await
        };

        match timeout(ROUND_TRIP_TIMEOUT, exchange).await {
            Ok(Ok(response)) if response.status == 200 => {
                if response.keep_alive {
                    *connection = Some(stream);
                }
                return Ok(response.body);
            }
            Ok(Err(error)) if reused && attempt == 0 && is_stale(&error) => {}
            Ok(Err(error)) => return Err(error),
            Ok(Ok(_)) | Err(_) => return Err(TunnelError::Refused),
        }
    }

    Err(TunnelError::Refused)
}

/// Сессия: гоняет байты между `inner` и мостом, пока обе стороны живы.
async fn run(endpoint: Endpoint, first: Connection, mut inner: DuplexStream) {
    let session = crate::random_token();
    let mut connection = Some(first);
    let mut pause = POLL_FIRST;
    let mut buffer = vec![0u8; MAX_PAYLOAD];

    loop {
        let sent = match timeout(pause, inner.read(&mut buffer)).await {
            Ok(Ok(0) | Err(_)) => return,
            Ok(Ok(read)) => read,
            Err(_) => 0,
        };

        let Some(payload) = buffer.get(..sent) else {
            return;
        };
        let Ok(received) = round_trip(&mut connection, &endpoint, &session, payload).await else {
            tracing::debug!("meek: round trip failed");
            return;
        };

        if !received.is_empty() && inner.write_all(&received).await.is_err() {
            return;
        }

        pause = if !received.is_empty() {
            Duration::ZERO
        } else if sent > 0 {
            POLL_FIRST
        } else {
            pause.max(POLL_FIRST).mul_f32(1.5).min(POLL_MAX)
        };
    }
}

/// Открывает сессию meek и возвращает её как поток.
///
/// Соединение с фронтом устанавливается до возврата: недоступный фронт —
/// ошибка сразу, а не молчащий поток.
pub(crate) async fn connect(endpoint: Endpoint) -> Result<DuplexStream, TunnelError> {
    let first = timeout(ROUND_TRIP_TIMEOUT, dial(&endpoint))
        .await
        .map_err(|_| TunnelError::Refused)??;
    let (outer, inner) = tokio::io::duplex(MAX_PAYLOAD * 2);
    tokio::spawn(run(endpoint, first, inner));

    Ok(outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_dial_the_front_and_address_the_bridge() {
        let endpoint = Endpoint::new("https://123.cdn.example.net/m/", Some("www.example.org"))
            .expect("точка");

        assert_eq!(endpoint.dial_host, "www.example.org");
        assert_eq!(endpoint.host, "123.cdn.example.net");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/m/");

        let direct = Endpoint::new("https://meek.example.net:8443", None).expect("без фронта");
        assert_eq!(direct.dial_host, "meek.example.net");
        assert_eq!(direct.host, "meek.example.net:8443");
        assert_eq!((direct.port, direct.path.as_str()), (8443, "/"));

        for (url, front) in [
            ("http://c.example.net", None),
            ("https://u@c.example.net", None),
            ("https://c.example.net", Some("a/b")),
            ("https://c.example.net", Some("")),
            ("https://", Some("www.example.org")),
        ] {
            assert!(Endpoint::new(url, front).is_err(), "{url} {front:?}");
        }
    }

    /// Запрос — как у эталона: `Host` моста, идентификатор сессии, тело.
    #[tokio::test]
    async fn the_request_carries_the_session() {
        let mut written = Vec::new();
        write_post(
            &mut written,
            "123.cdn.example.net",
            "/",
            &[("X-Session-Id", "abc")],
            b"TOR",
        )
        .await
        .expect("запись");

        let text = String::from_utf8(written).expect("текст");
        assert!(text.starts_with("POST / HTTP/1.1\r\nHost: 123.cdn.example.net\r\n"));
        assert!(text.contains("X-Session-Id: abc\r\n"));
        assert!(text.ends_with("Content-Length: 3\r\n\r\nTOR"));
    }

    #[tokio::test]
    async fn responses_are_read_by_length_chunks_or_close() {
        let mut by_length: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcNEXT";
        let response = read_response(&mut by_length, MAX_BODY)
            .await
            .expect("длина");
        assert_eq!(
            (response.status, response.body.as_slice()),
            (200, &b"abc"[..])
        );
        assert!(response.keep_alive);
        assert_eq!(by_length, b"NEXT");

        let mut chunked: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                                   2\r\nab\r\n1;x=y\r\nc\r\n0\r\nTrailer: 1\r\n\r\n";
        let response = read_response(&mut chunked, MAX_BODY).await.expect("куски");
        assert_eq!(response.body, b"abc");
        assert!(chunked.is_empty());

        let mut closing: &[u8] = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc";
        let response = read_response(&mut closing, MAX_BODY)
            .await
            .expect("до конца");
        assert_eq!(response.body, b"abc");
        assert!(!response.keep_alive);
    }

    /// 🔐 Ответ больше предела не читается в память целиком.
    #[tokio::test]
    async fn oversized_or_broken_responses_are_refused() {
        let mut long: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n";
        assert!(read_response(&mut long, 10).await.is_err());

        let mut chunks: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\n";
        assert!(read_response(&mut chunks, 10).await.is_err());

        let mut garbage: &[u8] = b"SSH-2.0-OpenSSH\r\n\r\n";
        assert!(read_response(&mut garbage, MAX_BODY).await.is_err());

        let mut empty: &[u8] = b"";
        assert!(is_stale(
            &read_response(&mut empty, MAX_BODY)
                .await
                .expect_err("пусто")
        ));
    }
}
