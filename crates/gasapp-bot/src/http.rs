// SPDX-License-Identifier: Apache-2.0

//! Транспорт движка бота: HTTP/1.1 поверх TLS, одно соединение на запрос.
//!
//! В приложении запросы выполняет платформа (и ведёт их через Tor). У
//! бота платформы нет, поэтому транспорт свой — намеренно маленький:
//! запрос, `Connection: close`, ответ целиком.
//!
//! # 🔐 Что здесь проверяется и чего нет
//!
//! * Сертификат сервера проверяется по корням Mozilla (`webpki-roots`),
//!   имя — по адресу из настроек. Закрепления сертификата (pinning),
//!   как в приложении, нет.
//! * Открытый HTTP разрешён только к своей же машине (`localhost`,
//!   `127.0.0.1`, `::1`) — для разработки; иначе нужен явный флаг.
//! * ⚠️ **Tor здесь нет.** Сервер видит адрес машины, где работает бот.
//!   «Анонимные» запросы ядра (чтение открытого канала, поиск) идут с
//!   того же адреса, что и подписанные: для бота, чей аккаунт серверу и
//!   так известен, это осознанная цена простоты.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use gasapp_net::client::{HttpRequest, HttpResponse, Transport};
use gasapp_types::{GasAppError, Result};

/// Предел ответа: медиа канала — до 32 МБ, очередь сообщений — до ~51 МБ.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Предел заголовков ответа.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Сколько ждать соединения и ответа.
const TIMEOUT: Duration = Duration::from_mins(1);

/// Куда ходит бот.
#[derive(Clone)]
pub struct HttpTransport {
    host: String,
    port: u16,
    /// `None` — открытый HTTP (только своя машина либо явный флаг).
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl HttpTransport {
    /// Разбирает адрес сервера: `https://host[:port]` либо
    /// `http://host[:port]`.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — это не адрес сервера либо открытый
    /// HTTP к чужой машине без `allow_http`.
    pub fn new(base_url: &str, allow_http: bool) -> Result<Self> {
        let base_url = base_url.trim().trim_end_matches('/');

        let (secure, rest) = if let Some(rest) = base_url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = base_url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(GasAppError::Malformed);
        };

        // Путь, параметры и данные входа в адресе сервера не нужны.
        if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
            return Err(GasAppError::Malformed);
        }

        let (host, port) = split_host_port(rest, if secure { 443 } else { 80 })?;

        if !secure && !allow_http && !is_loopback(&host) {
            return Err(GasAppError::Malformed);
        }

        Ok(Self {
            host,
            port,
            tls: if secure { Some(tls_config()?) } else { None },
        })
    }

    fn connect(&self) -> Result<TcpStream> {
        let address = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| GasAppError::Network)?
            .next()
            .ok_or(GasAppError::Network)?;

        let stream =
            TcpStream::connect_timeout(&address, TIMEOUT).map_err(|_| GasAppError::Network)?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
            .map_err(|_| GasAppError::Network)?;

        Ok(stream)
    }

    fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>> {
        let mut tcp = self.connect()?;

        let Some(config) = &self.tls else {
            tcp.write_all(wire).map_err(|_| GasAppError::Network)?;

            return read_all(&mut tcp);
        };

        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| GasAppError::Malformed)?;
        let session = rustls::ClientConnection::new(Arc::clone(config), name)
            .map_err(|_| GasAppError::Network)?;
        let mut stream = rustls::StreamOwned::new(session, tcp);

        stream.write_all(wire).map_err(|_| GasAppError::Network)?;

        read_all(&mut stream)
    }
}

impl Transport for HttpTransport {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // 🔐 Путь собирает ядро, но в строку запроса он попадает как
        // есть: перевод строки в нём дописал бы серверу свои заголовки.
        if !request.path.starts_with('/') || request.path.contains(['\r', '\n', ' ']) {
            return Err(GasAppError::Malformed);
        }

        let body: &[u8] = match (&request.body, &request.binary_body) {
            (Some(text), _) => text.as_bytes(),
            (None, Some(bytes)) => bytes,
            (None, None) => &[],
        };
        let content_type = if request.binary_body.is_some() {
            "application/octet-stream"
        } else {
            "application/json"
        };

        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\n",
            request.method.as_str(),
            request.path,
            self.host,
            body.len(),
        );

        for (name, value) in &request.headers {
            if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
                return Err(GasAppError::Malformed);
            }

            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }

        head.push_str("\r\n");

        let mut wire = head.into_bytes();
        wire.extend_from_slice(body);

        let (status, payload) = parse_response(&self.exchange(&wire)?)?;

        // Медиа и вложения — байтами, всё прочее — текстом: решает путь
        // запроса, а не заголовок ответа (как в приложении).
        if binary_download(request) {
            Ok(HttpResponse {
                status,
                body: String::new(),
                binary_body: payload,
            })
        } else {
            Ok(HttpResponse {
                status,
                body: String::from_utf8(payload).map_err(|_| GasAppError::Malformed)?,
                binary_body: Vec::new(),
            })
        }
    }
}

/// Скачивание байтов: вложение переписки либо медиа канала.
fn binary_download(request: &HttpRequest) -> bool {
    if request.method.as_str() != "GET" {
        return false;
    }

    let path = request.path.split('?').next().unwrap_or_default();

    path.starts_with("/v1/attachments/")
        || (path.starts_with("/v1/channels/") && path.contains("/media/"))
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| GasAppError::Crypto)?
    .with_root_certificates(roots)
    .with_no_client_auth();

    Ok(Arc::new(config))
}

fn split_host_port(rest: &str, default_port: u16) -> Result<(String, u16)> {
    // IPv6 в квадратных скобках: `[::1]:8443`.
    if let Some(inner) = rest.strip_prefix('[') {
        let (host, tail) = inner.split_once(']').ok_or(GasAppError::Malformed)?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| GasAppError::Malformed)?,
            None if tail.is_empty() => default_port,
            None => return Err(GasAppError::Malformed),
        };

        return Ok((host.to_owned(), port));
    }

    match rest.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((
            host.to_owned(),
            port.parse().map_err(|_| GasAppError::Malformed)?,
        )),
        Some(_) => Err(GasAppError::Malformed),
        None => Ok((rest.to_owned(), default_port)),
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Читает ответ до закрытия соединения, но не больше предела.
fn read_all(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                raw.extend_from_slice(chunk.get(..read).ok_or(GasAppError::Network)?);

                if raw.len() > MAX_RESPONSE_BYTES {
                    return Err(GasAppError::Network);
                }
            }
            // Сервер закрыл TLS без `close_notify`: если ответ к этому
            // времени получен целиком, длина тела это покажет.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err(GasAppError::Network),
        }
    }

    Ok(raw)
}

/// Разбирает ответ HTTP/1.1: код и тело.
///
/// 🔐 Тело принимается только целиком: по `Content-Length` либо по
/// кускам (`chunked`) до завершающего. Оборванный ответ — сбой сети, а
/// не короткий ответ: иначе обрыв соединения выглядел бы как пустой
/// список записей или усечённый файл.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let head_end = find(raw, b"\r\n\r\n").ok_or(GasAppError::Network)?;

    if head_end > MAX_HEAD_BYTES {
        return Err(GasAppError::Network);
    }

    let head = std::str::from_utf8(raw.get(..head_end).ok_or(GasAppError::Network)?)
        .map_err(|_| GasAppError::Network)?;
    let body = raw
        .get(head_end.saturating_add(4)..)
        .ok_or(GasAppError::Network)?;

    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or(GasAppError::Network)?;

    let mut length: Option<usize> = None;
    let mut chunked = false;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();

        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse().map_err(|_| GasAppError::Network)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }

    if chunked {
        return Ok((status, decode_chunked(body)?));
    }

    match length {
        Some(length) => Ok((
            status,
            body.get(..length).ok_or(GasAppError::Network)?.to_vec(),
        )),
        // Без длины тело кончается с соединением; ответы без тела
        // (204, 304) так и приходят.
        None => Ok((status, body.to_vec())),
    }
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    loop {
        let line_end = find(rest, b"\r\n").ok_or(GasAppError::Network)?;
        let line = std::str::from_utf8(rest.get(..line_end).ok_or(GasAppError::Network)?)
            .map_err(|_| GasAppError::Network)?;
        // Расширения куска (`;имя=значение`) не нужны.
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| GasAppError::Network)?;

        rest = rest
            .get(line_end.saturating_add(2)..)
            .ok_or(GasAppError::Network)?;

        if size == 0 {
            return Ok(out);
        }

        out.extend_from_slice(rest.get(..size).ok_or(GasAppError::Network)?);

        if out.len() > MAX_RESPONSE_BYTES {
            return Err(GasAppError::Network);
        }

        // За куском — перевод строки.
        rest = rest
            .get(size.saturating_add(2)..)
            .ok_or(GasAppError::Network)?;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_are_parsed_strictly() {
        let https = HttpTransport::new("https://example.org/", false).unwrap();
        assert_eq!((https.host.as_str(), https.port), ("example.org", 443));
        assert!(https.tls.is_some());

        let local = HttpTransport::new("http://127.0.0.1:8443", false).unwrap();
        assert_eq!((local.host.as_str(), local.port), ("127.0.0.1", 8443));
        assert!(local.tls.is_none());

        let v6 = HttpTransport::new("http://[::1]:9000", false).unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("::1", 9000));

        // Открытый HTTP к чужой машине — только с явным разрешением.
        assert!(HttpTransport::new("http://example.org", false).is_err());
        assert!(HttpTransport::new("http://example.org", true).is_ok());

        for bad in [
            "example.org",
            "ftp://example.org",
            "https://",
            "https://example.org/api",
            "https://user@example.org",
            "https://example.org:port",
        ] {
            assert!(HttpTransport::new(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_response_with_a_length_is_read_exactly() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhello";
        assert_eq!(parse_response(raw).unwrap(), (200, b"hello".to_vec()));

        let empty = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(parse_response(empty).unwrap(), (204, Vec::new()));
    }

    #[test]
    fn a_truncated_response_is_a_network_failure() {
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nhello";
        assert!(parse_response(short).is_err());

        let headless = b"HTTP/1.1 200 OK\r\nContent-Length: 5";
        assert!(parse_response(headless).is_err());

        let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(parse_response(cut).is_err());
    }

    #[test]
    fn a_chunked_response_is_joined() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap(), (200, b"hello world".to_vec()));
    }

    #[test]
    fn media_is_read_as_bytes_and_the_rest_as_text() {
        let get = |path: &str| HttpRequest {
            method: gasapp_net::client::Method::Get,
            path: path.to_owned(),
            body: None,
            binary_body: None,
            headers: Vec::new(),
            anonymous: true,
        };

        assert!(binary_download(&get("/v1/attachments/blob/x")));
        assert!(binary_download(&get("/v1/channels/feed/a/media/b")));
        assert!(binary_download(&get("/v1/channels/reader/d/a/media/b")));
        assert!(!binary_download(&get("/v1/channels/feed/a/posts?limit=5")));
        assert!(!binary_download(&get("/v1/channels/feed/a")));
    }
}
