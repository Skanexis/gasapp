// SPDX-License-Identifier: Apache-2.0

//! Локальный HTTP-интерфейс движка и веб-хуки.
//!
//! В Telegram бот ходит на сервер Telegram по HTTP, а сервер шлёт ему
//! события на веб-хук. В GasApp сервер содержимого не видит, поэтому и
//! то, и другое делает **движок на машине бота**:
//!
//! * `--listen 127.0.0.1:8081` — движок принимает команды по HTTP:
//!   `POST /sendMessage` с параметрами в теле JSON. `GET /getUpdates`
//!   отдаёт накопившиеся события.
//! * `--webhook https://…` — движок сам отправляет каждое событие
//!   `POST`-запросом на адрес программы бота.
//!
//! # 🔐 Кому открыт интерфейс
//!
//! Кто может слать движку команды, тот управляет ботом. Поэтому:
//!
//! * без `--secret` движок слушает только адрес своей машины;
//! * с `--secret` каждая команда обязана нести
//!   `Authorization: Bearer <секрет>`, а веб-хук получает его в
//!   заголовке `X-GasApp-Bot-Secret` — так программа бота отличает
//!   события движка от чужих запросов;
//! * сам интерфейс — открытый HTTP. Наружу его выставляют только за
//!   своим обратным прокси с TLS.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use gasapp_net::client::{HttpRequest, Method, Transport};
use gasapp_types::{GasAppError, Result};

use crate::http::HttpTransport;
use crate::runtime::MAX_COMMAND_BYTES;

/// Предел заголовков запроса к движку.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Сколько движок ждёт запрос целиком: он однопоточный, и медленный
/// клиент не должен останавливать обход сервера.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Запрос к движку.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// `GET` либо `POST`.
    pub method: String,
    /// Имя команды — путь без ведущей косой черты и без параметров.
    pub command: String,
    /// Секрет из `Authorization: Bearer …`, если прислан.
    pub bearer: Option<String>,
    /// Тело.
    pub body: Vec<u8>,
}

/// Разбирает запрос HTTP/1.1, прочитанный целиком.
///
/// # Errors
///
/// [`GasAppError::Malformed`] — это не запрос HTTP, тело длиннее
/// предела либо оборвано.
pub fn parse_request(raw: &[u8]) -> Result<ApiRequest> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(GasAppError::Malformed)?;
    let head = std::str::from_utf8(raw.get(..head_end).ok_or(GasAppError::Malformed)?)
        .map_err(|_| GasAppError::Malformed)?;
    let body = raw
        .get(head_end.saturating_add(4)..)
        .ok_or(GasAppError::Malformed)?;

    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().ok_or(GasAppError::Malformed)?.split(' ');
    let method = request_line.next().ok_or(GasAppError::Malformed)?;
    let target = request_line.next().ok_or(GasAppError::Malformed)?;

    let command = target
        .split('?')
        .next()
        .and_then(|path| path.strip_prefix('/'))
        .ok_or(GasAppError::Malformed)?;

    // Имя команды — буквы: всё прочее не команда, а попытка пройти
    // куда-то ещё.
    if command.is_empty() || !command.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(GasAppError::Malformed);
    }

    let mut length = 0usize;
    let mut bearer = None;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();

        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().map_err(|_| GasAppError::Malformed)?;
        } else if name.eq_ignore_ascii_case("authorization") {
            bearer = value.strip_prefix("Bearer ").map(str::to_owned);
        }
    }

    if length > MAX_COMMAND_BYTES {
        return Err(GasAppError::Malformed);
    }

    Ok(ApiRequest {
        method: method.to_owned(),
        command: command.to_owned(),
        bearer,
        body: body.get(..length).ok_or(GasAppError::Malformed)?.to_vec(),
    })
}

/// Читает запрос из соединения: заголовки, затем тело по длине.
///
/// # Errors
///
/// [`GasAppError::Network`] — соединение оборвалось либо клиент молчит;
/// [`GasAppError::Malformed`] — запрос больше предела либо не HTTP.
pub fn read_request(stream: &mut TcpStream) -> Result<ApiRequest> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(READ_TIMEOUT)))
        .map_err(|_| GasAppError::Network)?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8 * 1024];

    loop {
        // Запрос уже здесь целиком?
        match parse_request(&raw) {
            Ok(request) => return Ok(request),
            Err(_) if raw.len() > MAX_HEAD_BYTES.saturating_add(MAX_COMMAND_BYTES) => {
                return Err(GasAppError::Malformed);
            }
            Err(_) => {}
        }

        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(GasAppError::Network),
            Ok(read) => raw.extend_from_slice(chunk.get(..read).ok_or(GasAppError::Network)?),
        }
    }
}

/// Пишет ответ JSON и закрывает соединение.
pub fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    // Клиент мог уйти: ответ ему уже не нужен.
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush());
}

/// Сравнение секретов без раннего выхода: время ответа не должно
/// подсказывать, сколько первых знаков угадано.
#[must_use]
pub fn secrets_match(expected: &str, given: Option<&str>) -> bool {
    let Some(given) = given else {
        return false;
    };

    let mut difference = expected.len() ^ given.len();

    for (left, right) in expected.bytes().zip(given.bytes()) {
        difference |= usize::from(left ^ right);
    }

    difference == 0
}

/// Куда движок отправляет события.
pub struct Webhook {
    transport: HttpTransport,
    path: String,
    secret: Option<String>,
}

impl Webhook {
    /// Разбирает адрес веб-хука: `https://host[:port]/путь`. Открытый
    /// HTTP — только к своей машине либо с `allow_http`.
    ///
    /// # Errors
    ///
    /// [`GasAppError::Malformed`] — это не адрес веб-хука.
    pub fn new(url: &str, secret: Option<String>, allow_http: bool) -> Result<Self> {
        let url = url.trim();
        let scheme_end = url.find("://").ok_or(GasAppError::Malformed)?;
        let after_scheme = scheme_end.saturating_add(3);
        let path_start = url
            .get(after_scheme..)
            .and_then(|rest| rest.find('/'))
            .map(|offset| after_scheme.saturating_add(offset));

        let (base, path) = match path_start {
            Some(at) => url.split_at(at),
            None => (url, "/"),
        };

        if path.contains(['\r', '\n', ' ', '#']) {
            return Err(GasAppError::Malformed);
        }

        Ok(Self {
            transport: HttpTransport::new(base, allow_http)?,
            path: path.to_owned(),
            secret,
        })
    }

    /// Отправляет одно событие. `true` — программа бота его приняла
    /// (ответ `2xx`); иначе событие остаётся в очереди.
    #[must_use]
    pub fn deliver(&self, event: &str) -> bool {
        let headers = self
            .secret
            .iter()
            .map(|secret| ("X-GasApp-Bot-Secret".to_owned(), secret.clone()))
            .collect();

        self.transport
            .execute(&HttpRequest {
                method: Method::Post,
                path: self.path.clone(),
                body: Some(event.to_owned()),
                binary_body: None,
                headers,
                anonymous: false,
            })
            .is_ok_and(|response| (200..300).contains(&response.status))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_command_request_is_parsed() {
        let raw = b"POST /sendMessage?x=1 HTTP/1.1\r\nHost: localhost\r\n\
                    authorization: Bearer s3cret\r\nContent-Length: 9\r\n\r\n{\"a\": 1} trailing";
        let request = parse_request(raw).unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.command, "sendMessage");
        assert_eq!(request.bearer.as_deref(), Some("s3cret"));
        assert_eq!(request.body, b"{\"a\": 1} ");

        let get = parse_request(b"GET /getUpdates HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            (get.method.as_str(), get.command.as_str()),
            ("GET", "getUpdates")
        );
        assert!(get.body.is_empty() && get.bearer.is_none());
    }

    #[test]
    fn requests_that_are_not_commands_are_refused() {
        for bad in [
            &b"POST / HTTP/1.1\r\n\r\n"[..],
            b"POST /../etc/passwd HTTP/1.1\r\n\r\n",
            b"POST /send-message HTTP/1.1\r\n\r\n",
            b"POST /sendMessage HTTP/1.1\r\nContent-Length: 5\r\n\r\nabc",
            b"POST /sendMessage HTTP/1.1\r\nContent-Length: x\r\n\r\n",
            b"POST /sendMessage HTTP/1.1\r\n",
        ] {
            assert!(
                parse_request(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }

        let huge = format!(
            "POST /sendMessage HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_COMMAND_BYTES + 1
        );
        assert!(parse_request(huge.as_bytes()).is_err());
    }

    #[test]
    fn a_request_is_read_from_a_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .write_all(b"POST /getMe HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
                .unwrap();

            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            answer
        });

        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream).unwrap();
        assert_eq!(request.command, "getMe");

        write_response(&mut stream, 401, "{}");
        drop(stream);
        assert!(client
            .join()
            .unwrap()
            .starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn secrets_are_compared_in_full() {
        assert!(secrets_match("abc", Some("abc")));
        assert!(!secrets_match("abc", Some("abd")));
        assert!(!secrets_match("abc", Some("ab")));
        assert!(!secrets_match("abc", Some("abcd")));
        assert!(!secrets_match("abc", None));
    }

    #[test]
    fn webhook_addresses_are_parsed() {
        assert!(Webhook::new("http://127.0.0.1:9000/hook", None, false).is_ok());
        assert!(Webhook::new("https://bot.example/a/b?c=1", None, false).is_ok());
        assert!(Webhook::new("https://bot.example", None, false).is_ok());

        // Открытый HTTP к чужой машине — только с явным разрешением.
        assert!(Webhook::new("http://bot.example/hook", None, false).is_err());
        assert!(Webhook::new("http://bot.example/hook", None, true).is_ok());
        assert!(Webhook::new("bot.example/hook", None, true).is_err());
        assert!(Webhook::new("https://bot.example/a b", None, true).is_err());
    }
}
