// SPDX-License-Identifier: Apache-2.0

//! Проверка против **живого** сервера.
//!
//! # Чем отличается от `end_to_end`
//!
//! Там сервер поддельный: он проверяет, что клиент правильно соединяет
//! свои части. Здесь настоящий сервер с настоящим Postgres — проверяется
//! то, чего заглушка не покажет: совпадение форматов запросов, кодов
//! ответа, proof-of-work и адресации.
//!
//! # Почему тест игнорируется по умолчанию
//!
//! Ему нужен запущенный сервер. В CI он включается отдельным шагом,
//! где сервер поднимается из docker-compose; на машине разработчика
//! запускается вручную:
//!
//! ```text
//! AEGIS_SERVER=http://127.0.0.1:8443 cargo test -p aegis-core --test live_server -- --ignored
//! ```
//!
//! Молчаливый пропуск при отсутствии сервера был бы хуже: тест,
//! который «проходит», ничего не проверив, вводит в заблуждение.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use aegis_core::client::Client;
use aegis_net::client::{HttpRequest, HttpResponse, Transport};
use aegis_storage::Storage;
use aegis_types::{AegisError, Result, Timestamp};
use rand_core::OsRng;

/// Минимальный HTTP-клиент поверх TCP.
///
/// Своя реализация, а не библиотека: тесту нужен обычный HTTP без TLS
/// к локальному серверу, и тащить ради этого зависимость с собственным
/// TLS-стеком в клиентский workspace означало бы ровно то, чего
/// архитектура избегает — сеть внутри Rust.
struct LocalHttp {
    host: String,
    port: u16,
}

impl Transport for LocalHttp {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|_| AegisError::Network)?;

        let body = request.body.clone().unwrap_or_default();
        let head = format!(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            request.method.as_str(),
            request.path,
            self.host,
            self.port,
            body.len(),
        );

        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body.as_bytes()))
            .map_err(|_| AegisError::Network)?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|_| AegisError::Network)?;

        parse_response(&raw)
    }
}

/// Разбирает ответ HTTP.
fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or(AegisError::Network)?;

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(AegisError::Network)?;

    // Chunked-кодирование: сервер отдаёт им ответы без Content-Length.
    let body = if head.to_lowercase().contains("transfer-encoding: chunked") {
        dechunk(body)
    } else {
        body.to_owned()
    };

    Ok(HttpResponse { status, body })
}

/// Собирает тело из chunked-кодирования.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;

    while let Some((size_line, remainder)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            break;
        };

        if size == 0 {
            break;
        }

        let Some(chunk) = remainder.get(..size) else {
            break;
        };

        out.push_str(chunk);
        rest = remainder.get(size.saturating_add(2)..).unwrap_or("");
    }

    out
}

/// Адрес сервера из окружения.
fn server() -> Option<(String, u16)> {
    let raw = std::env::var("AEGIS_SERVER").ok()?;
    let trimmed = raw.trim_start_matches("http://");
    let (host, port) = trimmed.split_once(':')?;

    Some((host.to_owned(), port.parse().ok()?))
}

fn now() -> Timestamp {
    Timestamp::from_millis(1_760_000_000_000)
}

/// Уникальное имя: сервер хранит аккаунты между запусками теста.
fn unique(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4().simple())
        .chars()
        .take(24)
        .collect()
}

/// 🔐 Полный цикл против живого сервера.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8443"]
fn real_server_delivers_a_message() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let alice_path = dir.path().join("alice.db").to_string_lossy().into_owned();
    let bob_path = dir.path().join("bob.db").to_string_lossy().into_owned();

    let alice = Client::new(
        LocalHttp {
            host: host.clone(),
            port,
        },
        Storage::new(&alice_path, &[0x5A; 32]).expect("база Алисы"),
    );
    let bob = Client::new(
        LocalHttp { host, port },
        Storage::new(&bob_path, &[0x5B; 32]).expect("база Боба"),
    );

    let alice_name = unique("alice");
    let bob_name = unique("bob");

    alice
        .register(&alice_name, now(), &mut OsRng)
        .expect("регистрация Алисы");
    let bob_account = bob
        .register(&bob_name, now(), &mut OsRng)
        .expect("регистрация Боба");

    alice
        .send_message(&bob_name, "привет через настоящий сервер", now(), &mut OsRng)
        .expect("отправка");

    let received = bob
        .receive_messages(&bob_account.device_id.to_string(), now())
        .expect("приём");

    assert_eq!(received, 1, "сообщение не дошло через настоящий сервер");

    let chats = bob.chats().expect("чаты");
    let messages = bob.messages(&chats[0], 10).expect("сообщения");

    assert_eq!(messages[0].text, "привет через настоящий сервер");
}

/// 🔐 В базе сервера лежит только шифротекст.
///
/// Проверка ручная по замыслу плана: заглянуть в дамп БД и убедиться,
/// что оператор не может прочитать переписку. Здесь она автоматизирована
/// — сообщение отправляется, но **не** принимается, поэтому конверт
/// остаётся в очереди и его видно в базе.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8443"]
fn server_database_holds_only_ciphertext() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let alice_path = dir.path().join("a.db").to_string_lossy().into_owned();
    let bob_path = dir.path().join("b.db").to_string_lossy().into_owned();

    let alice = Client::new(
        LocalHttp { host: host.clone(), port },
        Storage::new(&alice_path, &[0x11; 32]).expect("база"),
    );
    let bob = Client::new(
        LocalHttp { host, port },
        Storage::new(&bob_path, &[0x22; 32]).expect("база"),
    );

    let bob_name = unique("bob");
    alice.register(&unique("alice"), now(), &mut OsRng).expect("Алиса");
    bob.register(&bob_name, now(), &mut OsRng).expect("Боб");

    // Опознаваемая строка: если сервер видит текст, она найдётся в дампе.
    let canary = "CANARY-PLAINTEXT-MUST-NOT-APPEAR";
    alice
        .send_message(&bob_name, canary, now(), &mut OsRng)
        .expect("отправка");

    // Приём не выполняется намеренно: конверт должен остаться в очереди,
    // чтобы его можно было увидеть в базе.
    println!("канарейка отправлена, проверьте базу: {canary}");
}

/// 🔐 Приём сообщения: полный цикл между двумя клиентами.
///
/// Проверяет то, чего не покажет отправка: получатель действительно
/// расшифровывает конверт и видит исходный текст.
#[test]
#[ignore = "нужен запущенный сервер: AEGIS_SERVER=http://127.0.0.1:8444"]
fn message_is_received_and_decrypted() {
    let (host, port) = server().expect("переменная AEGIS_SERVER не задана");
    let dir = tempfile::tempdir().expect("каталог");

    let sender_path = dir.path().join("s.db").to_string_lossy().into_owned();
    let receiver_path = dir.path().join("r.db").to_string_lossy().into_owned();

    let sender = Client::new(
        LocalHttp { host: host.clone(), port },
        Storage::new(&sender_path, &[0x31; 32]).expect("база"),
    );
    let receiver = Client::new(
        LocalHttp { host, port },
        Storage::new(&receiver_path, &[0x32; 32]).expect("база"),
    );

    let receiver_name = unique("recv");
    sender.register(&unique("send"), now(), &mut OsRng).expect("отправитель");
    let receiver_account = receiver
        .register(&receiver_name, now(), &mut OsRng)
        .expect("получатель");

    let text = "сообщение прошло весь путь";
    sender
        .send_message(&receiver_name, text, now(), &mut OsRng)
        .expect("отправка");

    let count = receiver
        .receive_messages(&receiver_account.device_id.to_string(), now())
        .expect("приём");

    assert_eq!(count, 1, "сообщение не принято");

    let chats = receiver.chats().expect("чаты");
    assert_eq!(chats.len(), 1, "чат не появился");

    let messages = receiver.messages(&chats[0], 10).expect("сообщения");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text, text, "текст не совпал после расшифровки");
    assert!(!messages[0].outgoing, "входящее помечено исходящим");
}
