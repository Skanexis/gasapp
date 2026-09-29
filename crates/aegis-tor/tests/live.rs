// SPDX-License-Identifier: Apache-2.0

//! Живая проверка встроенного Tor: настоящая сеть Tor, настоящий выход.
//!
//! Выключена по умолчанию — нужна сеть и минута на бутстрап:
//!
//! ```text
//! cargo test -p aegis-tor --test live -- --ignored --nocapture
//! ```

// Сбой вспомогательной функции — провал теста, а не отказ у пользователя.
#![allow(clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::{Duration, Instant};

use aegis_tor::{Allowlist, EmbeddedTor, TorSettings, TorStatus, Transport};

/// Разрешённое назначение: простой HTTP-сайт, чтобы не тащить TLS в тест.
const HOST: &str = "example.com";
const PORT: u16 = 80;

fn socks_connect(tor: &EmbeddedTor, host: &str) -> (TcpStream, u8) {
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, tor.port())).expect("мост");
    socket
        .set_read_timeout(Some(Duration::from_mins(3)))
        .expect("таймаут");

    // Приветствие с паролем моста (RFC 1929): без него мост не пускает.
    let (user, pass) = tor.socks_credentials();
    let mut hello = vec![5, 1, 2, 1, u8::try_from(user.len()).expect("длина")];
    hello.extend_from_slice(user.as_bytes());
    hello.push(u8::try_from(pass.len()).expect("длина"));
    hello.extend_from_slice(pass.as_bytes());
    socket.write_all(&hello).expect("приветствие");

    let mut granted = [0u8; 4];
    socket.read_exact(&mut granted).expect("ответ на пароль");
    assert_eq!(granted, [5, 2, 1, 0], "пароль моста не принят");

    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).expect("длина")];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&PORT.to_be_bytes());
    socket.write_all(&request).expect("запрос");

    let mut answer = [0u8; 10];
    socket.read_exact(&mut answer).expect("ответ");

    (socket, answer[1])
}

#[test]
#[ignore = "нужна сеть Tor"]
fn a_request_goes_through_real_tor_and_nothing_else_does() {
    // Журнал Arti — по RUST_LOG (например, RUST_LOG=info).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    let dir = tempfile::tempdir().expect("каталог");

    // Мосты — там, где Tor блокируют: AEGIS_TOR_BRIDGES — файл со
    // строками мостов, AEGIS_TOR_LYREBIRD — путь к lyrebird.
    let bridges: Vec<String> = std::env::var("AEGIS_TOR_BRIDGES")
        .map(|path| {
            std::fs::read_to_string(path)
                .expect("файл мостов")
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let transports = std::env::var("AEGIS_TOR_LYREBIRD")
        .map(|path| {
            vec![Transport::Managed {
                protocols: ["obfs4", "snowflake", "webtunnel", "meek_lite"]
                    .map(str::to_owned)
                    .to_vec(),
                path: path.into(),
                arguments: Vec::new(),
            }]
        })
        .unwrap_or_default();
    eprintln!("мостов: {}", bridges.len());
    let tor = EmbeddedTor::start(TorSettings {
        state_dir: dir.path().join("state"),
        cache_dir: dir.path().join("cache"),
        trusted_prefix: None,
        destinations: Allowlist::new([(HOST, PORT)]),
        bridges: bridges.clone(),
        transports,
        // Свой мост в Docker — на частном адресе.
        allow_private_bridges: std::env::var("AEGIS_TOR_ALLOW_PRIVATE").is_ok_and(|v| v == "1"),
    })
    .expect("запуск");

    // 🔐 Чужое назначение — отказ ещё до Tor.
    let (_, code) = socks_connect(&tor, "torproject.org");
    assert_eq!(code, 2, "мост пропустил чужое назначение");

    // Бутстрап: ход виден в выводе.
    let started = Instant::now();
    let mut last = None;
    while tor.status() != TorStatus::Ready && started.elapsed() < Duration::from_mins(3) {
        if last != Some(tor.status()) {
            last = Some(tor.status());
            eprintln!(
                "{:>5.1} с  {:?}",
                started.elapsed().as_secs_f32(),
                tor.status()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("бутстрап: {:?} за {:?}", tor.status(), started.elapsed());

    // Разрешённое назначение проходит.
    let started = Instant::now();
    let (mut socket, code) = socks_connect(&tor, HOST);
    assert_eq!(code, 0, "соединение через Tor не удалось");
    eprintln!("соединение через Tor: {:?}", started.elapsed());

    socket
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .expect("запрос");
    let mut response = Vec::new();
    let _ = socket.read_to_end(&mut response);
    assert!(response.starts_with(b"HTTP/1."), "ответ не HTTP");

    assert_eq!(tor.status(), TorStatus::Ready);
}

/// Соединение к серверу идёт на его onion-сервис, а не через выход.
///
/// `AEGIS_TOR_ONION=адрес.onion:порт` — onion-сервис, за которым
/// слушает что угодно по TCP (например, `server/deploy/onion`).
/// Проверяется, что встреча с onion-сервисом состоялась: мост ответил
/// успехом и дальше пошли байты.
#[test]
#[ignore = "нужна сеть Tor и свой onion-сервис"]
fn the_server_destination_reaches_its_onion_service() {
    let Ok(onion) = std::env::var("AEGIS_TOR_ONION") else {
        eprintln!("AEGIS_TOR_ONION не задан — пропуск");
        return;
    };
    let (onion_host, onion_port) = onion.rsplit_once(':').expect("адрес:порт");
    let onion_port: u16 = onion_port.parse().expect("порт");

    let dir = tempfile::tempdir().expect("каталог");
    let tor = EmbeddedTor::start(TorSettings {
        state_dir: dir.path().join("state"),
        cache_dir: dir.path().join("cache"),
        trusted_prefix: None,
        destinations: Allowlist::new([("aegis.test", PORT)])
            .via_onion("aegis.test", PORT, onion_host, onion_port)
            .expect("onion"),
        bridges: Vec::new(),
        transports: Vec::new(),
        allow_private_bridges: false,
    })
    .expect("запуск");

    let started = Instant::now();
    while tor.status() != TorStatus::Ready && started.elapsed() < Duration::from_mins(3) {
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("бутстрап: {:?} за {:?}", tor.status(), started.elapsed());

    let started = Instant::now();
    let (_socket, code) = socks_connect(&tor, "aegis.test");
    eprintln!("встреча с onion-сервисом: {:?}", started.elapsed());
    assert_eq!(code, 0, "onion-сервис сервера недостижим");
}
