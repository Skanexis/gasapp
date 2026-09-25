// SPDX-License-Identifier: Apache-2.0

//! Серверная половина SOCKS5 (RFC 1928) — ровно столько, сколько нужно
//! платформенному транспорту.
//!
//! # Что принимается
//!
//! * Способ аутентификации — только «без аутентификации» (0x00):
//!   слушатель доступен лишь на 127.0.0.1, а назначение ограничено
//!   списком (см. [`Allowlist`]).
//! * Команда — только CONNECT. BIND и UDP ASSOCIATE отвергаются.
//! * Адрес — имя хоста, IPv4 или IPv6. 🔐 Имя хоста передаётся в Tor
//!   неразрешённым: DNS выполняет выходной узел, а не устройство.
//!
//! Всё прочее — отказ с кодом RFC 1928 и закрытие соединения.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Версия протокола SOCKS.
const VERSION: u8 = 5;

/// Способ «без аутентификации».
const METHOD_NONE: u8 = 0x00;

/// «Ни один предложенный способ не подходит».
const METHOD_UNACCEPTABLE: u8 = 0xFF;

/// Команда CONNECT.
const COMMAND_CONNECT: u8 = 0x01;

/// Тип адреса: IPv4.
const ATYP_IPV4: u8 = 0x01;
/// Тип адреса: имя хоста.
const ATYP_DOMAIN: u8 = 0x03;
/// Тип адреса: IPv6.
const ATYP_IPV6: u8 = 0x04;

/// Коды ответа (RFC 1928, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Reply {
    /// Соединение установлено.
    Succeeded = 0x00,
    /// Назначение запрещено правилами.
    NotAllowed = 0x02,
    /// Узел недоступен.
    HostUnreachable = 0x04,
    /// Команда не поддерживается.
    CommandNotSupported = 0x07,
    /// Тип адреса не поддерживается.
    AddressNotSupported = 0x08,
}

/// Назначение, запрошенное клиентом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// Имя хоста или IP-адрес в текстовом виде.
    pub host: String,
    /// Порт.
    pub port: u16,
}

/// Почему рукопожатие не состоялось.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HandshakeError {
    /// Сбой чтения или записи.
    #[error("socks i/o")]
    Io(#[from] std::io::Error),
    /// Клиент говорит не на SOCKS5 либо нарушил формат.
    #[error("socks protocol")]
    Protocol,
    /// Запрос отвергнут; ответ клиенту уже отправлен.
    #[error("socks request refused")]
    Refused,
}

/// Назначения, к которым мост пропускает.
///
/// 🔐 Мост слушает на 127.0.0.1, а локальный адрес на Android общий для
/// всех приложений устройства. Без списка любое приложение могло бы
/// ходить в Tor через AEGIS — и, хуже, пользоваться нашим бутстрапом
/// как своим. Со списком чужое приложение достигает только сервера
/// AEGIS, куда ему и так можно без нас.
#[derive(Debug, Clone)]
pub struct Allowlist {
    entries: Vec<(String, u16)>,
}

impl Allowlist {
    /// Список из пар «хост, порт». Хосты сравниваются без учёта регистра.
    #[must_use]
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (S, u16)>,
        S: AsRef<str>,
    {
        Self {
            entries: entries
                .into_iter()
                .map(|(host, port)| (normalize(host.as_ref()), port))
                .collect(),
        }
    }

    /// Пуст ли список: такой мост никого никуда не пустит.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Порты назначений — для заранее построенных цепочек.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.entries.iter().map(|(_, port)| *port).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Разрешено ли назначение.
    pub(crate) fn permits(&self, target: &Target) -> bool {
        let host = normalize(&target.host);

        self.entries
            .iter()
            .any(|(allowed, port)| *allowed == host && *port == target.port)
    }
}

/// Хост в сравнимом виде: нижний регистр, без завершающей точки
/// (`example.org.` и `example.org` — одно имя) и без скобок IPv6.
fn normalize(host: &str) -> String {
    host.trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// Проводит рукопожатие и возвращает назначение.
///
/// После успеха ответ клиенту ещё **не** отправлен: его отправляет
/// вызывающий через [`reply`], когда узнает, удалось ли соединиться.
///
/// # Errors
///
/// [`HandshakeError`] — сбой ввода-вывода, нарушение протокола либо
/// отказ (ответ с кодом отказа уже отправлен).
pub(crate) async fn handshake<S>(stream: &mut S) -> Result<Target, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Приветствие: VER, NMETHODS, METHODS.
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let [version, count] = greeting;

    if version != VERSION || count == 0 {
        return Err(HandshakeError::Protocol);
    }

    let mut methods = vec![0u8; usize::from(count)];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&METHOD_NONE) {
        stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;

        return Err(HandshakeError::Refused);
    }

    stream.write_all(&[VERSION, METHOD_NONE]).await?;

    // Запрос: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let [version, command, reserved, address_type] = header;

    if version != VERSION || reserved != 0 {
        return Err(HandshakeError::Protocol);
    }

    if command != COMMAND_CONNECT {
        reply(stream, Reply::CommandNotSupported).await?;

        return Err(HandshakeError::Refused);
    }

    let host = match address_type {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let [length] = length;

            if length == 0 {
                return Err(HandshakeError::Protocol);
            }

            let mut name = vec![0u8; usize::from(length)];
            stream.read_exact(&mut name).await?;

            // 🔐 Только печатный ASCII: имя уходит в Tor как есть,
            // и управляющим символам в нём делать нечего.
            if !name.iter().all(u8::is_ascii_graphic) {
                reply(stream, Reply::AddressNotSupported).await?;

                return Err(HandshakeError::Refused);
            }

            String::from_utf8(name).map_err(|_| HandshakeError::Protocol)?
        }
        _ => {
            reply(stream, Reply::AddressNotSupported).await?;

            return Err(HandshakeError::Refused);
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;

    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Отправляет ответ на запрос.
///
/// Адрес привязки — всегда нулевой: настоящий адрес выходного узла
/// клиенту не нужен, и выдавать его незачем.
pub(crate) async fn reply<S>(stream: &mut S, code: Reply) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, code as u8, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Прогоняет рукопожатие на заданных байтах клиента.
    async fn run(client_bytes: &[u8]) -> (Result<Target, HandshakeError>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(client_bytes).await.expect("запись");
        // Клиент больше не пишет: оборванный запрос — конец потока,
        // а не вечное ожидание.
        client.shutdown().await.expect("закрытие записи");

        let result = handshake(&mut server).await;
        drop(server);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.expect("чтение");

        (result, answer)
    }

    fn connect_domain(host: &str, port: u16) -> Vec<u8> {
        let mut bytes = vec![
            5,
            1,
            0,
            5,
            1,
            0,
            3,
            u8::try_from(host.len()).expect("длина"),
        ];
        bytes.extend_from_slice(host.as_bytes());
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes
    }

    /// Обычный запрос платформы: имя хоста, неразрешённое.
    #[tokio::test]
    async fn a_domain_connect_is_parsed() {
        let (result, answer) = run(&connect_domain("aegis.example.org", 443)).await;

        assert_eq!(
            result.expect("рукопожатие"),
            Target {
                host: "aegis.example.org".to_owned(),
                port: 443
            }
        );
        // Только выбор способа: ответ на запрос — после соединения.
        assert_eq!(answer, [5, 0]);
    }

    #[tokio::test]
    async fn ip_addresses_are_parsed() {
        let (result, _) = run(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 2, 2, 0x20, 0xFB]).await;
        assert_eq!(result.expect("IPv4").host, "10.0.2.2");

        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        let (result, _) = run(&v6).await;
        assert_eq!(result.expect("IPv6").host, "::1");
    }

    /// 🔐 Клиент, требующий пароль, получает отказ, а не молчаливое
    /// «без пароля».
    #[tokio::test]
    async fn only_no_authentication_is_offered() {
        let (result, answer) = run(&[5, 1, 2]).await;

        assert!(matches!(result, Err(HandshakeError::Refused)));
        assert_eq!(answer, [5, 0xFF]);
    }

    #[tokio::test]
    async fn bind_and_udp_are_refused() {
        for command in [2u8, 3] {
            let (result, answer) = run(&[5, 1, 0, 5, command, 0, 1, 1, 1, 1, 1, 0, 80]).await;

            assert!(matches!(result, Err(HandshakeError::Refused)));
            assert_eq!(answer, [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[tokio::test]
    async fn malformed_requests_are_rejected() {
        // SOCKS4.
        assert!(matches!(
            run(&[4, 1, 0, 80]).await.0,
            Err(HandshakeError::Protocol)
        ));
        // Ноль способов.
        assert!(matches!(
            run(&[5, 0]).await.0,
            Err(HandshakeError::Protocol)
        ));
        // Пустое имя.
        assert!(matches!(
            run(&[5, 1, 0, 5, 1, 0, 3, 0, 0, 80]).await.0,
            Err(HandshakeError::Protocol)
        ));
        // Неизвестный тип адреса.
        assert!(matches!(
            run(&[5, 1, 0, 5, 1, 0, 9]).await.0,
            Err(HandshakeError::Refused)
        ));
        // Оборванный запрос.
        assert!(matches!(
            run(&[5, 1, 0, 5, 1]).await.0,
            Err(HandshakeError::Io(_))
        ));
    }

    /// 🔐 Управляющие символы и пробелы в имени хоста не проходят.
    #[tokio::test]
    async fn host_names_must_be_printable() {
        for name in ["a b.org", "evil\n.org", "x\0y"] {
            let (result, _) = run(&connect_domain(name, 443)).await;
            assert!(matches!(result, Err(HandshakeError::Refused)), "{name:?}");
        }
    }

    /// 🔐 Мост пускает только туда, куда разрешено, — вплоть до порта.
    #[test]
    fn the_allowlist_is_exact() {
        let list = Allowlist::new([("Aegis.Example.org", 443), ("2001:db8::1", 8443)]);
        let target = |host: &str, port| Target {
            host: host.to_owned(),
            port,
        };

        assert!(list.permits(&target("aegis.example.org", 443)));
        assert!(list.permits(&target("AEGIS.example.org.", 443)));
        assert!(list.permits(&target("2001:db8::1", 8443)));

        assert!(!list.permits(&target("aegis.example.org", 80)));
        assert!(!list.permits(&target("evil.example.org", 443)));
        assert!(!list.permits(&target("aegis.example.org.evil.org", 443)));
        assert!(!Allowlist::new(Vec::<(String, u16)>::new().into_iter()).permits(&target("x", 1)));
    }

    #[tokio::test]
    async fn replies_carry_no_real_address() {
        let (mut client, mut server) = tokio::io::duplex(64);
        reply(&mut server, Reply::NotAllowed).await.expect("ответ");
        drop(server);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.expect("чтение");
        assert_eq!(answer, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
}
