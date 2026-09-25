// SPDX-License-Identifier: Apache-2.0

//! `WebTunnel` — мост Tor под видом обычного HTTPS-сайта.
//!
//! # Зачем
//!
//! Там, где Tor блокируют (Россия, Иран, Китай), прямые подключения
//! к узлам режут по отпечатку. `WebTunnel` прячет канал Tor в соединение
//! с обычным веб-сервером: снаружи это HTTPS к сайту, внутри — поток
//! Tor. Сейчас это один из транспортов, которые переживают такие
//! блокировки.
//!
//! # Почему свой клиент, а не готовый
//!
//! Эталонный клиент (Tor Project, MIT) написан на Go; на Android его
//! возят в `IPtProxy`, а там lyrebird под GPL-3.0 — лицензия, которую
//! политика проекта не допускает (ADR-005). Протокол же прост, и его
//! клиент умещается здесь: ни внешних бинарников, ни GPL.
//!
//! # Протокол (как в `webtunnel/main/client`)
//!
//! 1. TCP до хоста из `url=` (адреса — только публичные).
//! 2. TLS с SNI = `servername=` или хост из URL. Сертификат —
//!    по корням `WebPKI` либо, если задан `cert=`, по закреплённому
//!    хешу цепочки.
//! 3. `GET /<путь> HTTP/1.1` с `Connection: upgrade`, `Upgrade: websocket`.
//! 4. Ответ `101 Switching Protocols` — дальше соединение несёт поток
//!    Tor как есть, без кадрирования WebSocket.
//!
//! # 🔐 Ограничения
//!
//! Слушатель на 127.0.0.1 доступен всем приложениям устройства, поэтому
//! он соединяется только с URL из настроенных мостов ([`Targets`]):
//! иначе это был бы открытый HTTPS-туннель для кого угодно.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Имя транспорта в строке моста.
pub const TRANSPORT: &str = "webtunnel";

/// Сколько ждать рукопожатия с Arti.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Сколько ждать TCP, TLS и HTTP Upgrade вместе.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Предел заголовков ответа сервера.
const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Предел одновременных соединений (Arti держит к мосту одно-два).
const MAX_CONNECTIONS: usize = 16;

/// Версия SOCKS.
const SOCKS_VERSION: u8 = 5;
/// Способ «логин и пароль» (RFC 1929): в нём Arti передаёт аргументы моста.
const METHOD_USERNAME: u8 = 0x02;
/// Способ «без аутентификации».
const METHOD_NONE: u8 = 0x00;

/// Что достижимо через туннель: URL из строк мостов.
#[derive(Debug, Clone, Default)]
pub struct Targets {
    urls: HashSet<String>,
    /// Пускать ли к частным адресам — только для проверки на своём
    /// мосту в локальной сети; см. [`Targets::allow_private`].
    allow_private: bool,
}

impl Targets {
    /// Собирает URL из строк мостов (`webtunnel <адрес> [<отпечаток>] url=… …`).
    #[must_use]
    pub fn from_bridge_lines<S: AsRef<str>>(lines: &[S]) -> Self {
        let urls = lines
            .iter()
            .filter_map(|line| {
                let line = line.as_ref().trim();
                let line = line.strip_prefix("Bridge ").unwrap_or(line);
                let mut words = line.split_whitespace();

                (words.next() == Some(TRANSPORT)).then_some(words)
            })
            .flat_map(|words| {
                words
                    .filter_map(|word| word.strip_prefix("url="))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();

        Self {
            urls,
            allow_private: false,
        }
    }

    /// Нет ни одного моста `WebTunnel`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// ⚠️ Разрешает мосты на частных адресах. Только для проверки
    /// с мостом в локальной сети (Docker): у настоящих мостов адреса
    /// публичные, и эталонный клиент частные отбрасывает так же.
    #[must_use]
    pub fn allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    fn permits(&self, url: &str) -> bool {
        self.urls.contains(url)
    }
}

/// Разобранные аргументы моста.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    /// Исходный `url=` — по нему сверяется список.
    url: String,
    host: String,
    port: u16,
    /// Путь без ведущей косой черты.
    path: String,
    tls: bool,
    server_name: String,
    /// Закреплённый хеш цепочки сертификатов.
    pinned: Option<Vec<u8>>,
}

/// Почему соединение не состоялось.
#[derive(Debug, thiserror::Error)]
enum TunnelError {
    #[error("webtunnel i/o")]
    Io(#[from] std::io::Error),
    #[error("webtunnel protocol")]
    Protocol,
    #[error("webtunnel refused")]
    Refused,
}

/// Разбирает аргументы PT: `k=v;k2=v2`, `\` экранирует следующий символ
/// (pt-spec, раздел 3.5).
fn parse_args(text: &str) -> Result<Vec<(String, String)>, TunnelError> {
    let mut args = Vec::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut in_key = true;
    let mut chars = text.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let escaped = chars.next().ok_or(TunnelError::Protocol)?;
                if in_key {
                    key.push(escaped);
                } else {
                    value.push(escaped);
                }
            }
            '=' if in_key => in_key = false,
            ';' => {
                if in_key {
                    return Err(TunnelError::Protocol);
                }
                args.push((std::mem::take(&mut key), std::mem::take(&mut value)));
                in_key = true;
            }
            _ => {
                if in_key {
                    key.push(ch);
                } else {
                    value.push(ch);
                }
            }
        }
    }

    if !in_key {
        args.push((key, value));
    } else if !key.is_empty() {
        return Err(TunnelError::Protocol);
    }

    Ok(args)
}

impl Endpoint {
    fn from_args(args: &[(String, String)]) -> Result<Self, TunnelError> {
        let get = |name: &str| {
            args.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };

        let url = get("url").ok_or(TunnelError::Protocol)?;
        let (tls, rest, default_port) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest, 443)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest, 80)
        } else {
            return Err(TunnelError::Protocol);
        };

        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_host_port(authority, default_port)?;

        if host.is_empty() || !path.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(TunnelError::Protocol);
        }

        let pinned = get("cert")
            .map(|text| base64_decode(text).ok_or(TunnelError::Protocol))
            .transpose()?;

        Ok(Self {
            url: url.to_owned(),
            server_name: get("servername").unwrap_or(&host).to_owned(),
            host,
            port,
            path: path.to_owned(),
            tls,
            pinned,
        })
    }
}

/// Хост и порт из `authority` URL (IPv6 — в квадратных скобках).
fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), TunnelError> {
    if authority.contains('@') {
        return Err(TunnelError::Protocol);
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(TunnelError::Protocol)?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| TunnelError::Protocol)?,
            None if after.is_empty() => default_port,
            None => return Err(TunnelError::Protocol),
        };

        return Ok((host.to_owned(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((
            host.to_owned(),
            port.parse().map_err(|_| TunnelError::Protocol)?,
        )),
        None => Ok((authority.to_owned(), default_port)),
    }
}

/// Стандартный base64 (как `cert=` в эталонном клиенте).
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;

    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// Хеш цепочки как в эталоне: `h1 = SHA256(c1)`, `hN = SHA256(hN-1 ‖ SHA256(cN))`.
fn chain_hash(chain: &[&[u8]]) -> Option<[u8; 32]> {
    let mut hash: Option<[u8; 32]> = None;

    for cert in chain {
        let own: [u8; 32] = Sha256::digest(cert).into();
        hash = Some(match hash {
            None => own,
            Some(previous) => {
                let mut hasher = Sha256::new();
                hasher.update(previous);
                hasher.update(own);
                hasher.finalize().into()
            }
        });
    }

    hash
}

/// Проверка сертификата по закреплённому хешу цепочки (`cert=`).
///
/// Так же, как в эталоне: при закреплении обычная проверка по корням
/// не нужна — совпадение хеша сильнее. Подпись рукопожатия проверяется
/// всегда.
#[derive(Debug)]
struct PinnedChain {
    pin: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain: Vec<&[u8]> = std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(AsRef::as_ref))
            .collect();

        let matches = chain_hash(&chain).is_some_and(|hash| {
            // Сравнение без раннего выхода.
            hash.len() == self.pin.len()
                && hash
                    .iter()
                    .zip(&self.pin)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        });

        if matches {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "webtunnel: pinned chain mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Настройки TLS для точки.
fn tls_config(endpoint: &Endpoint) -> Result<ClientConfig, TunnelError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| TunnelError::Protocol)?;

    let mut config = if let Some(pin) = &endpoint.pinned {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedChain {
                pin: pin.clone(),
                provider,
            }))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    // Как у обычного браузерного HTTPS: HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// Только публичные адреса: мост не должен уводить в локальную сеть.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 — уникальные локальные, fe80::/10 — канальные.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// TCP до первой отвечающей публичной точки.
async fn connect_tcp(endpoint: &Endpoint, allow_private: bool) -> Result<TcpStream, TunnelError> {
    let addresses: Vec<SocketAddr> =
        tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
            .await?
            .filter(|address| allow_private || is_public(address.ip()))
            .collect();

    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            let _ = stream.set_nodelay(true);

            return Ok(stream);
        }
    }

    Err(TunnelError::Refused)
}

/// HTTP Upgrade; возвращает байты, пришедшие сразу за заголовками.
async fn upgrade<S>(stream: &mut S, endpoint: &Endpoint) -> Result<Vec<u8>, TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Порядок и набор заголовков — как у net/http в эталонном клиенте.
    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\n\
         Connection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        path = endpoint.path,
        host = endpoint.server_name,
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(TunnelError::Protocol);
        }
        head.extend_from_slice(chunk.get(..read).ok_or(TunnelError::Protocol)?);

        if let Some(position) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if head.len() > MAX_RESPONSE_HEAD {
            return Err(TunnelError::Protocol);
        }
    };

    let (headers, rest) = head.split_at(end);
    let leftover = rest.get(4..).unwrap_or_default().to_vec();
    let text = std::str::from_utf8(headers).map_err(|_| TunnelError::Protocol)?;
    let mut lines = text.split("\r\n");

    let status = lines.next().unwrap_or_default();
    let switching = status.starts_with("HTTP/1.1 101") || status.starts_with("HTTP/1.0 101");

    let header = |name: &str| {
        text.split("\r\n").skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_ascii_lowercase())
        })
    };

    if switching
        && header("upgrade").as_deref() == Some("websocket")
        && header("connection").as_deref() == Some("upgrade")
    {
        Ok(leftover)
    } else {
        Err(TunnelError::Refused)
    }
}

/// Поток до моста: TCP, при `https` — TLS, затем Upgrade.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

async fn dial(
    endpoint: &Endpoint,
    allow_private: bool,
) -> Result<(Box<dyn Stream>, Vec<u8>), TunnelError> {
    let tcp = connect_tcp(endpoint, allow_private).await?;

    if endpoint.tls {
        let name = ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| TunnelError::Protocol)?;
        let connector = TlsConnector::from(Arc::new(tls_config(endpoint)?));
        let mut tls = connector.connect(name, tcp).await?;
        let leftover = upgrade(&mut tls, endpoint).await?;

        Ok((Box::new(tls), leftover))
    } else {
        let mut tcp = tcp;
        let leftover = upgrade(&mut tcp, endpoint).await?;

        Ok((Box::new(tcp), leftover))
    }
}

/// Рукопожатие SOCKS5 со стороны PT: аргументы — в логине и пароле.
async fn accept_socks<S>(stream: &mut S) -> Result<Vec<(String, String)>, TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let [version, count] = greeting;
    if version != SOCKS_VERSION || count == 0 {
        return Err(TunnelError::Protocol);
    }

    let mut methods = vec![0u8; usize::from(count)];
    stream.read_exact(&mut methods).await?;

    let mut args_text = Vec::new();

    if methods.contains(&METHOD_USERNAME) {
        stream.write_all(&[SOCKS_VERSION, METHOD_USERNAME]).await?;

        // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD.
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        let [auth_version, user_len] = header;
        if auth_version != 1 {
            return Err(TunnelError::Protocol);
        }
        let mut user = vec![0u8; usize::from(user_len)];
        stream.read_exact(&mut user).await?;
        let mut pass_len = [0u8; 1];
        stream.read_exact(&mut pass_len).await?;
        let mut pass = vec![0u8; usize::from(pass_len[0])];
        stream.read_exact(&mut pass).await?;

        args_text.extend_from_slice(&user);
        // pt-spec: пароль из одного NUL — «аргументы уместились в логин».
        if pass != [0] {
            args_text.extend_from_slice(&pass);
        }

        stream.write_all(&[1, 0]).await?;
    } else if methods.contains(&METHOD_NONE) {
        stream.write_all(&[SOCKS_VERSION, METHOD_NONE]).await?;
    } else {
        stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        return Err(TunnelError::Refused);
    }

    // Запрос CONNECT: адрес назначения — условный адрес моста, он не нужен.
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let [version, command, _, address_type] = request;
    if version != SOCKS_VERSION || command != 1 {
        return Err(TunnelError::Protocol);
    }
    let skip = match address_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        _ => return Err(TunnelError::Protocol),
    };
    let mut rest = vec![0u8; skip.saturating_add(2)];
    stream.read_exact(&mut rest).await?;

    let text = String::from_utf8(args_text).map_err(|_| TunnelError::Protocol)?;

    parse_args(&text)
}

/// Ответ на CONNECT.
async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> std::io::Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await
}

/// Обслуживает одно соединение от Arti.
async fn handle(mut socket: TcpStream, targets: &Targets) {
    let Ok(Ok(args)) = timeout(HANDSHAKE_TIMEOUT, accept_socks(&mut socket)).await else {
        return;
    };

    let endpoint = match Endpoint::from_args(&args) {
        Ok(endpoint) if targets.permits(&endpoint.url) => endpoint,
        _ => {
            tracing::debug!("webtunnel: bridge refused");
            let _ = reply(&mut socket, 0x02).await;
            return;
        }
    };

    let Ok(Ok((mut upstream, leftover))) =
        timeout(DIAL_TIMEOUT, dial(&endpoint, targets.allow_private)).await
    else {
        tracing::debug!("webtunnel: bridge unreachable");
        let _ = reply(&mut socket, 0x04).await;
        return;
    };

    if reply(&mut socket, 0).await.is_err() {
        return;
    }
    if !leftover.is_empty() && socket.write_all(&leftover).await.is_err() {
        return;
    }

    let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
}

/// Принимает соединения от Arti, пока жив слушатель.
pub(crate) async fn serve(listener: TcpListener, targets: Arc<Targets>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        let targets = Arc::clone(&targets);

        tokio::spawn(async move {
            handle(socket, &targets).await;
            drop(slot);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 \
                        url=https://bridge.example.org/s3cr3t ver=0.0.1";

    #[test]
    fn urls_come_from_webtunnel_lines_only() {
        let targets = Targets::from_bridge_lines(&[
            LINE,
            "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x iat-mode=0",
            "Bridge webtunnel 192.0.2.3:1 url=https://other.example.net/p",
        ]);

        assert!(targets.permits("https://bridge.example.org/s3cr3t"));
        assert!(targets.permits("https://other.example.net/p"));
        assert!(!targets.permits("https://evil.example.com/"));
        assert!(Targets::from_bridge_lines(&["obfs4 1.2.3.4:5 cert=y"]).is_empty());
    }

    /// Разбор — зеркало кодирования в Arti (`encode_settings`).
    #[test]
    fn pt_args_are_unescaped() {
        let args = parse_args(r"url=https://h/p;ver=0.0.1;odd\=key=a\;b\\c").expect("разбор");

        assert_eq!(
            args,
            vec![
                ("url".to_owned(), "https://h/p".to_owned()),
                ("ver".to_owned(), "0.0.1".to_owned()),
                ("odd=key".to_owned(), r"a;b\c".to_owned()),
            ]
        );
        assert!(parse_args("novalue").is_err());
        assert!(parse_args(r"k=v\").is_err());
        assert!(parse_args("").expect("пусто").is_empty());
    }

    #[test]
    fn endpoints_are_parsed_like_the_reference_client() {
        let args =
            parse_args("url=https://bridge.example.org:8443/a/b;servername=front.example.com")
                .expect("разбор");
        let endpoint = Endpoint::from_args(&args).expect("точка");

        assert_eq!(endpoint.host, "bridge.example.org");
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.path, "a/b");
        assert!(endpoint.tls);
        assert_eq!(endpoint.server_name, "front.example.com");

        let v6 = Endpoint::from_args(&parse_args("url=http://[2001:db8::2]/x").expect("разбор"))
            .expect("v6");
        assert_eq!(
            (v6.host.as_str(), v6.port, v6.tls),
            ("2001:db8::2", 80, false)
        );

        for bad in [
            "url=ftp://h/p",
            "url=https://user@h/p",
            "url=https:///p",
            "ver=1",
        ] {
            let args = parse_args(bad).expect("разбор");
            assert!(Endpoint::from_args(&args).is_err(), "{bad}");
        }
    }

    /// Хеш цепочки совпадает с эталонным алгоритмом.
    #[test]
    fn chain_hash_matches_the_reference() {
        let first: [u8; 32] = Sha256::digest(b"leaf").into();
        assert_eq!(chain_hash(&[b"leaf"]), Some(first));

        let second: [u8; 32] = Sha256::digest(b"ca").into();
        let mut joined = first.to_vec();
        joined.extend_from_slice(&second);
        let expected: [u8; 32] = Sha256::digest(&joined).into();
        assert_eq!(chain_hash(&[b"leaf", b"ca"]), Some(expected));
        assert_eq!(chain_hash(&[]), None);
    }

    /// 🔐 Мост не уводит в локальную сеть.
    #[test]
    fn only_public_addresses_are_dialled() {
        for private in [
            "10.0.2.2",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "0.0.0.0",
        ] {
            assert!(!is_public(private.parse().expect("адрес")), "{private}");
        }
        for public in ["1.1.1.1", "2606:4700::1111"] {
            assert!(is_public(public.parse().expect("адрес")), "{public}");
        }
    }

    /// Ответ 101 с нужными заголовками принимается, остаток сохраняется.
    #[tokio::test]
    async fn the_upgrade_is_checked() {
        let endpoint =
            Endpoint::from_args(&parse_args("url=https://b.example.org/path").expect("разбор"))
                .expect("точка");

        let (mut client, mut server) = tokio::io::duplex(4096);
        let exchange = tokio::spawn(async move {
            let mut request = vec![0u8; 256];
            let read = server.read(&mut request).await.expect("запрос");
            let text = String::from_utf8_lossy(request.get(..read).expect("срез")).into_owned();
            server
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\nTOR")
                .await
                .expect("ответ");
            text
        });

        let leftover = upgrade(&mut client, &endpoint).await.expect("upgrade");
        let request = exchange.await.expect("сервер");

        assert!(request.starts_with("GET /path HTTP/1.1\r\nHost: b.example.org\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
        assert_eq!(leftover, b"TOR");

        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            let _ = server.read(&mut buffer).await;
            let _ = server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        assert!(matches!(
            upgrade(&mut client, &endpoint).await,
            Err(TunnelError::Refused)
        ));
    }

    /// Аргументы доходят через логин и пароль SOCKS, как их шлёт Arti.
    #[tokio::test]
    async fn arguments_arrive_through_socks_credentials() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let user = b"url=https://b.example.org/p;ver=0.0.1";

        let mut bytes = vec![5, 1, 2, 1, u8::try_from(user.len()).expect("длина")];
        bytes.extend_from_slice(user);
        bytes.extend_from_slice(&[1, 0]);
        bytes.extend_from_slice(&[5, 1, 0, 1, 192, 0, 2, 3, 0, 1]);
        client.write_all(&bytes).await.expect("запись");

        let args = accept_socks(&mut server).await.expect("рукопожатие");
        assert_eq!(
            args.first().map(|(k, v)| (k.as_str(), v.as_str())),
            Some(("url", "https://b.example.org/p"))
        );

        let mut answer = [0u8; 4];
        client.read_exact(&mut answer).await.expect("ответ");
        assert_eq!(answer, [5, 2, 1, 0]);
    }
}
