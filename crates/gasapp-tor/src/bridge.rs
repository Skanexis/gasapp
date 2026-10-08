// SPDX-License-Identifier: Apache-2.0

//! Мост: локальный SOCKS5-слушатель → соединение через Tor.
//!
//! Отделён от Arti через [`Connector`], чтобы разбор, список назначений
//! и пересылку можно было проверить без сети Tor.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::socks::{self, Allowlist, Credentials, Reply, Target};

/// Сколько ждать рукопожатия SOCKS. Локальный клиент отвечает мгновенно;
/// молчащий дольше держит место зря.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Предел одновременных рукопожатий. Отдельный от слотов соединений:
/// 🔐 чужое приложение без пароля дальше рукопожатия не проходит,
/// и слоты, нужные мессенджеру, ему не достаются.
const MAX_HANDSHAKES: usize = 64;

/// Сколько ждать соединения через Tor. С запасом на первый бутстрап:
/// соединение, пришедшее до готовности, ждёт его, а не падает.
const CONNECT_TIMEOUT: Duration = Duration::from_mins(2);

/// Предел одновременных соединений. Приложению хватает нескольких
/// (HTTP и сокет уведомлений); предел не даёт чужому приложению
/// на устройстве истощить мост.
const MAX_CONNECTIONS: usize = 32;

/// Способ открыть поток до назначения.
pub(crate) trait Connector: Send + Sync + 'static {
    /// Открытый поток.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Открывает поток до `target`.
    fn connect(&self, target: &Target) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Принимает соединения, пока жив слушатель.
pub(crate) async fn serve<C: Connector>(
    listener: TcpListener,
    connector: Arc<C>,
    allow: Arc<Allowlist>,
    credentials: Option<Arc<Credentials>>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            // Временная нехватка дескрипторов и подобное: не повод
            // гасить мост, но и крутиться вхолостую незачем.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };

        // Нет места для рукопожатия — соединение закрывается сразу.
        let Ok(pending) = Arc::clone(&handshakes).try_acquire_owned() else {
            continue;
        };

        let connector = Arc::clone(&connector);
        let allow = Arc::clone(&allow);
        let credentials = credentials.clone();
        let slots = Arc::clone(&slots);

        tokio::spawn(async move {
            handle(
                socket,
                connector.as_ref(),
                &allow,
                credentials.as_deref(),
                pending,
                &slots,
            )
            .await;
        });
    }
}

/// Обслуживает одно соединение.
async fn handle<C: Connector>(
    mut socket: TcpStream,
    connector: &C,
    allow: &Allowlist,
    credentials: Option<&Credentials>,
    pending: tokio::sync::OwnedSemaphorePermit,
    slots: &Arc<Semaphore>,
) {
    let _ = socket.set_nodelay(true);

    let Ok(Ok(target)) = timeout(
        HANDSHAKE_TIMEOUT,
        socks::handshake(&mut socket, credentials),
    )
    .await
    else {
        return;
    };
    drop(pending);

    // Слот соединения — только после рукопожатия (и пароля).
    let Ok(_slot) = Arc::clone(slots).try_acquire_owned() else {
        let _ = socks::reply(&mut socket, Reply::HostUnreachable).await;
        return;
    };

    // 🔐 Назначение не из списка — отказ. Имя назначения в журнал не
    // пишется: журнал — не место для адресов.
    //
    // Разрешённое назначение может вести на onion-сервис сервера
    // (см. `Allowlist::via_onion`): соединяемся туда, куда оно ведёт.
    let Some(target) = allow.route(&target) else {
        tracing::debug!("tor bridge: destination refused");
        let _ = socks::reply(&mut socket, Reply::NotAllowed).await;

        return;
    };

    let Ok(Ok(mut upstream)) = timeout(CONNECT_TIMEOUT, connector.connect(&target)).await else {
        let _ = socks::reply(&mut socket, Reply::HostUnreachable).await;

        return;
    };

    if socks::reply(&mut socket, Reply::Succeeded).await.is_err() {
        return;
    }

    let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Соединитель без Tor: идёт на локальный порт, куда бы ни просили.
    struct Local(u16);

    impl Connector for Local {
        type Stream = TcpStream;

        fn connect(&self, _target: &Target) -> impl Future<Output = io::Result<TcpStream>> + Send {
            TcpStream::connect((Ipv4Addr::LOCALHOST, self.0))
        }
    }

    /// Эхо-сервер на случайном порту.
    async fn echo() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("эхо");
        let port = listener.local_addr().expect("адрес").port();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });

        port
    }

    async fn bridge(allow: Allowlist, upstream: u16) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("мост");
        let port = listener.local_addr().expect("адрес").port();
        tokio::spawn(serve(
            listener,
            Arc::new(Local(upstream)),
            Arc::new(allow),
            None,
        ));
        port
    }

    async fn request(bridge: u16, host: &str) -> (TcpStream, [u8; 12]) {
        let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, bridge))
            .await
            .expect("соединение");
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
        bytes.extend_from_slice(&443u16.to_be_bytes());
        socket.write_all(&bytes).await.expect("запрос");

        let mut answer = [0u8; 12];
        socket.read_exact(&mut answer).await.expect("ответ");
        (socket, answer)
    }

    /// Разрешённое назначение: ответ «успех», затем байты идут насквозь.
    #[tokio::test]
    async fn an_allowed_destination_is_relayed() {
        let port = bridge(Allowlist::new([("gasapp.example.org", 443)]), echo().await).await;
        let (mut socket, answer) = request(port, "gasapp.example.org").await;

        assert_eq!(answer, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        socket.write_all(b"ping").await.expect("запись");
        let mut back = [0u8; 4];
        socket.read_exact(&mut back).await.expect("чтение");
        assert_eq!(&back, b"ping");
    }

    /// 🔐 Чужое назначение — отказ «запрещено правилами», до соединения.
    #[tokio::test]
    async fn another_destination_is_refused() {
        let port = bridge(Allowlist::new([("gasapp.example.org", 443)]), echo().await).await;
        let (mut socket, answer) = request(port, "tracker.example.com").await;

        assert_eq!(answer, [5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).await.expect("закрытие");
        assert!(rest.is_empty());
    }

    /// Недоступное назначение — «узел недоступен», а не зависание.
    #[tokio::test]
    async fn an_unreachable_destination_is_reported() {
        // Порт, который только что освободился: соединение не удастся.
        let closed = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("порт");
            listener.local_addr().expect("адрес").port()
        };
        let port = bridge(Allowlist::new([("gasapp.example.org", 443)]), closed).await;
        let (_, answer) = request(port, "gasapp.example.org").await;

        assert_eq!(answer[3], Reply::HostUnreachable as u8);
    }
}
