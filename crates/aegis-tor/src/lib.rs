// SPDX-License-Identifier: Apache-2.0

//! Встроенный Tor: Arti внутри приложения вместо Orbot (ADR-024,
//! раздел 23.18 плана).
//!
//! # Зачем
//!
//! Tor по умолчанию обязателен (сервер не должен знать адресов), но с
//! Orbot это означало «поставьте ещё одно приложение и держите его
//! включённым». Встроенный Tor работает из коробки.
//!
//! # Как
//!
//! Сеть в проекте открывает платформа (`aegis-net::proxy`): её TLS
//! и пиннинг остаются в силе. Поэтому этот крейт не заменяет
//! транспорт, а делает то же, что делал Orbot, — поднимает SOCKS5 на
//! 127.0.0.1, только внутри процесса и на случайном порту. Платформа
//! подключается к нему, как прежде к Orbot; TLS идёт сквозь Tor до
//! самого сервера.
//!
//! # 🔐 Ограничения моста
//!
//! * Слушает только 127.0.0.1, порт случайный.
//! * Пускает только к назначениям из списка — к серверу AEGIS
//!   ([`socks::Allowlist`]). Локальный адрес на Android общий для всех
//!   приложений; без списка мост был бы открытым Tor-прокси для любого
//!   из них.
//! * Имена хостов разрешает выходной узел Tor, не устройство.
//! * Адреса назначений в журнал не пишутся.
//!
//! # Чего это НЕ меняет
//!
//! Tor прячет адрес от сервера, но не факт использования Tor от
//! провайдера. Мосты (obfs4, Snowflake) — отдельный шаг.

mod bridge;
pub mod socks;
pub mod webtunnel;

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BoolOrAuto, BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, DataStream, IsolationToken, StreamPrefs, TorClient};
use arti_client::{HasKind as _, TorClientConfig};
use futures::StreamExt as _;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;

pub use socks::Allowlist;

use bridge::Connector;
use socks::Target;

/// Первая пауза между попытками бутстрапа; дальше удваивается.
const RETRY_FIRST: Duration = Duration::from_secs(5);

/// Сколько ждать остановки задач при остановке Tor.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Предел паузы между попытками бутстрапа.
const RETRY_MAX: Duration = Duration::from_mins(1);

/// Настройки встроенного Tor.
#[derive(Debug, Clone)]
pub struct TorSettings {
    /// Каталог состояния Arti (охранные узлы и прочее — важно сохранять:
    /// постоянные охранные узлы защищают от части атак на анонимность).
    pub state_dir: PathBuf,
    /// Каталог кеша Arti (консенсус, дескрипторы).
    pub cache_dir: PathBuf,
    /// Каталог, который вместе с предками не проверяется на права доступа.
    ///
    /// На Android каталоги приложения принадлежат системе либо открыты
    /// на запись группе приложения, и проверка Arti их бы отвергла, хотя
    /// чужим приложениям они недоступны. Всё внутри него проверяется
    /// как обычно.
    pub trusted_prefix: Option<PathBuf>,
    /// Куда мост пускает.
    pub destinations: Allowlist,
    /// Мосты Tor — строки вида `obfs4 1.2.3.4:443 FINGERPRINT cert=…`
    /// (приставка `Bridge` допустима). Пусто — прямое подключение к сети
    /// Tor.
    ///
    /// ⚠️ Там, где Tor блокируют (Россия, Иран, Китай и др.), без мостов
    /// бутстрап не идёт: каналы до узлов открываются, но трафик режут.
    pub bridges: Vec<String>,
    /// Подключаемые транспорты (PT), через которые идут мосты.
    pub transports: Vec<Transport>,
    /// ⚠️ Мосты `WebTunnel` на частных адресах — только для проверки со
    /// своим мостом в локальной сети. Платформа это поле не выставляет.
    pub allow_private_bridges: bool,
}

/// Подключаемый транспорт: как добраться до моста.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Бинарник PT, который Arti запускает сам.
    Managed {
        /// Протоколы, которые он даёт (`obfs4`, `snowflake`, `webtunnel`…).
        protocols: Vec<String>,
        /// Путь к исполняемому файлу.
        path: PathBuf,
        /// Аргументы командной строки.
        arguments: Vec<String>,
    },
    /// PT, уже запущенный платформой: SOCKS на локальном порту
    /// (на Android — `IPtProxy`).
    Local {
        /// Протоколы, которые он даёт.
        protocols: Vec<String>,
        /// Его адрес.
        proxy: SocketAddr,
    },
}

/// Состояние встроенного Tor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorStatus {
    /// Подключается к сети Tor.
    Starting {
        /// Готовность, 0–100.
        percent: u8,
        /// Бутстрап застрял: нет сети, часы сбиты или Tor заблокирован.
        stalled: bool,
    },
    /// Готов пропускать соединения.
    Ready,
}

/// Отказ запуска.
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    /// Список назначений пуст: мост никого никуда не пустил бы.
    #[error("tor: no destinations")]
    NoDestinations,
    /// Настройки Arti не собрались (каталоги, права).
    #[error("tor: configuration")]
    Config,
    /// Рантайм или слушатель не поднялись.
    #[error("tor: runtime")]
    Runtime,
}

/// Работающий встроенный Tor.
///
/// Живёт, пока жив объект: при уничтожении рантайм останавливается,
/// и мост закрывается.
pub struct EmbeddedTor {
    port: u16,
    /// Порт для анонимных запросов: каждое соединение — своя цепочка.
    isolated_port: u16,
    status: watch::Receiver<TorStatus>,
    /// Мосты, с которыми запущен.
    bridges: Vec<String>,
    /// `Option` — чтобы [`Drop`] мог остановить рантайм с таймаутом.
    runtime: Option<Runtime>,
}

impl Drop for EmbeddedTor {
    /// Останавливает рантайм: задачи Arti и мосты закрываются, блокировка
    /// каталога состояния снимается — следующий запуск (например, уже
    /// с мостами) её получит.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
        }
    }
}

impl std::fmt::Debug for EmbeddedTor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedTor")
            .field("port", &self.port)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl EmbeddedTor {
    /// Запускает Tor и мост.
    ///
    /// Возвращается сразу: порт уже слушает, а бутстрап идёт в фоне.
    /// Соединение, пришедшее до готовности, ждёт её.
    ///
    /// # Errors
    ///
    /// [`TorError`] — пустой список назначений, негодные каталоги либо
    /// не поднялся рантайм.
    pub fn start(settings: TorSettings) -> Result<Self, TorError> {
        if settings.destinations.is_empty() {
            return Err(TorError::NoDestinations);
        }

        let mut settings = settings;

        // Arti требует, чтобы приложение выбрало провайдера TLS.
        // Повторная установка (второй запуск в процессе) — не ошибка.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("aegis-tor")
            .enable_all()
            .build()
            .map_err(|_| TorError::Runtime)?;

        // Мосты WebTunnel обслуживает свой клиент в этом же процессе
        // (`webtunnel`): Arti видит его как запущенный PT.
        let tunnel_targets = webtunnel::Targets::from_bridge_lines(&settings.bridges)
            .allow_private(settings.allow_private_bridges);

        let (listener, isolated_listener, tunnel) = runtime.block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|_| TorError::Runtime)?;
            let isolated_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|_| TorError::Runtime)?;
            let tunnel = if tunnel_targets.is_empty() {
                None
            } else {
                Some(
                    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .map_err(|_| TorError::Runtime)?,
                )
            };

            Ok::<_, TorError>((listener, isolated_listener, tunnel))
        })?;

        if let Some(tunnel) = &tunnel {
            settings.transports.push(Transport::Local {
                protocols: vec![webtunnel::TRANSPORT.to_owned()],
                proxy: tunnel.local_addr().map_err(|_| TorError::Runtime)?,
            });
        }

        let config = client_config(&settings)?;

        let client = runtime.block_on(async {
            TorClient::builder()
                .config(config)
                .bootstrap_behavior(BootstrapBehavior::OnDemand)
                .create_unbootstrapped()
                .map_err(|_| TorError::Config)
        })?;

        if let Some(tunnel) = tunnel {
            runtime.spawn(webtunnel::serve(tunnel, Arc::new(tunnel_targets)));
        }

        let port = listener.local_addr().map_err(|_| TorError::Runtime)?.port();
        let isolated_port = isolated_listener
            .local_addr()
            .map_err(|_| TorError::Runtime)?
            .port();
        let (status_tx, status) = watch::channel(TorStatus::Starting {
            percent: 0,
            stalled: false,
        });

        runtime.spawn(watch_bootstrap(Arc::clone(&client), status_tx));
        runtime.spawn(keep_bootstrapping(Arc::clone(&client)));
        let destinations = Arc::new(settings.destinations);
        runtime.spawn(bridge::serve(
            listener,
            Arc::new(Arti {
                client: Arc::clone(&client),
                isolated: false,
            }),
            Arc::clone(&destinations),
        ));
        runtime.spawn(bridge::serve(
            isolated_listener,
            Arc::new(Arti {
                client,
                isolated: true,
            }),
            destinations,
        ));

        Ok(Self {
            port,
            isolated_port,
            status,
            bridges: settings.bridges,
            runtime: Some(runtime),
        })
    }

    /// Порт моста на 127.0.0.1.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Порт моста для анонимных запросов: каждое соединение идёт своей
    /// цепочкой Tor (см. `Arti::isolated`).
    #[must_use]
    pub const fn isolated_port(&self) -> u16 {
        self.isolated_port
    }

    /// Мосты, с которыми запущен (пусто — без мостов).
    #[must_use]
    pub fn bridges(&self) -> &[String] {
        &self.bridges
    }

    /// Текущее состояние.
    #[must_use]
    pub fn status(&self) -> TorStatus {
        *self.status.borrow()
    }
}

/// Собирает настройки Arti.
fn client_config(settings: &TorSettings) -> Result<TorClientConfig, TorError> {
    let mut builder =
        TorClientConfigBuilder::from_directories(&settings.state_dir, &settings.cache_dir);

    // Цепочки к порту сервера строятся заранее, ещё до первого запроса:
    // иначе первый запрос ждёт постройки цепочки (секунды через Tor).
    let predicted = builder.preemptive_circuits().initial_predicted_ports();
    for port in settings.destinations.ports() {
        if !predicted.contains(&port) {
            predicted.push(port);
        }
    }

    if let Some(prefix) = &settings.trusted_prefix {
        builder
            .storage()
            .permissions()
            .ignore_prefix(prefix.clone());
    }

    if !settings.bridges.is_empty() {
        for line in &settings.bridges {
            let line = line.trim();
            let line = line.strip_prefix("Bridge ").unwrap_or(line);
            let bridge: BridgeConfigBuilder = line.parse().map_err(|_| TorError::Config)?;
            builder.bridges().bridges().push(bridge);
        }

        // 🔐 Явно: с мостами — только через мосты, без прямых узлов.
        builder.bridges().enabled(BoolOrAuto::Explicit(true));
    }

    for transport in &settings.transports {
        let mut config = TransportConfigBuilder::default();

        match transport {
            Transport::Managed {
                protocols,
                path,
                arguments,
            } => {
                config
                    .protocols(transport_names(protocols)?)
                    .path(CfgPath::new_literal(path.clone()))
                    .arguments(arguments.clone());
            }
            Transport::Local { protocols, proxy } => {
                config
                    .protocols(transport_names(protocols)?)
                    .proxy_addr(*proxy);
            }
        }

        builder.bridges().transports().push(config);
    }

    builder.build().map_err(|_| TorError::Config)
}

/// Имена протоколов PT.
fn transport_names(
    protocols: &[String],
) -> Result<Vec<arti_client::config::PtTransportName>, TorError> {
    protocols
        .iter()
        .map(|name| name.parse().map_err(|_| TorError::Config))
        .collect()
}

/// Переводит события бутстрапа Arti в [`TorStatus`].
async fn watch_bootstrap<R: tor_rtcompat::Runtime>(
    client: Arc<TorClient<R>>,
    status: watch::Sender<TorStatus>,
) {
    let mut events = client.bootstrap_events();

    while let Some(event) = events.next().await {
        let next = if event.ready_for_traffic() {
            TorStatus::Ready
        } else {
            TorStatus::Starting {
                percent: percent(event.as_frac()),
                stalled: event.blocked().is_some(),
            }
        };

        status.send_replace(next);
    }
}

/// Доля в проценты 0–100.
fn percent(fraction: f32) -> u8 {
    let clamped = if fraction.is_nan() {
        0.0
    } else {
        fraction.clamp(0.0, 1.0)
    };

    // Значение уже в 0..=100: усечение и знак не теряют ничего.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let value = (clamped * 100.0).round() as u8;

    value
}

/// Повторяет бутстрап, пока он не удастся: без сети при запуске
/// первая попытка провалится, и сеть может появиться позже.
async fn keep_bootstrapping<R: tor_rtcompat::Runtime>(client: Arc<TorClient<R>>) {
    let mut pause = RETRY_FIRST;

    while let Err(error) = client.bootstrap().await {
        tracing::warn!(kind = ?error.kind(), "tor bootstrap failed; retrying");
        tokio::time::sleep(pause).await;
        pause = pause.saturating_mul(2).min(RETRY_MAX);
    }
}

/// Соединитель через Arti.
///
/// `isolated` — каждое соединение в своей изоляции Arti, то есть на
/// своей цепочке. Для анонимных запросов (sealed sender, вложения,
/// поиск, журнал ключей): иначе они шли бы той же цепочкой, что
/// запросы за подписью устройства, и сервер связал бы их по выходному
/// узлу и времени.
struct Arti<R: tor_rtcompat::Runtime> {
    client: Arc<TorClient<R>>,
    isolated: bool,
}

impl<R: tor_rtcompat::Runtime> Connector for Arti<R> {
    type Stream = DataStream;

    fn connect(&self, target: &Target) -> impl Future<Output = io::Result<DataStream>> + Send {
        let client = Arc::clone(&self.client);
        let target = (target.host.clone(), target.port);
        let mut prefs = StreamPrefs::new();
        if self.isolated {
            prefs.set_isolation(IsolationToken::new());
        }

        async move {
            client
                .connect_with_prefs(target, &prefs)
                .await
                .map_err(|error| {
                    tracing::debug!(kind = ?error.kind(), "tor connect failed");
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "tor: destination unreachable",
                    )
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractions_become_percent() {
        assert_eq!(percent(0.0), 0);
        assert_eq!(percent(0.456), 46);
        assert_eq!(percent(1.0), 100);
        assert_eq!(percent(1.7), 100);
        assert_eq!(percent(-0.2), 0);
        assert_eq!(percent(f32::NAN), 0);
    }

    /// 🔐 Мост без назначений не запускается: он никого бы не пустил,
    /// а приложение считало бы сеть рабочей.
    #[test]
    fn an_empty_allowlist_is_refused() {
        let dir = tempfile::tempdir().expect("каталог");
        let result = EmbeddedTor::start(TorSettings {
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            trusted_prefix: None,
            destinations: Allowlist::new(Vec::<(String, u16)>::new()),
            bridges: Vec::new(),
            transports: Vec::new(),
            allow_private_bridges: false,
        });

        assert!(matches!(result, Err(TorError::NoDestinations)));
    }
}
