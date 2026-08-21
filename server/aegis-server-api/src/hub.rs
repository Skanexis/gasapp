// SPDX-License-Identifier: AGPL-3.0-only

//! WebSocket-хаб: уведомления о новых конвертах.
//!
//! # Что делает хаб
//!
//! Держит соединения устройств и сообщает им, что в очереди появился
//! конверт. Сам конверт по сокету **не** передаётся: клиент забирает
//! его обычным `GET /v1/messages/{device}`.
//!
//! # Почему уведомление, а не доставка
//!
//! Отправка конверта прямо в сокет выглядит эффективнее — на один
//! запрос меньше. Но она связала бы два факта, которые сервер не должен
//! связывать: «кто отправил» и «кто в этот момент был онлайн». Момент
//! доставки по сокету однозначно указывает на присутствие получателя,
//! а если отправитель тоже онлайн — на пару собеседников с точностью
//! до секунды. Именно эту корреляцию и собирают при наблюдении за
//! трафиком (раздел 15 плана).
//!
//! Уведомление такой связи не даёт: оно приходит и тому, кто открыл
//! приложение через час, а конверт забирается отдельным запросом,
//! неотличимым от периодического опроса.
//!
//! # Чего хаб не хранит
//!
//! Списка «кто онлайн» за пределами времени жизни соединения. Карта
//! очищается при разрыве, и после перезапуска сервера от неё не
//! остаётся ничего — присутствие пользователей не должно переживать
//! процесс, который его наблюдает.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

/// Сообщение, уходящее клиенту по сокету.
///
/// Ровно одно слово: конверт ждёт. Ни идентификатора конверта, ни
/// отправителя, ни количества — всё это сервер знает, но передавать
/// по сокету не обязан, а значит не передаёт.
const NOTIFY: &str = "envelope";

/// Размер очереди уведомлений на устройство.
///
/// Уведомления неразличимы между собой, поэтому копить их незачем:
/// клиент, получивший одно, заберёт из очереди всё, что там есть.
/// Единица означает «сообщи один раз и не накапливай».
const NOTIFY_QUEUE: usize = 1;

/// Карта подключённых устройств.
#[derive(Default)]
pub struct Hub {
    /// Отправители уведомлений по устройствам.
    ///
    /// `Mutex`, а не `RwLock`: операции короткие, а запись происходит
    /// при каждом подключении и отключении — то есть не реже чтения.
    connections: Mutex<HashMap<Uuid, mpsc::Sender<()>>>,
}

impl Hub {
    /// Создаёт пустой хаб.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Сообщает устройству, что для него есть конверт.
    ///
    /// Молча ничего не делает, если устройство не подключено: это
    /// штатный случай, а не ошибка — конверт останется в очереди
    /// до следующего запроса клиента.
    pub async fn notify(&self, device_id: Uuid) {
        let connections = self.connections.lock().await;

        if let Some(sender) = connections.get(&device_id) {
            // `try_send`, а не `send`: очередь размером в одно
            // уведомление уже полна, значит клиент ещё не забрал
            // предыдущее, и второе ничего не добавит. Ждать здесь
            // означало бы задержать ответ отправителю из-за того,
            // что получатель читает медленно.
            let _ = sender.try_send(());
        }
    }

    /// Регистрирует устройство и возвращает приёмник уведомлений.
    async fn connect(&self, device_id: Uuid) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel(NOTIFY_QUEUE);
        let mut connections = self.connections.lock().await;

        // Повторное подключение вытесняет прежнее: устройство одно,
        // и два сокета к нему означают, что старый уже мёртв, просто
        // разрыв ещё не заметили.
        connections.insert(device_id, sender);

        receiver
    }


    /// Подключает устройство — для интеграционных тестов.
    ///
    /// Отдельный метод, а не публичный `connect`: соединение обязано
    /// заводиться только обработчиком сокета, который снимает его при
    /// разрыве. Публичный `connect` позволил бы оставить в карте
    /// запись, которую никто не уберёт.
    #[cfg(feature = "test-hub")]
    pub async fn connect_for_test(&self, device_id: Uuid) -> mpsc::Receiver<()> {
        self.connect(device_id).await
    }
    /// Убирает устройство из карты.
    async fn disconnect(&self, device_id: Uuid) {
        let mut connections = self.connections.lock().await;
        connections.remove(&device_id);
    }

    /// Сколько устройств подключено.
    ///
    /// Только для тестов и метрик процесса: наружу это число не
    /// отдаётся — оно говорит о том, сколько людей сейчас в сети.
    #[must_use]
    pub async fn connected(&self) -> usize {
        self.connections.lock().await.len()
    }
}

/// Обработчик апгрейда до WebSocket.
///
/// # Аутентификации здесь нет
///
/// Соединение открывается по идентификатору устройства, который знает
/// и сервер, и отправители. Это допустимо, потому что по сокету не
/// уходит ничего, кроме слова «envelope»: подключившийся чужак узнает
/// лишь то, что кому-то пришёл конверт, — не содержимое, не отправителя
/// и не адресата.
///
/// Аутентификация подписью появится вместе с ней же на остальных
/// маршрутах; до тех пор добавлять её только сюда бессмысленно.
pub async fn websocket_handler(
    upgrade: WebSocketUpgrade,
    State(state): State<Arc<crate::routes::AppState>>,
    Path(device_id): Path<Uuid>,
) -> Response {
    upgrade.on_upgrade(move |socket| handle_socket(socket, state, device_id))
}

/// Ведёт одно соединение.
async fn handle_socket(
    mut socket: WebSocket,
    state: Arc<crate::routes::AppState>,
    device_id: Uuid,
) {
    let mut notifications = state.hub.connect(device_id).await;

    loop {
        tokio::select! {
            // Уведомление о конверте.
            notify = notifications.recv() => {
                if notify.is_none() {
                    break;
                }

                if socket.send(Message::Text(NOTIFY.to_owned())).await.is_err() {
                    break;
                }
            }

            // Входящие кадры от клиента.
            //
            // Клиент ничего осмысленного не присылает: сокет служит
            // только для уведомлений. Читать их всё равно нужно —
            // иначе не заметить закрытие соединения и пинги.
            incoming = socket.recv() => {
                match incoming {
                    // Закрытие, ошибка или конец потока — соединение
                    // кончилось, дальше слушать нечего.
                    None | Some(Err(_) | Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    state.hub.disconnect(device_id).await;
}


/// Канал `LISTEN/NOTIFY`, по которому узлы обмениваются уведомлениями.
///
/// Имя фиксировано и общее для всех узлов: они слушают один канал
/// и рассылают в него же.
pub const NOTIFY_CHANNEL: &str = "aegis_envelope";

/// Рассылает уведомление всем узлам кластера.
///
/// # Зачем это нужно
///
/// Хаб держит соединения только своего процесса. Когда узлов больше
/// одного, отправитель и получатель почти всегда оказываются на
/// разных: Алиса подключена к узлу A, Боб отправляет через узел B.
/// Без рассылки уведомление не дошло бы, и сообщение появилось бы
/// только при следующем открытии чата.
///
/// # Почему через базу, а не через Redis
///
/// База уже есть и уже является точкой отказа: сообщение всё равно
/// не примут, если она недоступна. Redis добавил бы второй сервис,
/// который надо поднимать, обновлять и защищать — а он по умолчанию
/// слушает без пароля, и это типовая причина утечек.
///
/// # Что уходит в канал
///
/// Только идентификатор устройства. Ни отправителя, ни содержимого:
/// полезная нагрузка `NOTIFY` попадает в журналы Postgres при
/// отладочном уровне логирования, и класть туда что-либо ещё значит
/// готовить утечку.
///
/// # Errors
///
/// Ошибка рассылки **не** должна отменять отправку: конверт уже
/// в очереди, и получатель заберёт его при следующем запросе.
/// Вызывающая сторона обязана залогировать и продолжить.
pub async fn broadcast(pool: &sqlx::PgPool, device_id: Uuid) -> Result<(), sqlx::Error> {
    // `pg_notify`, а не `NOTIFY`: второй не принимает параметры,
    // и идентификатор пришлось бы вставлять в текст запроса —
    // то есть строить SQL конкатенацией.
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(NOTIFY_CHANNEL)
        .bind(device_id.to_string())
        .execute(pool)
        .await
        .map(|_| ())
}

/// Слушает канал и раздаёт уведомления локальным соединениям.
///
/// Запускается один раз при старте узла и работает до остановки
/// процесса. При обрыве соединения с базой переподключается: без
/// этого узел молча перестал бы получать уведомления от соседей,
/// продолжая при этом обслуживать клиентов.
pub async fn listen(pool: sqlx::PgPool, hub: Arc<Hub>) {
    loop {
        match run_listener(&pool, &hub).await {
            Ok(()) => {
                // Слушатель завершился без ошибки — соединение закрыли
                // штатно. Такое случается при перезапуске базы.
                tracing::warn!("слушатель уведомлений завершился, переподключение");
            }
            Err(error) => {
                tracing::warn!(%error, "слушатель уведомлений оборвался");
            }
        }

        tokio::time::sleep(LISTEN_RETRY).await;
    }
}

/// Одна сессия слушателя: до первой ошибки.
async fn run_listener(pool: &sqlx::PgPool, hub: &Hub) -> Result<(), sqlx::Error> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen(NOTIFY_CHANNEL).await?;

    tracing::info!(channel = NOTIFY_CHANNEL, "слушатель уведомлений запущен");

    loop {
        let notification = listener.recv().await?;

        // Чужой формат полезной нагрузки — не повод падать: канал
        // общий, и в него мог написать кто-то ещё.
        let Ok(device_id) = Uuid::parse_str(notification.payload()) else {
            continue;
        };

        hub.notify(device_id).await;
    }
}

/// Пауза перед переподключением слушателя.
///
/// Секунда: слушатель один на узел, и частые попытки не создают
/// нагрузки, а задержка дольше означала бы, что после перезапуска
/// базы узел заметно долго не получает уведомлений.
const LISTEN_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notify_reaches_connected_device() {
        let hub = Hub::new();
        let device = Uuid::from_u128(1);

        let mut receiver = hub.connect(device).await;
        hub.notify(device).await;

        assert!(receiver.recv().await.is_some(), "уведомление не дошло");
    }

    /// Уведомление отключённому устройству не является ошибкой.
    ///
    /// Получатель офлайн — обычное дело: конверт ждёт его в очереди,
    /// и отправитель не должен об этом узнавать.
    #[tokio::test]
    async fn notify_to_absent_device_is_silent() {
        let hub = Hub::new();

        hub.notify(Uuid::from_u128(42)).await;

        assert_eq!(hub.connected().await, 0);
    }

    #[tokio::test]
    async fn disconnect_removes_device() {
        let hub = Hub::new();
        let device = Uuid::from_u128(7);

        let _receiver = hub.connect(device).await;
        assert_eq!(hub.connected().await, 1);

        hub.disconnect(device).await;
        assert_eq!(hub.connected().await, 0);
    }

    /// Повторное подключение вытесняет прежнее соединение.
    ///
    /// Устройство одно; два сокета означают, что старый уже мёртв,
    /// просто разрыв ещё не заметили. Держать оба — значит слать
    /// уведомления в никуда.
    #[tokio::test]
    async fn reconnect_replaces_previous_connection() {
        let hub = Hub::new();
        let device = Uuid::from_u128(3);

        let mut first = hub.connect(device).await;
        let mut second = hub.connect(device).await;

        hub.notify(device).await;

        assert_eq!(hub.connected().await, 1, "устройство должно быть одно");
        assert!(second.recv().await.is_some(), "новое соединение не получило");

        // Прежний приёмник закрыт вместе с вытесненным отправителем.
        assert!(first.recv().await.is_none(), "старое соединение осталось живым");
    }

    /// Второе уведомление не копится, пока не забрано первое.
    #[tokio::test]
    async fn notifications_do_not_pile_up() {
        let hub = Hub::new();
        let device = Uuid::from_u128(9);

        let mut receiver = hub.connect(device).await;

        hub.notify(device).await;
        hub.notify(device).await;
        hub.notify(device).await;

        assert!(receiver.recv().await.is_some());

        // Очередь опустела: уведомления неразличимы, и клиент,
        // получивший одно, заберёт из очереди всё сразу.
        assert!(receiver.try_recv().is_err(), "уведомления накопились");
    }
}
