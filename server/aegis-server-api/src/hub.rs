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
