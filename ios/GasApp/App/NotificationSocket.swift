// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Сокет уведомлений (`GET /v1/ws/{device}`): сервер говорит «конверт
/// ждёт» — и приём идёт сразу, а не по таймеру.
///
/// Прежде iOS только опрашивала очередь: в затишье раз в 20–45 секунд,
/// и новое сообщение в списке чатов появлялось с такой задержкой. Android
/// держит этот сокет давно (`NotificationSocket.kt`).
///
/// 🔐 По сокету приходит одно слово — `envelope`: ни отправителя, ни
/// конверта (`server/…/hub.rs`). Сами конверты забираются обычным
/// подписанным запросом, неотличимым от опроса. Сокет идёт тем же
/// маршрутом, что и остальные запросы (напрямую или через Tor), с той же
/// проверкой сертификата сервера (`PinningSessionDelegate`).
@MainActor
final class NotificationSocket {
    static let shared = NotificationSocket()

    /// Сокет открыт: опрос можно реже — о новом скажет сервер.
    private(set) var connected = false

    private var loop: Task<Void, Never>?
    private var task: URLSessionWebSocketTask?
    /// Будильник паузы между попытками: «подключиться сейчас».
    private var wake: CheckedContinuation<Void, Never>?

    /// Пинг: держит соединение (через Tor молчащее соединение может
    /// тихо умереть) и замечает обрыв.
    private static let pingEvery: UInt64 = 25_000_000_000

    private init() {}

    func start() {
        guard loop == nil else { return }
        loop = Task { [weak self] in await self?.run() }
    }

    func stop() {
        loop?.cancel()
        loop = nil
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        connected = false
        wakeUp()
    }

    /// Снова на экране или сеть сменилась: соединение могло умереть —
    /// открыть заново сейчас, не дожидаясь паузы.
    func reconnectNow() {
        task?.cancel(with: .goingAway, reason: nil)
        wakeUp()
    }

    private func wakeUp() {
        wake?.resume()
        wake = nil
    }

    private func run() async {
        var delay: Double = 1
        while !Task.isCancelled {
            let opened = await session()
            connected = false
            guard !Task.isCancelled else { break }
            // Через Tor — не дольше 15 с: соединение там рвётся чаще, а
            // пауза — это задержка сообщений.
            let ceiling: Double = NetworkRoute.current == .direct ? 30 : 15
            delay = opened ? 1 : min(ceiling, delay * 2)
            await pause(seconds: delay)
        }
    }

    private func pause(seconds: Double) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            wake = continuation
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                self?.wakeUp()
            }
        }
    }

    /// Одно соединение — до обрыва. `true` — оно открылось (сервер ответил
    /// на пинг), тогда следующая попытка — сразу.
    private func session() async -> Bool {
        guard let server = AppConfig.serverURL,
              let device = CoreStore.shared.deviceId,
              let messenger = try? CoreStore.shared.current(),
              let config = NetworkRoute.current.configuration(anonymous: false),
              var components = URLComponents(url: server, resolvingAgainstBaseURL: false)
        else { return false }
        components.scheme = server.scheme == "https" ? "wss" : "ws"
        components.path = "/v1/ws/\(device)"
        guard let url = components.url else { return false }

        // Подпись рукопожатия — от ядра: ключ устройства из него не выходит.
        guard let headers = try? await Background.run({
            try messenger.socketAuthHeaders(deviceId: device, nowMillis: CoreStore.nowMillis)
        }), !headers.isEmpty else { return false }

        var request = URLRequest(url: url)
        request.timeoutInterval = 45
        for header in headers {
            request.setValue(header.value, forHTTPHeaderField: header.name)
        }

        let session = URLSession(configuration: config,
                                 delegate: PinningSessionDelegate(pins: AppConfig.pins, host: server.host ?? ""),
                                 delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let socket = session.webSocketTask(with: request)
        task = socket
        socket.resume()

        // Открылся ли: сервер отвечает на пинг.
        guard await ping(socket) else { return false }
        connected = true
        // Сервер ответил — значит, связь есть: «Нет связи» от прошлой
        // ошибки приёма снимается сразу.
        Inbox.shared.serverReachable()
        // Пока сокета не было, могло прийти — забрать сразу.
        Inbox.shared.hurry()

        let pinger = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.pingEvery)
                guard !Task.isCancelled else { return }
                if await self?.ping(socket) != true {
                    socket.cancel(with: .goingAway, reason: nil)
                    return
                }
            }
        }
        defer { pinger.cancel() }

        while !Task.isCancelled {
            guard let message = try? await socket.receive() else { break }
            if case let .string(text) = message, text == "envelope" {
                Inbox.shared.hurry()
            }
        }
        socket.cancel(with: .goingAway, reason: nil)
        return true
    }

    private nonisolated func ping(_ socket: URLSessionWebSocketTask) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            socket.sendPing { error in continuation.resume(returning: error == nil) }
        }
    }
}
