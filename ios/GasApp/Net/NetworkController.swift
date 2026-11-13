// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Применяет выбранный режим сети: напрямую, SOCKS или встроенный Tor
/// (аналог `NetworkProxy` + `EmbeddedTor` на Android).
///
/// 🔐 Пока Tor не готов, маршрут закрыт ([NetworkRoute.closed]): запросы
/// не уходят вовсе, а не уходят напрямую.
///
/// # Почему Tor перезапускается после фона
///
/// Пока приложение приостановлено, iOS забирает у него сокеты, в том
/// числе слушающий порт моста Tor на 127.0.0.1. Arti при этом продолжает
/// говорить «готов», а запросы через порт не проходят: в настройках
/// «Tor подключён», на главной — «Нет связи», и так до перезапуска
/// приложения (снимки с iPhone, 2026-11-12). Поэтому после фона Tor
/// поднимается заново — с кэшем каталога это секунды — и маршрут
/// открывается, когда он снова готов. Сбои подряд при «готовом» Tor
/// лечатся так же ([requestFailed]).
final class NetworkController: @unchecked Sendable {
    static let shared = NetworkController()

    private let lock = NSLock()
    /// Режим, который применён сейчас; nil — ещё не применялся.
    private var mode: FfiProxy?
    private var bridges: [String] = []
    /// Ожидание готовности Tor: одно на запуск, прежнее отменяется.
    private var waiter: Task<Void, Never>?
    private var failuresInRow = 0
    /// Последнее известное состояние Tor. Экраны читают его, а не ядро:
    /// `embeddedTorStatus()` ждёт ту же блокировку, что держит запуск Tor
    /// (секунды), и вызов с главного потока замораживал интерфейс.
    private var cached = NetworkController.stopped

    private static let stopped = FfiTorStatus(
        running: false, ready: false, percent: 0, stalled: false, port: 0, isolatedPort: 0,
        bridges: false, socksUsername: "", socksPassword: ""
    )

    private init() {}

    /// Применяет режим из базы. `nil` (база не читается) — Tor: отказ
    /// в безопасную сторону, как умолчание ядра.
    func apply(proxy: FfiProxy?, bridges: [String]?) {
        lock.lock(); defer { lock.unlock() }
        let chosen = proxy ?? .tor
        mode = chosen
        self.bridges = Self.clean(bridges)
        failuresInRow = 0

        switch chosen {
        case .direct:
            waiter?.cancel(); waiter = nil
            stopEmbeddedTor()
            NetworkRoute.current = .direct
        case let .socks5(host, port):
            waiter?.cancel(); waiter = nil
            stopEmbeddedTor()
            NetworkRoute.current = .socks(host: host, port: port)
        case .tor:
            NetworkRoute.current = .closed
            // Заново, если Tor уже работал: после блокировки база
            // открывается снова, а порт моста мог умереть в фоне.
            startTorLocked(restart: cached.running)
        }
    }

    /// Состояние встроенного Tor (для экрана сети и регистрации) — без
    /// ожидания: последнее, что узнал фоновый опрос.
    var torStatus: FfiTorStatus {
        lock.lock(); defer { lock.unlock() }
        return cached
    }

    private func refresh() -> FfiTorStatus {
        let status = embeddedTorStatus()
        lock.lock(); cached = status; lock.unlock()
        return status
    }

    /// Применённый режим сети; nil — база ещё не открыта.
    var currentMode: FfiProxy? {
        lock.lock(); defer { lock.unlock() }
        return mode
    }

    /// Выбран Tor, а маршрут ещё закрыт — подключается.
    var isConnectingTor: Bool {
        lock.lock(); defer { lock.unlock() }
        guard case .tor = mode ?? .direct else { return false }
        return NetworkRoute.current == .closed
    }

    /// Приложение снова на экране после `seconds` в фоне.
    func didReturnToForeground(afterSeconds seconds: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        guard case .tor = mode ?? .direct, seconds >= 3 else { return }
        NetworkRoute.current = .closed
        startTorLocked(restart: true)
    }

    /// Перед каждым приёмом: открыть маршрут, если Tor готов, а ожидание
    /// уже закончилось, и поднять Tor, если он упал.
    /// ⚠️ Звать не с главного потока: спрашивает ядро (см. `cached`).
    func ensureRoute() {
        lock.lock()
        let wantsTor: Bool = { if case .tor = mode ?? .direct { return true }; return false }()
        lock.unlock()
        guard wantsTor else { return }
        let status = refresh()
        lock.lock(); defer { lock.unlock() }
        guard case .tor = mode ?? .direct else { return }
        if !status.running {
            NetworkRoute.current = .closed
            startTorLocked(restart: false)
        } else if status.ready, NetworkRoute.current == .closed {
            routeThroughTor(status)
        } else if !status.ready, isTorRoute {
            // Tor перестал быть готов — закрыть, а не слать мимо.
            NetworkRoute.current = .closed
            startWaiterLocked()
        }
    }

    /// Запрос удался.
    func requestSucceeded() {
        lock.lock(); failuresInRow = 0; lock.unlock()
    }

    /// Запрос не прошёл. Три сбоя подряд при «готовом» Tor — порт моста
    /// мёртв (см. описание типа): Tor перезапускается.
    func requestFailed() {
        lock.lock(); defer { lock.unlock() }
        guard case .tor = mode ?? .direct else { return }
        failuresInRow += 1
        guard failuresInRow >= 3, cached.ready else { return }
        failuresInRow = 0
        NetworkRoute.current = .closed
        startTorLocked(restart: true)
    }

    /// Ждёт готовности Tor не дольше `timeout` секунд.
    func awaitTor(timeout: TimeInterval, progress: @escaping @Sendable (FfiTorStatus) -> Void) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline, !Task.isCancelled {
            let status = refresh()
            progress(status)
            if status.ready {
                lock.lock(); routeThroughTor(status); lock.unlock()
                return true
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return false
    }

    // MARK: - Внутреннее (под `lock`)

    private func startTorLocked(restart: Bool) {
        guard let server = AppConfig.serverURL, let host = server.host else { return }

        let base = CoreStore.shared.dataDirectory.appendingPathComponent("tor", isDirectory: true)
        let state = base.appendingPathComponent("state", isDirectory: true)
        let cache = base.appendingPathComponent("cache", isDirectory: true)
        try? FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)

        let settings = FfiTorSettings(
            stateDir: state.path,
            cacheDir: cache.path,
            trustedPrefix: base.path,
            serverHost: host,
            serverPort: UInt16(server.port ?? 443),
            bridges: bridges,
            serverOnion: AppConfig.serverOnion
        )

        waiter?.cancel()
        waiter = Task.detached(priority: .userInitiated) { [weak self] in
            // С теми же мостами ядро не перезапускает Tor, а отдаёт
            // работающий; после фона он нужен заново — отсюда stop.
            if restart { stopEmbeddedTor() }
            _ = try? startEmbeddedTor(settings: settings)
            _ = self?.refresh()
            // Без предела по времени: с мостами подключение бывает долгим,
            // а прежний предел в 10 минут оставлял маршрут закрытым навсегда.
            _ = await self?.awaitTor(timeout: 365 * 24 * 3600) { _ in }
        }
    }

    private func startWaiterLocked() {
        waiter?.cancel()
        waiter = Task.detached(priority: .userInitiated) { [weak self] in
            _ = await self?.awaitTor(timeout: 365 * 24 * 3600) { _ in }
        }
    }

    private func routeThroughTor(_ status: FfiTorStatus) {
        // Пока ждали Tor, человек мог выбрать прямое соединение — тогда
        // маршрут уже не закрыт, и Tor его не перехватывает.
        guard case .tor = mode ?? .direct else { return }
        guard NetworkRoute.current == .closed || isTorRoute else { return }
        NetworkRoute.current = .tor(
            port: status.port, isolatedPort: status.isolatedPort,
            username: status.socksUsername, password: status.socksPassword
        )
    }

    private var isTorRoute: Bool {
        if case .tor = NetworkRoute.current { return true }
        return false
    }

    private static func clean(_ bridges: [String]?) -> [String] {
        // Мосты — строками, как их хранит ядро (`Messenger.torBridges`).
        (bridges ?? [])
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}
