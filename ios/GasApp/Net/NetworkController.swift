// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Применяет выбранный режим сети: напрямую, SOCKS или встроенный Tor
/// (аналог `NetworkProxy` + `EmbeddedTor` на Android).
///
/// 🔐 Пока Tor не готов, маршрут закрыт ([NetworkRoute.closed]): запросы
/// не уходят вовсе, а не уходят напрямую.
final class NetworkController: @unchecked Sendable {
    static let shared = NetworkController()

    private let lock = NSLock()
    private var watcher: Task<Void, Never>?

    private init() {}

    /// Применяет режим из базы. `nil` (база не читается) — Tor: отказ
    /// в безопасную сторону, как умолчание ядра.
    func apply(proxy: FfiProxy?, bridges: [String]?) {
        lock.lock(); defer { lock.unlock() }
        watcher?.cancel()
        watcher = nil

        switch proxy ?? .tor {
        case .direct:
            stopTor()
            NetworkRoute.current = .direct
        case let .socks5(host, port):
            stopTor()
            NetworkRoute.current = .socks(host: host, port: port)
        case .tor:
            NetworkRoute.current = .closed
            startTor(bridges: bridges)
        }
    }

    /// Состояние встроенного Tor (для экрана сети и регистрации).
    var torStatus: FfiTorStatus { embeddedTorStatus() }

    /// Ждёт готовности Tor не дольше `timeout` секунд.
    func awaitTor(timeout: TimeInterval, progress: @escaping @Sendable (FfiTorStatus) -> Void) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let status = embeddedTorStatus()
            progress(status)
            if status.ready {
                routeThroughTor(status)
                return true
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return false
    }

    private func startTor(bridges: [String]?) {
        guard let server = AppConfig.serverURL, let host = server.host else { return }

        let base = CoreStore.shared.dataDirectory.appendingPathComponent("tor", isDirectory: true)
        let state = base.appendingPathComponent("state", isDirectory: true)
        let cache = base.appendingPathComponent("cache", isDirectory: true)
        try? FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)

        // Мосты — строками, как их хранит ядро (`Messenger.torBridges`).
        let lines = (bridges ?? [])
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        let settings = FfiTorSettings(
            stateDir: state.path,
            cacheDir: cache.path,
            trustedPrefix: base.path,
            serverHost: host,
            serverPort: UInt16(server.port ?? 443),
            bridges: lines,
            serverOnion: AppConfig.serverOnion
        )

        Task.detached(priority: .userInitiated) { [weak self] in
            guard (try? startEmbeddedTor(settings: settings)) != nil else { return }
            // Маршрут откроется, когда Tor скажет «готов».
            _ = await self?.awaitTor(timeout: 600) { _ in }
        }
    }

    private func routeThroughTor(_ status: FfiTorStatus) {
        // Пока ждали Tor, человек мог выбрать прямое соединение — тогда
        // маршрут уже не закрыт, и Tor его не перехватывает.
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

    private func stopTor() {
        stopEmbeddedTor()
    }
}
