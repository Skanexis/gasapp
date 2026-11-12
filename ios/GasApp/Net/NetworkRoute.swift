// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Network)
import Network
#endif

/// Куда сейчас идёт сеть приложения (аналог `NetworkProxy` на Android).
///
/// 🔐 Отказ — в закрытую сторону: выбран Tor, но он не готов — запрос
/// не уходит вовсе, а не уходит напрямую. Прямой запрос при включённом
/// Tor выдал бы адрес человека.
enum NetworkRoute: Equatable, Sendable {
    /// Напрямую.
    case direct
    /// SOCKS5-прокси, указанный человеком.
    case socks(host: String, port: UInt16)
    /// Встроенный Tor: мост на 127.0.0.1 с логином на запуск.
    case tor(port: UInt16, isolatedPort: UInt16, username: String, password: String)
    /// Выбран Tor, но он ещё не готов: сеть закрыта.
    case closed

    private static let lock = NSLock()
    nonisolated(unsafe) private static var _current: NetworkRoute = .closed

    /// Текущий маршрут. До открытия базы — закрыт: выбор человека лежит
    /// в зашифрованной базе, и раньше его прочитать нечем.
    static var current: NetworkRoute {
        get { lock.lock(); defer { lock.unlock() }; return _current }
        set { lock.lock(); _current = newValue; lock.unlock() }
    }

    /// Настройка сессии под маршрут; nil — сеть закрыта.
    ///
    /// 🔐 Сессия «эфемерная»: без кеша, cookie и сохранённых учётных
    /// данных — на диске не остаётся следов запросов.
    func configuration(anonymous: Bool) -> URLSessionConfiguration? {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        // С запасом на Tor: построение цепочки занимает секунды.
        config.timeoutIntervalForRequest = 45
        config.timeoutIntervalForResource = 20 * 60
        #if !os(Linux)
        config.waitsForConnectivity = false
        #endif

        switch self {
        case .closed:
            return nil
        case .direct:
            // Напрямую сервер отвечает за доли секунды: 20 с без ответа —
            // уже сбой, а не медленная сеть (через Tor — 45 с, см. выше).
            config.timeoutIntervalForRequest = 20
            return config
        case let .socks(host, port):
            return Self.apply(socks: host, port: port, credentials: nil, to: config)
        case let .tor(port, isolatedPort, username, password):
            // 🔐 Анонимный запрос — через порт, где каждое соединение
            // получает свою цепочку: соседние анонимные запросы сервер
            // не свяжет между собой.
            return Self.apply(socks: "127.0.0.1", port: anonymous ? isolatedPort : port,
                              credentials: (username, password), to: config)
        }
    }

    private static func apply(
        socks host: String, port: UInt16, credentials: (String, String)?,
        to config: URLSessionConfiguration
    ) -> URLSessionConfiguration? {
        #if canImport(Network) && !os(Linux)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        var proxy = ProxyConfiguration(socksv5Proxy: .hostPort(host: NWEndpoint.Host(host), port: nwPort))
        if let credentials {
            proxy.applyCredential(username: credentials.0, password: credentials.1)
        }
        // 🔐 Без отката на прямое соединение: недоступный прокси — сбой
        // сети, а не запрос в обход.
        proxy.allowFailover = false
        config.proxyConfigurations = [proxy]
        return config
        #else
        return nil
        #endif
    }
}
