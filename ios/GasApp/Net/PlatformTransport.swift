// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// HTTP-транспорт для ядра — аналог `PlatformTransport.kt`.
///
/// 🔐 Сеть ведёт **платформа**, а не Rust: у ядра нет своего TLS-стека,
/// и пиннинг, обойдённый изнутри приложения, не защищал бы ни от чего.
/// Здесь — URLSession с проверкой пина ([PinningDelegate]), без
/// переадресаций, без кеша и cookie, с пределами размера ответа.
///
/// Ядро вызывает `execute` синхронно из своего потока, поэтому ответ
/// ждётся семафором. Вызывать ядро из главного потока нельзя
/// (см. [CoreStore]) — иначе он встал бы на время запроса.
final class PlatformTransport: HttpTransport, @unchecked Sendable {
    private let baseURL: URL
    private let pins: PinSet

    /// Предел текстового ответа: очередь — до 100 конвертов по 256 КБ
    /// в hex, около 51 МБ, с запасом. 🔐 Злонамеренный сервер не уронит
    /// приложение ответом в гигабайт.
    static let maxTextResponse = 64 * 1024 * 1024
    /// Предел скачанного вложения: сервер хранит до 101 МБ.
    static let maxBinaryResponse = 128 * 1024 * 1024

    init(baseURL: URL, pins: PinSet) {
        self.baseURL = baseURL
        self.pins = pins
    }

    func execute(
        method: String, path: String, body: String?, binaryBody: Data?,
        headers: [FfiHeader], anonymous: Bool
    ) throws -> FfiHttpResponse {
        // Маршрут — один раз на запрос: и настройка сессии, и её ключ.
        let route = NetworkRoute.current
        guard let url = URL(string: baseURL.absoluteString + path),
              let config = route.configuration(anonymous: anonymous)
        else {
            // Сеть закрыта (Tor выбран, но не готов) — сбой сети для ядра,
            // а не запрос в обход.
            throw FfiTransportError.Network
        }

        var request = URLRequest(url: url)
        request.httpMethod = method
        // 🔐 Заголовки подписи ставит ядро; транспорт их только переносит.
        for header in headers {
            request.setValue(header.value, forHTTPHeaderField: header.name)
        }
        // 🔐 Анонимный запрос не переиспользует соединение: соединение —
        // это цепочка Tor, соседние анонимные запросы сервер связал бы.
        if anonymous {
            request.setValue("close", forHTTPHeaderField: "Connection")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = Data(body.utf8)
        } else if let binaryBody {
            // Вложение уходит сырыми байтами: hex удвоил бы объём.
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            request.httpBody = binaryBody
        }

        let binary = Self.isBinaryDownload(method: method, path: path)
        let limit = binary ? Self.maxBinaryResponse : Self.maxTextResponse

        let host = baseURL.host ?? ""
        let delegate = TransportDelegate(pins: pins, host: host, limit: limit)

        #if canImport(Security)
        if anonymous {
            // 🔐 Анонимный запрос — своя сессия и своё соединение (своя
            // цепочка Tor): с соседними его не связать.
            let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
            defer { session.finishTasksAndInvalidate() }
            session.dataTask(with: request).resume()
        } else {
            // Обычные запросы — через одно соединение на маршрут: опрос
            // раз в несколько секунд не открывает каждый раз новый TLS.
            // Пин проверяется делегатом сессии на каждом новом соединении,
            // данные и пределы — делегатом задачи.
            let task = sharedSession(route: route, config: config, host: host).dataTask(with: request)
            task.delegate = delegate
            task.resume()
        }
        #else
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        session.dataTask(with: request).resume()
        #endif
        delegate.wait()

        // Любой сбой — таймаут, обрыв, отказ пиннинга, превышение
        // предела — для ядра «сеть недоступна»: повторы и очередь
        // отправки ждут именно этого.
        let data = delegate.data
        guard !delegate.failed, let http = delegate.response as? HTTPURLResponse else {
            throw FfiTransportError.Network
        }
        ClockCheck.observe(http.value(forHTTPHeaderField: "Date"))

        // 4xx/5xx — не ошибка, а ответ: ядро различает недоступность
        // сервера и его отказ. Текстом читается только заведомо текстовое.
        let status = UInt16(clamping: http.statusCode)
        let isBinary = binary && (200..<300).contains(http.statusCode)

        return FfiHttpResponse(
            status: status,
            body: isBinary ? "" : String(decoding: data, as: UTF8.self),
            binaryBody: isBinary ? data : Data()
        )
    }

    #if canImport(Security)
    private static let sessionLock = NSLock()
    nonisolated(unsafe) private static var shared: (route: NetworkRoute, session: URLSession)?

    /// Сбросить соединения — после возврата приложения из фона.
    ///
    /// Пока приложение приостановлено, iOS обрывает его сокеты, а общая
    /// сессия держит соединение HTTP/2 к серверу. Первый запрос после
    /// возврата шёл в мёртвое соединение и висел до таймаута либо падал
    /// «нет связи»: так выглядели «Отправить код ещё раз» и «Подтвердить»
    /// после похода в Почту за кодом (2026-11-13). Новая сессия открывает
    /// новое соединение сразу.
    static func resetConnections() {
        sessionLock.lock()
        defer { sessionLock.unlock() }
        shared?.session.invalidateAndCancel()
        shared = nil
    }

    /// Сессия текущего маршрута. 🔐 Сменился маршрут (Tor ↔ напрямую) —
    /// прежняя сессия закрывается: её соединения шли бы старым путём.
    private func sharedSession(route: NetworkRoute, config: URLSessionConfiguration, host: String) -> URLSession {
        Self.sessionLock.lock()
        defer { Self.sessionLock.unlock() }
        if let shared = Self.shared, shared.route == route {
            return shared.session
        }
        Self.shared?.session.invalidateAndCancel()
        let session = URLSession(configuration: config,
                                 delegate: PinningSessionDelegate(pins: pins, host: host),
                                 delegateQueue: nil)
        Self.shared = (route, session)
        return session
    }
    #endif

    /// Отдаёт ли запрос сырые байты: скачивание вложения или медиа
    /// канала. По методу и пути, а не по Content-Type: заголовку сервера
    /// не доверяется решать, сколько памяти потратит клиент.
    static func isBinaryDownload(method: String, path: String) -> Bool {
        guard method.uppercased() == "GET" else { return false }
        if path.hasPrefix("/v1/attachments/") { return true }
        return path.range(of: channelMediaPattern, options: .regularExpression) != nil
    }

    private static let channelMediaPattern =
        "^/v1/channels/(feed|reader/[0-9a-f-]{36})/[0-9a-f-]{36}/media/[0-9a-f-]{36}$"
}

/// Часы телефона против часов сервера — для подсказки «проверьте время»:
/// подписи запросов с неверным временем сервер отвергает.
enum ClockCheck {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var skew: TimeInterval = 0

    /// Расходятся ли часы больше чем на 5 минут.
    static var off: Bool {
        lock.lock(); defer { lock.unlock() }
        return abs(skew) > 300
    }

    /// Разбор заголовка `Date`. Один на всё приложение: прежде он
    /// создавался заново на каждый ответ сервера. Используется под `lock`.
    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return formatter
    }()

    static func observe(_ header: String?) {
        guard let header else { return }
        lock.lock()
        defer { lock.unlock() }
        guard let server = formatter.date(from: header) else { return }
        skew = Date().timeIntervalSince(server)
    }
}
