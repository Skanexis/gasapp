// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

/// 🔐 Пиннинг ключа TLS сервера — то же правило, что
/// `network_security_config.xml` на Android.
///
/// Сначала обычная проверка цепочки до системного корня (отзыв, срок,
/// имя), затем — совпадение SPKI SHA-256 хотя бы одного сертификата
/// цепочки с набором пинов из сборки. После даты `expiration` остаётся
/// только обычная проверка — как у Android: пиннинг «протухает», а не
/// обрывает связь навсегда.
struct PinSet: Sendable {
    let pins: Set<String>
    let expiration: Date?

    init(pins: [String], expiration: Date?) {
        self.pins = Set(pins.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })
        self.expiration = expiration
    }

    /// Действует ли набор на `now`.
    func isActive(now: Date = Date()) -> Bool {
        guard let expiration else { return true }
        return now < expiration
    }

    /// Совпадает ли хотя бы один SPKI из цепочки.
    func matches(spkiHashes: [String], now: Date = Date()) -> Bool {
        guard isActive(now: now) else { return true }
        return spkiHashes.contains(where: pins.contains)
    }
}

#if canImport(Security) && canImport(CryptoKit)
enum SPKI {
    /// Заголовки SubjectPublicKeyInfo (DER) для ключей, которые выдаёт
    /// `SecKeyCopyExternalRepresentation` без обёртки.
    private static let headers: [String: [UInt8]] = [
        "ec256": [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00],
        "ec384": [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                  0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00],
        "rsa2048": [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00],
        "rsa4096": [0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00],
    ]

    /// base64(SHA-256(SPKI)) сертификата; nil — тип ключа не поддержан.
    static func hash(of certificate: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(certificate),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let type = attributes[kSecAttrKeyType as String] as? String,
              let bits = attributes[kSecAttrKeySizeInBits as String] as? Int
        else { return nil }

        let name: String
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            name = "ec\(bits)"
        } else if type == (kSecAttrKeyTypeRSA as String) {
            name = "rsa\(bits)"
        } else {
            return nil
        }
        guard let header = headers[name] else { return nil }

        return Data(SHA256.hash(data: Data(header) + raw)).base64EncodedString()
    }
}
#endif

/// Делегат одного запроса: пиннинг, запрет переадресаций и предел
/// размера ответа — **во время** чтения, а не после: ответ в гигабайт
/// обрывается на пределе, а не ложится целиком в память.
final class TransportDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let pins: PinSet
    private let host: String
    private let limit: Int
    private let done = DispatchSemaphore(value: 0)

    private(set) var data = Data()
    private(set) var response: URLResponse?
    private(set) var failed = false

    init(pins: PinSet, host: String, limit: Int) {
        self.pins = pins
        self.host = host
        self.limit = limit
    }

    /// Ждёт конца запроса.
    func wait() { done.wait() }

    func urlSession(
        _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        // Заявленная длина больше предела — не читать вовсе.
        if response.expectedContentLength > Int64(limit) {
            failed = true
            completionHandler(.cancel)
            return
        }
        self.response = response
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        data.append(chunk)
        if data.count > limit {
            failed = true
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if error != nil { failed = true }
        done.signal()
    }

    /// 🔐 Переадресации запрещены: они увели бы запрос на другой хост,
    /// где пиннинг уже не применяется.
    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        PinCheck.evaluate(challenge, pins: pins, host: host, completionHandler)
    }
}

/// Делегат уровня сессии для переиспользуемой сессии: пиннинг на каждое
/// **новое соединение** (переиспользованное уже проверено им же).
final class PinningSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pins: PinSet
    private let host: String

    init(pins: PinSet, host: String) {
        self.pins = pins
        self.host = host
    }

    func urlSession(
        _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        PinCheck.evaluate(challenge, pins: pins, host: host, completionHandler)
    }
}

/// Проверка сервера — одна на все пути.
enum PinCheck {
    static func evaluate(
        _ challenge: URLAuthenticationChallenge, pins: PinSet, host: String,
        _ completionHandler: (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        #if canImport(Security) && canImport(CryptoKit)
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              challenge.protectionSpace.host == host
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 1. Обычная проверка: цепочка до системного корня, имя, срок.
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        guard SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 2. 🔐 Пин: ключ одного из сертификатов цепочки — из сборки.
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        guard pins.matches(spkiHashes: chain.compactMap(SPKI.hash(of:))) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
        #else
        // Без Security проверить пин нечем — соединение не принимается.
        completionHandler(.cancelAuthenticationChallenge, nil)
        #endif
    }
}
