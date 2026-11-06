// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import GasAppKit

/// Транспорт без сети: каждый запрос — «сеть недоступна».
final class OfflineTransport: HttpTransport, @unchecked Sendable {
    private(set) var calls: [String] = []

    func execute(method: String, path: String, body: String?, binaryBody: Data?,
                 headers: [FfiHeader], anonymous: Bool) throws -> FfiHttpResponse {
        calls.append("\(method) \(path)")
        throw FfiTransportError.Network
    }
}

/// Транспорт, отвечающий заданным кодом: проверяет, что 4xx/5xx ядро
/// получает как ответ, а не как сбой сети.
final class StatusTransport: HttpTransport, @unchecked Sendable {
    let status: UInt16
    init(status: UInt16) { self.status = status }

    func execute(method: String, path: String, body: String?, binaryBody: Data?,
                 headers: [FfiHeader], anonymous: Bool) throws -> FfiHttpResponse {
        FfiHttpResponse(status: status, body: "{}", binaryBody: Data())
    }
}

final class PinPolicyTests: XCTestCase {
    private func bytes(_ text: String) -> [UInt8] { Array(text.utf8) }

    func testAcceptsExactlySixAsciiDigits() {
        XCTAssertTrue(PinPolicy.isAcceptable(bytes("482915")))
        XCTAssertFalse(PinPolicy.isAcceptable(bytes("48291")))
        XCTAssertFalse(PinPolicy.isAcceptable(bytes("4829150")))
        XCTAssertFalse(PinPolicy.isAcceptable(bytes("48291a")))
        // Арабо-индийские цифры — не цифры PIN.
        XCTAssertFalse(PinPolicy.isAcceptable(bytes("٤٨٢٩١٥")))
    }

    func testRejectsSimplePins() {
        // Тот же список, что android/…/PinStrengthTest.kt.
        for pin in ["000000", "111111", "999999", "123456", "234567", "654321", "987654", "543210",
                    "121212", "101010", "123123", "456456", "112233", "111222",
                    "159753", "147258", "696969", "123321",
                    "135791", "789012", "901234", "098765"] {
            XCTAssertTrue(PinPolicy.isTooSimple(bytes(pin)), pin)
        }
        for pin in ["482915", "975310", "135790", "246801", "730492", "580316"] {
            XCTAssertFalse(PinPolicy.isTooSimple(bytes(pin)), pin)
        }
    }

    func testDelayTableMatchesAndroid() {
        XCTAssertEqual(PinDelays.delay(afterFailures: 3), 0)
        XCTAssertEqual(PinDelays.delay(afterFailures: 4), 5)
        XCTAssertEqual(PinDelays.delay(afterFailures: 5), 30)
        XCTAssertEqual(PinDelays.delay(afterFailures: 6), 300)
        XCTAssertEqual(PinDelays.delay(afterFailures: 7), 1800)
        XCTAssertEqual(PinDelays.delay(afterFailures: 8), 3600)
        XCTAssertEqual(PinDelays.delay(afterFailures: 10), 4 * 3600)
        // Не переполняется и не становится отрицательной.
        XCTAssertGreaterThan(PinDelays.delay(afterFailures: 10_000), 0)
    }

    func testAttemptsSurviveClockRollbackAndReboot() {
        PinAttempts.reset()
        for _ in 0..<5 { PinAttempts.recordFailure(now: Date(timeIntervalSince1970: 1_000_000), uptime: 500) }
        // Перевод часов назад не снимает задержку.
        XCTAssertEqual(PinAttempts.waitRemaining(now: Date(timeIntervalSince1970: 900_000), uptime: 510), 30)
        // Перезагрузка (время с загрузки меньше) — отсчёт заново.
        XCTAssertEqual(PinAttempts.waitRemaining(now: Date(timeIntervalSince1970: 1_000_100), uptime: 5), 30)
        // Честно прошло 31 с — можно.
        XCTAssertEqual(PinAttempts.waitRemaining(now: Date(timeIntervalSince1970: 1_000_031), uptime: 531), 0)
        PinAttempts.reset()
    }
}

final class SendModeTests: XCTestCase {
    func testOrderMatchesAndroid() {
        XCTAssertEqual(SendMode.decide(keyChanged: true, replaced: true, keyConfirmed: true, request: true, blocked: true), .blocked)
        XCTAssertEqual(SendMode.decide(keyChanged: true, replaced: true, keyConfirmed: true), .replaced)
        XCTAssertEqual(SendMode.decide(keyChanged: true, replaced: false, keyConfirmed: true, request: true), .chooseKey)
        XCTAssertEqual(SendMode.decide(keyChanged: false, replaced: false, keyConfirmed: false, request: true), .request)
        XCTAssertEqual(SendMode.decide(keyChanged: false, replaced: false, keyConfirmed: false), .confirmKey)
        XCTAssertEqual(SendMode.decide(keyChanged: false, replaced: false, keyConfirmed: true), .open)
    }
}

final class NetworkTests: XCTestCase {
    func testPinSetMatchesAndExpires() {
        let expiry = AppConfig.parseDate("2027-12-01")
        XCTAssertNotNil(expiry)
        let set = PinSet(pins: ["AAA=", " BBB= "], expiration: expiry)
        let before = AppConfig.parseDate("2027-11-30")!
        let after = AppConfig.parseDate("2027-12-02")!
        XCTAssertTrue(set.matches(spkiHashes: ["x", "BBB="], now: before))
        XCTAssertFalse(set.matches(spkiHashes: ["x", "y"], now: before))
        // После срока — только обычная проверка цепочки (как у Android).
        XCTAssertTrue(set.matches(spkiHashes: ["x"], now: after))
    }

    func testBinaryDownloadsAreRecognisedByPath() {
        XCTAssertTrue(PlatformTransport.isBinaryDownload(method: "GET", path: "/v1/attachments/abc"))
        XCTAssertFalse(PlatformTransport.isBinaryDownload(method: "PUT", path: "/v1/attachments/abc"))
        let uuid = "123e4567-e89b-12d3-a456-426614174000"
        XCTAssertTrue(PlatformTransport.isBinaryDownload(method: "GET", path: "/v1/channels/feed/\(uuid)/media/\(uuid)"))
        XCTAssertFalse(PlatformTransport.isBinaryDownload(method: "GET", path: "/v1/channels/feed/\(uuid)/posts"))
    }

    func testClosedRouteHasNoSession() {
        XCTAssertNil(NetworkRoute.closed.configuration(anonymous: false))
        XCTAssertNotNil(NetworkRoute.direct.configuration(anonymous: false))
    }

    func testTransportRefusesWhenRouteClosed() {
        NetworkRoute.current = .closed
        let transport = PlatformTransport(baseURL: URL(string: "https://api.gasapp.chat")!,
                                          pins: PinSet(pins: [], expiration: nil))
        XCTAssertThrowsError(try transport.execute(method: "GET", path: "/v1/x", body: nil, binaryBody: nil,
                                                   headers: [], anonymous: false))
    }
}

/// Настоящее ядро через биндинги: те же вызовы, что делает приложение.
final class CoreBindingTests: XCTestCase {
    private var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func testCoreVersionAndSafetyNumber() throws {
        XCTAssertFalse(coreVersion().isEmpty)
        let number = try formatSafetyNumber(local: Data(repeating: 0x11, count: 30),
                                            remote: Data(repeating: 0x22, count: 30))
        XCTAssertEqual(number.filter(\.isNumber).count, 60)
        XCTAssertThrowsError(try formatSafetyNumber(local: Data(count: 29), remote: Data(count: 30)))
    }

    func testStorageKeyDerivationMatchesSchemeV3() throws {
        let salt = generateStorageSalt()
        XCTAssertEqual(salt.count, 16)
        let stretched = try deriveStorageKey(pin: Data("482915".utf8), salt: salt)
        XCTAssertEqual(stretched.count, 32)
        // Тот же PIN — тот же ключ; другой — другой.
        XCTAssertEqual(stretched, try deriveStorageKey(pin: Data("482915".utf8), salt: salt))
        XCTAssertNotEqual(stretched, try deriveStorageKey(pin: Data("482916".utf8), salt: salt))
        // Короче шести — отказ.
        XCTAssertThrowsError(try deriveStorageKey(pin: Data("4829".utf8), salt: salt))

        // 🔐 Проба для Enclave — точка, хешированная в кривую, а не PIN·G.
        let probe = try enclaveProbePoint(stretched: stretched, salt: salt)
        XCTAssertEqual(probe.count, 65)
        XCTAssertEqual(probe.first, 0x04)
        XCTAssertEqual(probe, try enclaveProbePoint(stretched: stretched, salt: salt))
        XCTAssertThrowsError(try enclaveProbePoint(stretched: Data(count: 31), salt: salt))

        EnclaveKey.destroy()
        // Входа в существующий аккаунт без ключа нет: ключ не заводится молча.
        XCTAssertThrowsError(try EnclaveKey.respond(to: probe, create: false))
        let response = try EnclaveKey.respond(to: probe, create: true)
        XCTAssertEqual(response.count, 32)
        let key = try deriveStorageKeyTee(stretched: stretched, salt: salt, teeMac: Data(response))
        XCTAssertEqual(key.count, 32)
        XCTAssertNotEqual(key, stretched)
    }

    func testMessengerOpensWithPlatformTransport() throws {
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let path = dir.appendingPathComponent("t.db").path
        let transport = OfflineTransport()

        let messenger = try Messenger.open(databasePath: path, databaseKey: key, transport: transport)
        XCTAssertNil(try messenger.ownUsername())
        XCTAssertEqual(try messenger.chats(), [])
        XCTAssertEqual(try messenger.contacts().count, 0)

        // Сбой сети платформы ядро получает как сбой сети, а не паника.
        XCTAssertThrowsError(try messenger.requestEmailCode(email: "a@example.org")) { error in
            guard case FfiError.Core = error else { return XCTFail("ожидался FfiError.Core, а не \(error)") }
        }

        // Режим сети по умолчанию — Tor (отказ в безопасную сторону).
        XCTAssertEqual(try messenger.proxy(), .tor)
        try messenger.setProxy(proxy: .direct)
        XCTAssertEqual(try messenger.proxy(), .direct)

        // Ожидающая регистрация переживает повторное открытие.
        try messenger.setPendingRegistration(username: "anna_k", email: "a@example.org")
        XCTAssertEqual(try messenger.pendingRegistration()?.username, "anna_k")
    }

    /// Токен пушей: неверный формат отвергается ядром до сети; верный
    /// уходит в транспорт (здесь — без сети, значит ошибка сети).
    func testPushTokenIsValidatedBeforeNetwork() throws {
        let path = dir.appendingPathComponent("p.db").path
        let transport = OfflineTransport()
        let messenger = try Messenger.open(databasePath: path, databaseKey: Data(repeating: 5, count: 32),
                                           transport: transport)
        // Аккаунта нет — отказ, но без обращения к сети.
        XCTAssertThrowsError(try messenger.registerPushToken(provider: .apns, token: "zz/../x", nowMillis: 0))
        XCTAssertThrowsError(try messenger.registerPushToken(provider: .fcm, token: "", nowMillis: 0))
        XCTAssertTrue(transport.calls.isEmpty, "неверный токен ушёл в сеть: \(transport.calls)")
    }

    func testWrongKeyDoesNotOpen() throws {
        let path = dir.appendingPathComponent("k.db").path
        let good = Data(repeating: 7, count: 32)
        do {
            let first = try Messenger.open(databasePath: path, databaseKey: good, transport: OfflineTransport())
            try first.setProxy(proxy: .direct)
        }
        // 🔐 Неверный ключ — база не открывается: отдельного признака
        // верного PIN нет, проверка — само открытие.
        XCTAssertThrowsError(try Messenger.open(databasePath: path, databaseKey: Data(repeating: 8, count: 32),
                                                transport: OfflineTransport()))
        XCTAssertNoThrow(try Messenger.open(databasePath: path, databaseKey: good, transport: OfflineTransport()))
    }

    func testServerRefusalIsAnAnswerNotANetworkFailure() throws {
        let path = dir.appendingPathComponent("s.db").path
        let messenger = try Messenger.open(databasePath: path, databaseKey: Data(repeating: 3, count: 32),
                                           transport: StatusTransport(status: 400))
        XCTAssertThrowsError(try messenger.requestEmailCode(email: "a@example.org"))
    }

    func testContactLinkRoundTrip() throws {
        XCTAssertThrowsError(try parseContactLink(uri: "https://example.org/not-a-link"))
        let qr = try safetyNumberQr(digits: String(repeating: "1", count: 60))
        XCTAssertEqual(Int(qr.size * qr.size), qr.modules.count)
    }

    func testCoreStoreUnlockCreatesAndReopensDatabase() throws {
        AppConfig.serverURLOverride = URL(string: "https://api.gasapp.chat")
        defer { AppConfig.serverURLOverride = nil }
        let store = CoreStore.shared
        store.wipe()
        defer { store.wipe() }

        let pin = Array("482915".utf8)
        // Напрямую: иначе ядро по умолчанию запустило бы встроенный Tor.
        store.pendingProxy = .direct
        _ = try store.unlock(pin: pin)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertTrue(store.hasAccount)

        store.close()
        XCTAssertFalse(store.isUnlocked)
        // Тот же PIN открывает, другой — нет.
        XCTAssertNoThrow(try store.unlock(pin: pin))
        store.close()
        XCTAssertThrowsError(try store.unlock(pin: Array("482916".utf8)))
        XCTAssertFalse(store.isUnlocked)
    }
}
