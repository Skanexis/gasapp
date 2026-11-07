// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(Security)
import Security
#endif

/// Небольшие значения в Keychain: счётчик неверных PIN, флаги.
///
/// 🔐 Класс доступа — «только когда устройство разблокировано, только на
/// этом устройстве»: значения не уходят в резервную копию iCloud и на
/// другой телефон. Счётчик попыток, который восстанавливается из копии,
/// сбрасывался бы восстановлением.
///
/// В Linux-тестах (нет Security) — словарь в памяти.
enum SecureStore {
    private static let service = "org.gasapp.messenger.store"

    static func data(_ key: String) -> Data? {
        #if canImport(Security)
        var query = base(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
        #else
        return memory[key]
        #endif
    }

    @discardableResult
    static func set(_ value: Data, for key: String) -> Bool {
        #if canImport(Security)
        SecItemDelete(base(key) as CFDictionary)
        var item = base(key)
        item[kSecValueData as String] = value
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
        #else
        memory[key] = value
        return true
        #endif
    }

    static func remove(_ key: String) {
        #if canImport(Security)
        SecItemDelete(base(key) as CFDictionary)
        #else
        memory[key] = nil
        #endif
    }

    static func int(_ key: String) -> Int {
        guard let data = data(key), data.count == 8 else { return 0 }
        return Int(Int64(littleEndian: data.withUnsafeBytes { $0.loadUnaligned(as: Int64.self) }))
    }

    static func set(_ value: Int, for key: String) {
        var raw = Int64(value).littleEndian
        set(Data(bytes: &raw, count: 8), for: key)
    }

    /// 🔐 Стирает всё, что приложение держит в Keychain (удаление аккаунта).
    static func removeAll() {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
        #else
        memory.removeAll()
        #endif
    }

    #if canImport(Security)
    private static func base(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }
    #else
    nonisolated(unsafe) private static var memory: [String: Data] = [:]
    #endif
}

/// Счётчик неверных PIN и задержка до следующей попытки.
///
/// 🔐 Счётчик — в Keychain, а не в UserDefaults: его не сбросить
/// переустановкой поверх и не откатить копией. Время сверяется и по
/// часам, и по времени с загрузки: перевод часов назад задержку не
/// снимает, перезагрузка — начинает её отсчёт заново.
enum PinAttempts {
    private static let failuresKey = "pin.failures"
    private static let lastWallKey = "pin.last-wall"
    private static let lastUptimeKey = "pin.last-uptime"
    private static let wipeKey = "pin.wipe-enabled"

    static var failures: Int { SecureStore.int(failuresKey) }

    /// Сколько секунд ещё ждать до следующей попытки (0 — можно).
    static func waitRemaining(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> TimeInterval {
        let required = PinDelays.delay(afterFailures: failures)
        guard required > 0 else { return 0 }

        let lastWall = TimeInterval(SecureStore.int(lastWallKey))
        let lastUptime = TimeInterval(SecureStore.int(lastUptimeKey))

        // Прошедшее время — меньшее из двух оценок: часы можно перевести
        // вперёд, а время с загрузки после перезагрузки начинается с нуля.
        let byWall = now.timeIntervalSince1970 - lastWall
        let byUptime = uptime >= lastUptime ? uptime - lastUptime : 0
        let elapsed = max(0, min(byWall, byUptime))

        return max(0, required - elapsed)
    }

    static func recordFailure(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        SecureStore.set(failures + 1, for: failuresKey)
        SecureStore.set(Int(now.timeIntervalSince1970), for: lastWallKey)
        SecureStore.set(Int(uptime), for: lastUptimeKey)
    }

    /// 🔐 Засчитывает попытку **до** проверки PIN — как
    /// `PinAttempts.beginAttempt` на Android (аудит 2026-10-02, A-1).
    ///
    /// Прежде неверная попытка записывалась после проверки: убитое во
    /// время вывода ключа (Argon2 и Secure Enclave — доли секунды)
    /// приложение не записывало ничего, и PIN перебирался без задержек и
    /// без стирания. Теперь прерванная проверка остаётся неверной; верный
    /// PIN снимает её через [reset], непроверенный — через [cancelAttempt].
    ///
    /// - Returns: `false`, если запись не удалась — тогда проверять PIN
    ///   нельзя: проверка без записанной попытки и есть обход.
    static func beginAttempt(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        let before = failures
        recordFailure(now: now, uptime: uptime)
        return failures == before + 1
    }

    /// Снимает попытку, начатую [beginAttempt], не трогая прежние: PIN
    /// не сверялся вовсе (ключ Enclave недоступен, сбой не из-за PIN).
    /// 🔐 Счётчик возвращается на шаг, а не сбрасывается.
    static func cancelAttempt() {
        let current = failures
        if current > 0 { SecureStore.set(current - 1, for: failuresKey) }
    }

    static func reset() {
        SecureStore.remove(failuresKey)
        SecureStore.remove(lastWallKey)
        SecureStore.remove(lastUptimeKey)
    }

    /// Стирать ли данные после `PinDelays.wipeAfter` неверных попыток
    /// (по умолчанию выключено — как на Android).
    static var wipeEnabled: Bool {
        get { SecureStore.int(wipeKey) == 1 }
        set { SecureStore.set(newValue ? 1 : 0, for: wipeKey) }
    }

    static var shouldWipe: Bool { wipeEnabled && failures >= PinDelays.wipeAfter }
}
