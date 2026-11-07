// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Настройки сборки (ios/Config/*.xcconfig → Info.plist).
///
/// 🔐 Адрес сервера, onion-адрес и пины задаёт **сборка**, а не сервер:
/// подменить их сервер не может — как `BuildConfig` на Android.
enum AppConfig {
    private static func value(_ key: String) -> String {
        let raw = Bundle.main.object(forInfoDictionaryKey: key) as? String ?? ""
        // Незаменённая переменная сборки — то же, что пустое значение.
        return raw.hasPrefix("$(") ? "" : raw.trimmingCharacters(in: .whitespaces)
    }

    static var serverURL: URL? { serverURLOverride ?? URL(string: value("GASAPPServerURL")) }

    /// Только для тестов слоя ядра (нет Info.plist).
    nonisolated(unsafe) static var serverURLOverride: URL?

    /// «адрес.onion:443» или nil.
    static var serverOnion: String? {
        let onion = value("GASAPPServerOnion")
        return onion.isEmpty ? nil : onion
    }

    static var docsURL: URL { URL(string: value("GASAPPDocsURL")) ?? URL(string: "https://gasapp.eu")! }

    static var pins: PinSet {
        let list = value("GASAPPPins").split(separator: ",").map(String.init)
        return PinSet(pins: list, expiration: parseDate(value("GASAPPPinExpiration")))
    }

    static func parseDate(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.date(from: text)
    }
}
