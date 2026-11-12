// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Ссылка на контакт в двух видах.
///
/// * `https://gasapp.eu/add/#KEY.PQ?name=…` — для людей: мессенджеры
///   делают её кликабельной; с установленным GasApp iPhone открывает
///   приложение (Universal Links, `applinks:gasapp.eu`), без него —
///   страницу сайта со ссылкой на App Store.
/// * `gasapp://contact/KEY.PQ?name=…` — то, что разбирает ядро
///   (`parseContactLink`, `addContactFromLink`), и то, что лежит в QR.
///
/// 🔐 Ключ стоит после `#`: эту часть адреса браузер не отправляет на
/// сервер, поэтому сайт не узнаёт, чью ссылку открыли. И ссылка ничего
/// не добавляет сама: приложение сначала спрашивает человека.
enum ContactLinks {
    static let appPrefix = "gasapp://contact/"
    static let webPrefix = "https://gasapp.eu/add/#"

    private static let webPages = [
        "https://gasapp.eu/add/", "https://gasapp.eu/add",
        "https://www.gasapp.eu/add/", "https://www.gasapp.eu/add",
    ]

    /// Любой вид ссылки → вид для ядра; nil — это не ссылка на контакт.
    static func appLink(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix(appPrefix) {
            return appPrefix + trimmed.dropFirst(appPrefix.count)
        }
        guard let hash = trimmed.firstIndex(of: "#") else { return nil }
        let page = trimmed[..<hash].lowercased()
        let payload = trimmed[trimmed.index(after: hash)...]
        guard webPages.contains(page), !payload.isEmpty else { return nil }
        return appPrefix + payload
    }

    /// Вид для ядра → вид для людей (кнопка «Поделиться»).
    static func webLink(from appLink: String) -> String {
        guard appLink.hasPrefix(appPrefix) else { return appLink }
        return webPrefix + appLink.dropFirst(appPrefix.count)
    }
}
