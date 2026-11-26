// SPDX-License-Identifier: Apache-2.0

import Foundation
import SwiftUI

/// Ссылка на канал в двух видах — как у контакта ([ContactLinks]).
///
/// * `https://gasapp.eu/c/#…` — для людей: в Telegram, WhatsApp, почте её
///   можно нажать; с GasApp iPhone открывает приложение (Universal Links),
///   без него — страницу сайта. Прежде делились `gasapp://channel/…`, и в
///   других мессенджерах ссылка была просто текстом.
/// * `gasapp://channel/…` и `gasapp://channel-join/…` — то, что разбирает
///   ядро (`joinChannel`, `requestChannelJoin`), и то, что лежит в QR.
///
/// 🔐 Секрет канала — после «#»: на сервер сайта он не попадает.
enum ChannelLinks {
    static let openPrefix = "gasapp://channel/"
    static let joinPrefix = "gasapp://channel-join/"
    static let webPrefix = "https://gasapp.eu/c/#"
    /// Закрытый канал: в веб-ссылке — с этой меткой.
    static let webJoinMark = "join/"

    private static let webPages = [
        "https://gasapp.eu/c/", "https://gasapp.eu/c",
        "https://www.gasapp.eu/c/", "https://www.gasapp.eu/c",
    ]

    /// Вид для ядра — из любой формы; `nil` — это не ссылка на канал.
    static func appLink(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        for prefix in [joinPrefix, openPrefix] where trimmed.lowercased().hasPrefix(prefix) {
            return prefix + trimmed.dropFirst(prefix.count)
        }
        guard let hash = trimmed.firstIndex(of: "#") else { return nil }
        let page = trimmed[..<hash].lowercased()
        let payload = String(trimmed[trimmed.index(after: hash)...])
        guard webPages.contains(page), !payload.isEmpty else { return nil }
        if payload.hasPrefix(webJoinMark) {
            let rest = payload.dropFirst(webJoinMark.count)
            return rest.isEmpty ? nil : joinPrefix + rest
        }
        return openPrefix + payload
    }

    /// Вид для людей — им делятся.
    static func webLink(from appLink: String) -> String {
        if appLink.hasPrefix(joinPrefix) { return webPrefix + webJoinMark + appLink.dropFirst(joinPrefix.count) }
        if appLink.hasPrefix(openPrefix) { return webPrefix + appLink.dropFirst(openPrefix.count) }
        return appLink
    }
}

/// Куда ведёт ссылка, нажатая в переписке или в канале.
enum AppLink: Equatable {
    case contact(String)
    case channel(String)
    /// Нажатое `@имя` — как ссылка на контакт (см. `LinkText`).
    case mention(String)
    /// Заявка на администрирование канала, присланная владельцу в чат.
    case adminRequest(String)

    static let adminRequestPrefix = "gasapp://channel-admin/"

    /// Канал заявки (UUID строчными) — по первой части заявки.
    static func channelId(ofAdminRequest request: String) -> String? {
        guard request.lowercased().hasPrefix(adminRequestPrefix) else { return nil }
        let hex = request.dropFirst(adminRequestPrefix.count).prefix { $0 != "." }.lowercased()
        guard hex.count == 32, hex.allSatisfy(\.isHexDigit) else { return nil }
        let chars = Array(hex)
        let parts = [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(chars[$0]) }
        return parts.joined(separator: "-")
    }

    /// Схема, которой `LinkText` размечает `@имя` в тексте.
    static let mentionPrefix = "gasapp://mention/"

    /// `nil` — чужая ссылка (её открывает система).
    init?(_ url: URL) {
        let text = url.absoluteString
        if text.lowercased().hasPrefix(Self.adminRequestPrefix) {
            self = .adminRequest(text)
            return
        }
        if text.lowercased().hasPrefix(Self.mentionPrefix) {
            let name = String(text.dropFirst(Self.mentionPrefix.count))
            guard !name.isEmpty else { return nil }
            self = .mention(name)
            return
        }
        if let contact = ContactLinks.appLink(from: text) {
            self = .contact(contact)
        } else if let channel = ChannelLinks.appLink(from: text) {
            self = .channel(channel)
        } else {
            return nil
        }
    }
}

/// Текст сообщения со ссылками, которые можно нажать.
///
/// Ссылки GasApp (контакт, канал) открываются в приложении, остальные
/// `https` — в браузере (см. `AppModel.route`). Сам текст не меняется:
/// размечаются только найденные адреса.
enum LinkText {
    private static let pattern = try? NSRegularExpression(
        pattern: #"(gasapp://(contact|channel|channel-join|channel-admin)/[^\s]+|https?://[^\s]+)"#,
        options: [.caseInsensitive]
    )
    /// Знаки, которыми фраза заканчивается, а адрес — нет.
    private static let trailing = CharacterSet(charactersIn: ".,;:!?)»”'\"")

    /// `@имя` — по правилу имён (3–32 знака: латиница, цифры, «_»), не
    /// посреди слова: адрес почты упоминанием не считается.
    private static let mention = try? NSRegularExpression(
        pattern: #"(?<![A-Za-z0-9_@.])@([A-Za-z0-9_]{3,32})(?![A-Za-z0-9_])"#
    )

    static func attributed(_ text: String, link color: Color) -> AttributedString {
        var result = AttributedString(text)
        if text.contains("@"), let mention {
            let whole = NSRange(text.startIndex..., in: text)
            for match in mention.matches(in: text, range: whole) {
                guard let range = Range(match.range, in: text),
                      let nameRange = Range(match.range(at: 1), in: text),
                      let url = URL(string: AppLink.mentionPrefix + text[nameRange].lowercased()),
                      let lower = AttributedString.Index(range.lowerBound, within: result),
                      let upper = AttributedString.Index(range.upperBound, within: result) else { continue }
                result[lower..<upper].link = url
                result[lower..<upper].foregroundColor = color
            }
        }
        guard let pattern, text.contains("://") else { return result }
        let whole = NSRange(text.startIndex..., in: text)
        for match in pattern.matches(in: text, range: whole) {
            guard var range = Range(match.range, in: text) else { continue }
            // Точка или скобка в конце фразы — не часть адреса.
            while range.lowerBound < range.upperBound,
                  let last = text[range].unicodeScalars.last, trailing.contains(last) {
                range = range.lowerBound..<text.index(before: range.upperBound)
            }
            guard range.lowerBound < range.upperBound,
                  let url = URL(string: String(text[range])),
                  let lower = AttributedString.Index(range.lowerBound, within: result),
                  let upper = AttributedString.Index(range.upperBound, within: result) else { continue }
            result[lower..<upper].link = url
            result[lower..<upper].foregroundColor = color
            result[lower..<upper].underlineStyle = .single
        }
        return result
    }
}
