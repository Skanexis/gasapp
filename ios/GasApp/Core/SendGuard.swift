// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Можно ли писать в чат и что показать вместо поля ввода — то же
/// решение, что `SendGuard.kt` на Android.
///
/// 🔐 Это подсказка интерфейсу, а не защита: отправку с неподтверждённым
/// или сменившимся ключом отвергает ядро (`IdentityChanged`,
/// `PeerUnconfirmed`). Интерфейс лишь заранее объясняет почему.
enum SendMode: Equatable {
    /// Писать можно.
    case open
    /// Собеседник заблокирован человеком.
    case blocked
    /// Ключ собеседника сменился: сначала сверить.
    case chooseKey
    /// Запрос от незнакомца: принять или отклонить.
    case request
    /// Ключ назвал только сервер: сверить код безопасности или
    /// добавить по ссылке/QR самого собеседника.
    case confirmKey
    /// Аккаунт собеседника заменён другим.
    case replaced

    static func decide(
        keyChanged: Bool, replaced: Bool, keyConfirmed: Bool,
        request: Bool = false, blocked: Bool = false
    ) -> SendMode {
        // Блокировка — решение человека, оно важнее всего.
        if blocked { return .blocked }
        if replaced { return .replaced }
        if keyChanged { return .chooseKey }
        // Сначала согласие, потом сверка: сверять ключ с тем, с кем
        // человек не собирается разговаривать, незачем.
        if request { return .request }
        if !keyConfirmed { return .confirmKey }
        return .open
    }
}
