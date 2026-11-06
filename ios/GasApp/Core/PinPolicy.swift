// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Правила PIN — те же, что у Android (`core/Pin.kt`).
///
/// 🔐 PIN ровно из шести цифр ASCII: экран входа набирает ровно столько.
/// PIN другой длины дал бы ключ, который экран входа не воспроизведёт,
/// и база больше не открылась бы.
enum PinPolicy {
    static let length = 6

    /// Годится ли PIN: шесть цифр `0`–`9` (не «любые цифры Unicode»).
    static func isAcceptable(_ pin: [UInt8]) -> Bool {
        pin.count == length && pin.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    /// 🔐 Слишком ли PIN прост: такие перебирают первыми.
    static func isTooSimple(_ pin: [UInt8]) -> Bool {
        guard isAcceptable(pin) else { return false }

        let digits = pin.map { Int($0) - 0x30 }
        // Шаг по модулю 10: 135791 и 789012 «переходят» через 9 → 0.
        let steps = Set(zip(digits, digits.dropFirst()).map { ($1 - $0 + 10) % 10 })

        // 111111, 123456, 654321, 135791 — шаг один и тот же.
        if steps.count == 1 { return true }
        // 121212 — повтор пары; 123123 — повтор тройки.
        if (2..<length).allSatisfy({ digits[$0] == digits[$0 - 2] }) { return true }
        if (3..<length).allSatisfy({ digits[$0] == digits[$0 - 3] }) { return true }
        // 112233, 111222 — пары одинаковых.
        if stride(from: 0, to: length, by: 2).allSatisfy({ digits[$0] == digits[$0 + 1] }),
           Set(digits).count <= 3 {
            return true
        }

        return common.contains(String(decoding: pin, as: UTF8.self))
    }

    /// Частые PIN, которых не ловят правила выше (как в `Pin.kt`).
    private static let common: Set<String> = [
        "159753", "147258", "258369", "789456", "456123", "147852",
        "963852", "142536", "100200", "696969", "102030", "131313",
        "123654", "123321", "654456", "112358", "111222", "000111",
        "111000", "222111",
    ]
}

/// Задержки после неверных PIN — та же таблица, что `PinAttempts.kt`.
enum PinDelays {
    static let freeAttempts = 3
    static let wipeAfter = 10
    private static let maxDoublings = 20

    /// Сколько ждать после `failures` неверных попыток подряд, в секундах.
    static func delay(afterFailures failures: Int) -> TimeInterval {
        switch failures {
        case ...freeAttempts: return 0
        case 4: return 5
        case 5: return 30
        case 6: return 5 * 60
        case 7: return 30 * 60
        default:
            // 8 → час, 9 → два, 10 → четыре… Сдвиг ограничен, чтобы не
            // переполниться в отрицательную задержку.
            let steps = min(failures - 8, maxDoublings)
            return 3600 * pow(2, Double(steps))
        }
    }
}
