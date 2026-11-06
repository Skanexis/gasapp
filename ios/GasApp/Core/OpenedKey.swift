// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Отпечаток ключа открытой базы — аналог `OpenedKey.kt` на Android.
///
/// Нужен одному: при включении Face ID убедиться, что ключ из введённого
/// PIN действительно открывает базу. Хранится SHA-256 ключа, а не сам
/// ключ, и только пока база открыта.
struct OpenedKey {
    private var digest: Data?

    mutating func remember(_ key: [UInt8]) { digest = Self.hash(key) }
    mutating func forget() { digest = nil }
    func matches(_ key: [UInt8]) -> Bool { digest != nil && digest == Self.hash(key) }

    private static func hash(_ key: [UInt8]) -> Data {
        #if canImport(CryptoKit)
        return Data(SHA256.hash(data: Data(key)))
        #else
        // Linux-тесты: без CryptoKit сравнение по самим байтам.
        return Data(key)
        #endif
    }
}
