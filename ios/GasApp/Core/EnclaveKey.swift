// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

/// 🔐 Ответ Secure Enclave на растянутый PIN — вторая половина ключа базы.
///
/// Аналог `TeeKey` на Android. Ключ базы — `HKDF(PIN после Argon2id ‖
/// ответ оборудования)` (`derive_storage_key_tee` ядра). Ответ даёт ключ
/// P-256, который создан **внутри** Secure Enclave и оттуда не
/// извлекается: снятый с телефона файл базы вместе с солью не
/// перебирается на чужих машинах — каждая попытка требует этого самого
/// телефона.
///
/// # Как получается ответ
///
/// Растянутый PIN берётся скаляром ключа P-256 программно, его открытая
/// точка отдаётся Secure Enclave на ECDH, а общий секрет хешируется
/// SHA-256 в 32 байта. Одинаковый PIN — одинаковый ответ; другой PIN —
/// другой; без самого Enclave — никакого.
///
/// ⚠️ В симуляторе Secure Enclave нет: там ключ — обычный, в Keychain.
/// Это только для разработки; на телефоне всегда Enclave.
enum EnclaveKey {
    enum Failure: Error {
        /// Ключа в Enclave нет или он недоступен (телефон заблокирован,
        /// приложение переустановлено с восстановлением из копии).
        case unavailable
    }

    private static let tag = Data("org.gasapp.messenger.storage-key".utf8)

    /// Есть ли уже ключ (заведён при регистрации).
    static var exists: Bool {
        #if canImport(Security)
        return loadKey() != nil
        #else
        return testKey != nil
        #endif
    }

    /// Ответ на растянутый PIN (32 байта). Ключа нет — создаётся.
    static func respond(to stretched: [UInt8]) throws -> [UInt8] {
        #if canImport(CryptoKit) && canImport(Security)
        guard stretched.count == 32,
              let probe = try? P256.KeyAgreement.PrivateKey(rawRepresentation: Data(stretched).reducedScalar)
        else { throw Failure.unavailable }

        let key = try loadKey() ?? createKey()
        let point = probe.publicKey.x963Representation as CFData

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let peer = SecKeyCreateWithData(point, attributes as CFDictionary, nil),
              let shared = SecKeyCopyKeyExchangeResult(
                key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, nil) as Data?
        else { throw Failure.unavailable }

        return Array(SHA256.hash(data: shared))
        #else
        // Linux-тесты: детерминированный ответ без оборудования.
        if testKey == nil { testKey = (0..<32).map { _ in UInt8.random(in: 0...255) } }
        return zip(stretched, testKey ?? []).map { $0 ^ $1 }
        #endif
    }

    /// 🔐 Уничтожает ключ: база под ним больше не откроется ничем.
    static func destroy() {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ]
        SecItemDelete(query as CFDictionary)
        #else
        testKey = nil
        #endif
    }

    #if canImport(Security)
    private static func loadKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else { return nil }
        return (item as! SecKey)
    }

    private static func createKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        // 🔐 Только на этом устройстве и только пока оно разблокировано.
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error)
        else { throw Failure.unavailable }

        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
        ]
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        #if targetEnvironment(simulator)
        privateAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #else
        privateAttributes[kSecAttrAccessControl as String] = access
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        attributes[kSecPrivateKeyAttrs as String] = privateAttributes

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Failure.unavailable
        }
        return key
    }
    #else
    nonisolated(unsafe) private static var testKey: [UInt8]?
    #endif
}

private extension Data {
    /// Скаляр P-256 из 32 случайных байт: 0 и значения ≥ порядка группы
    /// ключом не являются. Вероятность попасть в них — около 2⁻³²,
    /// но тогда ответ не построился бы вовсе; первый байт сбрасывается
    /// до значения меньше порядка, а нулевой ключ исключается.
    var reducedScalar: Data {
        var bytes = [UInt8](self)
        // Порядок P-256 начинается с 0xFFFFFFFF00000000…: старший байт
        // меньше 0xFF гарантирует значение ниже порядка.
        if bytes[0] == 0xFF { bytes[0] = 0x7F }
        if bytes.allSatisfy({ $0 == 0 }) { bytes[31] = 1 }
        return Data(bytes)
    }
}
