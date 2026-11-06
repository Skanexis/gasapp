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
/// Ядро хеширует растянутый PIN **в кривую** P-256 (RFC 9380) — точка,
/// дискретного логарифма которой не знает никто. Enclave делает с ней
/// ECDH своим ключом, общий секрет хешируется SHA-256 в 32 байта.
/// Одинаковый PIN — одинаковый ответ; другой PIN — другой; без самого
/// Enclave — никакого (вычислительная задача Диффи — Хеллмана), даже
/// зная открытый ключ Enclave.
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

    /// Ответ Enclave на пробу (32 байта): `SHA-256(x(d · P))`.
    ///
    /// `probe` — точка-проба из ядра (`enclavePointProbe`): растянутый PIN,
    /// **хешированный в кривую**. 🔐 Не `PIN · G`: тогда ответ считался бы
    /// из открытого ключа Enclave без самого Enclave, и файл базы
    /// перебирался бы вне телефона (так было в первой версии — найдено
    /// на проверке; подробности — `gasapp_keystore::pin::enclave_probe`).
    ///
    /// `create` — завести ключ, если его нет: только при регистрации.
    /// 🔐 При входе в существующий аккаунт новый ключ не заводится: он
    /// всё равно не открыл бы базу, а неверный PIN и потерянный ключ
    /// выглядели бы одинаково.
    static func respond(to probe: Data, create: Bool) throws -> [UInt8] {
        #if canImport(CryptoKit) && canImport(Security)
        guard probe.count == 65, let key = try loadKey() ?? (create ? createKey() : nil) else {
            throw Failure.unavailable
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let peer = SecKeyCreateWithData(probe as CFData, attributes as CFDictionary, nil),
              let shared = SecKeyCopyKeyExchangeResult(
                key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, nil) as Data?
        else { throw Failure.unavailable }

        return Array(SHA256.hash(data: shared))
        #else
        // Linux-тесты: без оборудования — секрет в памяти, детерминированно.
        if testKey == nil {
            guard create else { throw Failure.unavailable }
            testKey = (0..<32).map { _ in UInt8.random(in: 0...255) }
        }
        let secret = testKey ?? []
        return Array(probe.prefix(32)).enumerated().map { $1 ^ secret[$0 % secret.count] }
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

