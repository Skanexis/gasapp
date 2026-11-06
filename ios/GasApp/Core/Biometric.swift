// SPDX-License-Identifier: Apache-2.0

import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif
#if canImport(Security)
import Security
#endif

/// Вход по Face ID / Touch ID — аналог `BiometricUnlock` на Android.
///
/// 🔐 Ключ базы кладётся в Keychain с доступом «только этот телефон,
/// только при текущем наборе отпечатков/лиц»: проверку лица делает
/// Secure Enclave, а не код приложения. Добавили новое лицо или палец —
/// запись перестаёт открываться, нужен PIN (`biometryCurrentSet`).
///
/// Включается только после ввода PIN, и только ключом, который
/// действительно открыл базу (`CoreStore.keyOpensStorage`): опечатка
/// в PIN не даст «включённую» биометрию, которая базу не открывает.
enum Biometric {
    private static let service = "org.gasapp.messenger.biometric"
    private static let account = "storage-key"

    enum Failure: Error { case unavailable, cancelled }

    /// Есть ли на телефоне настроенные Face ID или Touch ID.
    static var available: Bool {
        #if canImport(LocalAuthentication)
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        #else
        return false
        #endif
    }

    /// Название для интерфейса.
    static var name: String {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType == .touchID ? "Touch ID" : "Face ID"
        #else
        return "Face ID"
        #endif
    }

    static var enabled: Bool { SecureStore.int("biometric.enabled") == 1 }

    /// Запечатывает ключ базы под биометрию.
    static func enable(key: [UInt8]) throws {
        #if canImport(Security) && canImport(LocalAuthentication)
        disable()
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error)
        else { throw Failure.unavailable }

        let item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessControl as String: access,
            kSecValueData as String: Data(key),
        ]
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw Failure.unavailable }
        SecureStore.set(1, for: "biometric.enabled")
        #else
        throw Failure.unavailable
        #endif
    }

    /// Достаёт ключ — система сама показывает Face ID.
    static func key(reason: String) throws -> [UInt8] {
        #if canImport(Security) && canImport(LocalAuthentication)
        let context = LAContext()
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecUserCanceled || status == errSecAuthFailed { throw Failure.cancelled }
        guard status == errSecSuccess, let data = result as? Data else {
            // Лица или пальцы сменились — запись больше не действует.
            if status == errSecItemNotFound { disable() }
            throw Failure.unavailable
        }
        return [UInt8](data)
        #else
        throw Failure.unavailable
        #endif
    }

    static func disable() {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
        #endif
        SecureStore.set(0, for: "biometric.enabled")
    }
}
