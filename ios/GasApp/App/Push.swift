// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UserNotifications

/// Пустые пуш-уведомления Apple (APNs).
///
/// 🔐 Сервер (служба `gasapp-server-admin push` на машине базы) просит
/// Apple показать «Новое сообщение» — ключом строки `PUSH_NEW_MESSAGE`,
/// которую телефон переводит сам (`Localizable.strings`). Ни текста, ни
/// имени, ни чата: Apple видит лишь, что устройству что-то пришло, и
/// когда. Чаще раза в минуту сервер одно устройство не будит.
///
/// Токен называется серверу после каждого входа (он подписан ключом
/// устройства, а ключ доступен только при открытой базе) — Apple меняет
/// токен без спроса.
@MainActor
final class Push: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Push()

    private static let enabledKey = "push.enabled"

    /// Включены ли уведомления (по умолчанию — да; выключаются в настройках).
    var enabled: Bool {
        get { SecureStore.int(Self.enabledKey) != 2 }
        set { SecureStore.set(newValue ? 1 : 2, for: Self.enabledKey) }
    }

    private var pendingToken: String?

    /// После входа: спросить разрешение (один раз) и зарегистрироваться.
    func sync() {
        UNUserNotificationCenter.current().delegate = self
        guard enabled else {
            disable()
            return
        }
        Task {
            let center = UNUserNotificationCenter.current()
            let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
            if granted {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }

    /// Выключить: Apple — не будить, сервер — забыть токен. Только если
    /// токен был назван: иначе отзывать нечего.
    func disable() {
        guard SecureStore.int(Self.registeredKey) == 1 else { return }
        UIApplication.shared.unregisterForRemoteNotifications()
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task.detached(priority: .userInitiated) {
            if (try? messenger.unregisterPushToken(nowMillis: CoreStore.nowMillis)) != nil {
                await MainActor.run { SecureStore.set(0, for: Push.registeredKey) }
            }
        }
    }

    private static let registeredKey = "push.registered"

    /// Токен от Apple → серверу (за подписью устройства).
    func didRegister(token: Data) {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        pendingToken = hex
        send()
    }

    /// Отправляет токен, если база открыта; иначе — при следующем входе.
    func send() {
        guard enabled, let hex = pendingToken, let messenger = try? CoreStore.shared.current() else { return }
        // Отладочная сборка из Xcode получает токен песочницы APNs;
        // TestFlight и App Store — боевой.
        #if DEBUG
        let provider = FfiPushProvider.apnsSandbox
        #else
        let provider = FfiPushProvider.apns
        #endif
        Task.detached(priority: .userInitiated) {
            if (try? messenger.registerPushToken(provider: provider, token: hex, nowMillis: CoreStore.nowMillis)) != nil {
                await MainActor.run { SecureStore.set(1, for: Push.registeredKey) }
            }
        }
    }

    // MARK: - UNUserNotificationCenterDelegate

    /// Приложение открыто — баннер не нужен: новое и так на экране.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([])
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        // Нажатие открывает приложение — дальше экран входа по PIN.
        completionHandler()
    }
}

/// Делегат приложения — только ради токена APNs: SwiftUI его не отдаёт.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in Push.shared.didRegister(token: deviceToken) }
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // Без пушей приложение работает: сообщения придут при открытии.
    }

    /// 🔐 Сторонние клавиатуры — не в GasApp: с «полным доступом» они
    /// вправе отправлять набранное в сеть, то есть читать переписку до
    /// шифрования. Внутри приложения — только системная.
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier identifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        identifier != .keyboard
    }
}
