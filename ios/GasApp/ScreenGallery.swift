#if GASAPP_GALLERY
import SwiftUI

/// Галерея экранов для проверки на Mac (tools/mac-check.sh).
///
/// В обычную сборку не входит: флаг GASAPP_GALLERY задаёт только скрипт
/// проверки. Экран — из переменной окружения GASAPP_SCREEN, которую
/// симулятор передаёт как SIMCTL_CHILD_GASAPP_SCREEN. Без аккаунта
/// экраны показывают пустые состояния — проверяется вёрстка.
enum ScreenGallery {
    static let names = ["onboarding", "lock", "chats", "channels", "contacts", "addcontact", "settings", "backup", "security", "privacy", "network", "vault", "storage", "bots"]

    @ViewBuilder
    static func root() -> some View {
        switch ProcessInfo.processInfo.environment["GASAPP_SCREEN"] ?? "onboarding" {
        case "lock":
            LockScreen().gasScreen()
        // Верхние экраны — внутри настоящих вкладок: на снимке видна
        // нижняя панель, как у человека в приложении.
        case "chats":
            MainTabs(start: .chats)
        case "channels":
            MainTabs(start: .channels)
        case "contacts":
            MainTabs(start: .contacts)
        case "backup":
            NavigationStack { BackupScreen() }
        case "security":
            NavigationStack { SecurityScreen() }
        case "addcontact":
            NavigationStack { AddContactScreen { _, _ in } }
        case "settings":
            MainTabs(start: .settings)
        case "privacy":
            PrivacyCover()
        case "network":
            NavigationStack { NetworkScreen() }
        case "vault":
            NavigationStack { VaultScreen() }
        case "storage":
            NavigationStack { StorageScreen() }
        case "bots":
            NavigationStack { BotsScreen() }
        default:
            OnboardingFlow()
        }
    }
}
#endif
