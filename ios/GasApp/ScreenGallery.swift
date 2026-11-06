#if GASAPP_GALLERY
import SwiftUI

/// Галерея экранов для проверки на Mac (tools/mac-check.sh).
///
/// В обычную сборку не входит: флаг GASAPP_GALLERY задаёт только скрипт
/// проверки. Экран — из переменной окружения GASAPP_SCREEN, которую
/// симулятор передаёт как SIMCTL_CHILD_GASAPP_SCREEN. Без аккаунта
/// экраны показывают пустые состояния — проверяется вёрстка.
enum ScreenGallery {
    static let names = ["onboarding", "lock", "chats", "addcontact", "settings", "privacy"]

    @ViewBuilder
    static func root() -> some View {
        switch ProcessInfo.processInfo.environment["GASAPP_SCREEN"] ?? "onboarding" {
        case "lock":
            LockScreen().gasScreen()
        case "chats":
            ChatListScreen()
        case "addcontact":
            NavigationStack { AddContactScreen { _, _ in } }
        case "settings":
            NavigationStack { SettingsScreen() }
        case "privacy":
            PrivacyCover()
        default:
            OnboardingFlow()
        }
    }
}
#endif
