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
        // Вложенные экраны — открытыми из своей вкладки, как у человека:
        // со стрелкой «назад» и нижней панелью.
        case "backup":
            MainTabs(start: .settings, pushed: AnyView(BackupScreen()))
        case "security":
            MainTabs(start: .settings, pushed: AnyView(SecurityScreen()))
        case "addcontact":
            MainTabs(start: .contacts, pushed: AnyView(AddContactScreen { _, _ in }))
        case "settings":
            MainTabs(start: .settings)
        case "privacy":
            PrivacyCover()
        case "network":
            MainTabs(start: .settings, pushed: AnyView(NetworkScreen()))
        case "vault":
            MainTabs(start: .settings, pushed: AnyView(VaultScreen()))
        case "storage":
            MainTabs(start: .settings, pushed: AnyView(StorageScreen()))
        // «Мои боты» — лист поверх каналов, как в приложении.
        case "bots":
            MainTabs(start: .channels)
                .sheet(isPresented: .constant(true)) {
                    NavigationStack {
                        BotsScreen()
                            .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) {} } }
                    }
                }
        default:
            OnboardingFlow()
        }
    }
}
#endif
