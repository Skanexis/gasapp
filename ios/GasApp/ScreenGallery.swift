#if GASAPP_GALLERY
import SwiftUI

/// Галерея экранов для проверки на Mac (tools/mac-check.sh).
///
/// В обычную сборку не входит: флаг GASAPP_GALLERY задаёт только скрипт
/// проверки. Экран — из переменной окружения GASAPP_SCREEN, которую
/// симулятор передаёт как SIMCTL_CHILD_GASAPP_SCREEN.
enum ScreenGallery {
    static let names = ["ffi", "onboarding", "lock", "chats", "chat"]

    @ViewBuilder
    static func root() -> some View {
        switch ProcessInfo.processInfo.environment["GASAPP_SCREEN"] ?? "ffi" {
        case "onboarding":
            OnboardingView(onRegister: { _, _ in })
        case "lock":
            LockView(onUnlock: { _ in })
        case "chats":
            ChatListView(onOpenChat: { _ in }, onNewChat: {}, onSecurityCenter: {})
        case "chat":
            ChatView(peerName: "Анна", peerUsername: "anna_k", isVerified: true,
                     onVerify: {}, onBack: {})
        default:
            ContentView()
        }
    }
}
#endif
