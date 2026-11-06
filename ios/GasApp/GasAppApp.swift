import SwiftUI

@main
struct GasAppApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            #if GASAPP_GALLERY
            // Сборка проверки на Mac (tools/mac-check.sh): экран выбирается
            // переменной GASAPP_SCREEN, чтобы снять снимок каждого.
            ScreenGallery.root()
                .environment(model)
            #else
            RootView()
                .environment(model)
                .onChange(of: scenePhase) { _, phase in model.scenePhaseChanged(phase) }
            #endif
        }
    }
}

/// Корень: экран по фазе приложения и шторка поверх всего.
struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ZStack {
            GasAppColor.bgBase.ignoresSafeArea()

            switch model.phase {
            case .onboarding: OnboardingFlow()
            case .locked: LockScreen()
            case .unlocked: ChatListScreen()
            }

            // 🔐 Пока приложение не активно — шторка: снимок экрана для
            // переключателя приложений не покажет переписку.
            if model.coverVisible {
                PrivacyCover()
            }
        }
        .preferredColorScheme(.dark)
        .tint(GasAppColor.accent)
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            GasAppColor.bgBase.ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 44, weight: .bold))
                    .foregroundStyle(GasAppColor.accent)
                Text("GasApp")
                    .font(.system(size: 28, weight: .heavy, design: .rounded))
                    .foregroundStyle(GasAppColor.textPrimary)
            }
        }
    }
}
