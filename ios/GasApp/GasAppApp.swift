import SwiftUI

@main
struct GasAppApp: App {
    /// Только ради токена пуш-уведомлений (APNs): SwiftUI его не отдаёт.
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
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
    @Environment(\.isSceneCaptured) private var isCaptured

    var body: some View {
        ZStack {
            GasAppColor.bgBase.ignoresSafeArea()

            switch model.phase {
            case .onboarding: OnboardingFlow()
            case .locked: LockScreen()
            case .unlocked: MainTabs()
            }

            // 🔐 Пока приложение не активно — шторка: снимок экрана для
            // переключателя приложений не покажет переписку. То же — пока
            // экран записывается или транслируется (AirPlay, запись экрана).
            if model.coverVisible || isCaptured {
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
