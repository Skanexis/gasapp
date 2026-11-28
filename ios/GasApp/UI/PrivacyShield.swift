// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// 🔐 Шторка приватности в отдельном окне — поверх всего, что есть
/// в приложении.
///
/// # Зачем своё окно
///
/// Прежде `PrivacyCover` стоял в корневом `ZStack`. Листы (`.sheet`),
/// полноэкранные обложки и системные диалоги показываются над корнем —
/// и в переключателе приложений и записи экрана открытый лист с
/// перепиской оставался виден (аудит 2026-11-28). Окно с уровнем выше
/// алертов (`.alert + 1`) закрывает и их.
///
/// Поднимается, пока сцена не активна (`.inactive`, `.background`) и пока
/// экран записывается или транслируется (`UIScreen.isCaptured`);
/// опускается, когда приложение снова активно и экран никто не снимает.
@MainActor
final class PrivacyShield {
    static let shared = PrivacyShield()

    private var window: UIWindow?
    private var inactive = false
    private var observer: NSObjectProtocol?

    private init() {}

    /// Следить за записью экрана. Повторный вызов ничего не делает.
    func start() {
        if observer == nil {
            observer = NotificationCenter.default.addObserver(
                forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
            ) { _ in
                MainActor.assumeIsolated { PrivacyShield.shared.refresh() }
            }
        }
        refresh()
    }

    /// Сцена не активна (`true`) или снова активна (`false`).
    func setInactive(_ value: Bool) {
        inactive = value
        refresh()
    }

    /// Пересчитать: поднять или опустить шторку.
    func refresh() {
        if inactive || captured {
            raise()
        } else {
            lower()
        }
    }

    private var captured: Bool {
        if let scene = scene { return scene.screen.isCaptured }
        return UIScreen.main.isCaptured
    }

    /// Сцена приложения: активная, иначе любая на экране.
    private var scene: UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first { $0.activationState == .foregroundActive }
            ?? scenes.first { $0.activationState == .foregroundInactive }
            ?? scenes.first { $0.activationState == .background }
    }

    private func raise() {
        guard let scene else { return }
        if let window, window.windowScene === scene {
            window.isHidden = false
            return
        }
        let cover = UIWindow(windowScene: scene)
        cover.windowLevel = .alert + 1
        let host = UIHostingController(rootView: PrivacyCover().preferredColorScheme(.dark))
        host.view.backgroundColor = UIColor(GasAppColor.bgBase)
        cover.rootViewController = host
        cover.overrideUserInterfaceStyle = .dark
        // Не ключевое окно: клавиатура и фокус остаются у приложения.
        cover.isHidden = false
        window = cover
    }

    private func lower() {
        window?.isHidden = true
        window = nil
    }
}
