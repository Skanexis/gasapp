// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Состояние приложения: регистрация → блокировка → работа.
///
/// 🔐 База открыта только в фазе `.unlocked`. Уход в фон дольше
/// [autoLockAfter] закрывает её ([CoreStore.close]): ключ больше не
/// держится в памяти, и вернуться можно только по PIN.
@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case onboarding
        case locked
        case unlocked
    }

    private(set) var phase: Phase
    /// Шторка поверх содержимого, пока приложение не активно: снимок для
    /// переключателя приложений не покажет переписку.
    var coverVisible = false

    /// Сколько можно пробыть в фоне без повторного PIN.
    let autoLockAfter: TimeInterval = 30
    private var backgroundSince: Date?

    init() {
        phase = CoreStore.shared.hasAccount ? .locked : .onboarding
    }

    /// После успешного PIN или регистрации.
    func didUnlock() {
        phase = .unlocked
    }

    /// 🔐 Запереть сейчас.
    func lock() {
        // Приём останавливается вместе с базой: без неё ему нечем работать.
        Inbox.shared.stop()
        CoreStore.shared.close()
        phase = CoreStore.shared.hasAccount ? .locked : .onboarding
    }

    /// 🔐 Всё стёрто (удаление аккаунта, стирание после неверных PIN).
    func didWipe() {
        Inbox.shared.stop()
        CoreStore.shared.wipe()
        phase = .onboarding
    }

    func scenePhaseChanged(_ scene: ScenePhase) {
        switch scene {
        case .active:
            coverVisible = false
            if let since = backgroundSince, Date().timeIntervalSince(since) > autoLockAfter, phase == .unlocked {
                lock()
            }
            backgroundSince = nil
        case .inactive:
            coverVisible = true
        case .background:
            coverVisible = true
            backgroundSince = backgroundSince ?? Date()
        @unknown default:
            coverVisible = true
        }
    }
}

/// Работа с ядром — не в главном потоке: вызовы ядра блокируют
/// (сеть, Argon2id), и главный поток встал бы вместе с интерфейсом.
enum Background {
    static func run<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
        try await Task.detached(priority: .userInitiated) { try work() }.value
    }
}
