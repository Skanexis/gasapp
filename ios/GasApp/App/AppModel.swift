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

    /// Ссылка на контакт, с которой открыли приложение (Universal Link
    /// или `gasapp://contact/…`). Ждёт, пока откроется список чатов: там
    /// человек подтверждает, добавлять ли контакт. До PIN и регистрации
    /// она просто лежит здесь.
    var pendingContactLink: String?

    /// Приложение открыли по ссылке.
    func openURL(_ url: URL) {
        if let link = ContactLinks.appLink(from: url.absoluteString) {
            pendingContactLink = link
        }
    }
    /// Шторка поверх содержимого, пока приложение не активно: снимок для
    /// переключателя приложений не покажет переписку.
    var coverVisible = false

    /// Сколько можно пробыть в фоне без повторного PIN.
    var autoLockAfter: TimeInterval { TimeInterval(Self.autoLockSeconds) }

    /// Время до автоблокировки в фоне (настройки): 0 — сразу. По умолчанию
    /// 60 секунд — как `Settings.AUTO_LOCK_DEFAULT` на Android. В Keychain значение хранится со сдвигом на 1, чтобы
    /// «не задано» (0) отличалось от «сразу».
    static var autoLockSeconds: Int {
        get {
            let stored = SecureStore.int("autolock.seconds")
            return stored == 0 ? 60 : stored - 1
        }
        set { SecureStore.set(newValue + 1, for: "autolock.seconds") }
    }
    private var backgroundSince: Date?

    init() {
        phase = CoreStore.shared.hasAccount ? .locked : .onboarding
    }

    /// После успешного PIN или регистрации.
    func didUnlock() {
        phase = .unlocked
        // Токен пушей подписывается ключом устройства — он доступен
        // только сейчас, при открытой базе.
        Push.shared.sync()
        Push.shared.send()
    }

    /// Регистрация, прерванная на шаге кода: база открыта, имя и почта —
    /// в ней. Экран регистрации продолжит с кода.
    private(set) var resume: FfiPendingRegistration?

    func resumeRegistration(_ pending: FfiPendingRegistration) {
        resume = pending
        phase = .onboarding
    }

    func takeResume() -> FfiPendingRegistration? {
        defer { resume = nil }
        return resume
    }

    /// 🔐 Запереть сейчас.
    func lock() {
        // Приём останавливается вместе с базой: без неё ему нечем работать.
        Inbox.shared.stop()
        // 🔐 Расшифрованные вложения — только до блокировки.
        AttachmentCache.shared.clear()
        CoreStore.shared.close()
        phase = CoreStore.shared.hasAccount ? .locked : .onboarding
    }

    /// 🔐 Всё стёрто (удаление аккаунта, стирание после неверных PIN).
    func didWipe() {
        AttachmentCache.shared.clear()
        Inbox.shared.stop()
        CoreStore.shared.wipe()
        phase = .onboarding
    }

    func scenePhaseChanged(_ scene: ScenePhase) {
        switch scene {
        case .active:
            coverVisible = false
            // Соединения не пережили фон — новые при первом запросе.
            if backgroundSince != nil { PlatformTransport.resetConnections() }
            if let since = backgroundSince, Date().timeIntervalSince(since) > autoLockAfter, phase == .unlocked {
                lock()
            }
            if let since = backgroundSince, phase == .unlocked {
                // Порт моста Tor не переживает фон — поднять заново и сразу
                // забрать очередь (NetworkController, «Почему Tor
                // перезапускается после фона»).
                NetworkController.shared.didReturnToForeground(afterSeconds: Date().timeIntervalSince(since))
                Task { await Inbox.shared.receiveOnce() }
            }
            backgroundSince = nil
        case .inactive:
            coverVisible = true
        case .background:
            coverVisible = true
            backgroundSince = backgroundSince ?? Date()
            // 🔐 Хранилище файлов закрывается сразу при уходе в фон, не
            // дожидаясь таймаута (`onBackground`, как на Android).
            if let messenger = try? CoreStore.shared.current() { try? messenger.onBackground() }
            VaultFiles.clearOpened()
            scheduleBackgroundLock()
        @unknown default:
            coverVisible = true
        }
    }

    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    /// 🔐 Запирает базу через [autoLockAfter] в фоне — не дожидаясь
    /// возвращения. Иначе ключ базы жил бы в памяти приостановленного
    /// приложения сколько угодно, в том числе на заблокированном
    /// телефоне. iOS даёт фоновому заданию около 30 секунд; отбирает
    /// раньше — запираем сразу.
    private func scheduleBackgroundLock() {
        // «Сразу» — без ожидания и без фонового задания.
        if phase == .unlocked && autoLockAfter <= 0 {
            lock()
            return
        }
        guard phase == .unlocked, backgroundTask == .invalid else { return }
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "gasapp-autolock") { [weak self] in
            Task { @MainActor in self?.finishBackgroundLock(force: true) }
        }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64((self?.autoLockAfter ?? 30) * 1_000_000_000))
            self?.finishBackgroundLock(force: false)
        }
    }

    private func finishBackgroundLock(force: Bool) {
        let stillAway = backgroundSince != nil
        if stillAway && phase == .unlocked && (force || Date().timeIntervalSince(backgroundSince ?? Date()) >= autoLockAfter - 1) {
            lock()
        }
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
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
