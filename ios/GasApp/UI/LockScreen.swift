// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Вход по PIN — аналог `LockActivity`.
///
/// 🔐 PIN проверяет только открытие базы: неверный PIN даёт неверный
/// ключ, и база не открывается. После трёх неверных попыток — задержки
/// (`PinDelays`), после десяти — стирание, если человек его включил.
struct LockScreen: View {
    @Environment(AppModel.self) private var model

    @State private var digits: [UInt8] = []
    @State private var working = false
    @State private var error: String?
    @State private var waitLeft: TimeInterval = 0

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 28) {
            Spacer(minLength: 20)

            VStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 52, weight: .bold))
                    .foregroundStyle(GasAppColor.accent)
                Text(L10n.t("Введите PIN", "Enter PIN"))
                    .font(.system(size: 26, weight: .heavy, design: .rounded))
                    .foregroundStyle(GasAppColor.textPrimary)
                Text(status)
                    .font(.system(size: 15))
                    .foregroundStyle(error == nil ? GasAppColor.textSecondary : GasAppColor.error)
                    .multilineTextAlignment(.center)
                    .frame(minHeight: 40)
            }

            if working {
                ProgressView().tint(GasAppColor.accent).frame(height: 40)
            }

            PinPad(digits: $digits, isEnabled: !working && waitLeft <= 0) { submit() }

            if Biometric.enabled {
                Button {
                    unlockWithBiometric()
                } label: {
                    Label(Biometric.name, systemImage: Biometric.name == "Touch ID" ? "touchid" : "faceid")
                        .font(.system(size: 17, weight: .bold))
                        .foregroundStyle(GasAppColor.accent)
                }
                .disabled(working)
            }

            Spacer()
        }
        .padding(.horizontal, 24)
        // Во всю ширину: иначе экран узок, как клавиатура, и небо за ним
        // не доставало до краёв (снимок на Mac, 2026-11-07).
        .frame(maxWidth: .infinity)
        // Небо за заголовком, как сцена входа на Android: растворяется
        // в фоне до точек PIN, чтобы они не теряли контраст.
        .background(alignment: .top) {
            ZStack(alignment: .bottom) {
                Color.clear
                    .frame(maxWidth: .infinity)
                    .frame(height: 380)
                    .overlay { Image("SceneWelcome").resizable().scaledToFill() }
                    .clipped()
                    .opacity(0.85)
                LinearGradient(colors: [.clear, GasAppColor.bgBase], startPoint: .top, endPoint: .bottom)
                    .frame(height: 220)
            }
            .frame(height: 380)
            .ignoresSafeArea(edges: .top)
            .accessibilityHidden(true)
        }
        .gasScreen()
        .onAppear {
            waitLeft = PinAttempts.waitRemaining()
            if Biometric.enabled && waitLeft <= 0 { unlockWithBiometric() }
        }
        .onReceive(ticker) { _ in waitLeft = PinAttempts.waitRemaining() }
    }

    private var status: String {
        if waitLeft > 0 {
            return L10n.t("Слишком много попыток. Подождите \(Self.format(waitLeft))",
                          "Too many attempts. Wait \(Self.format(waitLeft))")
        }
        if let error { return error }
        return L10n.t("PIN нужен, чтобы открыть переписку", "Your PIN unlocks your messages")
    }

    private func submit() {
        var pin = digits
        digits.wipe()
        digits = []
        guard PinPolicy.isAcceptable(pin), PinAttempts.waitRemaining() <= 0 else {
            pin.wipe()
            return
        }

        working = true
        error = nil

        Task {
            var opened: Messenger?
            do {
                let copy = pin
                opened = try await Background.run { try CoreStore.shared.unlock(pin: copy) }
            } catch EnclaveKey.Failure.unavailable {
                // 🔐 Ключа Enclave нет (приложение восстановили из копии
                // на другой телефон): эта база здесь не откроется ничем.
                self.error = L10n.t("Ключ устройства недоступен. Базу на этом телефоне открыть нельзя.",
                                    "Device key unavailable. This database cannot be opened on this phone.")
            } catch is FfiError {
                // Ядро не открыло базу этим ключом — неверный PIN. Только
                // это идёт в счётчик попыток (ниже).
            } catch {
                // Сбой не из-за PIN (настройка сборки, соль, занятая база):
                // 🔐 в счётчик неверных попыток не идёт — иначе вёл бы
                // к стиранию данных.
                self.error = L10n.t("Не удалось открыть базу. Попробуйте ещё раз.",
                                    "Could not open the database. Try again.")
            }
            pin.wipe()
            working = false

            if let opened {
                PinAttempts.reset()
                await finishUnlock(opened)
                return
            }

            if self.error == nil {
                PinAttempts.recordFailure()
                if PinAttempts.shouldWipe {
                    model.didWipe()
                    return
                }
                let left = PinDelays.wipeAfter - PinAttempts.failures
                self.error = PinAttempts.wipeEnabled && left > 0
                    ? L10n.t("Неверный PIN. До стирания данных: \(left)",
                             "Wrong PIN. Attempts before wipe: \(left)")
                    : L10n.t("Неверный PIN", "Wrong PIN")
            }
            waitLeft = PinAttempts.waitRemaining()
        }
    }

    /// Вход по Face ID: ключ базы достаёт Secure Enclave после проверки лица.
    private func unlockWithBiometric() {
        working = true
        error = nil
        Task {
            do {
                let messenger = try await Background.run { () -> Messenger in
                    var key = try Biometric.key(reason: L10n.t("Открыть переписку", "Unlock your messages"))
                    defer { key.wipe() }
                    return try CoreStore.shared.unlock(key: key)
                }
                working = false
                PinAttempts.reset()
                await finishUnlock(messenger)
            } catch {
                working = false
                // Отменили или лицо не узнано — остаётся PIN. Ключ из записи
                // не открыл базу (её перешифровали) — запись больше не нужна.
                if error is FfiError { Biometric.disable() }
            }
        }
    }

    /// База открылась. Если регистрация не дошла до конца (приложение
    /// закрыли на шаге кода) — назад к коду из письма; пустая база без
    /// регистрации стирается.
    private func finishUnlock(_ messenger: Messenger) async {
        let state = try? await Background.run { () -> (String?, FfiPendingRegistration?) in
            (try messenger.ownUsername(), try messenger.pendingRegistration())
        }
        // 🔐 Сбой чтения — не повод стирать: только явное «аккаунта нет
        // и регистрации нет» ведёт к стиранию пустой базы.
        guard let state else {
            model.didUnlock()
            return
        }
        switch (state.0, state.1) {
        case (.some, _):
            model.didUnlock()
        case let (nil, .some(pending)):
            model.resumeRegistration(pending)
        case (nil, nil):
            model.didWipe()
        }
    }

    static func format(_ seconds: TimeInterval) -> String {
        let total = Int(seconds.rounded(.up))
        if total >= 3600 {
            return L10n.t("\(total / 3600) ч \((total % 3600) / 60) мин", "\(total / 3600) h \((total % 3600) / 60) min")
        }
        if total >= 60 { return "\(total / 60):\(String(format: "%02d", total % 60))" }
        return L10n.t("\(total) с", "\(total) s")
    }
}
