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

            Spacer()
        }
        .padding(.horizontal, 24)
        .gasScreen()
        .onAppear { waitLeft = PinAttempts.waitRemaining() }
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
            let opened: Bool
            do {
                let copy = pin
                _ = try await Background.run { try CoreStore.shared.unlock(pin: copy) }
                opened = true
            } catch EnclaveKey.Failure.unavailable {
                // 🔐 Ключа Enclave нет (приложение восстановили из копии
                // на другой телефон): эта база здесь не откроется ничем.
                opened = false
                self.error = L10n.t("Ключ устройства недоступен. Базу на этом телефоне открыть нельзя.",
                               "Device key unavailable. This database cannot be opened on this phone.")
            } catch {
                opened = false
            }
            pin.wipe()
            working = false

            if opened {
                PinAttempts.reset()
                model.didUnlock()
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

    static func format(_ seconds: TimeInterval) -> String {
        let total = Int(seconds.rounded(.up))
        if total >= 3600 {
            return L10n.t("\(total / 3600) ч \((total % 3600) / 60) мин", "\(total / 3600) h \((total % 3600) / 60) min")
        }
        if total >= 60 { return "\(total / 60):\(String(format: "%02d", total % 60))" }
        return L10n.t("\(total) с", "\(total) s")
    }
}
