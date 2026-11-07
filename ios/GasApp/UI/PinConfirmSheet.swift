// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Повторный ввод PIN перед важным действием (включение Face ID).
struct PinConfirmSheet: View {
    let title: String
    let onPin: ([UInt8]) -> Void

    @State private var digits: [UInt8] = []
    @Environment(\.dismiss) private var dismiss

    init(title: String, onPin: @escaping ([UInt8]) -> Void) {
        self.title = title
        self.onPin = onPin
    }

    var body: some View {
        VStack(spacing: 24) {
            Text(title).font(.system(size: 22, weight: .heavy, design: .rounded))
                .foregroundStyle(GasAppColor.textPrimary)
                .padding(.top, 32)
            PinPad(digits: $digits) {
                let pin = digits
                digits.wipe()
                digits = []
                dismiss()
                onPin(pin)
            }
            Button(L10n.t("Отмена", "Cancel")) { dismiss() }
                .foregroundStyle(GasAppColor.textTertiary)
            Spacer()
        }
        .padding(24)
        .gasScreen()
    }
}

/// Повторная проверка PIN для действий только для владельца (как
/// `Reauth` на Android).
///
/// 🔐 Эта сверка — тоже ответ на «верен ли PIN», поэтому она идёт через
/// тот же счётчик, что и вход: задержки, запись попытки до проверки и
/// стирание после десяти. Иначе открытое приложение было бы способом
/// перебирать PIN без задержек.
enum Reauth {
    enum Verdict {
        case ok
        /// Десятая неверная попытка — данные стёрты, нужен экран входа.
        case wiped
        case refused(String)
    }

    static func verify(pin: [UInt8]) async -> Verdict {
        var pin = pin
        defer { pin.wipe() }
        let wait = PinAttempts.waitRemaining()
        guard wait <= 0 else {
            return .refused(L10n.t("Слишком много неверных PIN. Подождите \(Int(wait.rounded(.up))) с.",
                                   "Too many wrong PINs. Wait \(Int(wait.rounded(.up))) s."))
        }
        guard PinAttempts.beginAttempt() else {
            return .refused(L10n.t("Не удалось сохранить попытку. Попробуйте ещё раз.", "Could not save the attempt. Try again."))
        }
        let copy = pin
        // nil — PIN не сверялся (сбой ключа Enclave и т. п.).
        let verdict = try? await Background.run { () -> Bool in
            var key = try CoreStore.shared.deriveKey(pin: copy)
            defer { key.wipe() }
            return CoreStore.shared.keyOpensStorage(key)
        }
        switch verdict {
        case true?:
            PinAttempts.reset()
            return .ok
        case false?:
            if PinAttempts.shouldWipe { return .wiped }
            return .refused(L10n.t("PIN не подошёл", "Wrong PIN"))
        case nil:
            PinAttempts.cancelAttempt()
            return .refused(L10n.t("Не удалось проверить PIN", "Could not check the PIN"))
        }
    }
}
