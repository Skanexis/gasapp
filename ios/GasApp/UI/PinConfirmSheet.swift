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
