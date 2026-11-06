// SPDX-License-Identifier: Apache-2.0

import SwiftUI

// Набор элементов интерфейса — тот же визуальный мир, что у Android:
// ночное небо, золотая «объёмная» кнопка с тёмной кромкой, карточки.

/// Главная кнопка: золото с кромкой снизу, как у Android `GasAppButton`.
struct GoldButton: View {
    let title: String
    var isLoading = false
    var isEnabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                if isLoading {
                    ProgressView().tint(GasAppColor.accentOn)
                } else {
                    Text(title)
                        .font(.system(size: 17, weight: .heavy, design: .rounded))
                        .foregroundStyle(GasAppColor.accentOn)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 54)
        }
        .buttonStyle(GoldButtonStyle())
        .disabled(!isEnabled || isLoading)
        .opacity(isEnabled ? 1 : 0.5)
        .accessibilityLabel(title)
    }
}

struct GoldButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        let pressed = configuration.isPressed
        return configuration.label
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(pressed ? GasAppColor.accentPressed : GasAppColor.accent)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(GasAppColor.accentEdgeDeep, lineWidth: 2)
            )
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(GasAppColor.accentEdge)
                    .offset(y: pressed ? 1 : 4)
            )
            .offset(y: pressed ? 3 : 0)
            .animation(.easeOut(duration: 0.08), value: pressed)
    }
}

/// Второстепенная кнопка: контур.
struct OutlineButton: View {
    let title: String
    var tone: Color = GasAppColor.textPrimary
    var isEnabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 16, weight: .bold, design: .rounded))
                .foregroundStyle(tone)
                .frame(maxWidth: .infinity, minHeight: 48)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(GasAppColor.line, lineWidth: 1.5)
                )
        }
        .disabled(!isEnabled)
        .opacity(isEnabled ? 1 : 0.5)
    }
}

/// Карточка-подложка.
struct Card<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous).fill(GasAppColor.bgCard)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(GasAppColor.line, lineWidth: 1)
            )
    }
}

/// Поле ввода с подписью и ошибкой.
struct Field: View {
    let title: String
    @Binding var text: String
    var placeholder = ""
    var error: String?
    var keyboard: UIKeyboardType = .default
    var contentType: UITextContentType?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(GasAppColor.textSecondary)
            TextField(placeholder, text: $text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(keyboard)
                .textContentType(contentType)
                .font(.system(size: 17))
                .foregroundStyle(GasAppColor.textPrimary)
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgRaised))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(error == nil ? GasAppColor.line : GasAppColor.error, lineWidth: 1.5)
                )
            if let error {
                Text(error)
                    .font(.system(size: 13))
                    .foregroundStyle(GasAppColor.error)
            }
        }
    }
}

/// Плашка-предупреждение (смена ключа, запрос, блокировка).
struct Banner: View {
    enum Tone { case warn, error, info, ok }

    let title: String
    let message: String
    var tone: Tone = .warn

    private var color: Color {
        switch tone {
        case .warn: GasAppColor.warn
        case .error: GasAppColor.error
        case .info: GasAppColor.info
        case .ok: GasAppColor.ok
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 15, weight: .bold)).foregroundStyle(color)
            Text(message).font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14).fill(color.opacity(0.13)))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(color.opacity(0.5), lineWidth: 1))
    }
}

/// Заголовок экрана в стиле GasApp.
struct ScreenTitle: View {
    let text: String
    var subtitle: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(text)
                .font(.system(size: 30, weight: .heavy, design: .rounded))
                .foregroundStyle(GasAppColor.textPrimary)
            if let subtitle {
                Text(subtitle)
                    .font(.system(size: 16))
                    .foregroundStyle(GasAppColor.textSecondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Цифровая клавиатура PIN. 🔐 Набранное хранится байтами и затирается
/// после использования (`take`), а не живёт неизменяемой строкой.
struct PinPad: View {
    @Binding var digits: [UInt8]
    var length = PinPolicy.length
    var isEnabled = true
    var onComplete: () -> Void = {}

    private let rows: [[String]] = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["", "0", "⌫"]]

    var body: some View {
        VStack(spacing: 24) {
            HStack(spacing: 14) {
                ForEach(0..<length, id: \.self) { index in
                    Circle()
                        .fill(index < digits.count ? GasAppColor.accent : Color.clear)
                        .overlay(Circle().stroke(GasAppColor.accent, lineWidth: 2))
                        .frame(width: 16, height: 16)
                }
            }
            .accessibilityLabel(L10n.t("Введено цифр: \(digits.count) из \(length)",
                                       "Digits entered: \(digits.count) of \(length)"))

            VStack(spacing: 14) {
                ForEach(rows, id: \.self) { row in
                    HStack(spacing: 22) {
                        ForEach(row, id: \.self) { key in
                            keyButton(key)
                        }
                    }
                }
            }
        }
        .disabled(!isEnabled)
        .opacity(isEnabled ? 1 : 0.5)
    }

    @ViewBuilder
    private func keyButton(_ key: String) -> some View {
        if key.isEmpty {
            Color.clear.frame(width: 76, height: 76)
        } else {
            Button {
                press(key)
            } label: {
                Text(key)
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .foregroundStyle(GasAppColor.textPrimary)
                    .frame(width: 76, height: 76)
                    .background(Circle().fill(GasAppColor.bgCard))
                    .overlay(Circle().stroke(GasAppColor.line, lineWidth: 1))
            }
            .accessibilityLabel(key == "⌫" ? L10n.t("Стереть", "Delete") : key)
        }
    }

    private func press(_ key: String) {
        if key == "⌫" {
            if !digits.isEmpty { digits[digits.count - 1] = 0; digits.removeLast() }
            return
        }
        guard digits.count < length, let byte = key.utf8.first else { return }
        digits.append(byte)
        if digits.count == length { onComplete() }
    }
}

extension View {
    /// Фон экрана GasApp.
    func gasScreen() -> some View {
        self
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(GasAppColor.bgBase.ignoresSafeArea())
            .toolbarBackground(GasAppColor.bgBase, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
    }
}
