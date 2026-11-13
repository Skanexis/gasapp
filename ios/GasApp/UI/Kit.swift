// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

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
                        .font(GasFont.sign(16))
                        .foregroundStyle(GasAppColor.accentOn)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 50)
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
        // Сдержаннее прежнего: кромка 3 вместо 4, обводка тоньше, угол 14
        // (DESIGN.md: кнопка 14) — та же «объёмная» кнопка, но спокойнее.
        return configuration.label
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(pressed ? GasAppColor.accentPressed : GasAppColor.accent)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(GasAppColor.accentEdgeDeep.opacity(0.6), lineWidth: 1)
            )
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(GasAppColor.accentEdge)
                    .offset(y: pressed ? 1 : 3)
            )
            .offset(y: pressed ? 2 : 0)
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
                .font(GasFont.sign(16))
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
                .font(GasFont.text(13, .semibold))
                .foregroundStyle(GasAppColor.textSecondary)
            TextField(placeholder, text: $text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(keyboard)
                .textContentType(contentType)
                .font(GasFont.text(17))
                .foregroundStyle(GasAppColor.textPrimary)
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgRaised))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(error == nil ? GasAppColor.line : GasAppColor.error, lineWidth: 1.5)
                )
            if let error {
                Text(error)
                    .font(GasFont.text(13))
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
            Text(title).font(GasFont.text(15, .bold)).foregroundStyle(color)
            Text(message).font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
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
                .font(GasFont.display(30))
                .foregroundStyle(GasAppColor.textPrimary)
            if let subtitle {
                Text(subtitle)
                    .font(GasFont.text(16))
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
                                       "Digits entered: \(digits.count) of \(length)", "Cifre inserite: \(digits.count) su \(length)"))

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
                    .font(GasFont.sign(30))
                    .foregroundStyle(GasAppColor.textPrimary)
                    .frame(width: 76, height: 76)
                    .background(Circle().fill(GasAppColor.bgCard))
                    .overlay(Circle().stroke(GasAppColor.line, lineWidth: 1))
            }
            .accessibilityLabel(key == "⌫" ? L10n.t("Стереть", "Delete", "Elimina") : key)
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

/// Пустой верхний список (чаты, каналы) — как на Android: карточка ночного
/// неба 216 × 136 со скруглением 24, золотой жетон 56 с иконкой раздела
/// на её нижнем краю, заголовок, пояснение и одно действие (DESIGN.md,
/// «Night scene», «Gold token»).
struct EmptyScene: View {
    let icon: String
    let title: String
    let text: String
    var action: String?
    var onAction: () -> Void = {}

    init(icon: String, title: String, text: String, action: String? = nil, onAction: @escaping () -> Void = {}) {
        self.icon = icon
        self.title = title
        self.text = text
        self.action = action
        self.onAction = onAction
    }

    var body: some View {
        VStack(spacing: 14) {
            ZStack(alignment: .bottom) {
                Color.clear
                    .frame(width: 216, height: 136)
                    .overlay { Image("SceneWelcome").resizable().scaledToFill() }
                    .clipShape(RoundedRectangle(cornerRadius: 24))
                    .overlay(RoundedRectangle(cornerRadius: 24).stroke(GasAppColor.line, lineWidth: 1))
                ZStack {
                    Circle().fill(GasAppColor.accentEdge).offset(y: 4)
                    Circle().fill(GasAppColor.accent)
                    Image(systemName: icon)
                        .font(.system(size: 22, weight: .bold))
                        .foregroundStyle(GasAppColor.accentOn)
                }
                .frame(width: 56, height: 56)
                .offset(y: 28)
            }
            .padding(.bottom, 34)
            .accessibilityHidden(true)

            Text(title)
                .font(GasFont.display(22))
                .foregroundStyle(GasAppColor.textPrimary)
                .multilineTextAlignment(.center)
            Text(text)
                .font(GasFont.text(15))
                .foregroundStyle(GasAppColor.textSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if let action {
                GoldButton(title: action, action: onAction)
                    .frame(maxWidth: 260)
                    .padding(.top, 6)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 48)
    }
}

/// Размер файла: «0 КБ», а не «Zero KB» (по умолчанию ByteCountFormatter
/// пишет ноль словом).
func formatBytes(_ bytes: Int64) -> String {
    let formatter = ByteCountFormatter()
    formatter.countStyle = .file
    formatter.allowsNonnumericFormatting = false
    return formatter.string(fromByteCount: bytes)
}

/// Аватар по имени — как `paintAvatar` на Android: инициалы цветом из
/// шести пастельных тонов поверх заливки того же цвета (16 %). Цвет
/// выбирается тем же хешем (`String.hashCode` Java), что на Android: один
/// человек — один цвет на обеих платформах. Зелёного, красного и
/// оранжевого среди тонов нет — цвет собеседника не читается как
/// состояние защиты.
struct Avatar: View {
    let name: String
    var size: CGFloat = 48
    var image: UIImage?

    private static let inks: [Color] = [
        Color(red: 1.0, green: 0.796, blue: 0.180),   // #FFCB2E
        Color(red: 0.369, green: 0.827, blue: 0.788), // #5ED3C9
        Color(red: 0.961, green: 0.604, blue: 0.722), // #F59AB8
        Color(red: 0.961, green: 0.690, blue: 0.541), // #F5B08A
        Color(red: 0.769, green: 0.663, blue: 1.0),   // #C4A9FF
        Color(red: 0.498, green: 0.769, blue: 0.961), // #7FC4F5
    ]

    var body: some View {
        let ink = Self.ink(for: name)
        ZStack {
            if let image {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                Circle().fill(ink.opacity(0.16))
                Text(Self.initials(of: name))
                    .font(GasFont.display(size * 0.38))
                    .foregroundStyle(ink)
                    .minimumScaleFactor(0.6)
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .accessibilityHidden(true)
    }

    static func ink(for name: String) -> Color {
        // Java String.hashCode: h = 31·h + UTF-16, с переполнением Int32.
        var hash: Int32 = 0
        for unit in name.utf16 { hash = hash &* 31 &+ Int32(unit) }
        let index = ((Int(hash) % inks.count) + inks.count) % inks.count
        return inks[index]
    }

    static func initials(of name: String) -> String {
        let parts = name.split(whereSeparator: { $0 == " " || $0 == "_" })
        if parts.count >= 2, let a = parts[0].first, let b = parts[1].first { return "\(a)\(b)".uppercased() }
        if let first = parts.first { return String(first.prefix(2)).uppercased() }
        return "?"
    }
}
