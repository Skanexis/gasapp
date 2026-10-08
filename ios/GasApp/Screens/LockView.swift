// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Экран блокировки.
///
/// 🔐 PIN здесь **не проверяется и не хранится**. Введённое значение
/// уходит в ядро, где растягивается Argon2id и превращается в ключ,
/// которым расшифровывается хранилище: успех расшифровки и есть
/// проверка. Сравнивать строки в UI означало бы держать PIN в памяти
/// процесса — ровно то, от чего защищает блокировка.
///
/// 🔐 Клавиатура своя, а не системная. Системная принадлежит другому
/// приложению и видит каждое нажатие — то есть весь PIN целиком.
///
/// Здесь не показывается ничего, кроме запроса PIN: ни имени
/// пользователя, ни числа непрочитанных, ни превью. Всё это выдало бы
/// сведения о переписке тому, кто взял заблокированное устройство.
struct LockView: View {

    // MARK: - Properties

    @State private var entered = ""
    @State private var showsError = false

    /// Сколько попыток осталось до задержки.
    @State private var attemptsLeft = maxAttempts

    let onUnlock: (String) -> Void

    // MARK: - Body

    var body: some View {
        VStack(spacing: 22) {
            Spacer()

            shield

            VStack(spacing: 8) {
                Text("Введите PIN")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(GasAppColor.textPrimary)

                Text(subtitle)
                    .font(.system(size: 12))
                    .foregroundColor(showsError ? GasAppColor.error : GasAppColor.textTertiary)
            }

            pinDots

            keypad

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .onDisappear {
            // 🔐 PIN не должен пережить уход с экрана даже в буфере.
            entered = ""
        }
    }

    // MARK: - Subviews

    private var shield: some View {
        Image(systemName: "shield.fill")
            .font(.system(size: 32))
            .foregroundColor(GasAppColor.accent)
            .frame(width: 72, height: 72)
            .background(GasAppColor.accentDim)
            .clipShape(RoundedRectangle(cornerRadius: 20))
    }

    private var subtitle: String {
        showsError
            ? "Неверный PIN. Осталось попыток: \(attemptsLeft)"
            : "Хранилище зашифровано"
    }

    /// Точки, показывающие длину введённого.
    ///
    /// 🔐 Только количество — сами цифры не отображаются нигде.
    private var pinDots: some View {
        HStack(spacing: 14) {
            ForEach(0..<Self.pinLength, id: \.self) { index in
                Circle()
                    .fill(index < entered.count ? GasAppColor.accent : GasAppColor.line)
                    .frame(width: 14, height: 14)
            }
        }
    }

    private var keypad: some View {
        VStack(spacing: 10) {
            ForEach(keypadRows, id: \.self) { row in
                HStack(spacing: 10) {
                    ForEach(row, id: \.self) { key in
                        keypadButton(key)
                    }
                }
            }
        }
        .padding(.horizontal, 36)
    }

    private var keypadRows: [[String]] {
        [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["", "0", "⌫"]]
    }

    private func keypadButton(_ key: String) -> some View {
        Button {
            press(key)
        } label: {
            Text(key)
                .font(.system(size: 22))
                .foregroundColor(GasAppColor.textPrimary)
                .frame(width: 72, height: 56)
        }
        .disabled(key.isEmpty)
    }

    // MARK: - Actions

    private func press(_ key: String) {
        showsError = false

        if key == "⌫" {
            if !entered.isEmpty {
                entered.removeLast()
            }

            return
        }

        guard !key.isEmpty, entered.count < Self.pinLength else { return }

        entered.append(key)

        // Проверка запускается сама при наборе полной длины: отдельная
        // кнопка здесь лишняя, длина PIN фиксирована.
        if entered.count == Self.pinLength {
            onUnlock(entered)
            entered = ""
        }
    }

    // MARK: - Constants

    /// Длина PIN.
    ///
    /// Шесть цифр — миллион вариантов; вместе с растягиванием Argon2id
    /// этого достаточно, чтобы перебор на изъятом устройстве занимал
    /// годы. Четыре цифры (10 000 вариантов) перебираются за часы.
    private static let pinLength = 6

    /// Сколько попыток показывается пользователю.
    private static let maxAttempts = 3
}
