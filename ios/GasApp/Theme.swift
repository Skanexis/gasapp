// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Палитра — дословно из `android/app/src/main/res/values/colors.xml`
/// (ночное небо, золотой акцент). Расхождение между платформами проще
/// всего заводится именно здесь, а заметить его на глаз трудно: менять
/// значения только вместе с Android.
///
/// Системные цвета (`.primary`, `.blue`) намеренно не используются:
/// они меняются между версиями iOS и разъезжаются с Android.
enum GasAppColor {

    // MARK: - Поверхности

    static let bgBase = Color(hex: 0x0E1238)
    static let bgRaised = Color(hex: 0x141A4A)
    static let bgCard = Color(hex: 0x1B2259)
    static let bgHover = Color(hex: 0x252E70)
    static let line = Color(hex: 0x343E85)

    // MARK: - Текст

    static let textPrimary = Color(hex: 0xF5F6FF)
    static let textSecondary = Color(hex: 0xC2C8F0)
    static let textTertiary = Color(hex: 0xA3ABDD)
    static let textQuaternary = Color(hex: 0x6670AD)

    // MARK: - Акцент (золото)

    static let accent = Color(hex: 0xFFCB2E)
    static let accentHover = Color(hex: 0xFFDA66)
    static let accentPressed = Color(hex: 0xF0A800)
    static let accentOn = Color(hex: 0x2B1600)
    static let accentEdge = Color(hex: 0xB86A00)
    static let accentEdgeDeep = Color(hex: 0x7A2E00)
    static let accentDim = Color(hex: 0xFFCB2E, opacity: 0.14)

    // MARK: - Состояния

    /// 🔐 Зелёный означает «проверено», красный — «внимание». Только по
    /// назначению: зелёная галочка у несверенного контакта обесценила бы
    /// саму сверку.
    static let ok = Color(hex: 0x4ADE94)
    static let warn = Color(hex: 0xFF9A4D)
    static let error = Color(hex: 0xFF7A85)
    static let info = Color(hex: 0x7FB8FF)

    static let okDim = Color(hex: 0x4ADE94, opacity: 0.13)
    static let warnDim = Color(hex: 0xFF9A4D, opacity: 0.13)
    static let errorDim = Color(hex: 0xFF7A85, opacity: 0.13)

    // MARK: - Сообщения

    static let bubbleOutgoing = Color(hex: 0x3A45B8)
    static let bubbleOutgoingText = Color(hex: 0xF5F6FF)
    static let bubbleOutgoingMeta = Color(hex: 0xD5DAFF)
}

extension Color {

    /// Собирает цвет из шестнадцатеричного значения.
    ///
    /// Принимает `Int`, а не строку: опечатка в строке даёт чёрный
    /// цвет молча, а неверное число не скомпилируется.
    init(hex: Int, opacity: Double = 1.0) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8) & 0xFF) / 255.0,
            blue: Double(hex & 0xFF) / 255.0,
            opacity: opacity
        )
    }
}
