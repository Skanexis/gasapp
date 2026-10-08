// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Палитра из UI kit.
///
/// Значения перенесены дословно из `design/secure-messenger-ui-kit.html`
/// и совпадают с `android/app/src/main/res/values/colors.xml`.
/// Расхождение между платформами проще всего заводится именно здесь,
/// а заметить его на глаз трудно.
///
/// Системные цвета (`.primary`, `.blue`) намеренно не используются:
/// они меняются между версиями iOS и разъезжаются с Android, где
/// такого понятия нет вовсе.
enum GasAppColor {

    // MARK: - Поверхности

    static let bgBase = Color(hex: 0x0D0F12)
    static let bgRaised = Color(hex: 0x15181D)
    static let bgCard = Color(hex: 0x1C2128)
    static let bgHover = Color(hex: 0x252B33)
    static let line = Color(hex: 0x2E353E)

    // MARK: - Текст

    /// Четыре ступени контраста, как в макете.
    static let textPrimary = Color(hex: 0xFFFFFF)
    static let textSecondary = Color(hex: 0xB9C1CC)
    static let textTertiary = Color(hex: 0x7C8796)
    static let textQuaternary = Color(hex: 0x596170)

    // MARK: - Акцент

    static let accent = Color(hex: 0x37B8FF)
    static let accentHover = Color(hex: 0x5CC6FF)
    static let accentPressed = Color(hex: 0x2AA3E8)
    static let accentOn = Color(hex: 0x06121B)

    /// Приглушённый акцент для подложек.
    static let accentDim = Color(hex: 0x37B8FF, opacity: 0.15)

    // MARK: - Состояния

    /// 🔐 Зелёный означает «проверено», красный — «внимание».
    ///
    /// Эти два цвета несут смысл безопасности и используются только
    /// по назначению: зелёная галочка у неверифицированного контакта
    /// обесценила бы саму верификацию.
    static let ok = Color(hex: 0x18C37A)
    static let warn = Color(hex: 0xE4B545)
    static let error = Color(hex: 0xE5484D)

    static let okDim = Color(hex: 0x18C37A, opacity: 0.15)
    static let warnDim = Color(hex: 0xE4B545, opacity: 0.15)
    static let errorDim = Color(hex: 0xE5484D, opacity: 0.15)

    /// Пузырь исходящего сообщения.
    ///
    /// Приглушённый синий, а не сплошной акцент: на сплошном белый
    /// текст читается хуже, а сам акцент перестаёт выделять то, что
    /// действительно требует внимания.
    static let bubbleOutgoing = Color(hex: 0x173850)
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
