// SPDX-License-Identifier: Apache-2.0
// Сгенерировано tools/gen-tokens.mjs из design/secure-messenger-ui-kit.html.
// НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — правки будут затёрты при следующей генерации.
// Источник правды по дизайну — UI kit (раздел 20 плана).

import SwiftUI

/// Дизайн-токены AEGIS.
public enum AegisTokens {

    // MARK: - Colors

    public enum Color {
        /// `#0D0F12`
        public static let bgBase = SwiftUI.Color(.sRGB, red: 0.0510, green: 0.0588, blue: 0.0706, opacity: 1)
        /// `#15181D`
        public static let bgRaised = SwiftUI.Color(.sRGB, red: 0.0824, green: 0.0941, blue: 0.1137, opacity: 1)
        /// `#1C2128`
        public static let bgCard = SwiftUI.Color(.sRGB, red: 0.1098, green: 0.1294, blue: 0.1569, opacity: 1)
        /// `#252B33`
        public static let bgHover = SwiftUI.Color(.sRGB, red: 0.1451, green: 0.1686, blue: 0.2000, opacity: 1)
        /// `#2E353E`
        public static let line = SwiftUI.Color(.sRGB, red: 0.1804, green: 0.2078, blue: 0.2431, opacity: 1)
        /// `#FFFFFF`
        public static let textPrimary = SwiftUI.Color(.sRGB, red: 1.0000, green: 1.0000, blue: 1.0000, opacity: 1)
        /// `#B9C1CC`
        public static let textSecondary = SwiftUI.Color(.sRGB, red: 0.7255, green: 0.7569, blue: 0.8000, opacity: 1)
        /// `#7C8796`
        public static let textMuted = SwiftUI.Color(.sRGB, red: 0.4863, green: 0.5294, blue: 0.5882, opacity: 1)
        /// `#596170`
        public static let textDisabled = SwiftUI.Color(.sRGB, red: 0.3490, green: 0.3804, blue: 0.4392, opacity: 1)
        /// `#37B8FF`
        public static let accentBase = SwiftUI.Color(.sRGB, red: 0.2157, green: 0.7216, blue: 1.0000, opacity: 1)
        /// `#5CC6FF`
        public static let accentHover = SwiftUI.Color(.sRGB, red: 0.3608, green: 0.7765, blue: 1.0000, opacity: 1)
        /// `#2AA3E8`
        public static let accentPressed = SwiftUI.Color(.sRGB, red: 0.1647, green: 0.6392, blue: 0.9098, opacity: 1)
        /// `#06121B`
        public static let accentOn = SwiftUI.Color(.sRGB, red: 0.0235, green: 0.0706, blue: 0.1059, opacity: 1)
        /// `rgba(55,184,255,.12)`
        public static let accentDim = SwiftUI.Color(.sRGB, red: 0.2157, green: 0.7216, blue: 1.0000, opacity: 0.12)
        /// `rgba(55,184,255,.38)`
        public static let accentLine = SwiftUI.Color(.sRGB, red: 0.2157, green: 0.7216, blue: 1.0000, opacity: 0.38)
        /// `#18C37A`
        public static let statusSuccess = SwiftUI.Color(.sRGB, red: 0.0941, green: 0.7647, blue: 0.4784, opacity: 1)
        /// `#E4B545`
        public static let statusWarning = SwiftUI.Color(.sRGB, red: 0.8941, green: 0.7098, blue: 0.2706, opacity: 1)
        /// `#E5484D`
        public static let statusError = SwiftUI.Color(.sRGB, red: 0.8980, green: 0.2824, blue: 0.3020, opacity: 1)
        /// `#37B8FF`
        public static let statusInfo = SwiftUI.Color(.sRGB, red: 0.2157, green: 0.7216, blue: 1.0000, opacity: 1)
        /// `rgba(24,195,122,.12)`
        public static let statusSuccessDim = SwiftUI.Color(.sRGB, red: 0.0941, green: 0.7647, blue: 0.4784, opacity: 0.12)
        /// `rgba(228,181,69,.12)`
        public static let statusWarningDim = SwiftUI.Color(.sRGB, red: 0.8941, green: 0.7098, blue: 0.2706, opacity: 0.12)
        /// `rgba(229,72,77,.12)`
        public static let statusErrorDim = SwiftUI.Color(.sRGB, red: 0.8980, green: 0.2824, blue: 0.3020, opacity: 0.12)
    }

    // MARK: - Radius

    public enum Radius {
        public static let input: CGFloat = 12
        public static let button: CGFloat = 14
        public static let card: CGFloat = 16
        public static let sheet: CGFloat = 24
    }

    // MARK: - Spacing

    public enum Space {
        public static let s4: CGFloat = 4
        public static let s8: CGFloat = 8
        public static let s16: CGFloat = 16
        public static let s24: CGFloat = 24
        public static let s32: CGFloat = 32
        public static let s40: CGFloat = 40
        public static let s48: CGFloat = 48
        public static let s64: CGFloat = 64
    }

    // MARK: - Motion

    public enum Motion {
        public static let fast: Double = 0.15
        public static let base: Double = 0.2
        public static let slow: Double = 0.25
        /// Единственная кривая системы — ease out.
        public static let ease = SwiftUI.Animation.timingCurve(0, 0, 0.2, 1)
    }

    // MARK: - Typography

    public enum Typography {
        public static let display = (size: CGFloat(32), lineHeight: CGFloat(40), weight: Font.Weight.bold)
        public static let h1 = (size: CGFloat(28), lineHeight: CGFloat(36), weight: Font.Weight.bold)
        public static let h2 = (size: CGFloat(24), lineHeight: CGFloat(32), weight: Font.Weight.semibold)
        public static let h3 = (size: CGFloat(20), lineHeight: CGFloat(28), weight: Font.Weight.semibold)
        public static let h4 = (size: CGFloat(17), lineHeight: CGFloat(24), weight: Font.Weight.semibold)
        public static let body = (size: CGFloat(15), lineHeight: CGFloat(22), weight: Font.Weight.regular)
        public static let caption = (size: CGFloat(13), lineHeight: CGFloat(18), weight: Font.Weight.regular)
        public static let button = (size: CGFloat(15), lineHeight: CGFloat(16), weight: Font.Weight.semibold)
        public static let label = (size: CGFloat(12), lineHeight: CGFloat(16), weight: Font.Weight.semibold)
    }

    // MARK: - Sizes

    public enum Size {
        public static let buttonSmall: CGFloat = 40
        public static let buttonMedium: CGFloat = 48
        public static let buttonLarge: CGFloat = 56
        public static let input: CGFloat = 48
        public static let listRowMin: CGFloat = 64
        public static let listRowMax: CGFloat = 72
        public static let avatar: [CGFloat] = [40, 48, 64, 88]
        public static let icon: [CGFloat] = [16, 20, 24, 32]
        public static let touchTarget: CGFloat = 48
        public static let screenMargin: CGFloat = 16
    }
}
