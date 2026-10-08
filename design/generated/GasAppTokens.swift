// SPDX-License-Identifier: Apache-2.0
// Сгенерировано tools/gen-tokens.mjs из design/secure-messenger-ui-kit.html.
// НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — правки будут затёрты при следующей генерации.
// Источник правды по дизайну — UI kit (раздел 20 плана).

import SwiftUI

/// Дизайн-токены GasApp.
public enum GasAppTokens {

    // MARK: - Colors

    public enum Color {
        /// `#0E1238`
        public static let bgBase = SwiftUI.Color(.sRGB, red: 0.0549, green: 0.0706, blue: 0.2196, opacity: 1)
        /// `#141A4A`
        public static let bgRaised = SwiftUI.Color(.sRGB, red: 0.0784, green: 0.1020, blue: 0.2902, opacity: 1)
        /// `#1B2259`
        public static let bgCard = SwiftUI.Color(.sRGB, red: 0.1059, green: 0.1333, blue: 0.3490, opacity: 1)
        /// `#252E70`
        public static let bgHover = SwiftUI.Color(.sRGB, red: 0.1451, green: 0.1804, blue: 0.4392, opacity: 1)
        /// `#343E85`
        public static let line = SwiftUI.Color(.sRGB, red: 0.2039, green: 0.2431, blue: 0.5216, opacity: 1)
        /// `#F5F6FF`
        public static let textPrimary = SwiftUI.Color(.sRGB, red: 0.9608, green: 0.9647, blue: 1.0000, opacity: 1)
        /// `#C2C8F0`
        public static let textSecondary = SwiftUI.Color(.sRGB, red: 0.7608, green: 0.7843, blue: 0.9412, opacity: 1)
        /// `#A3ABDD`
        public static let textMuted = SwiftUI.Color(.sRGB, red: 0.6392, green: 0.6706, blue: 0.8667, opacity: 1)
        /// `#6670AD`
        public static let textDisabled = SwiftUI.Color(.sRGB, red: 0.4000, green: 0.4392, blue: 0.6784, opacity: 1)
        /// `#FFCB2E`
        public static let accentBase = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.7961, blue: 0.1804, opacity: 1)
        /// `#FFDA66`
        public static let accentHover = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.8549, blue: 0.4000, opacity: 1)
        /// `#F0A800`
        public static let accentPressed = SwiftUI.Color(.sRGB, red: 0.9412, green: 0.6588, blue: 0.0000, opacity: 1)
        /// `#2B1600`
        public static let accentOn = SwiftUI.Color(.sRGB, red: 0.1686, green: 0.0863, blue: 0.0000, opacity: 1)
        /// `rgba(255,203,46,.14)`
        public static let accentDim = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.7961, blue: 0.1804, opacity: 0.14)
        /// `rgba(255,203,46,.40)`
        public static let accentLine = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.7961, blue: 0.1804, opacity: 0.4)
        /// `#4ADE94`
        public static let statusSuccess = SwiftUI.Color(.sRGB, red: 0.2902, green: 0.8706, blue: 0.5804, opacity: 1)
        /// `#FF9A4D`
        public static let statusWarning = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.6039, blue: 0.3020, opacity: 1)
        /// `#FF7A85`
        public static let statusError = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.4784, blue: 0.5216, opacity: 1)
        /// `#7FB8FF`
        public static let statusInfo = SwiftUI.Color(.sRGB, red: 0.4980, green: 0.7216, blue: 1.0000, opacity: 1)
        /// `rgba(74,222,148,.13)`
        public static let statusSuccessDim = SwiftUI.Color(.sRGB, red: 0.2902, green: 0.8706, blue: 0.5804, opacity: 0.13)
        /// `rgba(255,154,77,.13)`
        public static let statusWarningDim = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.6039, blue: 0.3020, opacity: 0.13)
        /// `rgba(255,122,133,.13)`
        public static let statusErrorDim = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.4784, blue: 0.5216, opacity: 0.13)
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
