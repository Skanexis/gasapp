// SPDX-License-Identifier: Apache-2.0
// Сгенерировано tools/gen-tokens.mjs из design/secure-messenger-ui-kit.html.
// НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — правки будут затёрты при следующей генерации.
// Источник правды по дизайну — UI kit (раздел 20 плана).

import SwiftUI

/// Дизайн-токены AEGIS.
public enum AegisTokens {

    // MARK: - Colors

    public enum Color {
        /// `#0F1629`
        public static let bgBase = SwiftUI.Color(.sRGB, red: 0.0588, green: 0.0863, blue: 0.1608, opacity: 1)
        /// `#151D34`
        public static let bgRaised = SwiftUI.Color(.sRGB, red: 0.0824, green: 0.1137, blue: 0.2039, opacity: 1)
        /// `#1B2442`
        public static let bgCard = SwiftUI.Color(.sRGB, red: 0.1059, green: 0.1412, blue: 0.2588, opacity: 1)
        /// `#242F52`
        public static let bgHover = SwiftUI.Color(.sRGB, red: 0.1412, green: 0.1843, blue: 0.3216, opacity: 1)
        /// `#2E3A5C`
        public static let line = SwiftUI.Color(.sRGB, red: 0.1804, green: 0.2275, blue: 0.3608, opacity: 1)
        /// `#F2F4FC`
        public static let textPrimary = SwiftUI.Color(.sRGB, red: 0.9490, green: 0.9569, blue: 0.9882, opacity: 1)
        /// `#B4BCD6`
        public static let textSecondary = SwiftUI.Color(.sRGB, red: 0.7059, green: 0.7373, blue: 0.8392, opacity: 1)
        /// `#8E99B8`
        public static let textMuted = SwiftUI.Color(.sRGB, red: 0.5569, green: 0.6000, blue: 0.7216, opacity: 1)
        /// `#5A6585`
        public static let textDisabled = SwiftUI.Color(.sRGB, red: 0.3529, green: 0.3961, blue: 0.5216, opacity: 1)
        /// `#8FA5FF`
        public static let accentBase = SwiftUI.Color(.sRGB, red: 0.5608, green: 0.6471, blue: 1.0000, opacity: 1)
        /// `#A8B9FF`
        public static let accentHover = SwiftUI.Color(.sRGB, red: 0.6588, green: 0.7255, blue: 1.0000, opacity: 1)
        /// `#7890F5`
        public static let accentPressed = SwiftUI.Color(.sRGB, red: 0.4706, green: 0.5647, blue: 0.9608, opacity: 1)
        /// `#0A1030`
        public static let accentOn = SwiftUI.Color(.sRGB, red: 0.0392, green: 0.0627, blue: 0.1882, opacity: 1)
        /// `rgba(143,165,255,.14)`
        public static let accentDim = SwiftUI.Color(.sRGB, red: 0.5608, green: 0.6471, blue: 1.0000, opacity: 0.14)
        /// `rgba(143,165,255,.40)`
        public static let accentLine = SwiftUI.Color(.sRGB, red: 0.5608, green: 0.6471, blue: 1.0000, opacity: 0.4)
        /// `#3DD598`
        public static let statusSuccess = SwiftUI.Color(.sRGB, red: 0.2392, green: 0.8353, blue: 0.5961, opacity: 1)
        /// `#F0B84C`
        public static let statusWarning = SwiftUI.Color(.sRGB, red: 0.9412, green: 0.7216, blue: 0.2980, opacity: 1)
        /// `#FF6B78`
        public static let statusError = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.4196, blue: 0.4706, opacity: 1)
        /// `#8FA5FF`
        public static let statusInfo = SwiftUI.Color(.sRGB, red: 0.5608, green: 0.6471, blue: 1.0000, opacity: 1)
        /// `rgba(61,213,152,.13)`
        public static let statusSuccessDim = SwiftUI.Color(.sRGB, red: 0.2392, green: 0.8353, blue: 0.5961, opacity: 0.13)
        /// `rgba(240,184,76,.13)`
        public static let statusWarningDim = SwiftUI.Color(.sRGB, red: 0.9412, green: 0.7216, blue: 0.2980, opacity: 0.13)
        /// `rgba(255,107,120,.13)`
        public static let statusErrorDim = SwiftUI.Color(.sRGB, red: 1.0000, green: 0.4196, blue: 0.4706, opacity: 0.13)
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
