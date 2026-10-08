// SPDX-License-Identifier: Apache-2.0
// Сгенерировано tools/gen-tokens.mjs из design/secure-messenger-ui-kit.html.
// НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — правки будут затёрты при следующей генерации.
// Источник правды по дизайну — UI kit (раздел 20 плана).

package org.gasapp.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Дизайн-токены GasApp. */
object GasAppTokens {

    object Colors {
        /** `#0E1238` */
        val bgBase = Color(0xFF0E1238)
        /** `#141A4A` */
        val bgRaised = Color(0xFF141A4A)
        /** `#1B2259` */
        val bgCard = Color(0xFF1B2259)
        /** `#252E70` */
        val bgHover = Color(0xFF252E70)
        /** `#343E85` */
        val line = Color(0xFF343E85)
        /** `#F5F6FF` */
        val textPrimary = Color(0xFFF5F6FF)
        /** `#C2C8F0` */
        val textSecondary = Color(0xFFC2C8F0)
        /** `#A3ABDD` */
        val textMuted = Color(0xFFA3ABDD)
        /** `#6670AD` */
        val textDisabled = Color(0xFF6670AD)
        /** `#FFCB2E` */
        val accentBase = Color(0xFFFFCB2E)
        /** `#FFDA66` */
        val accentHover = Color(0xFFFFDA66)
        /** `#F0A800` */
        val accentPressed = Color(0xFFF0A800)
        /** `#2B1600` */
        val accentOn = Color(0xFF2B1600)
        /** `rgba(255,203,46,.14)` */
        val accentDim = Color(0x24FFCB2E)
        /** `rgba(255,203,46,.40)` */
        val accentLine = Color(0x66FFCB2E)
        /** `#4ADE94` */
        val statusSuccess = Color(0xFF4ADE94)
        /** `#FF9A4D` */
        val statusWarning = Color(0xFFFF9A4D)
        /** `#FF7A85` */
        val statusError = Color(0xFFFF7A85)
        /** `#7FB8FF` */
        val statusInfo = Color(0xFF7FB8FF)
        /** `rgba(74,222,148,.13)` */
        val statusSuccessDim = Color(0x214ADE94)
        /** `rgba(255,154,77,.13)` */
        val statusWarningDim = Color(0x21FF9A4D)
        /** `rgba(255,122,133,.13)` */
        val statusErrorDim = Color(0x21FF7A85)
    }

    object Radius {
        val input = 12.dp
        val button = 14.dp
        val card = 16.dp
        val sheet = 24.dp
    }

    object Space {
        val s4 = 4.dp
        val s8 = 8.dp
        val s16 = 16.dp
        val s24 = 24.dp
        val s32 = 32.dp
        val s40 = 40.dp
        val s48 = 48.dp
        val s64 = 64.dp
    }

    object Motion {
        const val FAST_MS = 150
        const val BASE_MS = 200
        const val SLOW_MS = 250
    }

    object Typography {
        val display = TypeStyle(32.sp, 40.sp, FontWeight(700))
        val h1 = TypeStyle(28.sp, 36.sp, FontWeight(700))
        val h2 = TypeStyle(24.sp, 32.sp, FontWeight(600))
        val h3 = TypeStyle(20.sp, 28.sp, FontWeight(600))
        val h4 = TypeStyle(17.sp, 24.sp, FontWeight(600))
        val body = TypeStyle(15.sp, 22.sp, FontWeight(400))
        val caption = TypeStyle(13.sp, 18.sp, FontWeight(400))
        val button = TypeStyle(15.sp, 16.sp, FontWeight(600))
        val label = TypeStyle(12.sp, 16.sp, FontWeight(600))
    }

    object Size {
        val buttonSmall = 40.dp
        val buttonMedium = 48.dp
        val buttonLarge = 56.dp
        val input = 48.dp
        val listRowMin = 64.dp
        val listRowMax = 72.dp
        val avatar = listOf(40.dp, 48.dp, 64.dp, 88.dp)
        val icon = listOf(16.dp, 20.dp, 24.dp, 32.dp)
        val touchTarget = 48.dp
        val screenMargin = 16.dp
    }
}


/** Типографический стиль: размер, интерлиньяж, начертание. */
data class TypeStyle(
    val size: androidx.compose.ui.unit.TextUnit,
    val lineHeight: androidx.compose.ui.unit.TextUnit,
    val weight: FontWeight,
)
