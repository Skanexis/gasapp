// SPDX-License-Identifier: Apache-2.0
// Сгенерировано tools/gen-tokens.mjs из design/secure-messenger-ui-kit.html.
// НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — правки будут затёрты при следующей генерации.
// Источник правды по дизайну — UI kit (раздел 20 плана).

package org.aegis.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Дизайн-токены AEGIS. */
object AegisTokens {

    object Colors {
        /** `#0D0F12` */
        val bgBase = Color(0xFF0D0F12)
        /** `#15181D` */
        val bgRaised = Color(0xFF15181D)
        /** `#1C2128` */
        val bgCard = Color(0xFF1C2128)
        /** `#252B33` */
        val bgHover = Color(0xFF252B33)
        /** `#2E353E` */
        val line = Color(0xFF2E353E)
        /** `#FFFFFF` */
        val textPrimary = Color(0xFFFFFFFF)
        /** `#B9C1CC` */
        val textSecondary = Color(0xFFB9C1CC)
        /** `#7C8796` */
        val textMuted = Color(0xFF7C8796)
        /** `#596170` */
        val textDisabled = Color(0xFF596170)
        /** `#37B8FF` */
        val accentBase = Color(0xFF37B8FF)
        /** `#5CC6FF` */
        val accentHover = Color(0xFF5CC6FF)
        /** `#2AA3E8` */
        val accentPressed = Color(0xFF2AA3E8)
        /** `#06121B` */
        val accentOn = Color(0xFF06121B)
        /** `rgba(55,184,255,.12)` */
        val accentDim = Color(0x1F37B8FF)
        /** `rgba(55,184,255,.38)` */
        val accentLine = Color(0x6137B8FF)
        /** `#18C37A` */
        val statusSuccess = Color(0xFF18C37A)
        /** `#E4B545` */
        val statusWarning = Color(0xFFE4B545)
        /** `#E5484D` */
        val statusError = Color(0xFFE5484D)
        /** `#37B8FF` */
        val statusInfo = Color(0xFF37B8FF)
        /** `rgba(24,195,122,.12)` */
        val statusSuccessDim = Color(0x1F18C37A)
        /** `rgba(228,181,69,.12)` */
        val statusWarningDim = Color(0x1FE4B545)
        /** `rgba(229,72,77,.12)` */
        val statusErrorDim = Color(0x1FE5484D)
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
