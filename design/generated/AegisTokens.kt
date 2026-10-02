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
        /** `#0F1629` */
        val bgBase = Color(0xFF0F1629)
        /** `#151D34` */
        val bgRaised = Color(0xFF151D34)
        /** `#1B2442` */
        val bgCard = Color(0xFF1B2442)
        /** `#242F52` */
        val bgHover = Color(0xFF242F52)
        /** `#2E3A5C` */
        val line = Color(0xFF2E3A5C)
        /** `#F2F4FC` */
        val textPrimary = Color(0xFFF2F4FC)
        /** `#B4BCD6` */
        val textSecondary = Color(0xFFB4BCD6)
        /** `#8E99B8` */
        val textMuted = Color(0xFF8E99B8)
        /** `#5A6585` */
        val textDisabled = Color(0xFF5A6585)
        /** `#8FA5FF` */
        val accentBase = Color(0xFF8FA5FF)
        /** `#A8B9FF` */
        val accentHover = Color(0xFFA8B9FF)
        /** `#7890F5` */
        val accentPressed = Color(0xFF7890F5)
        /** `#0A1030` */
        val accentOn = Color(0xFF0A1030)
        /** `rgba(143,165,255,.14)` */
        val accentDim = Color(0x248FA5FF)
        /** `rgba(143,165,255,.40)` */
        val accentLine = Color(0x668FA5FF)
        /** `#3DD598` */
        val statusSuccess = Color(0xFF3DD598)
        /** `#F0B84C` */
        val statusWarning = Color(0xFFF0B84C)
        /** `#FF6B78` */
        val statusError = Color(0xFFFF6B78)
        /** `#8FA5FF` */
        val statusInfo = Color(0xFF8FA5FF)
        /** `rgba(61,213,152,.13)` */
        val statusSuccessDim = Color(0x213DD598)
        /** `rgba(240,184,76,.13)` */
        val statusWarningDim = Color(0x21F0B84C)
        /** `rgba(255,107,120,.13)` */
        val statusErrorDim = Color(0x21FF6B78)
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
