// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import android.content.res.Configuration
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import org.aegis.app.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Safety number виден целиком при 200% размера текста.
 *
 * Раздел 20.5 и пункт M8 «🧪 Тест: fingerprint при 200% Dynamic Type».
 *
 * # Почему именно этот экран, а не любой другой
 *
 * Safety number — единственное место в приложении, где **обрезание
 * текста меняет смысл**. Везде ещё обрезанная строка выглядит
 * обрезанной: многоточие видно, и человек понимает, что видит не всё.
 * Здесь он видит ряд цифр, сверяет их с цифрами собеседника, они
 * совпадают — и он нажимает «подтвердить».
 *
 * Если при крупном шрифте пропала последняя строка из четырёх,
 * сверены 45 цифр из 60. Подмена ключа, отличающаяся только в хвосте,
 * пройдёт проверку, которую человек считает пройденной полностью.
 * Именно поэтому пункт отдельной строкой в плане.
 *
 * # Как проверяется
 *
 * Разметка раздувается в контексте с `fontScale = 2.0`, измеряется
 * по ширине узкого телефона и проверяется на:
 *
 * * отсутствие многоточия в каждой строке (`getEllipsisCount`);
 * * все 60 цифр на месте;
 * * высота вида вмещает всю раскладку — ничего не срезано снизу.
 *
 * ⚠️ Перед проверками тест доказывает, что масштаб вообще применился:
 * сравнение при незаработавшем `fontScale` прошло бы всегда, ничего
 * не проверив (та же ловушка, что трижды поймана в разделе 23.5).
 *
 * # Чего тест не проверяет
 *
 * Как это выглядит. Читаемость, перенос по группам и то, помещается ли
 * всё без прокрутки, проверяются глазами на устройстве. Здесь
 * закрепляется только то, что можно закрепить: цифры не теряются.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SafetyNumberDynamicTypeTest {

    /** 🔐 При 200% ни одна строка не обрезана многоточием. */
    @Test
    fun fingerprint_is_not_ellipsised_at_double_font_scale() {
        val digits = inflateDigits(FONT_SCALE_DOUBLE)
        val layout = requireNotNull(digits.layout) { "вид не разметился" }

        for (line in 0 until layout.lineCount) {
            assertEquals(
                "строка $line обрезана многоточием при 200% размера текста",
                0,
                layout.getEllipsisCount(line),
            )
        }
    }

    /** 🔐 Все шестьдесят цифр на месте. */
    @Test
    fun every_digit_survives_double_font_scale() {
        val digits = inflateDigits(FONT_SCALE_DOUBLE)

        assertEquals(
            "показано не 60 цифр — сверять будут неполный отпечаток",
            DIGIT_COUNT,
            digits.text.count { it.isDigit() },
        )
    }

    /**
     * 🔐 Высота вида вмещает всю раскладку.
     *
     * Многоточия может не быть и тогда, когда текст просто уехал
     * за нижнюю границу: `TextView` рисует, что помещается, и молчит.
     */
    @Test
    fun nothing_is_clipped_below_at_double_font_scale() {
        val digits = inflateDigits(FONT_SCALE_DOUBLE)
        val layout = requireNotNull(digits.layout) { "вид не разметился" }

        val needed = layout.height + digits.paddingTop + digits.paddingBottom

        assertTrue(
            "раскладке нужно $needed px, а вид высотой ${digits.measuredHeight} px: " +
                "хвост отпечатка срезан снизу",
            digits.measuredHeight >= needed,
        )
    }

    /**
     * Ограничения на число строк нет.
     *
     * Самый вероятный способ сломать этот экран в будущем — добавить
     * `maxLines`, чтобы «аккуратнее смотрелось». При 100% разницы
     * не видно, при 200% пропадает половина отпечатка.
     */
    @Test
    fun the_fingerprint_view_has_no_line_limit() {
        val digits = inflateDigits(FONT_SCALE_DOUBLE)

        assertEquals(
            "у отпечатка появилось ограничение по числу строк",
            Int.MAX_VALUE,
            digits.maxLines,
        )
    }

    /**
     * Масштаб действительно применяется.
     *
     * ⚠️ Без этой проверки все остальные проходят и тогда, когда
     * `fontScale` не подействовал: текст рисуется обычного размера,
     * помещается, многоточий нет — и тест зелен, ничего не проверив.
     */
    @Test
    fun the_font_scale_actually_applies() {
        val normal = inflateDigits(FONT_SCALE_NORMAL).textSize
        val doubled = inflateDigits(FONT_SCALE_DOUBLE).textSize

        assertTrue(
            "при fontScale=2.0 размер текста не вырос ($normal → $doubled): " +
                "масштаб не применился, и остальные проверки ничего не значат",
            doubled > normal * 1.5f,
        )
    }

    /**
     * Раздувает экран сверки в контексте с заданным масштабом текста
     * и возвращает измеренный вид с цифрами.
     */
    private fun inflateDigits(fontScale: Float): TextView {
        val base: Context = ApplicationProvider.getApplicationContext()

        val configuration = Configuration(base.resources.configuration).apply {
            this.fontScale = fontScale
        }

        val scaled = base.createConfigurationContext(configuration)

        // Тема нужна явно: `createConfigurationContext` отдаёт голый
        // контекст, и без темы раздувание падает на атрибутах стиля.
        scaled.setTheme(R.style.Theme_AEGIS)

        val root = LayoutInflater.from(scaled).inflate(R.layout.activity_safety_number, null)
        val digits = root.findViewById<TextView>(R.id.safety_number_digits)

        // Настоящий отпечаток: 4 строки по 3 группы из 5 цифр (ADR-022).
        // Раскладка та же, что у `format_safety_number` в ядре.
        digits.text = SAMPLE_SAFETY_NUMBER

        // Ширина узкого телефона в пикселях при плотности 1: экран
        // на 320dp — тот случай, где обрезание проявляется первым.
        val widthSpec = View.MeasureSpec.makeMeasureSpec(
            (NARROW_PHONE_DP * base.resources.displayMetrics.density).toInt(),
            View.MeasureSpec.EXACTLY,
        )
        val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)

        root.measure(widthSpec, heightSpec)
        root.layout(0, 0, root.measuredWidth, root.measuredHeight)

        return digits
    }

    private companion object {
        const val FONT_SCALE_NORMAL = 1.0f
        const val FONT_SCALE_DOUBLE = 2.0f

        /** 320dp — самый узкий экран, который приложение поддерживает. */
        const val NARROW_PHONE_DP = 320

        const val DIGIT_COUNT = 60

        val SAMPLE_SAFETY_NUMBER = listOf(
            "38679 09329 07961",
            "31636 68792 91538",
            "01705 09531 22053",
            "70951 53139 67810",
        ).joinToString("\n")
    }
}
