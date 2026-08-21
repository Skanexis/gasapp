// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Ресурсы приложения соответствуют design/aegis.tokens.json.
 *
 * # Зачем это тест, а не договорённость
 *
 * Токены — источник истины для вёрстки, но Android не читает JSON
 * при сборке: значения продублированы в `dimens.xml` и `colors.xml`.
 * Дубликат без проверки расходится с оригиналом при первой же правке,
 * и расхождение замечают глазами через несколько экранов.
 *
 * Тест сверяет обе стороны и падает с указанием, что именно разошлось.
 */
@RunWith(RobolectricTestRunner::class)
class DesignTokensTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private val tokens: JSONObject by lazy {
        // Путь от каталога модуля: тест запускается из android/app.
        val file = File("../../design/aegis.tokens.json")

        assertTrue(
            "файл токенов не найден: ${file.absolutePath}",
            file.exists(),
        )

        JSONObject(file.readText())
    }

    /** Шкала отступов совпадает со `space` из токенов. */
    @Test
    fun spacing_scale_matches_tokens() {
        val expected = tokens.getJSONArray("space")
        val names = listOf(
            R.dimen.space_xs,
            R.dimen.space_s,
            R.dimen.space_m,
            R.dimen.space_l,
            R.dimen.space_xl,
            R.dimen.space_2xl,
            R.dimen.space_3xl,
            R.dimen.space_4xl,
        )

        assertEquals("число ступеней шкалы", expected.length(), names.size)

        for (index in names.indices) {
            assertEquals(
                "ступень шкалы отступов #$index",
                expected.getInt(index),
                dp(names[index]),
            )
        }
    }

    /** Скругления совпадают с `radius`. */
    @Test
    fun radii_match_tokens() {
        val radius = tokens.getJSONObject("radius")

        assertEquals(radius.getInt("input"), dp(R.dimen.radius_input))
        assertEquals(radius.getInt("button"), dp(R.dimen.radius_button))
        assertEquals(radius.getInt("card"), dp(R.dimen.radius_card))
        assertEquals(radius.getInt("sheet"), dp(R.dimen.radius_sheet))
    }

    /** Высоты кнопок, полей и строк совпадают с `size`. */
    @Test
    fun sizes_match_tokens() {
        val size = tokens.getJSONObject("size")

        assertEquals(size.getInt("buttonSmall"), dp(R.dimen.button_small))
        assertEquals(size.getInt("buttonMedium"), dp(R.dimen.button_medium))
        assertEquals(size.getInt("buttonLarge"), dp(R.dimen.button_large))
        assertEquals(size.getInt("input"), dp(R.dimen.input_height))
        assertEquals(size.getInt("listRowMin"), dp(R.dimen.list_row_min))
        assertEquals(size.getInt("listRowMax"), dp(R.dimen.list_row_max))
        assertEquals(size.getInt("screenMargin"), dp(R.dimen.screen_padding))

        // 🔐 Область нажатия — не вопрос вкуса: меньшая цель
        // промахивается, а промах в мессенджере отправляет сообщение
        // не тому или открывает не тот чат.
        assertEquals(size.getInt("touchTarget"), dp(R.dimen.touch_target))
    }

    /** Размеры аватаров и значков совпадают с токенами. */
    @Test
    fun avatar_and_icon_sizes_match_tokens() {
        val size = tokens.getJSONObject("size")

        val avatars = size.getJSONArray("avatar")
        val avatarDimens = listOf(
            R.dimen.avatar_s,
            R.dimen.avatar_m,
            R.dimen.avatar_l,
            R.dimen.avatar_xl,
        )

        for (index in avatarDimens.indices) {
            assertEquals(
                "размер аватара #$index",
                avatars.getInt(index),
                dp(avatarDimens[index]),
            )
        }

        val icons = size.getJSONArray("icon")
        val iconDimens = listOf(
            R.dimen.icon_xs,
            R.dimen.icon_s,
            R.dimen.icon_m,
            R.dimen.icon_l,
        )

        for (index in iconDimens.indices) {
            assertEquals(
                "размер значка #$index",
                icons.getInt(index),
                dp(iconDimens[index]),
            )
        }
    }

    /** Кегли типографской шкалы совпадают с `typography`. */
    @Test
    fun type_scale_matches_tokens() {
        val type = tokens.getJSONObject("typography")

        val pairs = listOf(
            "display" to R.dimen.text_display,
            "h1" to R.dimen.text_h1,
            "h2" to R.dimen.text_h2,
            "h3" to R.dimen.text_h3,
            "h4" to R.dimen.text_h4,
            "body" to R.dimen.text_body,
            "caption" to R.dimen.text_caption,
            "button" to R.dimen.text_button,
            "label" to R.dimen.text_label,
        )

        for ((name, dimen) in pairs) {
            assertEquals(
                "кегль $name",
                type.getJSONObject(name).getInt("size"),
                sp(dimen),
            )
        }
    }

    /** Палитра совпадает с `color`. */
    @Test
    fun palette_matches_tokens() {
        val color = tokens.getJSONObject("color")

        val background = color.getJSONObject("bg")
        assertColor(background.getString("base"), R.color.bg_base)
        assertColor(background.getString("raised"), R.color.bg_raised)
        assertColor(background.getString("card"), R.color.bg_card)
        assertColor(background.getString("hover"), R.color.bg_hover)

        assertColor(color.getString("line"), R.color.line)

        val text = color.getJSONObject("text")
        assertColor(text.getString("primary"), R.color.text_primary)
        assertColor(text.getString("secondary"), R.color.text_secondary)
        assertColor(text.getString("muted"), R.color.text_muted)
        assertColor(text.getString("disabled"), R.color.text_disabled)

        val accent = color.getJSONObject("accent")
        assertColor(accent.getString("base"), R.color.accent_base)
        assertColor(accent.getString("hover"), R.color.accent_hover)
        assertColor(accent.getString("pressed"), R.color.accent_pressed)
        assertColor(accent.getString("on"), R.color.accent_on)

        // 🔐 Цвета состояний проверяются наравне с остальными: зелёный
        // означает проверенное человеком, красный — состоявшуюся
        // проблему. Съехавший оттенок делает утверждение о безопасности
        // менее заметным.
        val status = color.getJSONObject("status")
        assertColor(status.getString("success"), R.color.status_ok)
        assertColor(status.getString("warning"), R.color.status_warn)
        assertColor(status.getString("error"), R.color.status_error)
        assertColor(status.getString("info"), R.color.status_info)
    }

    /** Шрифт макета доступен приложению. */
    @Test
    fun inter_font_is_bundled() {
        for (font in listOf(R.font.inter_regular, R.font.inter_semibold, R.font.inter_bold)) {
            assertTrue(
                "начертание Inter не найдено",
                context.resources.getResourceName(font).contains("inter"),
            )
        }
    }

    private fun dp(dimen: Int): Int {
        val pixels = context.resources.getDimension(dimen)

        return (pixels / context.resources.displayMetrics.density).toInt()
    }

    private fun sp(dimen: Int): Int {
        val pixels = context.resources.getDimension(dimen)

        return (pixels / context.resources.displayMetrics.scaledDensity).toInt()
    }

    /**
     * Сверяет цвет ресурса с шестнадцатеричной записью из токенов.
     *
     * Токены пишут цвет как `#RRGGBB`, Android хранит `AARRGGBB`:
     * сравниваются только цветовые каналы, потому что прозрачности
     * в токенах нет — она задаётся отдельными значениями вроде `dim`.
     */
    private fun assertColor(expected: String, colorRes: Int) {
        val actual = context.resources.getColor(colorRes, null) and 0xFFFFFF
        val wanted = expected.removePrefix("#").toInt(16)

        assertEquals(
            "цвет ${context.resources.getResourceEntryName(colorRes)}",
            String.format("%06X", wanted),
            String.format("%06X", actual),
        )
    }
}
