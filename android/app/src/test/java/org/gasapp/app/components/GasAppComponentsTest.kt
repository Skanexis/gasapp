// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.app.Activity
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

/**
 * Тесты компонентов дизайн-системы.
 *
 * Проверяется поведение, а не внешний вид: соответствие макету — задача
 * snapshot-тестов, которые пока отключены (см. `app/src/draft/README.md`).
 *
 * Robolectric нужен, потому что компоненты наследуют `View` и требуют
 * настоящий `Context` с темой; эмулятор при этом не запускается.
 */
@RunWith(RobolectricTestRunner::class)
class GasAppComponentsTest {

    /**
     * Компонентам нужен контекст с темой приложения: `AppCompat`-виджеты
     * бросают исключение на теме без нужных атрибутов.
     */
    private fun themedActivity(): Activity =
        Robolectric.buildActivity(Activity::class.java).get().apply {
            setTheme(R.style.Theme_GasApp)
        }

    // --- GasAppButton ---

    /**
     * Состояние загрузки не пропускает нажатие и меняет подпись.
     *
     * Блокировка — не косметика: без неё повторное нажатие отправит
     * операцию второй раз, пока первая ещё идёт. Кнопка при этом
     * не гаснет (UI kit: идущее действие — кнопка со спиннером).
     */
    @Test
    fun `loading state blocks clicks and swaps label`() {
        val button = GasAppButton(themedActivity())
        button.text = "Отправить"
        var clicks = 0
        button.setOnClickListener { clicks++ }

        button.isLoading = true

        assertTrue(button.isLoading)
        assertFalse("нажатие во время загрузки прошло", button.performClick())
        assertEquals("обработчик вызван во время загрузки", 0, clicks)
        assertTrue(
            "загрузка не подмешана в drawableState — кнопка выглядела бы погасшей",
            button.drawableState.contains(R.attr.state_loading),
        )
        assertEquals(
            ApplicationProvider.getApplicationContext<android.content.Context>()
                .getString(R.string.button_loading),
            button.text.toString(),
        )
    }

    /** После загрузки возвращаются исходная подпись и доступность. */
    @Test
    fun `leaving loading restores label and enabled state`() {
        val button = GasAppButton(themedActivity())
        button.text = "Отправить"
        button.setOnClickListener {}

        button.isLoading = true
        button.isLoading = false

        assertEquals("Отправить", button.text.toString())
        assertTrue(button.isEnabled)
        assertTrue("после загрузки нажатие не проходит", button.performClick())
    }

    /**
     * Размер из разметки действует.
     *
     * Прежде общие метрики ставились после размера и затирали его:
     * `gasappButtonSize="small"` давал ту же кнопку 48dp, что и без него.
     */
    @Test
    fun `size attribute changes the height`() {
        val activity = themedActivity()
        val small = GasAppButton(activity).apply { size = GasAppButton.Size.Small }
        val large = GasAppButton(activity).apply { size = GasAppButton.Size.Large }
        val density = activity.resources.displayMetrics.density

        assertEquals(40, (small.minHeight / density).toInt())
        assertEquals(56, (large.minHeight / density).toInt())
    }

    /** Прикладные состояния попадают в набор состояний drawable. */
    @Test
    fun `custom states reach the drawable state set`() {
        val button = GasAppButton(themedActivity())

        button.isError = true

        assertTrue(
            "state_error должен подмешиваться в drawableState",
            button.drawableState.contains(R.attr.state_error),
        )
    }

    /** По умолчанию прикладных состояний нет. */
    @Test
    fun `button starts in the normal state`() {
        val button = GasAppButton(themedActivity())

        assertFalse(button.isLoading)
        assertFalse(button.isError)
        assertTrue(button.isEnabled)
        assertFalse(button.drawableState.contains(R.attr.state_error))
        assertFalse(button.drawableState.contains(R.attr.state_loading))
    }

    // --- GasAppTextField ---

    /**
     * Флаг ошибки поля не конфликтует со встроенным свойством `error`.
     *
     * Именно на этом конфликте прежняя версия не компилировалась.
     */
    @Test
    fun `text field error state is independent from EditText error text`() {
        val field = GasAppTextField(themedActivity())

        field.hasError = true

        assertTrue(field.hasError)
        assertTrue(field.drawableState.contains(R.attr.state_error))
    }

    @Test
    fun `text field starts without error`() {
        val field = GasAppTextField(themedActivity())

        assertFalse(field.hasError)
        assertFalse(field.drawableState.contains(R.attr.state_error))
    }

    // --- GasAppListRow ---

    /**
     * Строка кликабельна и достижима с клавиатуры.
     *
     * Без этого состояния `pressed`/`focused` не наступают никогда, а строка
     * выпадает из навигации (раздел 20.5 — доступность).
     */
    @Test
    fun `list row is clickable and focusable`() {
        val row = GasAppListRow(themedActivity())

        assertTrue(row.isClickable)
        assertTrue(row.isFocusable)
    }

    /** Системные состояния обрабатываются платформой, а не перекрываются. */
    @Test
    fun `list row reflects selected state`() {
        val row = GasAppListRow(themedActivity())

        row.isSelected = true

        assertTrue(row.isSelected)
        assertTrue(row.drawableState.contains(android.R.attr.state_selected))
    }
}
