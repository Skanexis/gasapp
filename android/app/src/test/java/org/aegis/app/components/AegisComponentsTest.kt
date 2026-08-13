// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.app.Activity
import androidx.test.core.app.ApplicationProvider
import org.aegis.app.R
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
class AegisComponentsTest {

    /**
     * Компонентам нужен контекст с темой приложения: `AppCompat`-виджеты
     * бросают исключение на теме без нужных атрибутов.
     */
    private fun themedActivity(): Activity =
        Robolectric.buildActivity(Activity::class.java).get().apply {
            setTheme(R.style.Theme_AEGIS)
        }

    // --- AegisButton ---

    /**
     * Состояние загрузки блокирует кнопку и меняет подпись.
     *
     * Блокировка — не косметика: без неё повторное нажатие отправит
     * операцию второй раз, пока первая ещё идёт.
     */
    @Test
    fun `loading state disables button and swaps label`() {
        val button = AegisButton(themedActivity())
        button.text = "Отправить"

        button.isLoading = true

        assertTrue(button.isLoading)
        assertFalse("во время загрузки кнопка должна быть недоступна", button.isEnabled)
        assertEquals(
            ApplicationProvider.getApplicationContext<android.content.Context>()
                .getString(R.string.button_loading),
            button.text.toString(),
        )
    }

    /** После загрузки возвращаются исходная подпись и доступность. */
    @Test
    fun `leaving loading restores label and enabled state`() {
        val button = AegisButton(themedActivity())
        button.text = "Отправить"

        button.isLoading = true
        button.isLoading = false

        assertEquals("Отправить", button.text.toString())
        assertTrue(button.isEnabled)
    }

    /** Прикладные состояния попадают в набор состояний drawable. */
    @Test
    fun `custom states reach the drawable state set`() {
        val button = AegisButton(themedActivity())

        button.isError = true

        assertTrue(
            "state_error должен подмешиваться в drawableState",
            button.drawableState.contains(R.attr.state_error),
        )
    }

    /** По умолчанию прикладных состояний нет. */
    @Test
    fun `button starts in the normal state`() {
        val button = AegisButton(themedActivity())

        assertFalse(button.isLoading)
        assertFalse(button.isError)
        assertTrue(button.isEnabled)
        assertFalse(button.drawableState.contains(R.attr.state_error))
        assertFalse(button.drawableState.contains(R.attr.state_loading))
    }

    // --- AegisTextField ---

    /**
     * Флаг ошибки поля не конфликтует со встроенным свойством `error`.
     *
     * Именно на этом конфликте прежняя версия не компилировалась.
     */
    @Test
    fun `text field error state is independent from EditText error text`() {
        val field = AegisTextField(themedActivity())

        field.hasError = true

        assertTrue(field.hasError)
        assertTrue(field.drawableState.contains(R.attr.state_error))
    }

    @Test
    fun `text field starts without error`() {
        val field = AegisTextField(themedActivity())

        assertFalse(field.hasError)
        assertFalse(field.drawableState.contains(R.attr.state_error))
    }

    // --- AegisListRow ---

    /**
     * Строка кликабельна и достижима с клавиатуры.
     *
     * Без этого состояния `pressed`/`focused` не наступают никогда, а строка
     * выпадает из навигации (раздел 20.5 — доступность).
     */
    @Test
    fun `list row is clickable and focusable`() {
        val row = AegisListRow(themedActivity())

        assertTrue(row.isClickable)
        assertTrue(row.isFocusable)
    }

    /** Системные состояния обрабатываются платформой, а не перекрываются. */
    @Test
    fun `list row reflects selected state`() {
        val row = AegisListRow(themedActivity())

        row.isSelected = true

        assertTrue(row.isSelected)
        assertTrue(row.drawableState.contains(android.R.attr.state_selected))
    }
}
