// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.R
import org.gasapp.app.components.PinPad
import org.gasapp.app.core.Pin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 PIN набирается своей клавиатурой, а не системной.
 *
 * # Что здесь проверяется
 *
 * Системную клавиатуру поставляет кто угодно, и сторонняя получает каждую
 * цифру. При регистрации, в File Vault и при включении биометрии PIN
 * набирался в текстовое поле — то есть системной клавиатурой (аудит, Н1).
 * Теперь во всех этих местах [PinPad].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PinPadTest {

    private val context: Context = ApplicationProvider.getApplicationContext<Context>().apply {
        setTheme(R.style.Theme_GasApp)
    }

    private fun pad(onComplete: ((PinPad) -> Unit)? = null): Pair<View, PinPad> {
        val root = LayoutInflater.from(context).inflate(R.layout.dialog_pin, null)
        return root to PinPad(root, onComplete)
    }

    private fun View.press(vararg digits: Int) {
        val ids = listOf(
            R.id.key_0, R.id.key_1, R.id.key_2, R.id.key_3, R.id.key_4,
            R.id.key_5, R.id.key_6, R.id.key_7, R.id.key_8, R.id.key_9,
        )
        digits.forEach { findViewById<View>(ids[it]).performClick() }
    }

    @Test
    fun digits_are_collected_up_to_the_pin_length() {
        val (root, pad) = pad()

        root.press(4, 8, 2, 9, 1, 5, 7, 7)

        assertEquals("набрано больше, чем длина PIN", Pin.LENGTH, pad.length)
        assertEquals("482915", String(pad.take(), Charsets.US_ASCII))
    }

    @Test
    fun delete_removes_the_last_digit() {
        val (root, pad) = pad()

        root.press(1, 2, 3)
        root.findViewById<View>(R.id.key_delete).performClick()

        assertEquals(2, pad.length)
    }

    /** 🔐 Забранный PIN в клавиатуре не остаётся. */
    @Test
    fun taking_the_pin_wipes_the_buffer() {
        val (root, pad) = pad()

        root.press(1, 2, 3, 4, 5, 6)
        pad.take()

        assertEquals("PIN остался в клавиатуре после take()", 0, pad.length)
        assertFalse(pad.isComplete)
    }

    /** Полный PIN отдаётся один раз — на шестой цифре, не раньше и не снова. */
    @Test
    fun completion_fires_once_on_the_last_digit() {
        var calls = 0
        val (root, _) = pad { calls += 1 }

        root.press(1, 2, 3, 4, 5)
        assertEquals("завершение раньше последней цифры", 0, calls)

        root.press(6, 7, 8)
        assertEquals(1, calls)
    }

    @Test
    fun a_disabled_keypad_takes_no_digits() {
        val (root, pad) = pad()

        pad.setEnabled(false)

        assertFalse(root.findViewById<View>(R.id.key_1).isEnabled)
    }

    /**
     * 🔐 На экранах с PIN нет текстового поля для пароля.
     *
     * Поле с `numberPassword` — ровно то, что было: цифры PIN шли
     * через системную клавиатуру.
     */
    @Test
    fun no_pin_screen_has_a_password_text_field() {
        for (layout in listOf(
            R.layout.activity_onboarding,
            R.layout.activity_vault,
            R.layout.activity_lock,
            R.layout.dialog_pin,
        )) {
            val root = LayoutInflater.from(context).inflate(layout, null)
            val passwordFields = editTexts(root).filter { field ->
                val variation = field.inputType and InputType.TYPE_MASK_VARIATION
                variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
            }

            assertTrue(
                "${context.resources.getResourceEntryName(layout)}: PIN в текстовом поле",
                passwordFields.isEmpty(),
            )
            assertTrue(
                "${context.resources.getResourceEntryName(layout)}: нет своей клавиатуры",
                root.findViewById<View>(R.id.keypad) != null,
            )
        }
    }

    private fun editTexts(view: View): List<EditText> = when (view) {
        is EditText -> listOf(view)
        is ViewGroup -> (0 until view.childCount).flatMap { editTexts(view.getChildAt(it)) }
        else -> emptyList()
    }
}
