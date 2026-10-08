// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.View
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.OnboardingActivity
import org.gasapp.app.R
import org.gasapp.app.core.Pin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 🔐 PIN, принятый при регистрации, набирается на экране входа.
 *
 * # Что здесь проверяется
 *
 * Длина PIN записана в трёх местах: константа [Pin.LENGTH], поле
 * ввода на экране регистрации и ряд точек в разметке экрана входа.
 * Совпадать они обязаны, и совпадали не всегда.
 *
 * Регистрация принимала **от шести до двенадцати** цифр
 * (`maxLength="12"`, проверка «не короче шести»), а подсказка под
 * полем предлагала «не менее 6 цифр». Экран входа набирает ровно
 * шесть и другой длины выдать не может.
 *
 * Ключ базы выводится из PIN целиком, поэтому PIN из семи цифр
 * давал ключ, который экран входа не воспроизведёт никогда.
 * Проверки «верен ли PIN» в системе нет — она означала бы хранить
 * подсказку для перебора, — так что приложение говорило бы
 * «не удалось открыть», одинаково и навсегда.
 *
 * ⚠️ Попасть туда можно было, просто поверив подсказке под полем.
 *
 * # Чего тест не проверяет
 *
 * Стойкость шестизначного PIN саму по себе. Она держится не на длине,
 * а на Argon2id и на аппаратном секрете, который не покидает телефон
 * (`Core.deriveKey`), и на задержках после неверных попыток
 * (`PinAttempts`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PinLengthTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    /**
     * 🔐 На экране входа столько точек, сколько цифр в PIN.
     *
     * Третье место, где записана длина, — разметка. Разойдись она
     * с константой, и часть набранного осталась бы без отклика:
     * `renderDots` перебирает точки, а не введённые цифры.
     */
    @Test
    fun the_lock_screen_shows_one_dot_per_digit() {
        context.setTheme(R.style.Theme_GasApp)

        val root = LayoutInflater.from(context).inflate(R.layout.activity_lock, null)
        val dots = root.findViewById<ViewGroup>(R.id.pin_dots)

        assertEquals(
            "точек на экране входа не столько, сколько цифр в PIN",
            Pin.LENGTH,
            dots.childCount,
        )
    }

    /**
     * 🔐 PIN, который экрану входа не набрать, до регистрации не доходит.
     *
     * Семь цифр — ровно тот случай, в который звала прежняя подсказка
     * «не менее 6 цифр».
     */
    @Test
    fun a_pin_the_lock_screen_cannot_enter_is_refused() {
        assertTrue("шесть цифр должны приниматься", Pin.isAcceptable("123456".toByteArray()))

        assertFalse("семизначный PIN приняли — им не войти", Pin.isAcceptable("1234567".toByteArray()))
        assertFalse("двенадцатизначный PIN приняли", Pin.isAcceptable("123456789012".toByteArray()))
        assertFalse("слишком короткий PIN приняли", Pin.isAcceptable("12345".toByteArray()))
        assertFalse("пустой PIN приняли", Pin.isAcceptable("".toByteArray()))
    }

    /**
     * 🔐 Нецифры не проходят, даже те, что `isDigit()` считает цифрами.
     *
     * Клавиатура входа выдаёт только ASCII. Арабо-индийские цифры
     * `isDigit()` пропускает, а набрать их там нечем — вставить
     * в поле регистрации можно.
     */
    @Test
    fun digits_other_than_ascii_are_refused() {
        val arabicIndic = "\u0661\u0662\u0663\u0664\u0665\u0666"

        assertTrue("заготовка теста не из тех цифр", arabicIndic.all { it.isDigit() })
        assertEquals("заготовка теста не той длины", Pin.LENGTH, arabicIndic.length)

        assertFalse("PIN из ненабираемых цифр приняли", Pin.isAcceptable(arabicIndic.toByteArray()))
    }

    /**
     * 🔐 Клавиатура регистрации не набирает больше, чем экран входа.
     *
     * PIN набирается своей клавиатурой ([org.gasapp.app.components.PinPad]),
     * и предел — [Pin.LENGTH]. Двенадцать нажатий оставляют шесть цифр.
     */
    @Test
    fun the_registration_keypad_stops_at_the_lock_screen_length() {
        // ⚠️ Настоящая активность, а не раздутая разметка: клавиатуру
        // привязывает `onCreate`. Привяжи её тест сам — он проверял бы
        // свою привязку, а не приложение.
        val controller = Robolectric.buildActivity(OnboardingActivity::class.java).setup()

        try {
            val root = controller.get().window.decorView
            repeat(12) { root.findViewById<View>(R.id.key_1).performClick() }

            val dots = root.findViewById<ViewGroup>(R.id.pin_dots)
            val filled = (0 until dots.childCount).count { index ->
                shadowOf(dots.getChildAt(index).background).createdFromResId ==
                    R.drawable.bg_pin_dot_filled
            }

            assertEquals(
                "клавиатура регистрации набрала PIN длиннее набираемого на входе",
                Pin.LENGTH,
                filled,
            )
        } finally {
            // ⚠️ Закрыть обязательно, и вот почему.
            //
            // `AutoLock` считает показанные экраны в счётчике,
            // общем на весь процесс, и подписан на события
            // жизненного цикла из `GasAppApplication`. Поднятая
            // и не закрытая активность оставляет счётчик на единице
            // навсегда.
            //
            // Тогда `AutoLockTest` перестаёт видеть уход в фон —
            // его `onActivityStopped` уводит счётчик к единице,
            // а не к нулю, — и падает с «приложение не заперлось».
            // Причём в другом файле, только при совместном прогоне
            // и без единой подсказки на этот.
            controller.pause().stop().destroy()
        }
    }
}
