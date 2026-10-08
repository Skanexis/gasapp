// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.view.View
import android.view.ViewGroup
import org.gasapp.app.R
import org.gasapp.app.ui.PinFeedback
import org.gasapp.app.core.PinBuffer

/**
 * 🔐 Набор PIN своей клавиатурой — без системной.
 *
 * # Зачем
 *
 * Системную клавиатуру поставляет кто угодно. Сторонняя получает каждое
 * нажатие и вправе запомнить его или отправить куда угодно; флаги вроде
 * `IME_FLAG_NO_PERSONALIZED_LEARNING` — просьба, а не запрет. PIN здесь —
 * половина ключа базы, поэтому набирается только этой клавиатурой: при
 * регистрации, в File Vault и при включении биометрии, как и на экране
 * входа. Прежде в трёх этих местах стояли текстовые поля с системной
 * клавиатурой (аудит, Н1).
 *
 * Разметка — [R.layout.view_pin_dots] и [R.layout.view_pin_keypad];
 * [root] должен содержать обе.
 *
 * ⚠️ Экран входа держит ту же логику у себя (`LockActivity`) — с задержками
 * после неверных попыток и с блокировкой клавиш на время проверки.
 */
class PinPad(
    root: View,
    private val onComplete: ((PinPad) -> Unit)? = null,
) {
    private val entered = PinBuffer()
    private val dots: ViewGroup = root.findViewById(R.id.pin_dots)
    private val keys: List<View>

    init {
        val digits = listOf(
            R.id.key_0 to '0', R.id.key_1 to '1', R.id.key_2 to '2',
            R.id.key_3 to '3', R.id.key_4 to '4', R.id.key_5 to '5',
            R.id.key_6 to '6', R.id.key_7 to '7', R.id.key_8 to '8',
            R.id.key_9 to '9',
        )

        keys = digits.map { (id, digit) ->
            root.findViewById<View>(id).apply { setOnClickListener { append(digit) } }
        } + root.findViewById<View>(R.id.key_delete).apply {
            setOnClickListener { removeLast() }
        }

        render()
    }

    /** Набраны ли все цифры. */
    val isComplete: Boolean
        get() = entered.isComplete

    /** Сколько цифр набрано. */
    val length: Int
        get() = entered.length

    /**
     * Отдаёт набранный PIN и затирает буфер.
     *
     * 🔐 Одним вызовом: PIN не остаётся в клавиатуре после того, как
     * его забрали, — ни на экране, к которому вернутся через переключатель
     * задач, ни в памяти дольше нужного.
     */
    fun take(): ByteArray {
        val pin = entered.take()
        render()

        return pin
    }

    /** Отклик на неверный PIN: точки краснеют и вздрагивают (см. [PinFeedback]). */
    fun showWrong() {
        PinFeedback.wrong(dots) { render() }
    }

    /** 🔐 Затирает набранное. */
    fun clear() {
        entered.clear()
        render()
    }

    /** Включает и выключает клавиши — например, на время проверки PIN. */
    fun setEnabled(enabled: Boolean) {
        keys.forEach { key ->
            key.isEnabled = enabled
            key.alpha = if (enabled) 1f else DISABLED_ALPHA
        }
    }

    private fun append(digit: Char) {
        if (!entered.append(digit)) {
            return
        }

        render()

        if (isComplete) {
            onComplete?.invoke(this)
        }
    }

    private fun removeLast() {
        if (entered.length > 0) {
            entered.removeLast()
            render()
        }
    }

    /** 🔐 Только количество — сами цифры не отображаются нигде. */
    private fun render() {
        for (index in 0 until dots.childCount) {
            dots.getChildAt(index).setBackgroundResource(
                if (index < entered.length) R.drawable.bg_pin_dot_filled else R.drawable.bg_pin_dot,
            )
        }
    }

    private companion object {
        const val DISABLED_ALPHA = 0.3f
    }
}
