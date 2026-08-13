// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import androidx.appcompat.widget.AppCompatEditText
import org.aegis.app.R

/**
 * Поле ввода дизайн-системы AEGIS.
 *
 * Состояния `enabled`, `focused` и `pressed` обрабатывает платформа через
 * селектор `res/drawable/bg_aegis_text_field.xml`. Прикладное состояние
 * «ошибка» добавляется через [onCreateDrawableState].
 *
 * # Про имя свойства
 *
 * Флаг ошибки называется [hasError], а не `error`: у `EditText` уже есть
 * свойство `error` (текст всплывающей подсказки валидации). Прежняя версия
 * объявляла своё `getError` и получала конфликт с методом супертипа.
 */
class AegisTextField @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = androidx.appcompat.R.attr.editTextStyle,
) : AppCompatEditText(context, attrs, defStyleAttr) {

    /** Содержимое поля не прошло валидацию. */
    var hasError: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            refreshDrawableState()
        }

    init {
        setBackgroundResource(R.drawable.bg_aegis_text_field)
    }

    override fun onCreateDrawableState(extraSpace: Int): IntArray {
        val state = super.onCreateDrawableState(extraSpace + EXTRA_STATES)

        if (hasError) {
            mergeDrawableStates(state, STATE_ERROR)
        }

        return state
    }

    private companion object {
        const val EXTRA_STATES = 1

        val STATE_ERROR = intArrayOf(R.attr.state_error)
    }
}
