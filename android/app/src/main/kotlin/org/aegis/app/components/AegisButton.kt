// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import androidx.appcompat.widget.AppCompatButton
import org.aegis.app.R

/**
 * Кнопка дизайн-системы AEGIS с семью состояниями (раздел 20.4 плана).
 *
 * Состояния делятся на две группы:
 *
 * * **системные** — `enabled`, `pressed`, `focused`, `hovered`: ими управляет
 *   сама платформа, и перехватывать их сеттерами не нужно. Реакция задаётся
 *   селектором в `res/drawable/bg_aegis_button.xml`;
 * * **прикладные** — `loading` и `error`: платформа о них не знает, поэтому
 *   они хранятся здесь и подмешиваются в состояние через
 *   [onCreateDrawableState].
 *
 * # Почему не сеттеры
 *
 * Прежняя версия пыталась переопределить `setFocused` (такого метода в
 * `View` нет — фокус меняется через `requestFocus`/`clearFocus`) и читала
 * несуществующее свойство `isNotEnabled`. Из-за этого модуль не
 * компилировался. Здесь вместо перехвата состояний используется штатный
 * механизм Android — расширение набора состояний drawable.
 */
class AegisButton @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = android.R.attr.buttonStyle,
) : AppCompatButton(context, attrs, defStyleAttr) {

    /** Идёт длительная операция: кнопка недоступна и показывает подпись загрузки. */
    var isLoading: Boolean = false
        set(value) {
            if (field == value) return
            field = value

            if (value) {
                textBeforeLoading = text
                setText(R.string.button_loading)
            } else {
                text = textBeforeLoading
            }

            // Во время загрузки нажатие не должно проходить повторно.
            isEnabled = !value
            refreshDrawableState()
        }

    /** Последняя операция завершилась ошибкой. */
    var isError: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            refreshDrawableState()
        }

    private var textBeforeLoading: CharSequence = ""

    init {
        setBackgroundResource(R.drawable.bg_aegis_button)
        isFocusable = true
        isClickable = true
    }

    override fun onCreateDrawableState(extraSpace: Int): IntArray {
        val state = super.onCreateDrawableState(extraSpace + EXTRA_STATES)

        if (isLoading) {
            mergeDrawableStates(state, STATE_LOADING)
        }
        if (isError) {
            mergeDrawableStates(state, STATE_ERROR)
        }

        return state
    }

    private companion object {
        /** Сколько дополнительных состояний может добавить эта вью. */
        const val EXTRA_STATES = 2

        val STATE_LOADING = intArrayOf(R.attr.state_loading)
        val STATE_ERROR = intArrayOf(R.attr.state_error)
    }
}
