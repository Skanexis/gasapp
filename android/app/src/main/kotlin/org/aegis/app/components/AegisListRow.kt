// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout
import org.aegis.app.R

/**
 * Строка списка дизайн-системы AEGIS.
 *
 * Все состояния строки (`enabled`, `pressed`, `focused`, `selected`,
 * `activated`) — системные, платформа управляет ими сама. Задача этого
 * класса — только подключить селектор фона и разумные значения по умолчанию.
 *
 * # Что было не так
 *
 * Прежняя версия объявляла собственные `setSelected`, `setActivated`,
 * `isSelected`, `isActivated`, перекрывая одноимённые члены `LinearLayout`
 * без `override`, и читала несуществующее `isNotEnabled`. Перехватывать эти
 * состояния не нужно: `View` уже вызывает `refreshDrawableState` при их
 * изменении, а селектор ниже сам выбирает нужный фон.
 */
class AegisListRow @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    init {
        orientation = HORIZONTAL
        setBackgroundResource(R.drawable.bg_aegis_list_row)

        // Строка списка кликабельна и достижима с клавиатуры: без этого
        // состояния pressed/focused никогда не наступают, а строка
        // недоступна при навигации (раздел 20.5 — доступность).
        isClickable = true
        isFocusable = true

        val padding = resources.getDimensionPixelSize(R.dimen.list_row_padding)
        setPadding(padding, padding, padding, padding)
    }
}
