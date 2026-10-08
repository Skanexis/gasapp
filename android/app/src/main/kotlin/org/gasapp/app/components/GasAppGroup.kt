// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.content.Context
import android.util.AttributeSet
import android.view.ViewOutlineProvider
import android.widget.LinearLayout
import androidx.core.content.ContextCompat
import org.gasapp.app.R

/**
 * Группа строк (UI kit, Settings: grouped list) — карточка r16.
 *
 * Сама делает то, что прежде каждый экран делал руками:
 *
 * * обрезает содержимое по скруглению — подсветка нажатия крайних
 *   строк не вылезает за углы. Атрибут разметки `clipToOutline` есть
 *   только с API 31, метод — с 21;
 * * ставит разделители между строками с отступом под значок —
 *   и между строками, добавленными кодом, тоже.
 *
 * Фон и отступы — из стиля `GasAppGroup`.
 */
class GasAppGroup @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : LinearLayout(context, attrs) {

    init {
        orientation = VERTICAL
        outlineProvider = ViewOutlineProvider.BACKGROUND
        clipToOutline = true
        dividerDrawable = ContextCompat.getDrawable(context, R.drawable.divider_group)
        showDividers = SHOW_DIVIDER_MIDDLE
    }
}
