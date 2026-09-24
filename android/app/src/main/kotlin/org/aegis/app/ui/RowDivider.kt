// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.R

/**
 * Разделитель строк списка: волосяная линия от текста до края
 * (списки .row в UI kit).
 *
 * Линия начинается после аватара, а не от края: так строки читаются
 * как одна группа, а аватары не перечёркиваются. После последней
 * строки линии нет.
 */
class RowDivider(context: Context, startInsetDp: Int = DEFAULT_INSET_DP) : RecyclerView.ItemDecoration() {

    private val density = context.resources.displayMetrics.density
    private val inset = startInsetDp * density
    private val paint = Paint().apply {
        color = ContextCompat.getColor(context, R.color.line)
        strokeWidth = maxOf(1f, density / 2)
    }

    override fun onDraw(canvas: Canvas, parent: RecyclerView, state: RecyclerView.State) {
        val rtl = parent.layoutDirection == android.view.View.LAYOUT_DIRECTION_RTL
        val count = parent.childCount

        for (index in 0 until count - 1) {
            val child = parent.getChildAt(index)
            val y = child.bottom + child.translationY
            val start = if (rtl) parent.paddingLeft.toFloat() else parent.paddingLeft + inset
            val end = if (rtl) parent.width - parent.paddingRight - inset else (parent.width - parent.paddingRight).toFloat()

            canvas.drawLine(start, y, end, y, paint)
        }
    }

    private companion object {
        /** Поле 16 + аватар 48 + промежуток 12. */
        const val DEFAULT_INSET_DP = 76
    }
}
