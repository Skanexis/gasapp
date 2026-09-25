// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import org.aegis.app.R

/**
 * Заполняет пустое состояние (`view_empty_state.xml`, UI kit).
 *
 * Пустой экран — первое, что видит новый человек: одна строка серого
 * текста посреди экрана выглядит сломанным списком, а не приглашением.
 * Заголовок говорит, что здесь будет, пояснение — как это получить,
 * действие — ведёт туда сразу.
 */
object EmptyState {

    fun bind(
        root: View,
        @DrawableRes icon: Int,
        @StringRes title: Int,
        @StringRes body: Int,
        @StringRes action: Int? = null,
        onAction: (() -> Unit)? = null,
    ) {
        root.findViewById<ImageView>(R.id.empty_icon).setImageResource(icon)
        root.findViewById<TextView>(R.id.empty_title).setText(title)
        root.findViewById<TextView>(R.id.empty_body).setText(body)

        root.findViewById<View>(R.id.empty_action).apply {
            if (action != null && onAction != null) {
                (this as TextView).setText(action)
                setOnClickListener { onAction() }
                visibility = View.VISIBLE
            } else {
                visibility = View.GONE
            }
        }
    }
}
