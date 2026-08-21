// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import org.aegis.app.R

/**
 * Строка настройки со значением.
 *
 * Отличается от [SettingsToggle] тем, что не переключает состояние,
 * а показывает значение или ведёт дальше: «Язык — Системный»,
 * «Очистить загруженные файлы».
 *
 * Шеврон появляется только у строк, которые куда-то ведут. Строка
 * со стрелкой, которая никуда не ведёт, обещает переход и обманывает;
 * строка без стрелки, которая открывает экран, прячет его.
 */
object SettingsRow {

    /**
     * Настраивает строку.
     *
     * @param value подпись справа; `null` — значения нет.
     * @param onClick действие; `null` — строка справочная и не
     *   реагирует на нажатие.
     * @param destructive 🔐 действие необратимо: подпись красится
     *   цветом ошибки, чтобы отличаться от обычного перехода.
     */
    fun bind(
        root: View,
        @StringRes label: Int,
        value: String? = null,
        @DrawableRes icon: Int? = null,
        destructive: Boolean = false,
        onClick: (() -> Unit)? = null,
    ) {
        val labelView = root.findViewById<TextView>(R.id.row_label)
        labelView.setText(label)

        if (destructive) {
            labelView.setTextColor(
                androidx.core.content.ContextCompat.getColor(root.context, R.color.status_error),
            )
        }

        root.findViewById<TextView>(R.id.row_value).apply {
            if (value == null) {
                visibility = View.GONE
            } else {
                text = value
                visibility = View.VISIBLE
            }
        }

        root.findViewById<ImageView>(R.id.row_icon).apply {
            if (icon == null) {
                // Место сохраняется: иначе подписи соседних строк
                // разъедутся по левому краю.
                visibility = View.INVISIBLE
            } else {
                setImageResource(icon)
                visibility = View.VISIBLE
            }
        }

        root.findViewById<ImageView>(R.id.row_chevron).visibility =
            if (onClick == null) View.GONE else View.VISIBLE

        if (onClick == null) {
            root.isClickable = false
            root.setOnClickListener(null)
        } else {
            root.isClickable = true
            root.setOnClickListener { onClick() }
        }
    }
}
