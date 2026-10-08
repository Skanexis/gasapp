// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.appcompat.widget.SwitchCompat
import org.gasapp.app.R

/**
 * Строка настройки с переключателем.
 *
 * # Зачем обёртка
 *
 * Строка состоит из четырёх видов, и связывать их в каждом экране
 * настроек значило бы четырежды повторить один код. Разъехавшись
 * однажды, такие копии дают экран, где один переключатель показывает
 * состояние, а другой — нет.
 *
 * # Про порядок записи и показа
 *
 * 🔐 Переключатель сдвигается **после** успешной записи, а не до неё.
 * Настройка, которая выглядит включённой, но не сохранилась, опаснее
 * выключенной: пользователь считает, что защита работает, и ведёт себя
 * соответственно.
 */
class SettingsToggle private constructor(private val root: View) {

    private val switch: SwitchCompat = root.findViewById(R.id.toggle_switch)

    /** Включён ли переключатель. */
    var isChecked: Boolean
        get() = switch.isChecked
        set(value) {
            switch.isChecked = value
        }

    companion object {

        /**
         * Настраивает строку.
         *
         * @param onChange вызывается с желаемым состоянием и возвращает
         *   `true`, если запись удалась. При `false` переключатель
         *   остаётся в прежнем положении.
         */
        fun bind(
            root: View,
            @StringRes label: Int,
            @StringRes hint: Int? = null,
            @DrawableRes icon: Int? = null,
            checked: Boolean,
            onChange: (Boolean) -> Boolean,
        ): SettingsToggle {
            val toggle = SettingsToggle(root)

            root.findViewById<TextView>(R.id.toggle_label).setText(label)

            root.findViewById<TextView>(R.id.toggle_hint).apply {
                if (hint == null) {
                    visibility = View.GONE
                } else {
                    setText(hint)
                    visibility = View.VISIBLE
                }
            }

            root.findViewById<ImageView>(R.id.toggle_icon).apply {
                if (icon == null) {
                    // Место под значок сохраняется: без него подписи
                    // соседних строк разъедутся по левому краю.
                    visibility = View.INVISIBLE
                } else {
                    setImageResource(icon)
                    visibility = View.VISIBLE
                }
            }

            toggle.switch.isChecked = checked

            // Нажатие обрабатывает вся строка, а не только сам
            // переключатель: цель шириной в экран не промахивается,
            // а цель в 48dp у правого края — промахивается.
            root.setOnClickListener {
                val wanted = !toggle.switch.isChecked

                if (onChange(wanted)) {
                    toggle.switch.isChecked = wanted
                }
            }

            return toggle
        }
    }
}
