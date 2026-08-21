// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.app.Activity
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import org.aegis.app.R

/**
 * Подсветка активной вкладки нижней навигации.
 *
 * # Зачем отдельный код
 *
 * В раскладке активной жёстко помечена вкладка «Чаты»: разметка одна
 * на все экраны, и статически выделить в ней можно только что-то одно.
 * Из-за этого на экранах контактов и настроек подсвечивалась вкладка,
 * на которой пользователь не находится, — интерфейс сообщал неправду
 * о том, где человек сейчас.
 *
 * Здесь подсветка проставляется по факту: экран называет свою вкладку,
 * остальные приглушаются.
 */
object BottomNav {

    /** Вкладки нижней навигации. */
    enum class Tab(val viewId: Int) {
        Chats(R.id.nav_chats),
        Calls(R.id.nav_calls),
        Contacts(R.id.nav_contacts),
        Settings(R.id.nav_settings),
    }

    /**
     * Отмечает активную вкладку.
     *
     * Вызывается из `onCreate` каждого экрана с навигацией.
     */
    fun highlight(activity: Activity, active: Tab) {
        for (tab in Tab.entries) {
            val container = activity.findViewById<View>(tab.viewId) ?: continue
            val selected = tab == active

            val color = ContextCompat.getColor(
                activity,
                if (selected) R.color.accent_base else R.color.text_disabled,
            )

            // Иконка и подпись красятся вместе: подсветка только значка
            // читается как случайное различие, а не как «вы здесь».
            forEachChild(container) { child ->
                when (child) {
                    is ImageView -> child.setColorFilter(color)
                    is TextView -> child.setTextColor(color)
                    else -> Unit
                }
            }
        }
    }

    private inline fun forEachChild(view: View, action: (View) -> Unit) {
        if (view !is android.view.ViewGroup) {
            action(view)

            return
        }

        for (index in 0 until view.childCount) {
            action(view.getChildAt(index))
        }
    }
}
