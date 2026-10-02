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

    /** Вкладки нижней навигации и их экраны. */
    enum class Tab(val viewId: Int, val screen: Class<out Activity>) {
        Chats(R.id.nav_chats, org.aegis.app.ChatListActivity::class.java),
        Calls(R.id.nav_calls, org.aegis.app.CallsActivity::class.java),
        Contacts(R.id.nav_contacts, org.aegis.app.ContactsActivity::class.java),
        Settings(R.id.nav_settings, org.aegis.app.SettingsActivity::class.java),
    }

    /**
     * Подсвечивает активную вкладку и связывает остальные.
     *
     * Одно место на все экраны. Прежде каждый экран связывал вкладки
     * сам, и они разошлись: из настроек нельзя было перейти в контакты.
     *
     * `finish()` после перехода: вкладки — разделы одного уровня, и
     * накопление их в стеке заставляло бы жать «назад» столько раз,
     * сколько было переключений. Смена — плавным наплывом, без сдвига:
     * это переключение раздела, а не шаг вглубь. Активная вкладка
     * не обрабатывается — переход на себя сбросил бы состояние экрана.
     */
    fun bind(activity: Activity, active: Tab) {
        highlight(activity, active)

        for (tab in Tab.entries) {
            if (tab == active) continue

            activity.findViewById<View>(tab.viewId)?.setOnClickListener {
                val options = android.app.ActivityOptions.makeCustomAnimation(
                    activity,
                    android.R.anim.fade_in,
                    android.R.anim.fade_out,
                )
                activity.startActivity(android.content.Intent(activity, tab.screen), options.toBundle())
                activity.finish()
            }
        }
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
                if (selected) R.color.accent_base else R.color.text_tertiary,
            )

            // Иконка и подпись красятся вместе: подсветка только значка
            // читается как случайное различие, а не как «вы здесь».
            forEachChild(container) { child ->
                when (child) {
                    is ImageView -> {
                        child.setColorFilter(color)
                        // «Пилюля» под значком активной вкладки: видна
                        // с одного взгляда и не держится на одном цвете.
                        child.setBackgroundResource(if (selected) R.drawable.bg_nav_pill else 0)
                    }
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
