// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import kotlin.math.max

/**
 * Безопасная область каждого экрана: системные панели, вырез, клавиатура
 * и ширина на больших экранах.
 *
 * # Зачем
 *
 * С `targetSdk = 35` Android 15 и новее рисуют приложение от края до края
 * принудительно. Ни один экран отступов по системным панелям не делал:
 * шапки уходили под строку состояния, нижняя навигация — под полосу
 * жестов, а поле ввода сообщения — под клавиатуру (`adjustResize`
 * в этом режиме окно больше не сжимает). На эмуляторе API 34 этого
 * не видно, на большинстве новых телефонов — видно сразу.
 *
 * Здесь режим от края до края включается на всех версиях одинаково,
 * а отступы ставит одно место для всех экранов — иначе их пришлось бы
 * повторять в тридцати разметках, и следующий экран снова забыл бы.
 *
 * # Большие экраны
 *
 * На планшете и в горизонтальной ориентации строки списка и пузыри
 * растягивались на всю ширину — текст читался бы строкой в метр.
 * Содержимое ограничивается [MAX_CONTENT_WIDTH_DP] и встаёт по центру.
 */
object SafeArea {

    /** Наибольшая ширина содержимого на больших экранах. */
    private const val MAX_CONTENT_WIDTH_DP = 640

    fun install(application: Application) {
        application.registerActivityLifecycleCallbacks(
            object : Application.ActivityLifecycleCallbacks {
                override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                    WindowCompat.setDecorFitsSystemWindows(activity.window, false)
                }

                override fun onActivityStarted(activity: Activity) = apply(activity)

                override fun onActivityResumed(activity: Activity) = Unit

                override fun onActivityPaused(activity: Activity) = Unit

                override fun onActivityStopped(activity: Activity) = Unit

                override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

                override fun onActivityDestroyed(activity: Activity) = Unit
            },
        )
    }

    /**
     * Ставит отступы на корень содержимого экрана.
     *
     * Вызывается из `onStart`: к этому времени `setContentView` уже был,
     * а повторный вызов лишь заменяет слушателя тем же.
     */
    private fun apply(activity: Activity) {
        val content = activity.findViewById<ViewGroup>(android.R.id.content) ?: return
        val density = activity.resources.displayMetrics.density
        val maxWidth = (MAX_CONTENT_WIDTH_DP * density).toInt()

        ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())

            val width = view.width.takeIf { it > 0 } ?: view.resources.displayMetrics.widthPixels
            val usable = width - bars.left - bars.right
            val extra = max(0, (usable - maxWidth) / 2)

            view.setPadding(
                bars.left + extra,
                bars.top,
                bars.right + extra,
                max(bars.bottom, ime.bottom),
            )

            WindowInsetsCompat.CONSUMED
        }

        // Ширина известна только после разметки: на повороте и при
        // изменении размера окна отступы пересчитываются.
        content.removeOnLayoutChangeListener(WidthWatcher)
        content.addOnLayoutChangeListener(WidthWatcher)
        ViewCompat.requestApplyInsets(content)
    }

    /** Пересчитывает отступы, когда меняется ширина окна. */
    private object WidthWatcher : View.OnLayoutChangeListener {
        override fun onLayoutChange(
            view: View,
            left: Int,
            top: Int,
            right: Int,
            bottom: Int,
            oldLeft: Int,
            oldTop: Int,
            oldRight: Int,
            oldBottom: Int,
        ) {
            if (right - left != oldRight - oldLeft) {
                view.post { ViewCompat.requestApplyInsets(view) }
            }
        }
    }
}
