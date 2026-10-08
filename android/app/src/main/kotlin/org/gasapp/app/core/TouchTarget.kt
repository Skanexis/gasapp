// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.graphics.Rect
import android.view.MotionEvent
import android.view.TouchDelegate
import android.view.View
import android.view.ViewGroup
import androidx.core.view.doOnLayout

/**
 * Расширение области нажатия до 48dp.
 *
 * # Зачем
 *
 * Иконки в шапках экранов нарисованы в 24dp — так они и должны
 * выглядеть. Но нажимать в 24dp трудно: рекомендация платформы
 * и WCAG 2.5.5 — не меньше 48dp, и это не про эстетику. Мимо
 * маленькой цели промахивается любой в движущемся транспорте,
 * и постоянно промахивается тот, у кого тремор.
 *
 * # Почему не просто увеличить `layout_width`
 *
 * Потому что это изменило бы вид. Иконка 48dp в шапке высотой 56dp
 * выглядит иначе, а компенсировать отступами пришлось бы на каждом
 * экране по-своему — и проверить это можно только глазами
 * на устройстве.
 *
 * `TouchDelegate` разделяет две вещи, которые в разметке слиты:
 * **что видно** и **куда можно попасть**. Вид остаётся прежним,
 * область нажатия становится больше.
 *
 * # ⚠️ Почему свой композит, а не системный `TouchDelegate`
 *
 * У `View` ровно один `touchDelegate`: второй вызов
 * `setTouchDelegate` затирает первый. В шапке списка чатов иконок
 * две, и наивное применение расширило бы область только второй,
 * молча оставив первую как была.
 *
 * Поэтому делегаты складываются в [Composite], который перебирает
 * их по очереди.
 *
 * # ⚠️ Чего это не делает
 *
 * Не помогает, если две маленькие цели стоят вплотную: расширенные
 * области наложатся, и попадание достанется той, что раньше в списке.
 * Здесь между иконками 18dp, и пересечения нет — но при добавлении
 * третьей это надо считать заново, а не надеяться.
 */
object TouchTarget {

    /** Минимальная сторона области нажатия в dp. */
    const val MIN_DP = 48

    /**
     * Расширяет область нажатия [view] до [MIN_DP] в обе стороны.
     *
     * Можно вызывать до разметки: если размеров ещё нет, работа
     * откладывается до неё.
     *
     * Безопасно вызывать повторно: для одного и того же вида
     * прежний делегат заменяется, а не добавляется вторым.
     */
    fun expand(view: View) {
        // ⚠️ Решает **размер**, а не состояние разметки.
        //
        // Очевидный способ дождаться размеров — `post` или
        // `doOnLayout`. Оба спрашивают не о том: `post`
        // на неприсоединённом виде откладывает задачу до
        // присоединения к окну, а `doOnLayout` смотрит на флаг
        // «разметка запрошена», который после ручного `layout()`
        // остаётся взведённым. В обоих случаях расширение
        // не выполняется — молча.
        //
        // Здесь спрашивается прямо: размеры уже есть? Тогда считать
        // можно сейчас. Нет — ждём разметки.
        if (view.width > 0 && view.height > 0) {
            apply(view)

            return
        }

        view.doOnLayout { apply(view) }
    }

    /** Считает область и вешает делегата на родителя. */
    private fun apply(view: View) {
        val parent = view.parent as? ViewGroup ?: return

        val minimum = (MIN_DP * view.resources.displayMetrics.density).toInt()

        val bounds = Rect()
        view.getHitRect(bounds)

        val growX = ((minimum - bounds.width()) / 2).coerceAtLeast(0)
        val growY = ((minimum - bounds.height()) / 2).coerceAtLeast(0)

        if (growX == 0 && growY == 0) {
            return
        }

        bounds.inset(-growX, -growY)

        val composite = parent.touchDelegate as? Composite ?: Composite(view)
        composite.put(view, TouchDelegate(bounds, view))

        parent.touchDelegate = composite
    }

    /**
     * Несколько делегатов на одном родителе.
     *
     * Конструктор `TouchDelegate` требует вид и прямоугольник,
     * поэтому берётся любой из расширяемых видов и пустая область.
     * В разборе события этот «корневой» делегат не участвует:
     * [onTouchEvent] переопределён целиком, а пустая область
     * не накрывает ни одной точки.
     *
     * ⚠️ `View(null)` здесь не годится, хотя выглядит уместнее:
     * конструктор `View` лезет в `ViewConfiguration.get(context)`
     * и падает с `NullPointerException`.
     */
    private class Composite(anchor: View) : TouchDelegate(Rect(), anchor) {

        /**
         * Делегаты по видам.
         *
         * Карта, а не список: повторный вызов [expand] для того же
         * вида обязан заменить прежнюю область, иначе после поворота
         * экрана делегаты копились бы, и первый — с устаревшими
         * координатами — перехватывал бы нажатия.
         */
        private val delegates = LinkedHashMap<View, TouchDelegate>()

        fun put(view: View, delegate: TouchDelegate) {
            delegates[view] = delegate
        }

        /**
         * Отдаёт событие первому делегату, который его принял.
         *
         * ⚠️ Координаты события каждый делегат правит под себя,
         * поэтому опрашивать их по очереди одним и тем же событием
         * нельзя — для каждого берётся копия.
         */
        override fun onTouchEvent(event: MotionEvent): Boolean {
            for (delegate in delegates.values) {
                val copy = MotionEvent.obtain(event)

                val handled = try {
                    delegate.onTouchEvent(copy)
                } finally {
                    copy.recycle()
                }

                if (handled) {
                    return true
                }
            }

            return false
        }
    }
}
