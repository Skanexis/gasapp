// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import android.graphics.Rect
import android.view.TouchDelegate
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import androidx.test.core.app.ApplicationProvider
import org.aegis.app.core.TouchTarget
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 🔐 По маленькой иконке всё равно можно попасть.
 *
 * WCAG 2.5.5 и рекомендация платформы: область нажатия не меньше
 * 48dp. Иконки в шапках экранов нарисованы в 24dp — так они и должны
 * выглядеть, — поэтому область расширяется отдельно, через
 * `TouchDelegate`.
 *
 * # Почему это проверяется тестом, а не глазами
 *
 * Потому что глазами этого **не видно**. Вид не меняется: иконка
 * как была 24dp, так и осталась. Разница только в том, куда можно
 * попасть пальцем, — и заметит её лишь тот, кто промахивается,
 * то есть как раз тот, ради кого всё делается.
 *
 * Lint сюда не достаёт: `TouchTargetSizeCheck` живёт в Accessibility
 * Scanner и требует устройства, а id с таким именем lint не знает
 * (проверено — отвечает `UnknownIssueId`).
 *
 * # ⚠️ Чего тест не проверяет
 *
 * Что палец действительно попадёт. Проверяется геометрия делегата:
 * что область заведена, что она не меньше 48dp и что делегатов
 * столько, сколько расширенных видов. Настоящее нажатие —
 * по-прежнему ручная проверка на устройстве.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class TouchTargetTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    /** 🔐 Область нажатия маленькой иконки вырастает до 48dp. */
    @Test
    fun a_small_icon_gets_a_48dp_touch_area() {
        val (parent, icon) = smallIconInParent()

        TouchTarget.expand(icon)
        shadowOf(context.mainLooper).idle()

        val bounds = delegateBounds(parent)

        assertNotNull("делегат не заведён — область осталась 24dp", bounds)

        val minimum = dp(TouchTarget.MIN_DP)

        assertTrue(
            "ширина области ${bounds!!.width()} px, нужно не меньше $minimum",
            bounds.width() >= minimum,
        )
        assertTrue(
            "высота области ${bounds.height()} px, нужно не меньше $minimum",
            bounds.height() >= minimum,
        )
    }

    /**
     * Область расширяется вокруг иконки, а не сдвигается.
     *
     * Делегат, съехавший в сторону, «проходит» проверку размера
     * и при этом ловит нажатия мимо иконки — и не ловит по ней.
     */
    @Test
    fun the_touch_area_stays_centred_on_the_icon() {
        val (parent, icon) = smallIconInParent()

        TouchTarget.expand(icon)
        shadowOf(context.mainLooper).idle()

        val bounds = requireNotNull(delegateBounds(parent))

        val iconRect = Rect()
        icon.getHitRect(iconRect)

        assertTrue(
            "область $bounds не покрывает саму иконку $iconRect",
            bounds.contains(iconRect),
        )

        assertEquals(
            "область сдвинута по горизонтали",
            iconRect.centerX(),
            bounds.centerX(),
        )
        assertEquals(
            "область сдвинута по вертикали",
            iconRect.centerY(),
            bounds.centerY(),
        )
    }

    /**
     * 🔐 Две иконки у одного родителя получают по своей области.
     *
     * ⚠️ Самая вероятная ошибка в такой схеме: у `View` ровно один
     * `touchDelegate`, и второй вызов `setTouchDelegate` затирает
     * первый. Тогда область расширилась бы только у второй иконки,
     * а первая осталась бы 24dp — молча, без единого признака.
     *
     * Ровно такая пара стоит в шапке списка чатов.
     */
    @Test
    fun two_icons_under_one_parent_both_get_an_area() {
        val parent = FrameLayout(context)

        val first = icon()
        val second = icon()

        // Размер обязателен: вид без него измеряется в 0×0,
        // расширять нечего, и тест падал бы на своей же заготовке.
        parent.addView(first, ViewGroup.LayoutParams(dp(24), dp(24)))
        parent.addView(second, ViewGroup.LayoutParams(dp(24), dp(24)))

        layout(parent)

        TouchTarget.expand(first)
        TouchTarget.expand(second)
        shadowOf(context.mainLooper).idle()

        val delegate = parent.touchDelegate

        assertNotNull("делегатов нет вовсе", delegate)

        // У композита обе области, у системного делегата — одна.
        // Различаются они тем, что системный помнит один вид.
        val handled = countHandledCorners(parent, listOf(first, second))

        assertEquals(
            "расширена область не у обеих иконок: сработало $handled из 2",
            2,
            handled,
        )
    }

    /**
     * Вид, который и так достаточно велик, делегата не получает.
     *
     * Лишний делегат — это лишний перехватчик событий на родителе:
     * он ничего не улучшает и может отнять нажатие у соседа.
     */
    @Test
    fun a_large_enough_view_is_left_alone() {
        val parent = FrameLayout(context)
        val big = ImageView(context)

        parent.addView(big, ViewGroup.LayoutParams(dp(64), dp(64)))
        layout(parent)

        TouchTarget.expand(big)
        shadowOf(context.mainLooper).idle()

        assertNull(
            "виду 64dp завели делегат, хотя он и так больше 48dp",
            parent.touchDelegate,
        )
    }

    /** Порог — тот, что требует WCAG 2.5.5. */
    @Test
    fun the_minimum_matches_the_guideline() {
        assertEquals(48, TouchTarget.MIN_DP)
    }

    // --- вспомогательное ---------------------------------------------------

    private fun dp(value: Int): Int =
        (value * context.resources.displayMetrics.density).toInt()

    private fun icon(): ImageView = ImageView(context)

    /** Иконка 24dp внутри родителя, уже прошедшего разметку. */
    private fun smallIconInParent(): Pair<FrameLayout, ImageView> {
        val parent = FrameLayout(context)
        val small = icon()

        parent.addView(small, ViewGroup.LayoutParams(dp(24), dp(24)))
        layout(parent)

        return parent to small
    }

    /**
     * Размечает дерево вручную.
     *
     * ⚠️ Экран Robolectric здесь не нужен и не помогает: настоящего
     * прохода разметки он всё равно не даёт. Достаточно того, что
     * после `measure` + `layout` у видов появляются размеры, —
     * а [TouchTarget] смотрит именно на них, а не на флаг
     * «разметка запрошена».
     */
    private fun layout(parent: ViewGroup) {
        val spec = View.MeasureSpec.makeMeasureSpec(dp(360), View.MeasureSpec.EXACTLY)

        parent.measure(spec, spec)
        parent.layout(0, 0, parent.measuredWidth, parent.measuredHeight)
    }

    /** Область делегата родителя — через отражение, публичного доступа нет. */
    private fun delegateBounds(parent: ViewGroup): Rect? {
        val delegate = parent.touchDelegate ?: return null

        return boundsOf(delegate)
    }

    private fun boundsOf(delegate: TouchDelegate): Rect? {
        // У композита собственного прямоугольника нет — он хранит
        // вложенные делегаты; берём первый из них.
        val nested = runCatching {
            val field = delegate.javaClass.getDeclaredField("delegates")
            field.isAccessible = true

            @Suppress("UNCHECKED_CAST")
            (field.get(delegate) as Map<View, TouchDelegate>).values.firstOrNull()
        }.getOrNull()

        val target = nested ?: delegate

        return runCatching {
            val field = TouchDelegate::class.java.getDeclaredField("mBounds")
            field.isAccessible = true

            field.get(target) as Rect
        }.getOrNull()
    }

    /**
     * Сколько из перечисленных видов получили собственную область.
     *
     * Считается по вложенным делегатам композита: у каждого своя
     * запись, и её отсутствие означает невыполненное расширение.
     */
    private fun countHandledCorners(parent: ViewGroup, views: List<View>): Int {
        val delegate = parent.touchDelegate ?: return 0

        val nested = runCatching {
            val field = delegate.javaClass.getDeclaredField("delegates")
            field.isAccessible = true

            @Suppress("UNCHECKED_CAST")
            field.get(delegate) as Map<View, TouchDelegate>
        }.getOrNull() ?: return 0

        return views.count { nested.containsKey(it) }
    }
}
