// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.app.Activity
import android.view.View
import org.aegis.app.R
import org.aegis.app.ui.BottomNav
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * С каждой вкладки есть переход на каждую другую.
 *
 * Прежде каждый экран связывал вкладки сам, и из настроек нельзя было
 * перейти в контакты — вкладка молча не нажималась. Теперь связывает
 * [BottomNav.bind]; тест проходит все пары.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BottomNavTest {

    private fun screenWithNav(): Activity =
        Robolectric.buildActivity(Activity::class.java).setup().get().apply {
            setTheme(R.style.Theme_AEGIS)
            setContentView(R.layout.view_bottom_nav)
        }

    @Test
    fun every_tab_reaches_every_other_tab() {
        for (active in BottomNav.Tab.entries) {
            for (target in BottomNav.Tab.entries) {
                val activity = screenWithNav()
                BottomNav.bind(activity, active)

                activity.findViewById<View>(target.viewId).performClick()
                val started = shadowOf(activity).nextStartedActivity

                if (target == active) {
                    assertNull("вкладка $active перезапускает саму себя", started)
                } else {
                    assertEquals(
                        "с вкладки $active не перейти на $target",
                        target.screen.name,
                        started?.component?.className,
                    )
                }
            }
        }
    }
}
