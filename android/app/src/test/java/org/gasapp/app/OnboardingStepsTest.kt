// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Онбординг по шагам: приветствие → имя → PIN, назад — на шаг,
 * а не прочь с экрана. Возвращение из копии — сразу к PIN, и выбор
 * сети едет с ним.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class OnboardingStepsTest {

    private fun <T> withOnboarding(block: (OnboardingActivity) -> T): T {
        val controller = Robolectric.buildActivity(OnboardingActivity::class.java).setup()

        try {
            return block(controller.get())
        } finally {
            // Незакрытая активность держит счётчик AutoLock (см. PinLengthTest).
            controller.pause().stop().destroy()
        }
    }

    private fun textsIn(group: ViewGroup): List<TextView> =
        (0 until group.childCount).map { group.getChildAt(it) }.flatMap { child ->
            when (child) {
                is TextView -> listOf(child)
                is ViewGroup -> textsIn(child)
                else -> emptyList()
            }
        }

    private fun OnboardingActivity.shown(id: Int) = findViewById<View>(id).isShown

    private fun OnboardingActivity.click(id: Int) {
        findViewById<View>(id).performClick()
        shadowOf(Looper.getMainLooper()).idle()
    }

    @Test
    fun the_audit_warning_comes_before_any_input() = withOnboarding { activity ->
        assertTrue(activity.shown(R.id.onboarding_page_welcome))
        assertTrue(activity.shown(R.id.onboarding_start))
        assertTrue(activity.shown(R.id.onboarding_recover))
        assertFalse("поле имени на приветствии", activity.shown(R.id.onboarding_username))
        assertFalse("клавиатура PIN на приветствии", activity.shown(R.id.keypad))

        val warning = activity.getString(R.string.onboarding_audit_warning)
        val page = activity.findViewById<ViewGroup>(R.id.onboarding_page_welcome)
        val texts = textsIn(page)
        assertTrue("предупреждения об аудите нет на первом шаге", texts.any { it.text.toString() == warning })
    }

    @Test
    fun steps_go_forward_and_back() = withOnboarding { activity ->
        activity.click(R.id.onboarding_start)
        assertTrue(activity.shown(R.id.onboarding_username))
        assertTrue(activity.shown(R.id.onboarding_tor))
        assertFalse(activity.shown(R.id.keypad))

        activity.findViewById<EditText>(R.id.onboarding_username).setText("alice")

        activity.findViewById<EditText>(R.id.onboarding_email).setText("alice@example.org")
        activity.click(R.id.onboarding_next)
        assertTrue(activity.shown(R.id.keypad))
        assertTrue(activity.shown(R.id.onboarding_create))
        assertEquals(
            activity.getString(R.string.onboarding_create),
            activity.findViewById<TextView>(R.id.onboarding_create).text.toString(),
        )

        activity.onBackPressedDispatcher.onBackPressed()
        assertTrue("«Назад» с PIN не вернуло к имени", activity.shown(R.id.onboarding_username))
        assertEquals("имя потерялось при возврате", "alice", activity.findViewById<EditText>(R.id.onboarding_username).text.toString())

        activity.onBackPressedDispatcher.onBackPressed()
        assertTrue(activity.shown(R.id.onboarding_page_welcome))
        assertFalse("«Назад» с шага закрыло экран", activity.isFinishing)
    }

    @Test
    fun restore_goes_straight_to_the_pin_with_the_network_choice() = withOnboarding { activity ->
        activity.click(R.id.onboarding_recover)

        assertTrue(activity.shown(R.id.keypad))
        assertFalse(activity.shown(R.id.onboarding_username))
        assertTrue("при возвращении из копии нельзя выбрать сеть", activity.shown(R.id.onboarding_tor))
        assertSame(
            activity.findViewById<View>(R.id.onboarding_page_pin),
            activity.findViewById<View>(R.id.onboarding_network).parent,
        )
        assertEquals(
            activity.getString(R.string.onboarding_restore_continue),
            activity.findViewById<TextView>(R.id.onboarding_create).text.toString(),
        )

        activity.onBackPressedDispatcher.onBackPressed()
        assertTrue(activity.shown(R.id.onboarding_page_welcome))

        // Новый аккаунт после передумавшего возвращения: сеть снова на шаге имени.
        activity.click(R.id.onboarding_start)
        assertSame(
            activity.findViewById<View>(R.id.onboarding_page_username),
            activity.findViewById<View>(R.id.onboarding_network).parent,
        )
    }

    /** 🔐 Набранный PIN не ждёт в памяти, пока человек вернётся к шагу. */
    @Test
    fun leaving_the_pin_step_clears_the_pin() = withOnboarding { activity ->
        activity.click(R.id.onboarding_recover)
        repeat(3) { activity.click(R.id.key_7) }

        activity.onBackPressedDispatcher.onBackPressed()
        activity.click(R.id.onboarding_recover)

        val dots = activity.findViewById<ViewGroup>(R.id.pin_dots)
        val filled = (0 until dots.childCount).count { index ->
            shadowOf(dots.getChildAt(index).background).createdFromResId == R.drawable.bg_pin_dot_filled
        }
        assertEquals("PIN остался после ухода с шага", 0, filled)
    }
}
