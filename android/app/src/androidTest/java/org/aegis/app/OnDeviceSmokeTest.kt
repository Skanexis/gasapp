// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Root
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisSheet
import org.aegis.app.core.Pin
import org.hamcrest.Description
import org.hamcrest.Matcher
import org.hamcrest.Matchers.allOf
import org.hamcrest.TypeSafeMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Проверки на настоящей среде Android — эмуляторе или телефоне.
 *
 * # Зачем, если есть Robolectric
 *
 * Robolectric подменяет окна и `WindowManager` своими тенями. Здесь —
 * настоящие: `PhoneWindow`, флаги окна, которые видит система. Панель
 * действий роняла приложение именно в `PhoneWindow.requestFeature`,
 * и до этой правки ни одна проверка на устройстве не запускалась
 * автоматически: всё, что проверялось на эмуляторе, проверялось руками.
 *
 * Хранилище не открывается: экраны открываются без входа, и тогда запрет
 * снимков включён по умолчанию (`SecureWindow`). Экрану входа нужен только
 * файл базы — его ставит [StandInAccount].
 */
@RunWith(AndroidJUnit4::class)
class OnDeviceSmokeTest {

    /** Экран входа показывается только при наличии базы (см. [StandInAccount]). */
    @get:Rule
    val account = StandInAccount()

    /** Окно корня Espresso несёт `FLAG_SECURE`. */
    private fun secureRoot(): Matcher<Root> = object : TypeSafeMatcher<Root>() {
        override fun describeTo(description: Description) {
            description.appendText("окно с FLAG_SECURE")
        }

        override fun matchesSafely(root: Root): Boolean =
            root.windowLayoutParams.get().flags and WindowManager.LayoutParams.FLAG_SECURE != 0
    }

    /**
     * Панель действий открывается на настоящем окне — и не снимается.
     *
     * Прежде `AegisSheet.show()` бросал `AndroidRuntimeException`
     * («requestFeature() must be called before adding content») на каждой
     * панели приложения.
     */
    @Test
    fun an_action_sheet_opens_and_is_not_capturable() {
        ActivityScenario.launch(OnboardingActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                AegisSheet.on(activity, "Меню").action("Действие панели") {}.show()
            }

            onView(withText("Действие панели"))
                .inRoot(allOf(isDialog(), secureRoot()))
                .check(matches(isDisplayed()))
        }
    }

    /** 🔐 Диалог защищённого экрана не снимается — на настоящем окне. */
    @Test
    fun a_dialog_of_a_secure_screen_is_not_capturable() {
        ActivityScenario.launch(OnboardingActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                AegisDialog(activity)
                    .message("Текст диалога")
                    .show()
            }

            onView(withText("Текст диалога"))
                .inRoot(allOf(isDialog(), secureRoot()))
                .check(matches(isDisplayed()))
        }
    }

    /** 🔐 Экран регистрации не снимается, пока хранилище закрыто. */
    @Test
    fun the_registration_screen_is_not_capturable() {
        ActivityScenario.launch(OnboardingActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val flags = activity.window.attributes.flags

                assertTrue(
                    "экран регистрации снимается",
                    flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
                )
            }
        }
    }

    /**
     * 🔐 PIN при регистрации и на экране входа — своей клавиатурой:
     * шесть точек, клавиши, и ни одного поля пароля.
     */
    @Test
    fun pin_screens_have_the_keypad_and_no_password_field() {
        for (screen in listOf(OnboardingActivity::class.java, LockActivity::class.java)) {
            ActivityScenario.launch(screen).use { scenario ->
                // Регистрация — по шагам: PIN на своём шаге.
                if (screen == OnboardingActivity::class.java) {
                    onView(withId(R.id.onboarding_start)).perform(click())
                    onView(withId(R.id.onboarding_username)).perform(replaceText("alice"))
                    onView(withId(R.id.onboarding_next)).perform(click())
                }
                onView(withId(R.id.keypad)).check(matches(isDisplayed()))

                scenario.onActivity { activity ->
                    val root = activity.window.decorView
                    val dots = root.findViewById<ViewGroup>(R.id.pin_dots)

                    assertEquals("${screen.simpleName}: точек не столько, сколько цифр", Pin.LENGTH, dots.childCount)

                    val passwordFields = editTexts(root).filter { field ->
                        field.inputType and android.text.InputType.TYPE_MASK_VARIATION ==
                            android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
                    }
                    assertTrue("${screen.simpleName}: PIN в текстовом поле", passwordFields.isEmpty())
                }
            }
        }
    }

    private fun editTexts(view: View): List<EditText> = when (view) {
        is EditText -> listOf(view)
        is ViewGroup -> (0 until view.childCount).flatMap { editTexts(view.getChildAt(it)) }
        else -> emptyList()
    }
}
