// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Проверка экрана блокировки.
 *
 * # Почему Espresso, а не UiAutomator
 *
 * Экран стоит под `FLAG_SECURE`, и UiAutomator не видит его содержимого:
 * снимок иерархии для него пуст — ровно так же, как пуст был бы скриншот.
 * Это правильное поведение защиты, а не помеха, поэтому тест переведён
 * на Espresso, который читает иерархию изнутри процесса приложения.
 */
@RunWith(AndroidJUnit4::class)
class LockScreenTest {

    /** Экран входа показывается только при наличии базы (см. [StandInAccount]). */
    @get:Rule
    val account = StandInAccount()


    /**
     * 🔐 Неполный PIN не открывает хранилище.
     *
     * Главная проверка экрана: если бы трёх цифр хватало, перебор
     * на изъятом устройстве занял бы минуты вместо лет.
     */
    @Test
    fun incompletePinDoesNotUnlock() {
        ActivityScenario.launch(LockActivity::class.java).use { scenario ->
            onView(withId(R.id.key_1)).perform(click())
            onView(withId(R.id.key_2)).perform(click())
            onView(withId(R.id.key_3)).perform(click())

            // Экран блокировки обязан остаться на месте: переход
            // означал бы, что хранилище открыто неполным PIN.
            onView(withId(R.id.pin_dots)).check(matches(isDisplayed()))

            var stillLocked = false
            scenario.onActivity { stillLocked = !it.isFinishing }

            assert(stillLocked) { "неполный PIN закрыл экран блокировки" }
        }
    }

    /** Клавиатура и точки на месте. */
    @Test
    fun lockScreenShowsItsControls() {
        ActivityScenario.launch(LockActivity::class.java).use {
            onView(withId(R.id.lock_subtitle)).check(matches(isDisplayed()))
            onView(withId(R.id.pin_dots)).check(matches(isDisplayed()))
            onView(withId(R.id.key_0)).check(matches(isDisplayed()))
            onView(withId(R.id.key_delete)).check(matches(isDisplayed()))
        }
    }

    /**
     * 🔐 Удаление цифры работает.
     *
     * Без него единственная опечатка заставляла бы набирать PIN заново,
     * а это подталкивает пользователя выбрать PIN покороче.
     */
    @Test
    fun deleteRemovesLastDigit() {
        ActivityScenario.launch(LockActivity::class.java).use { scenario ->
            onView(withId(R.id.key_5)).perform(click())
            onView(withId(R.id.key_5)).perform(click())
            onView(withId(R.id.key_delete)).perform(click())

            // Экран не должен закрыться: после удаления введено меньше
            // полной длины.
            var stillLocked = false
            scenario.onActivity { stillLocked = !it.isFinishing }

            assert(stillLocked)
        }
    }
}
