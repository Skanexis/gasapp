// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Проверка списка чатов.
 *
 * Espresso, а не UiAutomator: он читает иерархию изнутри процесса,
 * поэтому не зависит от того, разрешён ли системе снимок экрана.
 */
@RunWith(AndroidJUnit4::class)
class ChatListScreenTest {

    /** Список отрисовывается и показывает строки чатов. */
    @Test
    fun chatListShowsRows() {
        ActivityScenario.launch(ChatListActivity::class.java).use {
            onView(withId(R.id.chat_list)).check(matches(isDisplayed()))
            onView(withText("Lena Novak")).check(matches(isDisplayed()))
        }
    }

    /**
     * 🔐 Превью не переживают сворачивание приложения.
     *
     * Строки списка содержат расшифрованный текст. Если бы они
     * оставались после ухода в фон, их показал бы снимок экрана
     * в переключателе задач.
     */
    @Test
    fun previewsAreClearedWhenStopped() {
        ActivityScenario.launch(ChatListActivity::class.java).use { scenario ->
            onView(withText("Lena Novak")).check(matches(isDisplayed()))

            scenario.moveToState(Lifecycle.State.CREATED)

            onView(withText("Lena Novak")).check(doesNotExist())
        }
    }

    /**
     * Индикатор соединения по умолчанию скрыт.
     *
     * Постоянный зелёный «онлайн» приучает не смотреть на индикатор,
     * поэтому баннер показывается только когда связи нет.
     */
    @Test
    fun connectionBannerHiddenWhenOnline() {
        ActivityScenario.launch(ChatListActivity::class.java).use {
            onView(withId(R.id.connection_banner))
                .check(matches(androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility(
                    androidx.test.espresso.matcher.ViewMatchers.Visibility.GONE,
                )))
        }
    }

    /** Нижняя навигация присутствует на главном экране. */
    @Test
    fun bottomNavigationIsPresent() {
        ActivityScenario.launch(ChatListActivity::class.java).use {
            onView(withId(R.id.nav_chats)).check(matches(isDisplayed()))
            onView(withId(R.id.nav_contacts)).check(matches(isDisplayed()))
            onView(withId(R.id.nav_settings)).check(matches(isDisplayed()))
        }
    }
}
