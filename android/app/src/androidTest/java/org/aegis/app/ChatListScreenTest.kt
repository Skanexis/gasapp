// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Проверка списка чатов. */
@RunWith(AndroidJUnit4::class)
class ChatListScreenTest {

    private lateinit var device: UiDevice

    private val pkg: String
        get() = InstrumentationRegistry.getInstrumentation().targetContext.packageName

    @Before
    fun setUp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    /** Список отрисовывается и показывает строки чатов. */
    @Test
    fun chatListShowsRows() {
        ActivityScenario.launch(ChatListActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "chat_list")), TIMEOUT)

            assertNotNull(device.findObject(By.res(pkg, "chat_list")))
            assertNotNull(device.findObject(By.text("Lena Novak")))
        }
    }

    /**
     * 🔐 Превью не переживают сворачивание приложения.
     *
     * Строки списка содержат расшифрованный текст. Если бы они
     * оставались после ухода в фон, их показал бы снимок экрана
     * в переключателе задач — то есть кому угодно, кто взял
     * разблокированное устройство.
     */
    @Test
    fun previewsAreClearedWhenStopped() {
        ActivityScenario.launch(ChatListActivity::class.java).use { scenario ->
            device.wait(Until.hasObject(By.text("Lena Novak")), TIMEOUT)

            scenario.moveToState(Lifecycle.State.CREATED)
            device.wait(Until.gone(By.text("Lena Novak")), TIMEOUT)

            assertNull(
                "превью пережило уход с экрана",
                device.findObject(By.text("Lena Novak")),
            )
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
            device.wait(Until.hasObject(By.res(pkg, "chat_list")), TIMEOUT)

            assertNull(device.findObject(By.res(pkg, "connection_banner")))
        }
    }

    private companion object {
        const val TIMEOUT = 5_000L
    }
}
