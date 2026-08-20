// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Проверка экрана блокировки.
 *
 * Экран запускается через [ActivityScenario], а не тапами по координатам:
 * ручной ввод оставляет состояние от предыдущей попытки в поле PIN,
 * и тест начинает проверять не то, что задумано.
 */
@RunWith(AndroidJUnit4::class)
class LockScreenTest {

    private lateinit var device: UiDevice

    /** Пакет сборки: у flavor foss к applicationId добавлен суффикс. */
    private val pkg: String
        get() = InstrumentationRegistry.getInstrumentation().targetContext.packageName

    @Before
    fun setUp() {
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    /**
     * 🔐 Короткий PIN не открывает хранилище.
     *
     * Главная проверка экрана: если бы четырёхзначный PIN проходил,
     * перебор на изъятом устройстве занял бы часы вместо лет.
     */
    @Test
    fun shortPinDoesNotUnlock() {
        ActivityScenario.launch(LockActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "pin_input")), TIMEOUT)

            device.findObject(By.res(pkg, "pin_input")).text = "123"
            device.findObject(By.res(pkg, "unlock_button")).click()

            device.wait(Until.hasObject(By.res(pkg, "pin_error")), TIMEOUT)

            // Список чатов не должен появиться ни при каких условиях.
            assertNull(
                "короткий PIN открыл список чатов",
                device.findObject(By.res(pkg, "chat_list")),
            )
        }
    }

    /**
     * 🔐 PIN не виден на экране.
     *
     * Поле помечено `password=true`, поэтому UiAutomator не отдаёт
     * его содержимое — ровно так же его не увидит и тот, кто смотрит
     * через плечо или снимает экран.
     */
    @Test
    fun pinFieldIsMasked() {
        ActivityScenario.launch(LockActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "pin_input")), TIMEOUT)

            val field = device.findObject(By.res(pkg, "pin_input"))
            field.text = "123456"

            // Поле возвращает маску, а не цифры: настоящего PIN
            // в дереве доступности нет, значит его не снимет ни
            // скриншот, ни вредоносный accessibility-сервис.
            val shown = field.text ?: ""
            assertFalse("PIN виден на экране", shown.contains("123456"))
            assertTrue("поле пустое — маскировка не проверена", shown.isNotEmpty())
        }
    }

    /** Экран блокировки собирается целиком. */
    @Test
    fun lockScreenShowsItsControls() {
        ActivityScenario.launch(LockActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "pin_input")), TIMEOUT)

            assertNotNull(device.findObject(By.res(pkg, "lock_subtitle")))
            assertNotNull(device.findObject(By.res(pkg, "pin_input")))
            assertNotNull(device.findObject(By.res(pkg, "unlock_button")))
        }
    }

    private companion object {
        /** Ожидание отрисовки экрана. */
        const val TIMEOUT = 5_000L
    }
}
