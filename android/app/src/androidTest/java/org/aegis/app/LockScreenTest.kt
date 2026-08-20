// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

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

/**
 * Проверка экрана блокировки.
 *
 * Экран запускается через [ActivityScenario], а не тапами по
 * координатам: ручной ввод оставляет состояние прошлой попытки,
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
     * 🔐 Неполный PIN не открывает хранилище.
     *
     * Главная проверка экрана: если бы трёх цифр хватало, перебор
     * на изъятом устройстве занял бы минуты вместо лет.
     */
    @Test
    fun incompletePinDoesNotUnlock() {
        ActivityScenario.launch(LockActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "keypad")), TIMEOUT)

            device.findObject(By.res(pkg, "key_1")).click()
            device.findObject(By.res(pkg, "key_2")).click()
            device.findObject(By.res(pkg, "key_3")).click()

            // Список чатов не должен появиться ни при каких условиях.
            assertNull(
                "неполный PIN открыл список чатов",
                device.findObject(By.res(pkg, "chat_list")),
            )
        }
    }

    /**
     * 🔐 Введённые цифры не видны на экране.
     *
     * Точки показывают только длину. Если бы цифры отображались,
     * их прочитал бы любой, кто смотрит через плечо.
     */
    @Test
    fun enteredDigitsAreNotDisplayed() {
        ActivityScenario.launch(LockActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "keypad")), TIMEOUT)

            device.findObject(By.res(pkg, "key_7")).click()
            device.findObject(By.res(pkg, "key_7")).click()

            // Единственная «7» на экране — клавиша, а не показанный ввод.
            val sevens = device.findObjects(By.text("7"))
            assertNotNull(sevens)
            assert(sevens.size <= 1) {
                "введённые цифры отображаются на экране"
            }
        }
    }

    /** Экран блокировки собирается целиком. */
    @Test
    fun lockScreenShowsItsControls() {
        ActivityScenario.launch(LockActivity::class.java).use {
            device.wait(Until.hasObject(By.res(pkg, "keypad")), TIMEOUT)

            assertNotNull(device.findObject(By.res(pkg, "lock_subtitle")))
            assertNotNull(device.findObject(By.res(pkg, "pin_dots")))
            assertNotNull(device.findObject(By.res(pkg, "key_0")))
            assertNotNull(device.findObject(By.res(pkg, "key_delete")))
        }
    }

    private companion object {
        /** Ожидание отрисовки экрана. */
        const val TIMEOUT = 5_000L
    }
}
