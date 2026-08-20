package org.aegis.app

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import androidx.test.uiautomator.By
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented test for FFI integration in MainActivity.
 * This test verifies that FFI function calls work correctly on Android emulator/device.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityFFITest {

    private lateinit var device: UiDevice

    @Before
    fun setUp() {
        // Initialize UiDevice instance
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    }

    @After
    fun tearDown() {
        // Clean up if needed
    }

    @Test
    fun testFfiFunctionsReturnExpectedResults() {
        // MainActivity открывается напрямую, а не через launcher:
        // точкой входа приложения стал экран блокировки, и launcher-intent
        // приводил бы сюда не тот экран.
        ActivityScenario.launch(MainActivity::class.java)

        device.wait(Until.hasObject(By.res(PACKAGE, "core_version_text")), 5000)

        // Проверяются идентификаторы view и содержимое, а не текст
        // интерфейса: строки локализованы, и привязка к ним делала бы
        // тест ложно-красным при первом же переводе. Прежняя редакция
        // искала английские подписи, которых в приложении никогда
        // не было, — тест не мог пройти в принципе.
        val coreVersionText = device.findObject(By.res(PACKAGE, "core_version_text"))
        assertNotNull("core_version_text не найден", coreVersionText)

        val protocolVersionText = device.findObject(By.res(PACKAGE, "protocol_version_text"))
        assertNotNull("protocol_version_text не найден", protocolVersionText)

        val safetyNumberText = device.findObject(By.res(PACKAGE, "safety_number_text"))
        assertNotNull("safety_number_text не найден", safetyNumberText)

        // Ядро отдало версию протокола: на экране есть её номер.
        // Пустое поле означало бы, что вызов через FFI не состоялся.
        val protocolValue = protocolVersionText.text.orEmpty()
        assertTrue(
            "версия протокола не отображена: '$protocolValue'",
            protocolValue.contains(Regex("\\d")),
        )

        // 🔐 Safety number — 60 десятичных цифр (ADR-022). Проверяется
        // именно количество: оно доказывает, что отпечатки вычислены
        // ядром, а не подставлена заглушка.
        val digits = safetyNumberText.text.orEmpty().filter(Char::isDigit)
        assertEquals("safety number должен содержать 60 цифр", 60, digits.length)
    }

    /**
     * Повторные пересоздания экрана не роняют ядро.
     *
     * Прежняя редакция искала «любой TextView» и проходила бы, даже
     * если бы ядро не отвечало вовсе. Здесь проверяется то, что
     * действительно может сломаться: переход через границу FFI при
     * каждом пересоздании activity.
     */
    @Test
    fun ffiSurvivesActivityRecreation() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            repeat(RECREATIONS) {
                scenario.recreate()
                device.wait(Until.hasObject(By.res(PACKAGE, "core_version_text")), 5000)
            }

            val version = device.findObject(By.res(PACKAGE, "core_version_text"))
            assertNotNull("ядро перестало отвечать после пересоздания", version)
            assertTrue("версия ядра пуста", version.text.isNotEmpty())
        }
    }

    private companion object {
        /**
         * Имя пакета под тестом.
         *
         * Берётся из контекста, а не задаётся строкой: flavor добавляет
         * суффикс (`.foss` / `.gms`), и жёсткое значение сделало бы тест
         * рабочим ровно для одного варианта сборки.
         */
        /** Сколько раз пересоздаётся activity. */
        const val RECREATIONS = 3

        val PACKAGE: String
            get() = ApplicationProvider.getApplicationContext<Context>().packageName
    }
}