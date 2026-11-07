// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Context
import android.content.Intent
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import java.io.File
import org.gasapp.app.core.AccountWipe
import org.gasapp.app.core.AutoLock
import org.gasapp.app.core.Core
import org.gasapp.app.core.Settings
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 🔐 После автоблокировки переписка недоступна без PIN.
 *
 * Открытый пункт раздела 19.3: «требует инструментального прогона
 * с жизненным циклом». Модульный `AutoLockTest` двигает часы
 * Robolectric; здесь — настоящий уход приложения в фон кнопкой
 * «Домой» и настоящий таймер.
 *
 * Проверяется вся цепочка, а не один флаг:
 *
 *  1. ушли в фон → хранилище закрылось само, без возвращения;
 *  2. ядро отказывает в данных, а не отдаёт их из кеша;
 *  3. экран переписки не открывается — вместо него вход;
 *  4. неверный PIN базу не открывает;
 *  5. верный открывает, и данные на месте: запирание — не стирание.
 */
@RunWith(AndroidJUnit4::class)
class AutoLockOnDeviceTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext

    @Before
    fun openAFreshStorage() {
        assumeFalse(
            "на устройстве есть настоящая база — её PIN неизвестен, трогать её нельзя",
            File(context.filesDir, "gasapp.db").exists(),
        )

        NotificationsAllowed.grant()

        Core.unlock(context, TEST_PIN.toByteArray()).apply {
            // Ноль — «запирать сразу после ухода»: самый строгий режим,
            // и тест не ждёт минуту умолчания.
            setSettingInt(Settings.AUTO_LOCK_SECONDS, 0)
            setSettingBool(MARKER_KEY, true)
        }
    }

    @After
    fun wipeIt() {
        Core.close()
        AccountWipe.wipe(context)

        // Экраны входа, открытые тестом, закрываются системой
        // с опозданием; после этого сторож забывает отлучку. Иначе он
        // запирал экран следующего теста того же прогона: отлучка
        // с порогом «сразу» осталась от этого (см. forgetAbsenceForTests).
        instrumentation.waitForIdleSync()
        Thread.sleep(SETTLE_MILLIS)
        instrumentation.runOnMainSync { AutoLock.forgetAbsenceForTests() }
    }

    @Test
    fun after_auto_lock_the_data_needs_the_pin_again() {
        val device = UiDevice.getInstance(instrumentation)

        ActivityScenario.launch(ChatListActivity::class.java).use { scenario ->
            assertEquals(
                "список чатов не открылся при открытом хранилище",
                Lifecycle.State.RESUMED,
                scenario.state,
            )

            device.pressHome()
            waitUntil("хранилище не закрылось после ухода в фон") { !Core.isUnlocked }
        }

        // 2. Ядро отказывает, а не отдаёт закешированное.
        try {
            Core.messenger()
            fail("после автоблокировки ядро отдало хранилище без PIN")
        } catch (expected: IllegalStateException) {
            // ожидаемо
        }

        // 3. Экран переписки закрывается сторожем, открывается вход.
        val lock = instrumentation.addMonitor(LockActivity::class.java.name, null, false)
        try {
            val intent = Intent(context, ChatListActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

            ActivityScenario.launch<ChatListActivity>(intent).use { scenario ->
                assertEquals(
                    "список чатов открылся после автоблокировки",
                    Lifecycle.State.DESTROYED,
                    scenario.state,
                )
            }

            val redirected = instrumentation.waitForMonitorWithTimeout(lock, TIMEOUT_MILLIS)
            assertNotNull("после автоблокировки не открылся вход", redirected)
            redirected?.finish()

            // Остановка экрана входа доходит до AutoLock асинхронно;
            // дождаться её надо до повторного входа ниже, иначе
            // порог «0» из этого теста запер бы экраны следующих.
            instrumentation.waitForIdleSync()
        } finally {
            instrumentation.removeMonitor(lock)
        }

        // 4. Неверный PIN.
        val wrong = runCatching { Core.unlock(context, "000000".toByteArray()) }
        assertTrue("неверный PIN открыл базу", wrong.isFailure)
        assertFalse(Core.isUnlocked)

        // 5. Верный PIN — и данные те же.
        val messenger = Core.unlock(context, TEST_PIN.toByteArray())
        assertTrue(
            "после повторного входа данных нет — запирание стёрло базу",
            messenger.settingBool(MARKER_KEY, false),
        )

        // Порог — обратно к умолчанию: AutoLock живёт весь процесс,
        // и «запирать сразу» из этого теста запирало бы экраны
        // следующих тестов того же прогона.
        messenger.setSettingInt(Settings.AUTO_LOCK_SECONDS, Settings.AUTO_LOCK_DEFAULT)
    }

    private fun waitUntil(message: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MILLIS

        while (!condition()) {
            if (System.currentTimeMillis() > deadline) fail(message)
            Thread.sleep(POLL_MILLIS)
        }
    }

    private companion object {
        const val TEST_PIN = "975310"
        const val MARKER_KEY = "test_marker_survives_lock"
        const val TIMEOUT_MILLIS = 10_000L
        const val POLL_MILLIS = 100L
        const val SETTLE_MILLIS = 2_000L
    }
}
