// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 🔐 Переписка не открывается мимо входа — на настоящем устройстве.
 *
 * После гибели процесса Android восстанавливает последний экран сам,
 * не спрашивая приложение. Сторож в `AutoLock.onActivityCreated`
 * закрывает любой экран приложения, кроме входа и регистрации, пока
 * хранилище закрыто, и открывает вход. Модульный тест
 * (`ProcessDeathLockTest`) проверяет это на Robolectric; здесь — на ART,
 * с настоящим восстановлением экрана.
 *
 * ⚠️ Прежде здесь был тест списка чатов, открывавший его без входа
 * и ждавший демонстрационного собеседника «Lena Novak». После сторожа
 * он не мог пройти в принципе — и не проходил, но проверки на устройстве
 * никто не запускал.
 */
@RunWith(AndroidJUnit4::class)
class LockGuardOnDeviceTest {

    @Test
    fun the_chat_list_does_not_open_while_the_storage_is_locked() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()

        // Куда ведёт сторож, зависит от того, заведён ли аккаунт:
        // на свежей установке — регистрация, иначе — вход.
        val lock = instrumentation.addMonitor(LockActivity::class.java.name, null, false)
        val onboarding = instrumentation.addMonitor(OnboardingActivity::class.java.name, null, false)

        try {
            ActivityScenario.launch(ChatListActivity::class.java).use { scenario ->
                assertEquals(
                    "список чатов открылся без входа",
                    Lifecycle.State.DESTROYED,
                    scenario.state,
                )
            }

            val redirected = instrumentation.waitForMonitorWithTimeout(lock, TIMEOUT_MILLIS)
                ?: instrumentation.waitForMonitorWithTimeout(onboarding, TIMEOUT_MILLIS)

            assertNotNull("вместо переписки не открылись ни вход, ни регистрация", redirected)
            redirected?.finish()
        } finally {
            instrumentation.removeMonitor(lock)
            instrumentation.removeMonitor(onboarding)
        }
    }

    private companion object {
        const val TIMEOUT_MILLIS = 5_000L
    }
}
