// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.ChatActivity
import org.gasapp.app.LockActivity
import org.gasapp.app.OnboardingActivity
import org.gasapp.app.R
import org.gasapp.app.core.AutoLock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 🔐 После гибели процесса переписка не открывается без PIN.
 *
 * # Что здесь проверяется
 *
 * Система, убившая процесс по памяти, при возвращении восстанавливает
 * верхний экран задачи. В новом процессе хранилище закрыто, а
 * `AutoLock` отлучки не видел (`backgroundedAt == 0`) и не запирал.
 * Экран переписки показывал имя собеседника из extras и черновик
 * из сохранённого состояния — без PIN.
 *
 * Нашёл аудитор; тест перенесён из его рабочей копии.
 *
 * # Чего тест не проверяет
 *
 * Настоящую гибель процесса: её имитирует сброс состояния `AutoLock`
 * и закрытое хранилище, которое в юнит-тесте закрыто всегда.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ProcessDeathLockTest {

    private val application: Application
        get() = ApplicationProvider.getApplicationContext()

    @Before
    fun startLikeANewProcess() {
        // Объекты процесса начинают с чистого листа.
        AutoLock::class.java.getDeclaredField("visible").apply {
            isAccessible = true
            setInt(AutoLock, 0)
        }
        AutoLock::class.java.getDeclaredField("backgroundedAt").apply {
            isAccessible = true
            setLong(AutoLock, 0L)
        }
        shadowOf(application).clearNextStartedActivities()
    }

    /** 🔐 Восстановленный экран переписки закрывается и уводит на вход. */
    @Test
    fun a_chat_restored_after_process_death_is_locked() {
        val intent = Intent(application, ChatActivity::class.java)
            .putExtra(ChatActivity.EXTRA_CHAT_NAME, "Алиса Иванова")
            .putExtra(ChatActivity.EXTRA_CHAT_ID, "chat-1")
            .putExtra(ChatActivity.EXTRA_PEER_USERNAME, "alice")

        // Система восстанавливает экран с сохранённым состоянием.
        val saved = Bundle()
        val controller = Robolectric.buildActivity(ChatActivity::class.java, intent).setup(saved)

        try {
            val restored = controller.get()
            val next = shadowOf(application).nextStartedActivity?.component?.className

            val title = restored.findViewById<TextView>(R.id.chat_title).text.toString()

            assertTrue(
                "экран переписки восстановлен без PIN: заголовок «$title»",
                restored.isFinishing,
            )

            // Аккаунта в тесте нет — значит, на регистрацию; с аккаунтом —
            // на блокировку. Главное — не остаться в переписке.
            assertTrue(
                "увёл не на вход, а на $next",
                next == LockActivity::class.java.name || next == OnboardingActivity::class.java.name,
            )
        } finally {
            // ⚠️ Закрыть обязательно: AutoLock считает показанные экраны
            // счётчиком, общим на процесс (см. PinLengthTest).
            controller.pause().stop().destroy()
        }
    }

    /** 🔐 Черновик сообщения не попадает в сохранённое состояние экрана. */
    @Test
    fun the_draft_is_not_saved_in_instance_state() {
        val view = android.view.LayoutInflater.from(application.apply { setTheme(R.style.Theme_GasApp) })
            .inflate(R.layout.activity_chat, null)
        val input = view.findViewById<EditText>(R.id.message_input)

        assertEquals("черновик сохраняется в состоянии экрана", false, input.isSaveEnabled)
    }
}
