// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import java.time.Duration
import org.aegis.app.core.SecureClipboard
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 🔐 Скопированное не переживает минуту.
 *
 * MASVS STORAGE-2 («нет данных в буфере обмена дольше 60 сек»)
 * и раздел 19.2 («`ClipboardManager` — помечать `EXTRA_IS_SENSITIVE`»).
 *
 * # Почему тест понадобился отдельно
 *
 * Оба свойства невидимы при обычной работе: приложение копирует,
 * вставка работает, и ничто не показывает, что содержимое осталось
 * в буфере до конца дня. В чек-листе MASVS этот пункт стоял 🟡 ровно
 * с формулировкой «теста нет».
 *
 * # Про время
 *
 * Очистка идёт отложенной задачей `Handler`, поэтому тест не ждёт
 * минуту, а двигает часы Robolectric (`idleFor`). Настоящее ожидание
 * сделало бы прогон тестов на минуту длиннее за каждую проверку —
 * и его бы выключили.
 *
 * `LooperMode.PAUSED` (умолчание в Robolectric 4) обязателен: в режиме
 * LEGACY отложенные задачи выполняются немедленно, и проверка «до
 * срока содержимое на месте» прошла бы, ничего не проверив.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecureClipboardTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val clipboard: ClipboardManager
        get() = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    @After
    fun clear() {
        SecureClipboard.clear(context)
    }

    /** Скопированное доступно сразу: иначе вставлять было бы нечего. */
    @Test
    fun copied_text_is_available_immediately() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        assertEquals(SECRET, currentText())
    }

    /**
     * 🔐 Содержимое помечено чувствительным.
     *
     * Без пометки Android 13+ показывает **сам текст** во всплывающем
     * окне поверх приложения — того самого, которое этот текст прячет
     * от снимка экрана.
     */
    @Test
    fun copied_text_is_marked_sensitive() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        val extras = clipboard.primaryClipDescription?.extras

        assertTrue(
            "содержимое не помечено EXTRA_IS_SENSITIVE",
            extras?.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE, false) == true,
        )
    }

    /** До срока содержимое на месте — минута даётся на вставку. */
    @Test
    fun copied_text_survives_until_the_deadline() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        advance(SecureClipboard.TTL_MILLIS - 1_000L)

        assertEquals("содержимое исчезло раньше срока", SECRET, currentText())
    }

    /** 🔐 По истечении срока буфер пуст. */
    @Test
    fun copied_text_is_gone_after_the_deadline() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        advance(SecureClipboard.TTL_MILLIS)

        assertNull("содержимое пережило свой срок", currentText())
    }

    /**
     * 🔐 Запирание стирает буфер, не дожидаясь срока.
     *
     * Таймер живёт в процессе приложения, и убитый системой процесс его
     * не выполнит. Запирание — момент, после которого ничего
     * из переписки на устройстве быть не должно.
     */
    @Test
    fun locking_clears_the_clipboard_before_the_deadline() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        SecureClipboard.clear(context)

        assertNull("запирание не стёрло буфер", currentText())
    }

    /**
     * Второе копирование не уносится сроком первого.
     *
     * Без снятия прежнего таймера текст, скопированный на 59-й секунде,
     * исчезал бы через секунду — то есть поведение зависело бы от того,
     * когда копировали в прошлый раз.
     */
    @Test
    fun a_second_copy_gets_its_own_deadline() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        advance(SecureClipboard.TTL_MILLIS - 1_000L)

        SecureClipboard.copySensitive(context, LABEL, OTHER)

        // Момент, в который сработал бы таймер первого копирования.
        advance(2_000L)

        assertEquals("второе копирование унесено сроком первого", OTHER, currentText())
    }

    /**
     * 🔐 Чужое содержимое приложение не трогает.
     *
     * За минуту человек мог скопировать что-то в другом приложении.
     * Стирать это мессенджеру не за чем — и по сроку, и при запирании.
     */
    @Test
    fun foreign_clipboard_content_is_left_alone() {
        SecureClipboard.copySensitive(context, LABEL, SECRET)

        // Кто-то другой положил в буфер своё.
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("other app", OTHER))

        advance(SecureClipboard.TTL_MILLIS)

        assertEquals("стёрто чужое содержимое", OTHER, currentText())

        SecureClipboard.clear(context)

        assertEquals("запирание стёрло чужое содержимое", OTHER, currentText())
    }

    /** Срок — ровно тот, что требует раздел 25. */
    @Test
    fun deadline_matches_the_plan() {
        assertEquals(60_000L, SecureClipboard.TTL_MILLIS)
    }

    /** Двигает часы главного цикла, выполняя созревшие задачи. */
    private fun advance(millis: Long) {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(millis))
    }

    /** Текст в буфере; `null` — буфер пуст. */
    private fun currentText(): String? {
        val clip = clipboard.primaryClip ?: return null

        if (clip.itemCount == 0) {
            return null
        }

        return clip.getItemAt(0).coerceToText(context)?.toString()?.takeIf { it.isNotEmpty() }
    }

    private companion object {
        const val LABEL = "AEGIS"
        const val SECRET = "текст сообщения"
        const val OTHER = "что-то своё"
    }
}
