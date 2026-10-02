// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.aegis.app.core.PinAttempts
import org.aegis.app.core.PinAttempts.Moment
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * 🔐 Ограничение перебора PIN — таблица раздела 19.3.
 *
 * Проверяется то, что нельзя увидеть в коде экрана: что попытка
 * засчитывается до проверки, что счётчик переживает перезапуск, что
 * задержка растёт по таблице и что её не снять ни часами, ни
 * перезагрузкой (аудит 2026-10-02, A-1 и A-2).
 */
@RunWith(RobolectricTestRunner::class)
class PinAttemptsTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Before
    fun reset() {
        PinAttempts.recordSuccess(context)
    }

    /**
     * Первые три попытки проходят без ожидания.
     *
     * Три опечатки подряд — обычное дело, и наказывать за них означало
     * бы наказывать в основном владельца телефона.
     */
    @Test
    fun first_three_failures_do_not_delay() {
        repeat(3) { PinAttempts.beginAttempt(context, AT) }

        assertEquals(3, PinAttempts.failures(context))
        assertEquals(0L, PinAttempts.remainingMillis(context, AT))
    }

    /**
     * 🔐 Попытка засчитана ещё до проверки (A-1).
     *
     * Прежде неверная попытка записывалась после проверки, и поворот
     * экрана в эту секунду отменял запись. Здесь проверки нет вовсе —
     * её «прервали», — а попытка уже на диске.
     */
    @Test
    fun an_interrupted_check_still_counts() {
        repeat(4) { PinAttempts.beginAttempt(context, AT) }

        assertEquals(4, PinAttempts.failures(context))
        assertEquals(5_000L, PinAttempts.remainingMillis(context, AT))
    }

    /** Верный PIN снимает и попытку, засчитанную до проверки. */
    @Test
    fun success_clears_the_counter() {
        repeat(6) { PinAttempts.beginAttempt(context, AT) }
        PinAttempts.recordSuccess(context)

        assertEquals(0, PinAttempts.failures(context))
        assertEquals(0L, PinAttempts.remainingMillis(context, AT))
    }

    /** Таблица задержек раздела 19.3, дословно. */
    @Test
    fun delay_table_matches_the_plan() {
        assertEquals(0L, PinAttempts.delayMillis(1))
        assertEquals(0L, PinAttempts.delayMillis(3))
        assertEquals(5_000L, PinAttempts.delayMillis(4))
        assertEquals(30_000L, PinAttempts.delayMillis(5))
        assertEquals(300_000L, PinAttempts.delayMillis(6))
        assertEquals(1_800_000L, PinAttempts.delayMillis(7))
        assertEquals(3_600_000L, PinAttempts.delayMillis(8))
    }

    /** С восьмой попытки задержка удваивается на каждой следующей. */
    @Test
    fun delay_doubles_after_the_eighth_failure() {
        assertEquals(PinAttempts.delayMillis(8) * 2, PinAttempts.delayMillis(9))
        assertEquals(PinAttempts.delayMillis(9) * 2, PinAttempts.delayMillis(10))
    }

    /** Удвоение не переполняется и не становится отрицательным. */
    @Test
    fun delay_never_overflows_into_negative() {
        listOf(30, 60, 100, 1_000, Int.MAX_VALUE).forEach { failures ->
            assertTrue(
                "задержка отрицательна при $failures попытках",
                PinAttempts.delayMillis(failures) > 0L,
            )
        }
    }

    /** Ожидание сокращается по мере того, как идёт монотонное время. */
    @Test
    fun remaining_delay_shrinks_as_time_passes() {
        repeat(4) { PinAttempts.beginAttempt(context, AT) }

        assertEquals(5_000L, PinAttempts.remainingMillis(context, AT))
        assertEquals(2_000L, PinAttempts.remainingMillis(context, AT.after(3_000L)))
        assertEquals(0L, PinAttempts.remainingMillis(context, AT.after(5_000L)))
        assertEquals(0L, PinAttempts.remainingMillis(context, AT.after(10_000L)))
    }

    /**
     * 🔐 Настенные часы ни при чём (A-2).
     *
     * Прежде срок считался по ним, и перевод даты вперёд в настройках
     * снимал любую задержку. Теперь в расчёт идёт только время от
     * загрузки: пока оно не прошло, ждать придётся, что бы ни показывали
     * часы.
     */
    @Test
    fun the_wall_clock_is_not_consulted() {
        repeat(8) { PinAttempts.beginAttempt(context, AT) }

        // Час задержки; монотонно прошла секунда — «перевод часов на сутки
        // вперёд» здесь нечем выразить, и в этом смысл.
        assertEquals(3_599_000L, PinAttempts.remainingMillis(context, AT.after(1_000L)))
    }

    /**
     * 🔐 Перезагрузка начинает ожидание заново.
     *
     * Сколько прошло до перезагрузки, честно узнать нельзя (настенным
     * часам веры нет), поэтому отсчёт идёт сначала — с первой проверки
     * после загрузки.
     */
    @Test
    fun a_reboot_restarts_the_wait() {
        repeat(5) { PinAttempts.beginAttempt(context, AT) }

        val afterReboot = Moment(elapsed = 40_000L, boot = AT.boot + 1)

        assertEquals(30_000L, PinAttempts.remainingMillis(context, afterReboot))
        assertEquals(20_000L, PinAttempts.remainingMillis(context, afterReboot.after(10_000L)))
    }

    /**
     * 🔐 Время, пошедшее назад, — тоже перезагрузка: номер загрузки
     * система может не отдать.
     */
    @Test
    fun monotonic_time_going_backwards_restarts_the_wait() {
        repeat(5) { PinAttempts.beginAttempt(context, AT) }

        val unknownBoot = Moment(elapsed = AT.elapsed - 1_000L, boot = -1)

        assertEquals(30_000L, PinAttempts.remainingMillis(context, unknownBoot))
    }

    /**
     * 🔐 Счётчик переживает перезапуск приложения.
     *
     * Проверяется через новый контекст приложения: значение читается
     * не из поля объекта, а с диска.
     */
    @Test
    fun counter_survives_process_restart() {
        repeat(5) { PinAttempts.beginAttempt(context, AT) }

        val afterRestart: Context = ApplicationProvider.getApplicationContext()

        assertEquals(5, PinAttempts.failures(afterRestart))
        assertEquals(30_000L, PinAttempts.remainingMillis(afterRestart, AT))
    }

    /** Стирание — только по выбору человека (раздел 19.3). */
    @Test
    fun wipe_is_off_by_default_and_never_fires_when_off() {
        assertFalse("стирание включено по умолчанию", PinAttempts.wipeEnabled(context))

        for (failures in 0..1_000) {
            assertFalse("выключенное стирание сработало на $failures", PinAttempts.shouldWipe(failures, enabled = false))
        }
    }

    /** Ровно на десятой неверной попытке — не раньше. */
    @Test
    fun wipe_fires_at_the_tenth_failure_not_before() {
        for (failures in 0 until PinAttempts.WIPE_AFTER) {
            assertFalse("стирание раньше десятой попытки: $failures", PinAttempts.shouldWipe(failures, enabled = true))
        }

        assertEquals(10, PinAttempts.WIPE_AFTER)
        assertTrue(PinAttempts.shouldWipe(10, enabled = true))
        assertTrue("после десятой стирание не срабатывает", PinAttempts.shouldWipe(11, enabled = true))
    }

    /** Выбор переживает перезапуск и забывается при удалении аккаунта. */
    @Test
    fun wipe_choice_survives_restart_and_is_forgotten_with_the_account() {
        PinAttempts.setWipeEnabled(context, true)
        assertTrue(PinAttempts.wipeEnabled(context))

        PinAttempts.forget(context)
        assertFalse("выбор пережил удаление аккаунта", PinAttempts.wipeEnabled(context))
    }

    private fun Moment.after(millis: Long): Moment = copy(elapsed = elapsed + millis)

    private companion object {
        /** Фиксированная отметка: тест не зависит от часов. */
        val AT = Moment(elapsed = 100_000L, boot = 7)
    }
}
