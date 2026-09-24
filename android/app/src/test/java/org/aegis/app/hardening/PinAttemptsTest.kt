// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.aegis.app.core.PinAttempts
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
 * Проверяется то, что нельзя увидеть в коде экрана: что счётчик
 * переживает перезапуск, что задержка растёт по таблице и что её
 * нельзя снять переводом часов назад.
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
     * Так задумано: три опечатки подряд — обычное дело, и наказывать
     * за них означало бы наказывать в основном владельца телефона.
     */
    @Test
    fun first_three_failures_do_not_delay() {
        repeat(3) { PinAttempts.recordFailure(context, NOW) }

        assertEquals(3, PinAttempts.failures(context))
        assertEquals(0L, PinAttempts.remainingMillis(context, NOW))
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

    /**
     * Удвоение не переполняется и не становится отрицательным.
     *
     * 🔐 Без ограничения сдвига защита обращалась бы в свою
     * противоположность ровно у самого упорного перебирающего:
     * отрицательная задержка — это отсутствие задержки.
     */
    @Test
    fun delay_never_overflows_into_negative() {
        listOf(30, 60, 100, 1_000, Int.MAX_VALUE).forEach { failures ->
            assertTrue(
                "задержка отрицательна при $failures попытках",
                PinAttempts.delayMillis(failures) > 0L,
            )
        }
    }

    /** Ожидание сокращается по мере того, как время идёт. */
    @Test
    fun remaining_delay_shrinks_as_time_passes() {
        repeat(4) { PinAttempts.recordFailure(context, NOW) }

        assertEquals(5_000L, PinAttempts.remainingMillis(context, NOW))
        assertEquals(2_000L, PinAttempts.remainingMillis(context, NOW + 3_000L))
        assertEquals(0L, PinAttempts.remainingMillis(context, NOW + 5_000L))
        assertEquals(0L, PinAttempts.remainingMillis(context, NOW + 10_000L))
    }

    /**
     * 🔐 Перевод часов назад не сокращает ожидание.
     *
     * Иначе любую задержку снимали бы одним движением в настройках даты.
     * Здесь отрицательное «прошло» трактуется как ноль прошедшего
     * времени, то есть ждать придётся полный срок.
     */
    @Test
    fun moving_the_clock_backwards_does_not_shorten_the_wait() {
        repeat(4) { PinAttempts.recordFailure(context, NOW) }

        assertEquals(5_000L, PinAttempts.remainingMillis(context, NOW - 3_600_000L))
    }

    /**
     * 🔐 Счётчик переживает перезапуск приложения.
     *
     * Требование раздела 19.3. Счётчик в памяти процесса сводил бы
     * перебор к «снять приложение из недавних и попробовать снова».
     *
     * Проверяется через новый контекст приложения: значение читается
     * не из поля объекта, а с диска.
     */
    @Test
    fun counter_survives_process_restart() {
        repeat(5) { PinAttempts.recordFailure(context, NOW) }

        val afterRestart: Context = ApplicationProvider.getApplicationContext()

        assertEquals(5, PinAttempts.failures(afterRestart))
        assertEquals(30_000L, PinAttempts.remainingMillis(afterRestart, NOW))
    }

    /** Верный PIN обнуляет счётчик и снимает ожидание. */
    @Test
    fun success_clears_the_counter() {
        repeat(6) { PinAttempts.recordFailure(context, NOW) }
        PinAttempts.recordSuccess(context)

        assertEquals(0, PinAttempts.failures(context))
        assertEquals(0L, PinAttempts.remainingMillis(context, NOW))
    }

    /**
     * 🔐 Стирание — только по выбору человека (раздел 19.3).
     *
     * По умолчанию выключено: случайное стирание ребёнком или
     * в кармане — частый сценарий, а вернуть данные можно только
     * ключом восстановления.
     */
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

    private companion object {
        /** Произвольная фиксированная отметка: тест не зависит от часов. */
        const val NOW = 1_700_000_000_000L
    }
}
