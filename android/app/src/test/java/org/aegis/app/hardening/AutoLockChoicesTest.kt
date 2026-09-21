// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import org.aegis.app.core.Settings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 Срок автоблокировки можно выбрать, и выбор честен.
 *
 * # Что здесь проверяется
 *
 * Настройку читали `AutoLock` и центр безопасности, но ни один экран
 * её не записывал: срок был минутой навсегда. Комментарии в `Settings`
 * обещали, что его можно поменять, а проверка центра безопасности
 * «не дольше пяти минут» не могла не пройти — то есть не проверяла
 * ничего.
 *
 * # Чего тест не проверяет
 *
 * Сам экран: он пишет в зашифрованную базу, которой в юнит-тесте нет.
 * Проверяется набор вариантов, из которого экран строит выбор.
 */
class AutoLockChoicesTest {

    private val choices = Settings.AUTO_LOCK_CHOICES

    /** Умолчание есть среди вариантов: иначе строка показала бы срок, которого не выбрать. */
    @Test
    fun the_default_is_one_of_the_choices() {
        assertTrue(
            "умолчания нет среди вариантов",
            Settings.AUTO_LOCK_DEFAULT in choices,
        )
    }

    /**
     * 🔐 Нет «сразу».
     *
     * `AutoLock` запирает, когда отлучка не короче порога; при нуле он
     * запирал бы от поворота экрана и от системного выбора файла.
     */
    @Test
    fun no_choice_locks_on_every_screen_change() {
        assertTrue(
            "вариант короче 30 секунд запирал бы от поворота экрана",
            choices.all { it >= MIN_SENSIBLE_SECONDS },
        )
    }

    /**
     * 🔐 Проверка центра безопасности может не пройти.
     *
     * Будь все варианты в пределах рекомендованного, пункт «не дольше
     * пяти минут» был бы зелёным всегда — как и был, пока настройку
     * нельзя было поменять вовсе.
     */
    @Test
    fun the_security_check_can_actually_fail() {
        assertTrue(
            "ни один вариант не превышает предел: проверка вырождена",
            choices.any { it > Settings.AUTO_LOCK_RECOMMENDED_MAX },
        )
        assertTrue(
            "ни один вариант не укладывается в предел: проверку не пройти",
            choices.any { it <= Settings.AUTO_LOCK_RECOMMENDED_MAX },
        )
    }

    /** Варианты идут по возрастанию: так они и показываются. */
    @Test
    fun choices_are_in_ascending_order() {
        assertEquals(choices.sorted(), choices)
        assertEquals("варианты повторяются", choices.size, choices.toSet().size)
    }

    private companion object {
        const val MIN_SENSIBLE_SECONDS = 30L
    }
}
