// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import org.aegis.app.core.OpenedKey
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 Проверка PIN при включении биометрии.
 *
 * # Что здесь проверяется
 *
 * Ключ, выведенный из введённого PIN, запечатывался в конверт Keystore
 * без проверки: опечатка давала «включённую» биометрию, которая базу
 * не открывала никогда. Теперь запечатывается только ключ, совпавший
 * с ключом открытой базы ([OpenedKey]).
 */
class OpenedKeyTest {

    private val right = ByteArray(32) { 0x11 }
    private val typo = ByteArray(32) { 0x12 }

    @Test
    fun the_key_the_storage_was_opened_with_matches() {
        val opened = OpenedKey().apply { remember(right) }

        assertTrue(opened.matches(right.copyOf()))
    }

    @Test
    fun a_key_from_a_mistyped_pin_does_not_match() {
        val opened = OpenedKey().apply { remember(right) }

        assertFalse("ключ из неверного PIN принят", opened.matches(typo))
    }

    /** Закрытая база не подтверждает ничего. */
    @Test
    fun nothing_matches_once_the_storage_is_closed() {
        val opened = OpenedKey().apply {
            remember(right)
            forget()
        }

        assertFalse("после закрытия базы ключ всё ещё подтверждается", opened.matches(right))
    }
}
