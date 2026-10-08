// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import org.gasapp.app.core.PinBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 Буфер PIN не оставляет цифр в памяти.
 *
 * Прежде PIN набирался в `StringBuilder` и уходил в ядро строкой:
 * `setLength(0)` символы не стирает, строку не стереть вовсе, и дамп
 * памяти запертого приложения показывал PIN (эмулятор, 2026-09-25).
 */
class PinBufferTest {

    private fun storage(buffer: PinBuffer): ByteArray =
        PinBuffer::class.java.getDeclaredField("digits").apply { isAccessible = true }.get(buffer) as ByteArray

    @Test
    fun take_returns_the_digits_and_wipes_the_buffer() {
        val buffer = PinBuffer()
        "482915".forEach(buffer::append)

        assertTrue(buffer.isComplete)
        assertArrayEquals("482915".toByteArray(), buffer.take())
        assertEquals(0, buffer.length)
        assertTrue("цифры остались в буфере после take()", storage(buffer).all { it == 0.toByte() })
    }

    @Test
    fun removing_a_digit_wipes_its_place() {
        val buffer = PinBuffer()
        "12".forEach(buffer::append)

        buffer.removeLast()

        assertEquals(1, buffer.length)
        assertEquals("стёртая цифра осталась в памяти", 0.toByte(), storage(buffer)[1])
    }

    @Test
    fun clear_wipes_everything() {
        val buffer = PinBuffer()
        "987".forEach(buffer::append)

        buffer.clear()

        assertTrue(storage(buffer).all { it == 0.toByte() })
    }

    @Test
    fun only_six_ascii_digits_are_accepted() {
        val buffer = PinBuffer()

        assertFalse("нецифра принята", buffer.append('a'))
        assertFalse("арабо-индийская цифра принята", buffer.append('١'))
        "1234567".forEach(buffer::append)

        assertEquals(6, buffer.length)
    }
}
