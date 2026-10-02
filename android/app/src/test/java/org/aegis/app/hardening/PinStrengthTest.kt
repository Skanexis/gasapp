// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import org.aegis.app.core.Pin
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 Простые PIN не выбираются (аудит 2026-10-02).
 *
 * Перебор начинают со списка частых PIN, а не с `000000` подряд: с ними
 * задержки и аппаратная половина ключа держат минуты, а не сутки.
 */
class PinStrengthTest {

    @Test
    fun the_usual_suspects_are_refused() {
        listOf(
            "000000", "111111", "999999",
            "123456", "234567", "654321", "987654",
            "543210",
            "121212", "101010", "123123", "456456",
            "112233", "111222",
            "159753", "147258", "696969", "123321",
        ).forEach { pin ->
            assertTrue("$pin принят", Pin.isTooSimple(pin.toByteArray()))
        }
    }

    @Test
    fun ordinary_pins_pass() {
        listOf("482915", "975310", "135790", "246801", "730492", "580316").forEach { pin ->
            assertFalse("$pin отвергнут", Pin.isTooSimple(pin.toByteArray()))
        }
    }

    /** Не шесть цифр — это вопрос [Pin.isAcceptable], не простоты. */
    @Test
    fun malformed_input_is_not_judged() {
        assertFalse(Pin.isTooSimple("12345".toByteArray()))
        assertFalse(Pin.isTooSimple("abcdef".toByteArray()))
    }
}
