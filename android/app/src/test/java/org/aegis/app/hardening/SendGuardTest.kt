// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import org.aegis.app.core.SendGuard
import org.aegis.app.core.SendGuard.Mode
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 🔐 Экран переписки показывает то же решение, что примет ядро.
 *
 * Само решение принимает ядро (`AegisError::IdentityChanged`,
 * тесты — в `aegis-core/tests/end_to_end.rs`); здесь проверяется, что
 * экран не предлагает писать туда, куда ядро не отправит, и не
 * запрещает там, где отправит.
 */
class SendGuardTest {

    @Test
    fun an_ordinary_contact_is_open() {
        assertEquals(Mode.OPEN, SendGuard.decide(keyChanged = false, replaced = false, keyConfirmed = true))
    }

    @Test
    fun two_keys_under_one_name_ask_to_choose() {
        assertEquals(Mode.CHOOSE_KEY, SendGuard.decide(keyChanged = true, replaced = false, keyConfirmed = true))
    }

    /** Заменённый ключ — только чтение, даже если имя снова стало неоднозначным. */
    @Test
    fun a_replaced_key_is_read_only() {
        assertEquals(Mode.REPLACED, SendGuard.decide(keyChanged = false, replaced = true, keyConfirmed = true))
        assertEquals(Mode.REPLACED, SendGuard.decide(keyChanged = true, replaced = true, keyConfirmed = true))
    }

    /** 🔐 Ключ, который назвал только сервер, — сначала сверка. */
    @Test
    fun an_unconfirmed_key_asks_to_confirm() {
        assertEquals(Mode.CONFIRM_KEY, SendGuard.decide(keyChanged = false, replaced = false, keyConfirmed = false))
        // Неоднозначность имени и замена важнее: о них надо сказать первыми.
        assertEquals(Mode.CHOOSE_KEY, SendGuard.decide(keyChanged = true, replaced = false, keyConfirmed = false))
        assertEquals(Mode.REPLACED, SendGuard.decide(keyChanged = false, replaced = true, keyConfirmed = false))
    }

    /** 🔐 Непринятый запрос закрыт до согласия — даже при сверенном ключе. */
    @Test
    fun an_incoming_request_waits_for_consent() {
        assertEquals(
            Mode.REQUEST,
            SendGuard.decide(keyChanged = false, replaced = false, keyConfirmed = true, request = true),
        )
        assertEquals(
            Mode.REQUEST,
            SendGuard.decide(keyChanged = false, replaced = false, keyConfirmed = false, request = true),
        )
        // Смена ключа важнее: о ней надо сказать первой.
        assertEquals(
            Mode.CHOOSE_KEY,
            SendGuard.decide(keyChanged = true, replaced = false, keyConfirmed = true, request = true),
        )
    }
}
