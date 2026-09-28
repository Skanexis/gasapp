// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import org.aegis.app.core.ReadMarks
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.aegis.FfiDeliveryStatus
import uniffi.aegis.FfiMessage

/**
 * Счётчик непрочитанных: входящие новее отметки прочтения.
 */
class ReadMarksTest {

    private fun message(at: Long, outgoing: Boolean) = FfiMessage(
        messageId = "m$at",
        text = "",
        timestamp = at,
        outgoing = outgoing,
        status = FfiDeliveryStatus.DELIVERED,
    )

    @Test
    fun only_incoming_messages_after_the_mark_are_unread() {
        val messages = listOf(
            message(100, outgoing = false),
            message(200, outgoing = true),
            message(300, outgoing = false),
            message(400, outgoing = false),
        )

        assertEquals(3, ReadMarks.count(messages, mark = 0))
        assertEquals(2, ReadMarks.count(messages, mark = 100))
        assertEquals("сообщение ровно на отметке уже прочитано", 1, ReadMarks.count(messages, mark = 300))
        assertEquals(0, ReadMarks.count(messages, mark = 400))
    }

    @Test
    fun own_messages_are_never_unread() {
        val messages = listOf(message(500, outgoing = true), message(600, outgoing = true))

        assertEquals(0, ReadMarks.count(messages, mark = 0))
    }
}
