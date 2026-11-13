// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import org.gasapp.app.core.ReadMarks
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.gasapp.FfiDeliveryStatus
import uniffi.gasapp.FfiMessage

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

    /**
     * Короткий путь списка чатов: последнее сообщение не новее отметки —
     * переписку ради счётчика не читают. Он обязан давать тот же ноль,
     * что и полный подсчёт, при любой отметке.
     */
    @Test
    fun last_message_not_newer_than_the_mark_means_nothing_is_unread() {
        val messages = listOf(
            message(100, outgoing = false),
            message(200, outgoing = true),
            message(300, outgoing = false),
        )

        for (mark in listOf(0L, 99L, 100L, 250L, 299L, 300L, 301L, 1_000L)) {
            if (!ReadMarks.isNewer(messages.last(), mark)) {
                assertEquals("отметка $mark", 0, ReadMarks.count(messages, mark))
            }
        }

        assertEquals(false, ReadMarks.isNewer(messages.last(), mark = 300))
        assertEquals(true, ReadMarks.isNewer(messages.last(), mark = 299))
    }

    @Test
    fun own_messages_are_never_unread() {
        val messages = listOf(message(500, outgoing = true), message(600, outgoing = true))

        assertEquals(0, ReadMarks.count(messages, mark = 0))
    }
}
