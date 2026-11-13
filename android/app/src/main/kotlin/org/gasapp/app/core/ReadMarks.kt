// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import uniffi.gasapp.FfiMessage
import uniffi.gasapp.Messenger

/**
 * Докуда прочитан каждый чат — для счётчика непрочитанных в списке.
 *
 * Отметка — время последнего показанного сообщения. Непрочитанные —
 * входящие новее неё.
 *
 * 🔐 Хранится в зашифрованной базе (настройки ядра), а не в
 * `SharedPreferences`: идентификаторы чатов и время чтения —
 * сведения о переписке, и в открытом файле им не место. На сервер
 * отметка не уходит: квитанции о прочтении — отдельная настройка.
 */
object ReadMarks {

    /** Сколько последних сообщений просматривать при подсчёте. */
    const val SCAN_LIMIT: UInt = 100u

    /**
     * Сколько непрочитанных в чате; [last] — его последнее сообщение.
     *
     * Сообщения ядро отдаёт по времени, поэтому последнее — самое
     * новое: если оно не новее отметки, непрочитанных нет, и сотню
     * сообщений ради нуля расшифровывать незачем. Так у прочитанного
     * чата (а их в списке большинство) читается одно сообщение, а не
     * [SCAN_LIMIT].
     */
    fun unread(messenger: Messenger, chatId: String, last: FfiMessage?): Int {
        if (last == null) return 0

        val mark = messenger.settingInt(key(chatId), 0L)
        if (!isNewer(last, mark)) return 0

        return count(messenger.messages(chatId, SCAN_LIMIT), mark)
    }

    /** Новее ли отметки самое свежее сообщение чата. */
    internal fun isNewer(last: FfiMessage, mark: Long): Boolean = last.timestamp > mark

    /** Входящие новее [mark]: свои сообщения непрочитанными не бывают. */
    internal fun count(messages: List<FfiMessage>, mark: Long): Int =
        messages.count { !it.outgoing && it.timestamp > mark }

    /** Отмечает чат прочитанным до [upToMillis]; назад отметка не двигается. */
    fun markRead(messenger: Messenger, chatId: String, upToMillis: Long) {
        if (upToMillis > messenger.settingInt(key(chatId), 0L)) {
            messenger.setSettingInt(key(chatId), upToMillis)
        }
    }

    private fun key(chatId: String) = "chat_read_at:$chatId"
}
