// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import uniffi.aegis.FfiMessage
import uniffi.aegis.Messenger

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

    /** Сколько входящих новее отметки среди [messages]. */
    fun unread(messenger: Messenger, chatId: String, messages: List<FfiMessage>): Int =
        count(messages, messenger.settingInt(key(chatId), 0L))

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
