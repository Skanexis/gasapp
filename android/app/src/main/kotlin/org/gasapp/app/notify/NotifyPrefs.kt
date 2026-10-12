// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.notify

import android.content.Context
import android.content.SharedPreferences

/**
 * Состояние уведомлений — **вне** зашифрованной базы (ADR-040).
 *
 * Фоновая проверка идёт, пока приложение заперто: базы она не открывает,
 * и всё, что ей нужно, лежит здесь. 🔐 Здесь нет ничего, кроме токена
 * уведомлений и идентификатора устройства: токен отвечает только «есть
 * ли новое», а идентификатор устройства сервер знает и так. Ни имён, ни
 * текста, ни списка собеседников.
 */
internal class NotifyPrefs(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Человек хочет уведомления. По умолчанию — да. */
    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_ENABLED, value).apply()

    /** Токен, hex; `null` — не заведён либо отозван. */
    var token: String?
        get() = prefs.getString(KEY_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_TOKEN, value).apply()

    /** Устройство, для которого зарегистрирован токен. */
    var device: String?
        get() = prefs.getString(KEY_DEVICE, null)
        set(value) = prefs.edit().putString(KEY_DEVICE, value).apply()

    /**
     * Сеть — прямое соединение: фоновой проверке можно выходить в сеть.
     *
     * 🔐 Режим сети лежит в зашифрованной базе, и в фоне его не прочитать.
     * Поэтому его отражение здесь, и только «прямое или нет»: при Tor
     * или прокси фоновая проверка не ходит никуда — прямой запрос выдал
     * бы адрес тому, кто выбрал его скрыть.
     */
    var direct: Boolean
        get() = prefs.getBoolean(KEY_DIRECT, false)
        set(value) = prefs.edit().putBoolean(KEY_DIRECT, value).apply()

    /** Уведомление о текущей очереди уже показано — повторять не нужно. */
    var notified: Boolean
        get() = prefs.getBoolean(KEY_NOTIFIED, false)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFIED, value).apply()

    /** Разрешение на уведомления уже спрашивали (Android 13+). */
    var askedPermission: Boolean
        get() = prefs.getBoolean(KEY_ASKED, false)
        set(value) = prefs.edit().putBoolean(KEY_ASKED, value).apply()

    /** Забывает всё — при стирании аккаунта. */
    fun clear() {
        prefs.edit().clear().commit()
    }

    private companion object {
        const val FILE = "gasapp_notify"
        const val KEY_ENABLED = "enabled"
        const val KEY_TOKEN = "token"
        const val KEY_DEVICE = "device"
        const val KEY_DIRECT = "direct"
        const val KEY_NOTIFIED = "notified"
        const val KEY_ASKED = "asked_permission"
    }
}
