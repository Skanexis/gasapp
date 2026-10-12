// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.notify

import android.content.Context
import uniffi.gasapp.FfiProxy
import uniffi.gasapp.Messenger
import uniffi.gasapp.generateNotifyToken

/**
 * Приводит уведомления в соответствие с настройкой, разрешением и сетью.
 *
 * Вызывается, пока база открыта: после входа, при смене режима сети и
 * при переключении уведомлений. Только здесь есть ключ устройства,
 * которым подписывается регистрация токена.
 */
object NotifySetup {

    /**
     * Синхронизирует. Сетевой вызов — только из фонового потока.
     *
     * Сбой сети не ошибка: токен заведётся при следующем входе.
     */
    @Synchronized
    fun sync(context: Context, messenger: Messenger) {
        val prefs = NotifyPrefs(context)
        val device = runCatching { messenger.ownDeviceId() }.getOrNull() ?: return
        val now = System.currentTimeMillis()

        prefs.direct = runCatching { messenger.proxy() }.getOrNull() is FfiProxy.Direct

        if (!prefs.enabled || !Notifier.permitted(context)) {
            if (prefs.token != null) {
                // Сначала сервер: не вышло — токен остаётся и отзовётся позже.
                if (runCatching { messenger.unregisterNotifyToken(now) }.isSuccess) {
                    prefs.token = null
                }
            }
            NotifyJob.cancel(context)
            Notifier.cancel(context)

            return
        }

        Notifier.ensureChannel(context)

        if (prefs.token == null || prefs.device != device) {
            val token = generateNotifyToken()

            try {
                if (runCatching { messenger.registerNotifyToken(token, now) }.isFailure) return

                prefs.token = token.joinToString("") { "%02x".format(it) }
                prefs.device = device
            } finally {
                token.fill(0)
            }
        }

        if (prefs.direct) NotifyJob.schedule(context) else NotifyJob.cancel(context)
    }

    /** Приложение открыто: уведомление больше не нужно. */
    fun onAppOpened(context: Context) {
        Notifier.cancel(context)
        NotifyPrefs(context).notified = false
    }

    /** Стирание аккаунта: ни расписания, ни токена, ни уведомления. */
    fun forget(context: Context) {
        NotifyJob.cancel(context)
        Notifier.cancel(context)
        NotifyPrefs(context).clear()
    }
}
