// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.net

import android.os.Handler
import android.os.Looper
import org.gasapp.app.BuildConfig
import org.gasapp.app.core.Core

/**
 * Один сокет уведомлений на все экраны.
 *
 * # Зачем
 *
 * Прежде каждый экран открывал свой [NotificationSocket] в `onStart`
 * и закрывал в `onStop`. Переход из списка в чат и обратно означал
 * два новых соединения: TLS-рукопожатие, подпись, а через Tor — ещё
 * и новую цепочку. Это секунды без уведомлений на каждом переходе
 * и самая дорогая для батареи работа радио — на пустом месте.
 *
 * Здесь сокет живёт, пока виден хотя бы один экран-подписчик, и
 * переживает переход между экранами.
 *
 * # 🔐 Присутствие
 *
 * Правило прежнее: открытый сокет — признак присутствия, и в фоне он
 * закрыт. Между уходом последнего экрана и закрытием — [LINGER_MS]:
 * ровно столько, чтобы следующий экран успел подписаться. Свёрнутое
 * приложение теряет сокет через полторы секунды, а не мгновенно, —
 * наблюдателю канала это ничего не добавляет.
 *
 * Все методы вызываются из главного потока.
 */
object NotificationHub {

    /** Сколько сокет ждёт следующего экрана после ухода последнего. */
    private const val LINGER_MS = 1_500L

    private val main = Handler(Looper.getMainLooper())
    private val listeners = LinkedHashSet<() -> Unit>()

    private var socket: NotificationSocket? = null
    private var socketDevice: String? = null

    private val closeTask = Runnable { closeNow() }

    /** Когда начался последний удавшийся приём очереди (`elapsedRealtime`). */
    private var fetchedAt = 0L

    /** Когда уведомление пришло, а слушать было некому; `0` — не было. */
    private var missedAt = 0L

    /**
     * Можно ли не забирать очередь при показе экрана.
     *
     * Каждый экран при показе спрашивал сервер: открыл чат, вернулся,
     * открыл другой — три подписанных запроса за несколько секунд, и
     * все три почти всегда пустые. Если сокет слушает дольше, чем
     * прошло с последнего приёма, и ни одно уведомление не потеряно,
     * нового на сервере нет: о нём сказал бы сокет.
     *
     * Только в пределах [FRESH_MS]: соединение через Tor умирает и
     * молча, а запрос при показе экрана — страховка от этого.
     */
    fun caughtUp(): Boolean {
        val since = socket?.connectedSince ?: 0L
        val now = android.os.SystemClock.elapsedRealtime()

        // Приём должен начаться после подключения сокета и после
        // последнего потерянного уведомления: только тогда он их покрыл.
        return since != 0L && fetchedAt >= since && fetchedAt > missedAt && now - fetchedAt < FRESH_MS
    }

    /** Очередь забрана; [startedAt] — когда запрос начался (`elapsedRealtime`). */
    fun fetched(startedAt: Long) {
        fetchedAt = startedAt
    }

    /** Сколько последнему приёму верят без нового запроса. */
    private const val FRESH_MS = 30_000L

    /**
     * Подписывает экран на уведомления о новых конвертах.
     *
     * [listener] вызывается в главном потоке. Тот же объект передаётся
     * в [unsubscribe].
     */
    fun subscribe(listener: () -> Unit) {
        main.removeCallbacks(closeTask)
        listeners.add(listener)

        val device = Core.deviceId ?: return

        // Устройство сменилось (другой аккаунт после стирания) —
        // прежний сокет адресован не ему.
        if (socket != null && socketDevice != device) closeNow()

        if (socket == null) {
            socketDevice = device
            socket = NotificationSocket(
                baseUrl = BuildConfig.GASAPP_SERVER_URL,
                deviceId = device,
                onEnvelope = { main.post(::dispatch) },
            ).also { it.connect() }
        }
    }

    /** Отписывает экран; без подписчиков сокет закрывается после паузы. */
    fun unsubscribe(listener: () -> Unit) {
        listeners.remove(listener)

        if (listeners.isEmpty()) {
            main.removeCallbacks(closeTask)
            main.postDelayed(closeTask, LINGER_MS)
        }
    }

    private fun dispatch() {
        if (listeners.isEmpty()) missedAt = android.os.SystemClock.elapsedRealtime()

        // Копия: подписчик вправе отписаться из своего же вызова.
        for (listener in listeners.toList()) listener()
    }

    private fun closeNow() {
        socket?.close()
        socket = null
        socketDevice = null
    }
}
