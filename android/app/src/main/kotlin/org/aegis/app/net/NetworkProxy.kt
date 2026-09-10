// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.net

import android.os.Build
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import uniffi.aegis.FfiProxy

/**
 * Прокси, через который идёт вся сеть приложения (ADR-024).
 *
 * # Почему одно место на всё
 *
 * 🔐 Прокси обязан действовать и на HTTP, и на сокет уведомлений.
 * Сокет, идущий напрямую при включённом Tor, выдаёт адрес так же, как
 * и запрос, — только незаметнее. Поэтому оба канала берут прокси
 * отсюда, а не держат каждый свою копию настройки.
 *
 * # Три обязательства из `aegis-net::proxy`
 *
 * 1. **Отказ закрытым.** Прокси передаётся соединению явно, поэтому
 *    при недоступном прокси соединение падает, а не уходит напрямую.
 *    Повреждённая настройка переводит сеть в состояние «закрыто».
 * 2. **DNS через прокси.** Адрес назначения передаётся неразрешённым
 *    (`createUnresolved`): имя сервера уходит прокси, а не в DNS
 *    провайдера.
 * 3. **Все каналы.** См. выше.
 *
 * # ⚠️ Android старше 7.0
 *
 * До Android 7.0 реализация SOCKS в платформе не основана на OpenJDK,
 * и передачу имени хоста прокси (а значит, DNS через прокси) там
 * гарантировать нельзя. Режимы с прокси на таких устройствах закрывают
 * сеть: лучше не подключиться, чем подключиться с утечкой адреса через
 * DNS. Проверено по устройству платформы, а не на устройстве, — это
 * отмечено в плане как открытый пункт.
 */
object NetworkProxy {

    private sealed class State {
        object Direct : State()
        data class Through(val proxy: Proxy) : State()
        object Blocked : State()
    }

    @Volatile
    private var state: State = State.Direct

    /** Умеет ли платформа передавать прокси имя хоста (Android 7.0+). */
    val proxySupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N

    /** Идёт ли сеть через прокси: сокет по этому признаку чаще переподключается. */
    val isProxied: Boolean
        get() = state is State.Through

    /**
     * Применяет режим, прочитанный из ядра.
     *
     * `null` — режим прочитать не удалось. 🔐 Тогда сеть закрывается:
     * повреждённая запись «Tor» не должна превращаться в «напрямую».
     */
    fun apply(mode: FfiProxy?) {
        state = when (mode) {
            null -> State.Blocked
            is FfiProxy.Direct -> State.Direct
            is FfiProxy.Orbot -> through(ORBOT_HOST, ORBOT_PORT)
            is FfiProxy.Socks5 -> through(mode.host, mode.port.toInt())
        }
    }

    /**
     * Прокси для очередного соединения.
     *
     * @throws IOException сеть закрыта: настройка повреждена либо прокси
     *   не поддерживается платформой.
     */
    @Throws(IOException::class)
    fun current(): Proxy = when (val snapshot = state) {
        is State.Direct -> Proxy.NO_PROXY
        is State.Through -> snapshot.proxy
        is State.Blocked -> throw IOException("network closed: proxy unavailable")
    }

    /**
     * Открывает сокет до `host:port` с учётом прокси.
     *
     * 🔐 При прокси адрес назначения неразрешённый: имя сервера уходит
     * прокси, и DNS на устройстве не выполняется.
     */
    @Throws(IOException::class)
    fun connect(host: String, port: Int, timeoutMs: Int): Socket {
        val proxy = current()

        return if (proxy == Proxy.NO_PROXY) {
            Socket().apply { connect(InetSocketAddress(host, port), timeoutMs) }
        } else {
            Socket(proxy).apply { connect(InetSocketAddress.createUnresolved(host, port), timeoutMs) }
        }
    }

    private fun through(host: String, port: Int): State =
        if (proxySupported) {
            State.Through(Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port)))
        } else {
            State.Blocked
        }

    /** Адрес Orbot: совпадает с `aegis-net::proxy::ORBOT_HOST`. */
    private const val ORBOT_HOST = "127.0.0.1"

    /** SOCKS-порт Orbot: совпадает с `aegis-net::proxy::ORBOT_SOCKS_PORT`. */
    private const val ORBOT_PORT = 9050
}
