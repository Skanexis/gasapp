// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.net

import android.content.Context
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
        /**
         * Через прокси. [anonymous] — для анонимных запросов: у встроенного
         * Tor это отдельный порт, где каждое соединение идёт своей
         * цепочкой; у внешнего SOCKS5 — тот же прокси.
         */
        data class Through(val proxy: Proxy, val anonymous: Proxy) : State()
        object Blocked : State()
    }

    /**
     * 🔐 До чтения настройки сеть закрыта.
     *
     * Настройка живёт в зашифрованной базе, и до её открытия режима
     * не знает никто. Прежде здесь стояло «напрямую»: запрос, ушедший
     * до [apply], выдал бы серверу адрес, хотя по умолчанию выбран Tor.
     */
    @Volatile
    private var state: State = State.Blocked

    /** Выбран ли встроенный Tor. */
    @Volatile
    private var tor: Boolean = false

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
     *
     * Для Tor встроенный Tor запускается здесь же с мостами [bridges]
     * (или перезапускается, если мосты другие): режим без запущенного
     * моста — закрытая сеть. `null` в [bridges] — список мостов
     * прочитать не удалось; 🔐 тогда сеть тоже закрывается: без мостов
     * там, где они нужны, прямая попытка выдала бы Tor провайдеру.
     *
     * Другие режимы останавливают встроенный Tor: незачем держать
     * цепочки, которыми никто не пользуется.
     */
    fun apply(context: Context, mode: FfiProxy?, bridges: List<String>? = emptyList()) {
        tor = mode is FfiProxy.Tor
        state = when (mode) {
            null -> State.Blocked
            is FfiProxy.Direct -> State.Direct
            is FfiProxy.Tor -> bridges
                ?.let { EmbeddedTor.ensureStarted(context, it) }
                ?.takeIf { it != 0 }
                // 🔐 Без изолированного порта — закрыто: анонимный запрос
                // по общей цепочке связал бы себя с подписанными.
                ?.let { port -> EmbeddedTor.isolatedPort().takeIf { it != 0 }?.let { port to it } }
                ?.let { (port, isolated) -> through(LOCALHOST, port, isolated) }
                ?: State.Blocked
            is FfiProxy.Socks5 -> through(mode.host, mode.port.toInt(), mode.port.toInt())
        }

        if (mode != null && mode !is FfiProxy.Tor) {
            EmbeddedTor.stop()
        }

        // Заранее — только Tor без мостов (см. EmbeddedTor, «Прогрев»).
        EmbeddedTor.rememberPrewarm(context, mode is FfiProxy.Tor && bridges != null && bridges.isEmpty())
    }

    /** Идёт ли сеть через встроенный Tor — для индикатора подключения. */
    val viaEmbeddedTor: Boolean
        get() = tor

    /**
     * Прокси для очередного соединения.
     *
     * @param anonymous запрос без подписи устройства (sealed sender,
     *   вложения, поиск, журнал ключей). 🔐 Через встроенный Tor он идёт
     *   своей цепочкой — см. `HttpRequest::anonymous` в ядре.
     * @throws IOException сеть закрыта: настройка повреждена либо прокси
     *   не поддерживается платформой.
     */
    @Throws(IOException::class)
    fun current(anonymous: Boolean = false): Proxy = when (val snapshot = state) {
        is State.Direct -> Proxy.NO_PROXY
        is State.Through -> if (anonymous) snapshot.anonymous else snapshot.proxy
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

    private fun through(host: String, port: Int, anonymousPort: Int): State =
        if (proxySupported) {
            State.Through(
                Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port)),
                Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, anonymousPort)),
            )
        } else {
            State.Blocked
        }

    /** Адрес моста встроенного Tor: только петля устройства. */
    private const val LOCALHOST = "127.0.0.1"
}
