// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.net

import android.content.Context
import android.net.Uri
import java.io.File
import kotlinx.coroutines.delay
import org.aegis.app.BuildConfig
import uniffi.aegis.FfiTorSettings
import uniffi.aegis.FfiTorStatus
import uniffi.aegis.embeddedTorStatus
import uniffi.aegis.startEmbeddedTor
import uniffi.aegis.stopEmbeddedTor

/**
 * Встроенный Tor (Arti в ядре, `aegis-tor`) — вместо Orbot.
 *
 * Ядро поднимает SOCKS5-мост на 127.0.0.1 со случайным портом;
 * [NetworkProxy] направляет туда всю сеть приложения — так же, как
 * прежде на Orbot. TLS и пиннинг остаются платформенными и идут
 * сквозь Tor до самого сервера.
 *
 * 🔐 Мост пускает только к серверу AEGIS: локальный адрес на Android
 * общий для всех приложений, и без этого ограничения любое из них
 * пользовалось бы нашим Tor.
 *
 * # Мосты
 *
 * Там, где Tor блокируют, он подключается через мосты WebTunnel
 * (клиент — в ядре, без сторонних программ). Смена мостов перезапускает
 * Tor, и порт может смениться — поэтому порт всегда берётся отсюда,
 * а не запоминается.
 *
 * # Прогрев
 *
 * Подключение к сети Tor занимает секунды. Чтобы они не ложились
 * на первый запрос, Tor запускается заранее: на экране регистрации
 * и при старте приложения, если в прошлый раз выбран Tor без мостов
 * ([rememberPrewarm]). С мостами заранее не запускается: до открытия
 * базы их не прочитать, а прямая попытка там, где Tor блокируют,
 * лишь выдала бы её провайдеру.
 */
object EmbeddedTor {

    /** Порт моста; 0 — не запущен. */
    @Volatile
    private var port: Int = 0

    /**
     * Мосты, введённые до появления базы (на экране регистрации).
     *
     * [org.aegis.app.core.Core.open] сохраняет их в новую базу **до**
     * применения режима сети. Иначе Tor на миг перезапустился бы без
     * мостов — прямой попыткой, которая там, где Tor блокируют, выдаёт
     * его провайдеру.
     */
    @Volatile
    private var pendingBridges: String? = null

    /** Запоминает мосты, введённые до появления базы. */
    fun setPendingBridges(text: String?) {
        pendingBridges = text?.takeIf { it.isNotBlank() }
    }

    /** Забирает мосты, введённые до появления базы. */
    fun takePendingBridges(): String? = pendingBridges.also { pendingBridges = null }

    /** Строки отложенных мостов — для запуска Tor до появления базы. */
    fun pendingBridgeLines(): List<String> =
        pendingBridges?.lines()?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()

    /**
     * Запускает Tor с этими мостами (или перезапускает с другими)
     * и возвращает порт моста.
     *
     * Возвращается сразу: подключение к сети Tor идёт в фоне, а
     * соединение, пришедшее раньше, ждёт его. 0 — запустить не удалось;
     * тогда [NetworkProxy] закрывает сеть, а не идёт напрямую.
     */
    @Synchronized
    fun ensureStarted(context: Context, bridges: List<String>): Int {
        val server = Uri.parse(BuildConfig.AEGIS_SERVER_URL)
        val host = server.host ?: return 0
        val serverPort = if (server.port > 0) server.port else DEFAULT_HTTPS_PORT

        val noBackup = context.applicationContext.noBackupFilesDir
        val tor = File(noBackup, "tor")

        port = runCatching {
            startEmbeddedTor(
                FfiTorSettings(
                    // 🔐 Всё — в no_backup: охранные узлы постоянны для
                    // устройства, и по ним устройство узнаётся, так что
                    // в резервную копию Android им нельзя.
                    stateDir = File(tor, "state").path,
                    cacheDir = File(tor, "cache").path,
                    // Arti проверяет права на каталоги. Системные каталоги
                    // приложения (no_backup, cache) открыты на запись группе
                    // приложения, и проверку не прошли бы, хотя чужим
                    // приложениям они недоступны (UID и SELinux). Поэтому
                    // no_backup и его предки не проверяются, а каталоги
                    // Tor внутри него Arti создаёт сам и проверяет целиком.
                    trustedPrefix = noBackup.path,
                    serverHost = host,
                    serverPort = serverPort.toUShort(),
                    bridges = bridges,
                ),
            ).toInt()
        }.getOrDefault(0)

        return port
    }

    /** Останавливает Tor: выбран другой способ выхода в сеть. */
    @Synchronized
    fun stop() {
        runCatching { stopEmbeddedTor() }
        port = 0
    }

    /** Порт запущенного моста; 0 — не запущен. */
    fun port(): Int = port

    /** Состояние подключения — для индикатора. */
    fun status(): FfiTorStatus = runCatching { embeddedTorStatus() }.getOrElse { STOPPED }

    /**
     * Ждёт готовности Tor, сообщая ход в [onProgress].
     *
     * @return готов ли Tor к концу ожидания.
     */
    suspend fun awaitReady(timeoutMs: Long, onProgress: suspend (FfiTorStatus) -> Unit): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs

        while (true) {
            val status = status()
            if (status.ready) return true
            if (!status.running || System.currentTimeMillis() >= deadline) return false

            onProgress(status)
            delay(POLL_MS)
        }
    }

    /**
     * Запоминает, запускать ли Tor при следующем старте приложения
     * до ввода PIN: только если выбран Tor без мостов.
     *
     * Хранится вне зашифрованной базы — её до PIN не открыть. Выдаёт
     * это лишь одно: что приложение ходит через Tor; каталог состояния
     * Tor на том же устройстве выдаёт то же самое.
     */
    fun rememberPrewarm(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_PREWARM, enabled).apply()
    }

    /** Прогрев при старте приложения, если в прошлый раз выбран Tor. */
    fun prewarmIfChosen(context: Context) {
        if (prefs(context).getBoolean(KEY_PREWARM, false)) {
            ensureStarted(context, emptyList())
        }
    }

    /**
     * Долго ли уже подключается — повод предложить мост.
     *
     * Застрявший бутстрап ([FfiTorStatus.stalled]) — сразу; иначе —
     * после [SLOW_MS] без готовности.
     */
    fun looksBlocked(status: FfiTorStatus, connectingSinceMs: Long): Boolean =
        status.running && !status.ready &&
            (status.stalled || System.currentTimeMillis() - connectingSinceMs > SLOW_MS)

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val STOPPED = FfiTorStatus(
        running = false,
        ready = false,
        percent = 0u,
        stalled = false,
        port = 0u,
        bridges = false,
    )

    private const val DEFAULT_HTTPS_PORT = 443

    private const val POLL_MS = 500L

    /** Сколько подключения без готовности считать признаком блокировки. */
    private const val SLOW_MS = 45_000L

    private const val PREFS = "aegis_network"

    private const val KEY_PREWARM = "tor_prewarm"
}
