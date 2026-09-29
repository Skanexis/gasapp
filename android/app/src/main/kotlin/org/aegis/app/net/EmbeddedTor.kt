// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.net

import android.content.Context
import android.net.Uri
import java.io.File
import java.net.Authenticator
import java.net.PasswordAuthentication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.aegis.app.BuildConfig
import uniffi.aegis.FfiTorSettings
import uniffi.aegis.FfiTorStatus
import uniffi.aegis.embeddedTorStatus
import uniffi.aegis.startEmbeddedTor
import uniffi.aegis.stopEmbeddedTor
import uniffi.aegis.validateTorBridges

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
 * **Встроенные мосты** едут в сборке (`assets/tor/bridges.txt`, см.
 * задачу `aegisBridges`). Сначала Tor подключается напрямую; если за
 * [SLOW_MS] не вышло или бутстрап застрял — сам перезапускается через
 * встроенные мосты и запоминает это ([KEY_BUILTIN]): следующий запуск
 * сразу идёт через них, без прямой попытки, которая там, где Tor
 * блокируют, выдаёт его провайдеру. Свои мосты человека дополняются
 * встроенными — чем больше мостов, тем труднее заблокировать все.
 *
 * # Onion-адрес сервера
 *
 * Если сборка знает onion-сервис сервера ([BuildConfig.AEGIS_SERVER_ONION]),
 * мост ведёт соединения к серверу туда: без выходного узла, и сервер
 * достижим даже без публичного адреса. TLS и пиннинг — прежние.
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

        val builtin = builtinBridges(context)
        val effective = when {
            // Свои мосты — вместе со встроенными: больше мостов, больше
            // шансов, что хоть часть не заблокирована.
            bridges.isNotEmpty() -> (bridges + builtin).distinct()
            usesBuiltin(context) && builtin.isNotEmpty() -> builtin
            else -> emptyList()
        }

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
                    bridges = effective,
                    serverOnion = BuildConfig.AEGIS_SERVER_ONION.ifBlank { null },
                ),
            ).toInt()
        }.getOrDefault(0)

        if (port != 0) installAuthenticator()

        // Отсчёт «долго подключается» — заново при каждой смене пути.
        if (effective != lastEffective) {
            lastEffective = effective
            startedAt = System.currentTimeMillis()
        }

        // Напрямую, а встроенные мосты есть — следить, не заблокирован ли Tor.
        if (port != 0 && effective.isEmpty() && builtin.isNotEmpty()) {
            watchForBlocking(context.applicationContext)
        }

        return port
    }

    /**
     * Встроенные мосты сборки — только годные строки.
     *
     * Каждая проверяется ядром по отдельности: одна испорченная строка
     * иначе отвергла бы весь список, и Tor не запустился бы вовсе.
     */
    fun builtinBridges(context: Context): List<String> =
        builtinCache ?: runCatching {
            context.applicationContext.assets.open(BUILTIN_BRIDGES_ASSET)
                .bufferedReader(Charsets.UTF_8)
                .use { it.readLines() }
        }
            .getOrDefault(emptyList())
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .filter { line -> runCatching { validateTorBridges(line) }.getOrDefault(false) }
            .also { builtinCache = it }

    @Volatile
    private var builtinCache: List<String>? = null

    /** Мосты последнего запуска и его время — для отсчёта блокировки. */
    @Volatile
    private var lastEffective: List<String>? = null

    @Volatile
    private var startedAt: Long = 0L

    /**
     * Пора ли предложить человеку свои мосты.
     *
     * Только когда Tor не подключается, а помочь нечем: встроенных
     * мостов нет либо Tor уже идёт через них и всё равно не подключился.
     * Пока приложение само может переключиться на встроенные — не
     * предлагает: предложение раньше времени только сбивало бы.
     */
    fun needsUserBridges(context: Context): Boolean {
        val status = status()
        val blocked = status.running && !status.ready &&
            (status.stalled || System.currentTimeMillis() - startedAt > SLOW_MS)

        return blocked && (status.bridges || builtinBridges(context).isEmpty())
    }

    /** Шёл ли Tor в прошлый раз через встроенные мосты. */
    fun usesBuiltin(context: Context): Boolean = prefs(context).getBoolean(KEY_BUILTIN, false)

    /**
     * Следит за прямым подключением и при признаках блокировки
     * переключается на встроенные мосты.
     *
     * Один сторож на процесс: повторный запуск прежнего не дублирует.
     */
    private fun watchForBlocking(context: Context) {
        if (watcher?.isActive == true) return

        watcher = watchScope.launch {
            val since = System.currentTimeMillis()

            while (true) {
                delay(WATCH_MS)
                val status = status()

                // Остановлен, готов или уже с мостами — следить не за чем.
                if (!status.running || status.ready || status.bridges) return@launch

                if (looksBlocked(status, since)) {
                    prefs(context).edit().putBoolean(KEY_BUILTIN, true).apply()
                    ensureStarted(context, emptyList())

                    return@launch
                }
            }
        }
    }

    @Volatile
    private var watcher: Job? = null

    private val watchScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Ставит [BridgeAuthenticator] источником паролей процесса.
     *
     * Платформенный SOCKS (libcore, OpenJDK) спрашивает пароль SOCKS5
     * у [Authenticator]. Повторная установка того же объекта безвредна.
     */
    fun installAuthenticator() {
        Authenticator.setDefault(BridgeAuthenticator)
    }

    /**
     * 🔐 Отдаёт пароль моста — только для SOCKS на 127.0.0.1 и только
     * на портах запущенного моста. Любой другой запрос пароля (другой
     * хост, другой порт, HTTP) — `null`: пароль моста никуда больше
     * не уходит.
     */
    private object BridgeAuthenticator : Authenticator() {
        override fun getPasswordAuthentication(): PasswordAuthentication? {
            if (requestingProtocol?.startsWith("SOCKS", ignoreCase = true) != true) return null
            if (requestingHost != BRIDGE_HOST) return null

            val status = status()
            val ours = status.running &&
                (requestingPort == status.port.toInt() || requestingPort == status.isolatedPort.toInt())

            return if (ours) {
                PasswordAuthentication(status.socksUsername, status.socksPassword.toCharArray())
            } else {
                null
            }
        }
    }

    /** Останавливает Tor: выбран другой способ выхода в сеть. */
    @Synchronized
    fun stop() {
        runCatching { stopEmbeddedTor() }
        port = 0
    }

    /** Порт запущенного моста; 0 — не запущен. */
    fun port(): Int = port

    /**
     * Порт для анонимных запросов: каждое соединение — своя цепочка
     * Tor. 0 — не запущен.
     */
    fun isolatedPort(): Int = status().isolatedPort.toInt()

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

    /**
     * Прогрев при старте приложения, если в прошлый раз выбран Tor.
     *
     * Если Tor в прошлый раз понадобились встроенные мосты — сразу
     * с ними: они в сборке, а не в базе, и до PIN доступны.
     */
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
        isolatedPort = 0u,
        bridges = false,
        socksUsername = "",
        socksPassword = "",
    )

    private const val DEFAULT_HTTPS_PORT = 443

    /** Адрес моста: петля устройства (как в [NetworkProxy]). */
    private const val BRIDGE_HOST = "127.0.0.1"

    private const val POLL_MS = 500L

    /** Сколько подключения без готовности считать признаком блокировки. */
    private const val SLOW_MS = 45_000L

    private const val PREFS = "aegis_network"

    private const val KEY_PREWARM = "tor_prewarm"

    /** Tor понадобились встроенные мосты — дальше сразу через них. */
    private const val KEY_BUILTIN = "tor_builtin_bridges"

    /** Файл встроенных мостов в assets. */
    private const val BUILTIN_BRIDGES_ASSET = "tor/bridges.txt"

    /** Как часто сторож смотрит на прямое подключение. */
    private const val WATCH_MS = 2_000L
}
