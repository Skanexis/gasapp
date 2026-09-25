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
 */
object EmbeddedTor {

    /** Порт моста; 0 — не запущен. */
    @Volatile
    private var port: Int = 0

    /**
     * Запускает Tor, если он ещё не запущен, и возвращает порт моста.
     *
     * Возвращается сразу: подключение к сети Tor идёт в фоне, а
     * соединение, пришедшее раньше, ждёт его. 0 — запустить не удалось;
     * тогда [NetworkProxy] закрывает сеть, а не идёт напрямую.
     */
    @Synchronized
    fun ensureStarted(context: Context): Int {
        if (port != 0) return port

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
                ),
            ).toInt()
        }.getOrDefault(0)

        return port
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

    private val STOPPED = FfiTorStatus(running = false, ready = false, percent = 0u, stalled = false, port = 0u)

    private const val DEFAULT_HTTPS_PORT = 443

    private const val POLL_MS = 500L
}
