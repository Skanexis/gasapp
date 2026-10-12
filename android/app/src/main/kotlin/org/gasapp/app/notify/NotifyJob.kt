// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.notify

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import org.gasapp.app.BuildConfig
import org.gasapp.app.core.AutoLock
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL

/**
 * Фоновая проверка «есть ли новое» (ADR-040).
 *
 * Системный планировщик будит её примерно раз в четверть часа, когда
 * есть сеть, — не чаще: так решает система, и так экономится батарея.
 * Проверка не открывает базу и не знает PIN: она предъявляет серверу
 * токен уведомлений и получает «да» или «нет».
 *
 * 🔐 Только при прямом соединении ([NotifyPrefs.direct]). С Tor или
 * прокси она не выходит в сеть вовсе: прямой запрос выдал бы адрес тому,
 * кто выбрал его скрыть. Тогда уведомления приходят, только пока
 * приложение открыто, — и экран настроек говорит об этом.
 *
 * Платформенный `JobScheduler`, а не библиотека: сборка `foss` обходится
 * без Google, а лишняя зависимость ради одного таймера не нужна.
 */
class NotifyJob : JobService() {

    @Volatile
    private var worker: Thread? = null

    override fun onStartJob(params: JobParameters): Boolean {
        val prefs = NotifyPrefs(this)
        val token = prefs.token
        val device = prefs.device

        // На экране — нечего уведомлять: приложение и так покажет новое.
        if (!prefs.enabled || !prefs.direct || token == null || device == null || AutoLock.inForeground) {
            return false
        }

        worker = Thread({
            val pending = runCatching { check(device, token) }.getOrNull()

            when (pending) {
                true -> if (!prefs.notified) {
                    Notifier.showNewMessages(this)
                    prefs.notified = true
                }
                // Очередь пуста — следующее сообщение снова стоит уведомления.
                false -> prefs.notified = false
                // Сервер не знает токена: при следующем входе он заведётся заново.
                null -> {}
            }

            jobFinished(params, false)
        }, "gasapp-notify").apply { start() }

        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        worker?.interrupt()
        worker = null

        return true
    }

    /**
     * Спрашивает сервер. `null` — не вышло (сеть) либо токен забыт.
     *
     * 🔐 Тот же `HttpURLConnection`, что у основного транспорта: на него
     * действует пиннинг сертификата из сетевой политики приложения.
     * Прокси — явно нет: проверка идёт только при прямом соединении.
     */
    private fun check(device: String, token: String): Boolean? {
        val url = URL(BuildConfig.GASAPP_SERVER_URL.trimEnd('/') + "/v1/notify/check")
        val connection = url.openConnection(Proxy.NO_PROXY) as HttpURLConnection

        try {
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")

            val body = JSONObject().put("device_id", device).put("token", token).toString().toByteArray()
            connection.setFixedLengthStreamingMode(body.size)
            connection.outputStream.use { it.write(body) }

            return when (connection.responseCode) {
                HttpURLConnection.HTTP_OK -> {
                    // С пределом: ответ от сервера — не повод читать гигабайт.
                    val text = connection.inputStream.use { stream ->
                        val buffer = ByteArray(MAX_RESPONSE)
                        var read = 0
                        while (read < buffer.size) {
                            val got = stream.read(buffer, read, buffer.size - read)
                            if (got < 0) break
                            read += got
                        }
                        String(buffer, 0, read, Charsets.UTF_8)
                    }
                    JSONObject(text).optBoolean("pending", false)
                }
                HttpURLConnection.HTTP_UNAUTHORIZED -> {
                    NotifyPrefs(this).token = null
                    null
                }
                else -> null
            }
        } catch (_: IOException) {
            return null
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val JOB_ID = 4_042
        private const val PERIOD_MS = 15 * 60 * 1000L
        private const val TIMEOUT_MS = 15_000
        private const val MAX_RESPONSE = 256

        /** Ставит проверку по расписанию (повторная постановка ничего не меняет). */
        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            if (scheduler.getPendingJob(JOB_ID) != null) return

            scheduler.schedule(
                JobInfo.Builder(JOB_ID, ComponentName(context, NotifyJob::class.java))
                    .setPeriodic(PERIOD_MS)
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPersisted(true)
                    .build(),
            )
        }

        /** Снимает проверку с расписания. */
        fun cancel(context: Context) {
            context.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
        }
    }
}
