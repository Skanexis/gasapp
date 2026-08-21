// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.net

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import uniffi.aegis.FfiException
import uniffi.aegis.FfiHeader
import uniffi.aegis.FfiHttpResponse
import uniffi.aegis.HttpTransport

/**
 * HTTP-транспорт для ядра.
 *
 * 🔐 Сеть намеренно ведёт **платформа**, а не Rust.
 *
 * Ядро умеет собрать запрос и разобрать ответ, но собственного
 * TLS-стека у него нет и не будет: он обошёл бы настройки Android —
 * то есть пиннинг из `network_security_config.xml`, системные отзывы
 * сертификатов и корпоративные политики. Пиннинг, который можно
 * обойти изнутри приложения, не защищает ни от чего.
 *
 * Используется `HttpURLConnection`, а не сторонний клиент: он входит
 * в платформу и подчиняется её конфигурации безопасности без
 * дополнительной настройки, которую легко забыть.
 */
class PlatformTransport(private val baseUrl: String) : HttpTransport {

    override fun execute(
        method: String,
        path: String,
        body: String?,
        headers: List<FfiHeader>,
    ): FfiHttpResponse {
        val connection = openConnection(method, path)

        try {
            // 🔐 Заголовки подписи ставит ядро: приватный ключ живёт
            // там и в UI не попадает. Транспорт их только переносит.
            for (header in headers) {
                connection.setRequestProperty(header.name, header.value)
            }

            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toByteArray()) }
            }

            val status = connection.responseCode

            // Тело читается и при ошибке: сервер объясняет отказ
            // в теле ответа, и потерять его значит потерять причину.
            val stream = if (status in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }

            val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()

            return FfiHttpResponse(status = status.toUShort(), body = text)
        } catch (error: IOException) {
            // Сбой сети — это исключение; отказ сервера (4xx/5xx) им
            // не является и возвращается выше как обычный ответ.
            // Ядро реагирует на эти случаи по-разному: первый повторяет
            // через очередь, второй показывает пользователю.
            throw FfiException.Core("network unavailable: ${error.javaClass.simpleName}")
        } finally {
            connection.disconnect()
        }
    }

    private fun openConnection(method: String, path: String): HttpURLConnection {
        val url = URL("$baseUrl$path")
        val connection = url.openConnection() as HttpURLConnection

        connection.requestMethod = method
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS

        // 🔐 Редиректы выключены намеренно.
        //
        // Следование за редиректом позволило бы серверу — или тому,
        // кто его подменил, — увести запрос на другой хост, где
        // пиннинг уже не применяется.
        connection.instanceFollowRedirects = false

        return connection
    }

    private companion object {
        /** Ожидание установления соединения. */
        const val CONNECT_TIMEOUT_MS = 15_000

        /**
         * Ожидание ответа.
         *
         * Заметно больше времени соединения: регистрация включает
         * серверную проверку proof-of-work, и слишком короткий таймаут
         * обрывал бы её на медленной сети.
         */
        const val READ_TIMEOUT_MS = 30_000
    }
}
