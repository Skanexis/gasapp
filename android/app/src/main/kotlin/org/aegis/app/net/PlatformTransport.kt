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
 *
 * # Прокси (ADR-024)
 *
 * Прокси передаётся соединению явно из [NetworkProxy]. Явный прокси
 * не откатывается на прямое соединение: недоступный Orbot означает
 * ошибку сети, а не запрос в обход Tor. TLS идёт сквозь туннель до
 * сервера, поэтому пиннинг продолжает действовать.
 */
class PlatformTransport(private val baseUrl: String) : HttpTransport {

    override fun execute(
        method: String,
        path: String,
        body: String?,
        binaryBody: ByteArray?,
        headers: List<FfiHeader>,
    ): FfiHttpResponse {
        // Открытие соединения тоже внутри обработки ошибок: закрытая сеть
        // (повреждённая настройка прокси) — это сбой сети для ядра,
        // а не исключение, пересекающее границу FFI.
        val connection = try {
            openConnection(method, path)
        } catch (error: IOException) {
            throw FfiException.Core("network unavailable: ${error.javaClass.simpleName}")
        }

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
            } else if (binaryBody != null) {
                // Вложение уходит сырыми байтами: hex удвоил бы объём,
                // и стомегабайтный файл занял бы двести мегабайт
                // трафика и памяти.
                //
                // setFixedLengthStreamingMode обязателен: без него
                // HttpURLConnection буферизует всё тело в памяти,
                // чтобы посчитать Content-Length, и крупный файл
                // кладёт приложение по нехватке памяти.
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/octet-stream")
                connection.setFixedLengthStreamingMode(binaryBody.size)
                connection.outputStream.use { it.write(binaryBody) }
            }

            val status = connection.responseCode

            // Тело читается и при ошибке: сервер объясняет отказ
            // в теле ответа, и потерять его значит потерять причину.
            val stream = if (status in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }

            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)

            // Ответ отдаётся и текстом, и байтами: какой из них нужен,
            // знает ядро — оно и решает по запросу. Разбирать здесь
            // Content-Type значило бы дублировать это решение в месте,
            // которое о запросе ничего не знает.
            //
            // Текстом читается только то, что заведомо текстовое:
            // декодировать стомегабайтный блоб в строку значило бы
            // сделать ровно то, чего эта ветка избегает.
            val isBinary = binaryDownload(method, path) && status in 200..299

            return FfiHttpResponse(
                status = status.toUShort(),
                body = if (isBinary) "" else bytes.toString(Charsets.UTF_8),
                binaryBody = if (isBinary) bytes else ByteArray(0),
            )
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

    /**
     * Отдаёт ли этот запрос сырые байты.
     *
     * Скачивание вложения — единственный такой случай. Проверяется
     * по методу и пути, а не по Content-Type ответа: заголовок
     * приходит от сервера, и доверять ему в вопросе «читать ли это
     * как текст» значило бы позволить серверу решать, сколько памяти
     * потратит клиент.
     */
    private fun binaryDownload(method: String, path: String): Boolean =
        method.equals("GET", ignoreCase = true) && path.startsWith("/v1/attachments/")

    @Throws(IOException::class)
    private fun openConnection(method: String, path: String): HttpURLConnection {
        val url = URL("$baseUrl$path")

        // 🔐 Прокси передаётся явно: `openConnection()` без аргумента
        // спросил бы системный ProxySelector и при недоступном прокси
        // мог бы уйти напрямую. Явный прокси так не делает.
        val connection = url.openConnection(NetworkProxy.current()) as HttpURLConnection

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
        /**
         * Ожидание установления соединения.
         *
         * С запасом на Tor: построение цепочки занимает секунды,
         * и слишком короткий таймаут выдавал бы работающий Tor
         * за недоступную сеть.
         */
        const val CONNECT_TIMEOUT_MS = 30_000

        /**
         * Ожидание ответа.
         *
         * Заметно больше времени соединения: регистрация включает
         * серверную проверку proof-of-work, и слишком короткий таймаут
         * обрывал бы её на медленной сети.
         */
        const val READ_TIMEOUT_MS = 45_000
    }
}
