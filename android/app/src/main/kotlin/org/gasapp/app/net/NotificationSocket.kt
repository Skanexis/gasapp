// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.net

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.net.URI
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import org.gasapp.app.core.Core

/**
 * Потолок задержки переподключения через прокси: 15 секунд.
 *
 * Через Tor цепочки рвутся чаще, и минута ожидания после каждого
 * обрыва означала бы минуту без уведомлений (ADR-024).
 */
private const val PROXIED_MAX_RETRY_MS = 15_000L

/**
 * Ожидание установления соединения сокета.
 *
 * С запасом на построение цепочки Tor.
 */
private const val SOCKET_CONNECT_TIMEOUT_MS = 30_000

/**
 * Сокет уведомлений о новых конвертах.
 *
 * 🔐 Соединение открывает **платформа** через `SSLSocketFactory`,
 * а не Rust и не сторонняя библиотека. Причина та же, что у HTTP:
 * собственный TLS-стек обошёл бы настройки Android — то есть пиннинг
 * из `network_security_config.xml`, системные отзывы сертификатов
 * и корпоративные политики.
 *
 * # Почему рукописный WebSocket
 *
 * В Android нет `java.net.http.WebSocket` (он появился в Java 11,
 * которого на платформе нет), а OkHttp тянет за собой собственный
 * сетевой слой и настраивается отдельно — про эту настройку легко
 * забыть, и тогда пиннинг перестанет применяться молча.
 *
 * Здесь реализована та часть RFC 6455, которая нужна: рукопожатие,
 * чтение текстовых кадров и ответ на ping. Отправлять клиенту нечего,
 * поэтому исходящих кадров, кроме close и pong, нет.
 *
 * # Что приходит по сокету
 *
 * Одно слово: `envelope`. Ни конверта, ни отправителя, ни количества.
 * Сам конверт клиент забирает обычным запросом — так момент доставки
 * не связывается с присутствием получателя.
 *
 * # 🔐 Рукопожатие подписывается
 *
 * Апгрейд начинается обычным `GET`, и в него ставятся те же заголовки
 * подписи, что и в остальные запросы: `x-gasapp-signature`
 * и `x-gasapp-issued-at`. Подпись строит ядро
 * ([uniffi.gasapp.Messenger.socketAuthHeaders]) — приватный ключ наружу
 * не выходит, а подпись привязана к пути и времени и для другого
 * запроса не годится.
 *
 * Прежде рукопожатие было анонимным, и сервер его принимал. Это
 * означало, что поток уведомлений любого устройства открыт кому
 * угодно: «одно слово `envelope`» само по себе безобидно, но **время**
 * его прихода — это и есть метаданные, которые раздел 15 велит
 * не отдавать. Находка внутреннего пентеста, раздел 23.6.
 */
class NotificationSocket(
    private val baseUrl: String,
    private val deviceId: String,
    private val onEnvelope: () -> Unit,
) {

    @Volatile
    private var closedByUs = false

    private var socket: Socket? = null
    private var worker: Thread? = null

    /** Открывает соединение в фоновом потоке. */
    fun connect() {
        closedByUs = false

        worker = Thread {
            var delay = MIN_RETRY_MS

            while (!closedByUs) {
                val clean = runCatching { runSession() }.isSuccess

                if (closedByUs) {
                    break
                }

                // Задержка растёт от секунды до минуты. Попытки раз
                // в секунду разряжали бы батарею и создавали узнаваемый
                // рисунок трафика; отказ после первой неудачи оставил бы
                // пользователя без уведомлений до перезапуска.
                //
                // Через прокси потолок ниже: цепочки Tor рвутся чаще.
                val ceiling = if (NetworkProxy.isProxied) PROXIED_MAX_RETRY_MS else MAX_RETRY_MS
                delay = if (clean) MIN_RETRY_MS else (delay * 2).coerceAtMost(ceiling)

                runCatching { Thread.sleep(delay) }
            }
        }.apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Закрывает соединение.
     *
     * 🔐 Вызывается при уходе приложения в фон: открытый сокет —
     * непрерывный признак присутствия, видимый наблюдателю канала,
     * даже когда по нему ничего не идёт.
     */
    fun close() {
        closedByUs = true
        runCatching { socket?.close() }
        socket = null
        worker?.interrupt()
        worker = null
    }

    /** Ведёт одну сессию до разрыва. */
    private fun runSession() {
        val uri = URI.create(baseUrl)
        val secure = uri.scheme == "https"

        // 🔐 Запрет открытого текста из network_security_config на голые
        // сокеты не распространяется: он действует на HTTP-стек платформы.
        // Адрес без https в релизе — ошибка сборки, и сокет не должен
        // молча пойти открытым текстом, пока запросы отказывают.
        if (!secure && !org.gasapp.app.BuildConfig.DEBUG) {
            throw IOException("сокет уведомлений только по TLS")
        }
        val port = if (uri.port > 0) uri.port else if (secure) DEFAULT_TLS_PORT else DEFAULT_PORT

        // 🔐 Сокет открывается через тот же прокси, что и HTTP: сокет,
        // идущий напрямую при включённом Tor, выдал бы адрес так же,
        // как и запрос. При закрытой сети соединение не открывается.
        val raw = NetworkProxy.connect(uri.host, port, SOCKET_CONNECT_TIMEOUT_MS)

        val connection = if (secure) {
            // Фабрика платформы: она применяет network_security_config,
            // включая пиннинг. Свой SSLContext здесь означал бы отказ
            // от этих проверок. TLS накладывается поверх уже открытого,
            // возможно проксированного, сокета — до сервера, а не до прокси.
            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(raw, uri.host, port, true) as SSLSocket

            tls.startHandshake()

            // 🔐 Сверка имени хоста с сертификатом.
            //
            // `HttpsURLConnection` сверяет имя сам, а голый `SSLSocket` —
            // нет: прежде сокет уведомлений принимал любой сертификат,
            // прошедший цепочку доверия, с чужим именем. Сверка через
            // HostnameVerifier, а не через SSLParameters, потому что
            // последний путь есть только с Android 7.0, а приложение
            // поддерживает 5.0.
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(uri.host, tls.session)) {
                tls.close()
                throw IOException("имя сервера не совпало с сертификатом")
            }

            tls
        } else {
            raw
        }

        socket = connection
        connection.soTimeout = READ_TIMEOUT_MS

        val output = connection.getOutputStream()
        val input = connection.getInputStream()

        handshake(output, input, uri.host, port)
        readFrames(input, output)
    }

    /**
     * Выполняет рукопожатие WebSocket.
     *
     * 🔐 Подпись строится **на каждую сессию заново**, а не один раз
     * при создании объекта: она привязана ко времени выпуска, и сервер
     * отвергает просроченную. Переподключение через час после разрыва
     * предъявило бы подпись часовой давности.
     */
    private fun handshake(
        output: OutputStream,
        input: InputStream,
        host: String,
        port: Int,
    ) {
        val key = ByteArray(WS_KEY_BYTES).also { SecureRandom().nextBytes(it) }
        val encodedKey = Base64.getEncoder().encodeToString(key)

        val path = "/v1/ws/$deviceId"

        // Путь в подписи обязан совпадать со строкой запроса байт в байт:
        // сервер подписывает то, что видит в `parts.uri.path()`.
        val auth = Core.messenger().socketAuthHeaders(deviceId, System.currentTimeMillis())

        val request = buildString {
            append("GET $path HTTP/1.1\r\n")
            append("Host: $host:$port\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: $encodedKey\r\n")
            append("Sec-WebSocket-Version: 13\r\n")

            auth.forEach { header ->
                append("${header.name}: ${header.value}\r\n")
            }

            append("\r\n")
        }

        output.write(request.toByteArray())
        output.flush()

        val response = readHeaders(input)
        if (!response.contains("101")) {
            // 401 отличается от прочих отказов тем, что повтор его не
            // исправит: подпись не подошла, и следующая попытка
            // построит такую же. Сообщение это различает, иначе в логе
            // виден лишь бесконечный цикл переподключений.
            if (response.contains("401")) {
                throw IOException("сервер отверг подпись рукопожатия сокета")
            }

            throw IOException("сервер отказал в апгрейде до WebSocket")
        }
    }

    /** Читает заголовки ответа до пустой строки. */
    private fun readHeaders(input: InputStream): String {
        val builder = StringBuilder()

        while (!builder.endsWith("\r\n\r\n")) {
            val byte = input.read()
            if (byte < 0) {
                throw IOException("соединение закрыто во время рукопожатия")
            }

            builder.append(byte.toChar())

            if (builder.length > MAX_HEADER_BYTES) {
                throw IOException("заголовки ответа слишком длинные")
            }
        }

        return builder.toString()
    }

    /** Читает кадры до закрытия соединения. */
    private fun readFrames(input: InputStream, output: OutputStream) {
        while (!closedByUs) {
            val first = input.read()
            if (first < 0) {
                return
            }

            val opcode = first and OPCODE_MASK
            val length = readLength(input)

            // Кадр от сервера не маскируется (RFC 6455), поэтому тело
            // читается как есть.
            val payload = ByteArray(length)
            var read = 0
            while (read < length) {
                val chunk = input.read(payload, read, length - read)
                if (chunk < 0) {
                    return
                }
                read += chunk
            }

            when (opcode) {
                OPCODE_TEXT -> onEnvelope()
                OPCODE_PING -> {
                    // Управляющий кадр длиннее 125 байт запрещён RFC 6455, и
                    // ответный pong с ним не уложился бы в короткую длину.
                    if (length > MAX_CONTROL_PAYLOAD) throw IOException("ping недопустимой длины")
                    sendPong(output, payload)
                }
                OPCODE_CLOSE -> return
                else -> {}
            }
        }
    }

    /** Читает длину полезной нагрузки кадра. */
    private fun readLength(input: InputStream): Int {
        val second = input.read()
        if (second < 0) {
            throw IOException("кадр оборван")
        }

        val short = second and LENGTH_MASK

        return when {
            short < EXTENDED_16 -> short
            short == EXTENDED_16 -> {
                val high = input.read()
                val low = input.read()
                if (high < 0 || low < 0) {
                    throw IOException("кадр оборван")
                }
                (high shl 8) or low
            }
            // Кадры длиннее 64 КБ по этому сокету не приходят: он
            // передаёт одно слово. Такой кадр означает чужой протокол.
            else -> throw IOException("кадр недопустимой длины")
        }
    }

    /** Отвечает на ping, чтобы сервер не считал соединение мёртвым. */
    private fun sendPong(output: OutputStream, payload: ByteArray) {
        val mask = ByteArray(MASK_BYTES).also { SecureRandom().nextBytes(it) }
        val frame = ByteArray(2 + MASK_BYTES + payload.size)

        frame[0] = (FIN_BIT or OPCODE_PONG).toByte()
        frame[1] = (MASK_BIT or payload.size).toByte()
        mask.copyInto(frame, 2)

        // Кадры клиента обязаны маскироваться (RFC 6455): сервер
        // отвергнет немаскированный.
        for (index in payload.indices) {
            frame[2 + MASK_BYTES + index] = (payload[index].toInt() xor mask[index % MASK_BYTES].toInt()).toByte()
        }

        output.write(frame)
        output.flush()
    }

    private companion object {
        /** Начальная задержка переподключения. */
        const val MIN_RETRY_MS = 1_000L

        /**
         * Потолок задержки.
         *
         * Минута: дольше означало бы, что пользователь после перерыва
         * ждёт уведомлений слишком долго, хотя сеть уже есть.
         */
        const val MAX_RETRY_MS = 60_000L

        /**
         * Таймаут чтения.
         *
         * Больше интервала ping сервера: срабатывание таймаута
         * при живом соединении вызывало бы переподключения на пустом
         * месте.
         */
        const val READ_TIMEOUT_MS = 90_000

        /** Длина ключа рукопожатия. */
        const val WS_KEY_BYTES = 16

        /** Предел размера заголовков ответа. */
        const val MAX_HEADER_BYTES = 8192

        /** Порт HTTPS по умолчанию. */
        const val DEFAULT_TLS_PORT = 443

        /** Порт HTTP по умолчанию. */
        const val DEFAULT_PORT = 80

        /** Маска кода операции в первом байте кадра. */
        const val OPCODE_MASK = 0x0F

        /** Маска длины во втором байте. */
        const val LENGTH_MASK = 0x7F

        /** Признак расширенной 16-битной длины. */
        const val EXTENDED_16 = 126

        /** Текстовый кадр. */
        const val OPCODE_TEXT = 0x1

        /** Закрытие. */
        const val OPCODE_CLOSE = 0x8

        /** Ping. */
        const val OPCODE_PING = 0x9

        /** Pong. */
        const val OPCODE_PONG = 0xA

        /** Бит FIN. */
        const val FIN_BIT = 0x80

        /** Бит маскирования. */
        const val MASK_BIT = 0x80

        /** Длина маски. */
        const val MASK_BYTES = 4

        /** Предел полезной нагрузки управляющего кадра (RFC 6455, 5.5). */
        const val MAX_CONTROL_PAYLOAD = 125
    }
}
