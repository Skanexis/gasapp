// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import org.aegis.app.net.EmbeddedTor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.aegis.FfiTorSettings
import uniffi.aegis.startEmbeddedTor
import uniffi.aegis.stopEmbeddedTor

/**
 * 🔐 Встроенный Tor на устройстве: мост на 127.0.0.1 пускает только
 * знающего пароль, а платформенный SOCKS (libcore) пароль предъявляет.
 *
 * Модульные тесты ядра проверяют пароль моста своим клиентом; здесь —
 * настоящий `java.net.Socket(Proxy)` Android, которым ходит приложение.
 * Без поддержки пароля в libcore приложение осталось бы без сети.
 *
 * Нужна сеть: назначение — example.com через настоящий Tor.
 */
@RunWith(AndroidJUnit4::class)
class EmbeddedTorOnDeviceTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun stop() {
        stopEmbeddedTor()
    }

    @Test
    fun the_bridge_admits_the_app_with_its_password_and_no_one_else() {
        // Мост приложения мог быть поднят прогревом — со своим назначением.
        stopEmbeddedTor()

        val base = File(context.noBackupFilesDir, "tor-on-device-test")
        val port = startEmbeddedTor(
            FfiTorSettings(
                stateDir = File(base, "state").path,
                cacheDir = File(base, "cache").path,
                trustedPrefix = context.noBackupFilesDir.path,
                serverHost = HOST,
                serverPort = PORT.toUShort(),
                bridges = emptyList(),
            ),
        ).toInt()
        EmbeddedTor.installAuthenticator()

        // 1. Без пароля: мост отвечает «ни один способ не подходит».
        Socket("127.0.0.1", port).use { raw ->
            raw.getOutputStream().write(byteArrayOf(5, 1, 0))
            val answer = ByteArray(2)
            raw.getInputStream().read(answer)
            assertEquals("мост пустил без пароля", 0xFF, answer[1].toInt() and 0xFF)
        }

        // 2. Платформенный SOCKS с паролем — до example.com через Tor.
        val ready = waitReady()
        assumeTrue("Tor не подключился за отведённое время — сети нет", ready)

        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved("127.0.0.1", port))
        Socket(proxy).use { socket ->
            socket.soTimeout = 120_000
            socket.connect(InetSocketAddress.createUnresolved(HOST, PORT), 120_000)
            socket.getOutputStream().write("GET / HTTP/1.0\r\nHost: $HOST\r\n\r\n".toByteArray())
            val head = ByteArray(12)
            val read = socket.getInputStream().read(head)
            assertTrue("ответ не HTTP", read > 0 && String(head, 0, read).startsWith("HTTP/1."))
        }
    }

    private fun waitReady(): Boolean {
        val deadline = System.currentTimeMillis() + 180_000
        while (System.currentTimeMillis() < deadline) {
            if (EmbeddedTor.status().ready) return true
            Thread.sleep(500)
        }
        return false
    }

    private companion object {
        const val HOST = "example.com"
        const val PORT = 80
    }
}
