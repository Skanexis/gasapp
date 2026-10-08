// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.gasapp.computeFingerprint
import uniffi.gasapp.coreVersion
import uniffi.gasapp.formatSafetyNumber
import uniffi.gasapp.generateIdentityPublicKey
import uniffi.gasapp.protocolVersion

/**
 * Ядро на Rust загружается и считает на настоящем устройстве.
 *
 * Модульные тесты приложения нативной библиотеки не видят вовсе: .so
 * для Android настольная JVM не загрузит. Здесь — `libgasapp.so` из APK,
 * JNA и UniFFI на настоящем ART.
 *
 * ⚠️ Прежде это проверялось через демонстрационный экран M1
 * (`MainActivity`). С тех пор экран без открытого хранилища закрывается
 * сторожем блокировки, и тест не проходил ни разу — а раз проверки
 * на устройстве никто не запускал, этого никто и не видел.
 */
@RunWith(AndroidJUnit4::class)
class NativeCoreOnDeviceTest {

    @Test
    fun the_core_loads_and_reports_its_versions() {
        assertTrue("версия ядра пуста", coreVersion().isNotBlank())
        assertTrue("версия протокола нулевая", protocolVersion() > 0u)
    }

    /**
     * 🔐 Safety number считает ядро: 60 цифр (ADR-022), и одна и та же
     * пара ключей даёт одни и те же цифры.
     */
    @Test
    fun a_safety_number_is_computed_by_the_core() {
        val local = generateIdentityPublicKey()
        val remote = generateIdentityPublicKey()

        assertEquals("публичный ключ не 32 байта", 32, local.size)

        val localPrint = computeFingerprint(local, "local".toByteArray())
        val remotePrint = computeFingerprint(remote, "remote".toByteArray())

        assertArrayEquals(
            "отпечаток одного ключа разный от вызова к вызову",
            localPrint,
            computeFingerprint(local, "local".toByteArray()),
        )

        val digits = formatSafetyNumber(localPrint, remotePrint).filter(Char::isDigit)

        assertEquals("safety number не из 60 цифр", 60, digits.length)
    }
}
