// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import org.gasapp.app.core.AccountWipe
import org.gasapp.app.core.AppSignature
import org.gasapp.app.core.Core
import org.gasapp.app.core.HardwareKey
import org.gasapp.app.core.KeyAttestation
import org.gasapp.app.core.TeeKey
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 🔐 Половина ключа хранилища, живущая в Keystore, — на настоящем Keystore.
 *
 * # Зачем на устройстве
 *
 * MASVS CRYPTO-2.2 стоял 🟡 с формулировкой «половина на стороне
 * Keystore вне устройства не выполняется и тестами не покрыта».
 * Robolectric Keystore не эмулирует: всё, что здесь проверяется,
 * в модульном тесте было бы проверкой заглушки.
 *
 * # Что проверяется
 *
 *  * байты ключа-обёртки приложению не отдаются;
 *  * секрет не лежит на диске открытым текстом;
 *  * без ключа Keystore файл секрета не расшифровывается — и вместо
 *    ошибки не появляется молча новый секрет (иначе база открылась бы
 *    «чужим» ключом и выглядела бы повреждённой, а не запертой);
 *  * система называет, где лежит ключ;
 *  * аттестация на настоящем Keystore проходит путь целиком:
 *    цепочка сходится, вызов совпал, в расширении — наш пакет
 *    и подпись, совпадающая с той, что видит `PackageManager`.
 *
 * ⚠️ На эмуляторе корень аттестации не Google — это ожидаемо, и тест
 * требует лишь, чтобы проверка не **провалилась**. Что на настоящем
 * телефоне итог будет «оборудование подтверждает», здесь не доказано.
 */
@RunWith(AndroidJUnit4::class)
class HardwareKeyOnDeviceTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun openAFreshStorage() {
        assumeFalse(
            "на устройстве есть настоящая база — её PIN неизвестен, трогать её нельзя",
            File(context.filesDir, "gasapp.db").exists(),
        )

        Core.unlock(context, TEST_PIN.toByteArray())
    }

    @After
    fun wipeIt() {
        AccountWipe.wipe(context)
    }

    /**
     * Ключ, на котором держится база (схема v3, [TeeKey]), заведён
     * при входе и из Keystore не отдаётся.
     *
     * ⚠️ До 2026-11-07 здесь проверялся ключ схемы v2
     * (`gasapp.storage.kek`), которого у новых аккаунтов нет вовсе:
     * тест падал на «ключа-обёртки нет», а ключ v3 не проверялся.
     */
    @Test
    fun the_storage_key_is_not_exportable() {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = store.getEntry(TEE_ALIAS, null) as? KeyStore.SecretKeyEntry

        assertNotNull("после входа ключа хранилища в Keystore нет", entry)
        assertNull("Keystore отдал байты ключа хранилища", entry!!.secretKey.encoded)
    }

    /**
     * 🔐 Ключ v3 пропал — база не открывается, и новый ключ молча
     * не появляется (иначе верный PIN давал бы «неверный PIN»).
     */
    @Test
    fun a_lost_storage_key_is_not_silently_recreated() {
        assertTrue("после входа ключа хранилища нет", TeeKey.exists())

        // Удаляется только ключ — отметка о его создании остаётся,
        // как после сброса Keystore системой.
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(TEE_ALIAS)

        try {
            TeeKey.respond(context, ByteArray(32))
            fail("без ключа Keystore ответ на PIN всё равно получен")
        } catch (expected: TeeKey.KeyUnavailable) {
            assertTrue("утрата ключа не названа утратой", expected.lost)
        }
        assertFalse("ключ хранилища создан заново молча", TeeKey.exists())
    }

    @Test
    fun the_secret_is_not_on_disk_in_the_clear() {
        val secret = HardwareKey.secret(context)
        val onDisk = File(context.filesDir, SECRET_FILE).readBytes()

        assertFalse("секрет лежит на диске открытым текстом", contains(onDisk, secret))
    }

    /**
     * 🔐 Без ключа Keystore секрет потерян — и это видно.
     *
     * Так выглядит скопированный на другое устройство `gasapp.hw`:
     * ключа, которым он зашифрован, там нет.
     */
    @Test
    fun without_the_keystore_key_the_secret_cannot_be_recovered() {
        val before = HardwareKey.secret(context)

        HardwareKey.destroy()

        try {
            val after = HardwareKey.secret(context)
            fail(
                "без ключа Keystore секрет «расшифровался»" +
                    if (after.contentEquals(before)) " — прежним" else " — новым, молча",
            )
        } catch (expected: Exception) {
            // ожидаемо: расшифровывать нечем
        }
    }

    @Test
    fun the_system_reports_where_the_key_lives() {
        val level = TeeKey.securityLevel()

        Log.i(TAG, "ключ хранилища: $level")
        assertNotNull("система не сказала, где лежит ключ хранилища", level)
    }

    @Test
    fun attestation_runs_end_to_end_on_a_real_keystore() {
        val verdict = KeyAttestation.run()

        Log.i(TAG, "аттестация: ${verdict.outcome} ${verdict.reason.orEmpty()}")

        // ⚠️ У образов эмулятора промежуточный сертификат программной
        // аттестации просрочен (образ API 28 — 2026-11). На телефоне это
        // провал, и он здесь остаётся провалом; пропускается только
        // эмулятор и только по этой причине.
        assumeTrue(
            "эмулятор: сертификат программной аттестации образа просрочен",
            !(isEmulator() && verdict.reason.orEmpty().endsWith("вне срока")),
        )

        assertNotEquals(
            "аттестация провалилась: ${verdict.reason}",
            KeyAttestation.Outcome.FAILED,
            verdict.outcome,
        )

        val description = verdict.description!!

        assertTrue(
            "в аттестации не наш пакет: ${description.packageNames}",
            context.packageName in description.packageNames,
        )

        // Второй свидетель подписи сходится с первым — иначе проверка
        // подписи провалила бы и настоящую сборку.
        val installed = AppSignature.installedDigests(context)
        assertEquals("подписант не один", 1, installed.size)
        assertTrue(
            "подпись в аттестации не та, что видит PackageManager",
            description.signatureDigests.any { it.contentEquals(installed[0]) },
        )

        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(
            "временный ключ аттестации остался в Keystore",
            store.aliases().toList().any { it.startsWith("gasapp.attestation") },
        )
    }

    private fun isEmulator(): Boolean =
        Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish" || Build.FINGERPRINT.contains("generic")

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { start ->
            needle.indices.all { haystack[start + it] == needle[it] }
        }

    private companion object {
        const val TAG = "HardwareKeyOnDevice"
        const val TEST_PIN = "246801"
        const val TEE_ALIAS = "gasapp_storage_tee_v3"
        const val SECRET_FILE = "gasapp.hw"
    }
}
