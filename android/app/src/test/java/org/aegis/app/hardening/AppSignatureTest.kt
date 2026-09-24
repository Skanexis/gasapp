// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import org.aegis.app.core.AppSignature
import org.aegis.app.core.AppSignature.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 🔐 Проверка подписи APK во время работы (MASVS RESILIENCE-2.1).
 *
 * Решение принимается по двум свидетелям — `PackageManager`
 * и аттестации — и провал любого из них — провал проверки.
 */
class AppSignatureTest {

    private val ours = ByteArray(32) { 0x11 }
    private val theirs = ByteArray(32) { 0x22 }
    private val oursHex = ours.joinToString("") { "%02x".format(it) }

    @Test
    fun our_signature_matches() {
        assertEquals(Verdict.MATCH, AppSignature.judge(oursHex, listOf(ours), attested = null))
        assertEquals(Verdict.MATCH, AppSignature.judge(oursHex, listOf(ours), attested = listOf(ours)))
    }

    /** Запись с двоеточиями — так её печатают keytool и apksigner. */
    @Test
    fun colon_separated_expectation_is_accepted() {
        val colons = oursHex.chunked(2).joinToString(":").uppercase()

        assertEquals(Verdict.MATCH, AppSignature.judge(colons, listOf(ours), attested = null))
    }

    @Test
    fun repackaged_apk_is_detected() {
        assertEquals(Verdict.MISMATCH, AppSignature.judge(oursHex, listOf(theirs), attested = null))
    }

    /**
     * 🔐 Система в процессе говорит «наша», оборудование — «чужая».
     *
     * Так выглядит перехват `PackageManager` в пересобранном APK:
     * подделать ответ системы в своём процессе можно, подпись TEE — нет.
     */
    @Test
    fun attestation_disagreeing_with_package_manager_is_a_mismatch() {
        assertEquals(Verdict.MISMATCH, AppSignature.judge(oursHex, listOf(ours), attested = listOf(theirs)))
    }

    /** Ротация ключа v3: в аттестации история, наша подпись в ней есть. */
    @Test
    fun rotation_history_in_attestation_is_accepted() {
        assertEquals(Verdict.MATCH, AppSignature.judge(oursHex, listOf(ours), attested = listOf(theirs, ours)))
    }

    /** 🔐 Второй подписант рядом с нашим. */
    @Test
    fun a_second_signer_is_a_mismatch() {
        assertEquals(Verdict.MISMATCH, AppSignature.judge(oursHex, listOf(ours, theirs), attested = null))
    }

    /** Подпись прочитать не удалось — это не «совпало». */
    @Test
    fun no_installed_signature_is_a_mismatch() {
        assertEquals(Verdict.MISMATCH, AppSignature.judge(oursHex, emptyList(), attested = null))
    }

    @Test
    fun malformed_expectation_is_a_mismatch_not_a_pass() {
        assertEquals(Verdict.MISMATCH, AppSignature.judge("не-шестнадцатеричное", listOf(ours), attested = null))
        assertEquals(Verdict.MISMATCH, AppSignature.judge("abcd", listOf(ours), attested = null))
    }

    @Test
    fun debug_build_is_reported_as_unchecked() {
        assertEquals(Verdict.NOT_CONFIGURED, AppSignature.judge("", listOf(ours), attested = null))
    }
}
