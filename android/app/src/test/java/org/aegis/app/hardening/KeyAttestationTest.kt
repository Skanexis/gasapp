// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import kotlin.random.Random
import org.aegis.app.core.Der
import org.aegis.app.core.KeyAttestation
import org.aegis.app.core.KeyAttestation.Outcome
import org.aegis.app.hardening.AttestationFixtures.CHALLENGE
import org.aegis.app.hardening.AttestationFixtures.Description
import org.aegis.app.hardening.AttestationFixtures.chain
import org.aegis.app.hardening.AttestationFixtures.keyDescription
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 🔐 Аттестация ключей (MASVS RESILIENCE-1.3).
 *
 * # Что здесь проверяется
 *
 * Логика проверки цепочки: её ошибка — это «оборудование подтверждает
 * защиту» на устройстве, где защиты нет. Каждый путь отказа проверяется
 * отдельно, и в каждом тесте меняется ровно одно условие относительно
 * цепочки, которая проходит.
 *
 * # Чего здесь не проверяется
 *
 * Настоящая цепочка Google: её корень подписывает только оборудование.
 * Она проверяется на устройстве (`KeyAttestationOnDeviceTest`); здесь
 * доверенный корень передаётся явно. Корни Google сверены отдельно —
 * с опубликованными сертификатами.
 */
class KeyAttestationTest {

    private fun evaluate(
        c: AttestationFixtures.Chain,
        challenge: ByteArray = CHALLENGE,
        trustRoot: Boolean = true,
        certificates: List<X509Certificate> = c.certificates,
    ): KeyAttestation.Verdict = KeyAttestation.evaluate(
        chain = certificates,
        challenge = challenge,
        publicKey = c.leafKey.public,
        now = Date(),
        trustedRoots = if (trustRoot) listOf(KeyAttestation.sha256(c.root.public.encoded)) else emptyList(),
    )

    // --- корни Google ------------------------------------------------------

    /**
     * 🔐 Суммы в коде — от опубликованных корней Google.
     *
     * Опечатка в одной цифре означала бы «подтверждение не ведёт
     * к корню Google» на каждом настоящем телефоне — а мутация «убрать
     * корень» проходила бы незамеченной без этой сверки.
     */
    @Test
    fun google_root_keys_match_the_published_certificates() {
        val pem = javaClass.classLoader!!.getResource("google_attestation_roots.pem")!!.readText()
        val roots = Regex("-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)
            .findAll(pem)
            .map { Base64.getMimeDecoder().decode(it.groupValues[1]) }
            .map { CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()) as X509Certificate }
            .toList()

        assertEquals("опубликованных корней два", 2, roots.size)

        roots.forEach { root ->
            // Самоподпись: испорченный при копировании сертификат её не пройдёт.
            root.verify(root.publicKey)
        }

        val expected = roots.map { KeyAttestation.sha256(it.publicKey.encoded).toList() }.toSet()
        val inCode = KeyAttestation.GOOGLE_ROOT_KEYS.map { it.toList() }.toSet()

        assertEquals("суммы корней в коде не совпадают с сертификатами Google", expected, inCode)
    }

    // --- разбор расширения -------------------------------------------------

    @Test
    fun key_description_is_parsed() {
        val digest = ByteArray(32) { 9 }
        val parsed = KeyAttestation.parseDescription(
            keyDescription(Description(attestationLevel = 2, keymasterLevel = 2, signatureDigests = listOf(digest))),
        )

        assertEquals(200, parsed.attestationVersion)
        assertEquals(KeyAttestation.Level.STRONGBOX, parsed.attestationLevel)
        assertEquals(KeyAttestation.Level.STRONGBOX, parsed.keymasterLevel)
        assertArrayEquals(CHALLENGE, parsed.challenge)
        assertEquals(KeyAttestation.Boot.VERIFIED, parsed.boot)
        assertEquals(true, parsed.bootloaderLocked)
        assertEquals(listOf("org.aegis.app"), parsed.packageNames)
        assertEquals(1, parsed.signatureDigests.size)
        assertArrayEquals(digest, parsed.signatureDigests[0])
    }

    /**
     * 🔐 `RootOfTrust` в программной части не засчитывается.
     *
     * Программную часть заполняет система, а не оборудование:
     * «загрузчик заперт» оттуда — слова системы о самой себе.
     */
    @Test
    fun root_of_trust_outside_the_hardware_list_is_ignored() {
        val parsed = KeyAttestation.parseDescription(keyDescription(Description(rootOfTrustInHardware = false)))

        assertNull("RootOfTrust из программной части принят", parsed.boot)
        assertNull(parsed.bootloaderLocked)
    }

    // --- итог проверки -----------------------------------------------------

    @Test
    fun hardware_key_with_locked_verified_boot_passes() {
        val verdict = evaluate(chain())

        assertEquals(verdict.reason, Outcome.TRUSTED_HARDWARE, verdict.outcome)
        assertTrue(verdict.passed)
    }

    @Test
    fun unlocked_bootloader_fails() {
        val verdict = evaluate(chain(keyDescription(Description(bootloaderLocked = false))))

        assertEquals(Outcome.BOOT_NOT_VERIFIED, verdict.outcome)
        assertFalse(verdict.passed)
    }

    @Test
    fun unverified_boot_fails() {
        // 2 — Unverified: загрузка без проверки подписи системы.
        val verdict = evaluate(chain(keyDescription(Description(bootState = 2))))

        assertEquals(Outcome.BOOT_NOT_VERIFIED, verdict.outcome)
    }

    @Test
    fun root_of_trust_from_software_list_does_not_pass() {
        val verdict = evaluate(chain(keyDescription(Description(rootOfTrustInHardware = false))))

        assertEquals(Outcome.BOOT_NOT_VERIFIED, verdict.outcome)
    }

    @Test
    fun software_key_fails() {
        val verdict = evaluate(chain(keyDescription(Description(attestationLevel = 0, keymasterLevel = 0))))

        assertEquals(Outcome.SOFTWARE_ONLY, verdict.outcome)
    }

    /** Программный keymaster под аппаратной аттестацией — тоже программный ключ. */
    @Test
    fun software_keymaster_fails_even_with_hardware_attestation() {
        val verdict = evaluate(chain(keyDescription(Description(attestationLevel = 1, keymasterLevel = 0))))

        assertEquals(Outcome.SOFTWARE_ONLY, verdict.outcome)
    }

    /** Эмулятор и программная аттестация: корень не Google. */
    @Test
    fun unknown_root_is_not_trusted() {
        val verdict = evaluate(chain(), trustRoot = false)

        assertEquals(Outcome.UNTRUSTED_ROOT, verdict.outcome)
        assertNull("подписям из недоверенной цепочки поверили", verdict.trustedSignatureDigests)
    }

    /** 🔐 Повтор чужого или прошлого ответа. */
    @Test
    fun wrong_challenge_fails() {
        val verdict = evaluate(chain(), challenge = ByteArray(32) { 0x55 })

        assertEquals(Outcome.FAILED, verdict.outcome)
    }

    /** 🔐 Настоящая цепочка, но удостоверяет не наш ключ. */
    @Test
    fun chain_for_another_key_fails() {
        val c = chain()
        val verdict = KeyAttestation.evaluate(
            chain = c.certificates,
            challenge = CHALLENGE,
            publicKey = AttestationFixtures.ecKeyPair().public,
            now = Date(),
            trustedRoots = listOf(KeyAttestation.sha256(c.root.public.encoded)),
        )

        assertEquals(Outcome.FAILED, verdict.outcome)
    }

    /** 🔐 Промежуточный подписан не корнем, который предъявлен. */
    @Test
    fun broken_signature_fails() {
        val c = chain()
        val stranger = AttestationFixtures.ecKeyPair()
        val forgedIntermediate = AttestationFixtures.certificate(
            "intermediate",
            c.certificates[1].publicKey,
            "root",
            stranger.private,
        )

        val verdict = evaluate(c, certificates = listOf(c.certificates[0], forgedIntermediate, c.certificates[2]))

        assertEquals(Outcome.FAILED, verdict.outcome)
    }

    /**
     * 🔐 Атакующий достраивает цепочку.
     *
     * Настоящий аппаратный ключ, у которого есть сертификат, подписывает
     * ещё один сертификат — для программного ключа атакующего — и кладёт
     * в него «аттестацию» с нужными полями. Документация Google: доверять
     * можно лишь вхождению расширения, ближайшему к корню.
     */
    @Test
    fun extension_below_a_genuine_attestation_is_rejected() {
        val genuine = chain()
        val attacker = AttestationFixtures.ecKeyPair()

        val forged = AttestationFixtures.certificate(
            subject = "forged",
            subjectKey = attacker.public,
            issuer = "leaf",
            issuerKey = genuine.leafKey.private,
            extension = keyDescription(),
            serial = 4,
        )

        val verdict = KeyAttestation.evaluate(
            chain = listOf(forged) + genuine.certificates,
            challenge = CHALLENGE,
            publicKey = attacker.public,
            now = Date(),
            trustedRoots = listOf(KeyAttestation.sha256(genuine.root.public.encoded)),
        )

        assertEquals(Outcome.FAILED, verdict.outcome)
    }

    @Test
    fun missing_extension_fails() {
        val c = chain()
        val bare = AttestationFixtures.certificate("leaf", c.leafKey.public, "intermediate", c.root.private)

        val verdict = evaluate(c, certificates = listOf(bare, c.certificates[2]))

        assertEquals(Outcome.FAILED, verdict.outcome)
    }

    @Test
    fun empty_chain_fails() {
        val verdict = KeyAttestation.evaluate(emptyList(), CHALLENGE, chain().leafKey.public, Date())

        assertEquals(Outcome.FAILED, verdict.outcome)
    }

    // --- враждебный вход ---------------------------------------------------

    @Test
    fun truncated_der_is_rejected() {
        val der = keyDescription()

        for (cut in 1 until der.size) {
            try {
                KeyAttestation.parseDescription(der.copyOf(cut))
                fail("обрезанная до $cut байт запись разобрана")
            } catch (expected: IllegalArgumentException) {
                // ожидаемо
            }
        }
    }

    @Test
    fun indefinite_length_is_rejected() {
        try {
            Der.parseSingle(byteArrayOf(0x30, 0x80.toByte(), 0x00, 0x00))
            fail("неопределённая длина принята")
        } catch (expected: Der.MalformedDer) {
            // ожидаемо
        }
    }

    @Test
    fun length_beyond_the_buffer_is_rejected() {
        try {
            Der.parseSingle(byteArrayOf(0x04, 0x84.toByte(), 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x00))
            fail("длина больше записи принята")
        } catch (expected: Der.MalformedDer) {
            // ожидаемо
        }
    }

    /**
     * 🔐 Любой испорченный байт даёт отказ разбора, а не другое исключение.
     *
     * Иное исключение — `IndexOutOfBounds`, `OutOfMemory` — вылетело бы
     * мимо `evaluate` и уронило центр безопасности; хуже того,
     * «испорченная запись» могла бы разобраться в правдоподобную.
     */
    @Test
    fun corrupted_descriptions_never_escape_as_other_exceptions() {
        val original = keyDescription()
        val random = Random(20260924)

        repeat(20_000) {
            val mutated = original.copyOf()
            repeat(1 + random.nextInt(4)) {
                mutated[random.nextInt(mutated.size)] = random.nextInt(256).toByte()
            }

            try {
                KeyAttestation.parseDescription(mutated)
            } catch (expected: IllegalArgumentException) {
                // ожидаемо: отказ разбора
            }
        }
    }
}
