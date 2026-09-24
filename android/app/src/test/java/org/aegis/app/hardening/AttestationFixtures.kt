// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Сборка цепочек аттестации для тестов — DER руками, подписи настоящие.
 *
 * Настоящая цепочка Google в тесте недостижима: её корень подписывает
 * только оборудование. Поэтому цепочка собирается здесь, а корень
 * передаётся в `KeyAttestation.evaluate` как доверенный явно.
 * Проверяется ровно логика проверки — порядок подписей, место
 * расширения, вызов, уровни, — а не то, чем подписал Google.
 */
internal object AttestationFixtures {

    // --- DER ---------------------------------------------------------------

    fun tlv(tag: Int, content: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + length(content.size) + content

    fun length(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
    }

    fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, concat(*parts))

    fun set(vararg parts: ByteArray): ByteArray = tlv(0x31, concat(*parts))

    fun int(value: Long): ByteArray = tlv(0x02, BigInteger.valueOf(value).toByteArray())

    fun enumerated(value: Int): ByteArray = tlv(0x0A, BigInteger.valueOf(value.toLong()).toByteArray())

    fun octets(value: ByteArray): ByteArray = tlv(0x04, value)

    fun bool(value: Boolean): ByteArray = tlv(0x01, byteArrayOf(if (value) 0xFF.toByte() else 0))

    fun nul(): ByteArray = byteArrayOf(0x05, 0x00)

    /** Явный контекстный тег, в том числе с номером больше 30. */
    fun explicit(number: Int, inner: ByteArray): ByteArray {
        val id = if (number < 31) {
            byteArrayOf((0xA0 or number).toByte())
        } else {
            val septets = mutableListOf<Int>()
            var n = number
            do {
                septets.add(0, n and 0x7F)
                n = n shr 7
            } while (n > 0)

            byteArrayOf(0xBF.toByte()) + ByteArray(septets.size) { i ->
                (septets[i] or if (i < septets.size - 1) 0x80 else 0).toByte()
            }
        }

        return id + length(inner.size) + inner
    }

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        val out = ByteArrayOutputStream()
        out.write((arcs[0] * 40 + arcs[1]).toInt())

        for (arc in arcs.drop(2)) {
            val septets = mutableListOf<Int>()
            var n = arc
            do {
                septets.add(0, (n and 0x7F).toInt())
                n = n shr 7
            } while (n > 0)
            septets.forEachIndexed { i, s -> out.write(s or if (i < septets.size - 1) 0x80 else 0) }
        }

        return tlv(0x06, out.toByteArray())
    }

    fun concat(vararg parts: ByteArray): ByteArray =
        ByteArrayOutputStream().apply { parts.forEach(::write) }.toByteArray()

    // --- KeyDescription ----------------------------------------------------

    class Description(
        val attestationLevel: Int = 1,
        val keymasterLevel: Int = 1,
        val challenge: ByteArray = CHALLENGE,
        val bootState: Int = 0,
        val bootloaderLocked: Boolean = true,
        /** Куда положить RootOfTrust: в аппаратную часть или (подлог) в программную. */
        val rootOfTrustInHardware: Boolean = true,
        val packageName: String = "org.aegis.app",
        val signatureDigests: List<ByteArray> = listOf(ByteArray(32) { 7 }),
    )

    fun keyDescription(d: Description = Description()): ByteArray {
        val rootOfTrust = explicit(
            704,
            seq(octets(ByteArray(32) { 1 }), bool(d.bootloaderLocked), enumerated(d.bootState), octets(ByteArray(32) { 2 })),
        )

        val appId = explicit(
            709,
            octets(
                seq(
                    set(seq(octets(d.packageName.toByteArray()), int(1))),
                    set(*d.signatureDigests.map(::octets).toTypedArray()),
                ),
            ),
        )

        // Прочие поля списка — чтобы разбор шёл мимо них, как на устройстве.
        val purpose = explicit(1, set(int(2)))
        val algorithm = explicit(2, int(3))
        val noAuth = explicit(503, nul())

        val software = if (d.rootOfTrustInHardware) seq(appId) else seq(rootOfTrust, appId)
        val hardware = if (d.rootOfTrustInHardware) seq(purpose, algorithm, noAuth, rootOfTrust) else seq(purpose, algorithm, noAuth)

        return seq(
            int(200),
            enumerated(d.attestationLevel),
            int(200),
            enumerated(d.keymasterLevel),
            octets(d.challenge),
            octets(ByteArray(0)),
            software,
            hardware,
        )
    }

    // --- X.509 -------------------------------------------------------------

    fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private val ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))

    private fun name(cn: String): ByteArray = seq(set(seq(oid("2.5.4.3"), tlv(0x0C, cn.toByteArray()))))

    /**
     * Сертификат `subject`, подписанный `issuerKey`.
     *
     * @param extension содержимое расширения аттестации или `null`
     */
    fun certificate(
        subject: String,
        subjectKey: PublicKey,
        issuer: String,
        issuerKey: PrivateKey,
        extension: ByteArray? = null,
        serial: Long = 1,
    ): X509Certificate {
        val validity = seq(tlv(0x17, "200101000000Z".toByteArray()), tlv(0x18, "20491231235959Z".toByteArray()))

        val extensions = extension?.let {
            explicit(3, seq(seq(oid("1.3.6.1.4.1.11129.2.1.17"), octets(it))))
        } ?: ByteArray(0)

        val tbs = seq(
            explicit(0, int(2)),
            int(serial),
            ECDSA_SHA256,
            name(issuer),
            validity,
            name(subject),
            subjectKey.encoded,
            extensions,
        )

        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(issuerKey)
            update(tbs)
            sign()
        }

        val der = seq(tbs, ECDSA_SHA256, tlv(0x03, byteArrayOf(0) + signature))

        return CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    }

    /** Цепочка лист → промежуточный → корень, как её отдаёт Keystore. */
    class Chain(val leafKey: KeyPair, val root: KeyPair, val certificates: List<X509Certificate>)

    fun chain(description: ByteArray = keyDescription()): Chain {
        val root = ecKeyPair()
        val intermediate = ecKeyPair()
        val leaf = ecKeyPair()

        return Chain(
            leafKey = leaf,
            root = root,
            certificates = listOf(
                certificate("leaf", leaf.public, "intermediate", intermediate.private, description, serial = 3),
                certificate("intermediate", intermediate.public, "root", root.private, serial = 2),
                certificate("root", root.public, "root", root.private, serial = 1),
            ),
        )
    }

    val CHALLENGE: ByteArray = ByteArray(32) { it.toByte() }
}
