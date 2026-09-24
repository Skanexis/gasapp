// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * 🔐 Аттестация ключей: хранит ли устройство ключи в защищённом
 * оборудовании на самом деле (MASVS RESILIENCE-1.3, раздел 7.3).
 *
 * # Зачем, если Keystore и так говорит «аппаратный»
 *
 * Раздел 7.3: «на части устройств Keystore врёт». `KeyInfo` — ответ
 * операционной системы, и на изменённой прошивке он такой, какой
 * нужен изменившему. Аттестация — ответ **самого** защищённого
 * оборудования: сертификат нового ключа, подписанный ключом,
 * зашитым в TEE или StrongBox при производстве, по цепочке до корня
 * Google. Подделать её, не вынув ключ из чипа, нельзя.
 *
 * Заодно аттестация сообщает то, чего приложению иначе не узнать:
 * заперт ли загрузчик и проверена ли загрузка (`RootOfTrust`).
 * Разблокированный загрузчик означает, что система могла быть
 * заменена целиком, и все прочие проверки устройства становятся
 * ответами этой системы.
 *
 * # Как устроено
 *
 * 1. В Keystore заводится временный ключ EC P-256 со случайным вызовом
 *    (challenge) — StrongBox при наличии, как и ключ хранилища.
 * 2. Цепочка его сертификатов проверяется подпись за подписью; корень
 *    сверяется с открытыми ключами корней Google ([GOOGLE_ROOT_KEYS]).
 * 3. Из листа читается расширение `1.3.6.1.4.1.11129.2.1.17`: уровень
 *    защиты, вызов, состояние загрузки и подпись приложения, как её
 *    видит система.
 * 4. Ключ удаляется: он нужен только для проверки.
 *
 * # Чего это не даёт
 *
 * ⚠️ **Проверка локальная.** Её выполняет само приложение, и на
 * устройстве, где атакующий исполняет код в процессе приложения,
 * он подменит и ответ этой функции. Настоящая сила аттестации —
 * у проверяющего **снаружи** устройства; сервер AEGIS её не
 * запрашивает сознательно: это отдало бы серверу модель устройства,
 * версию прошивки и уровень исправлений — метаданные, которых
 * сервер знать не должен (раздел 15).
 *
 * ⚠️ **Отзыв не проверяется.** Google публикует список отозванных
 * ключей аттестации, но запрос к нему сообщал бы Google, что на этом
 * устройстве стоит AEGIS. Утёкшие ключи аттестации известны для
 * отдельных моделей; на них проверка может ошибиться в сторону
 * «защищено».
 *
 * Итог идёт в центр безопасности как проверка, а не как запрет, —
 * по тем же причинам, что и детект root ([DeviceIntegrity]).
 */
object KeyAttestation {

    /** Уровень защиты — `SecurityLevel` схемы аттестации. */
    enum class Level { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX }

    /** Состояние проверенной загрузки — `VerifiedBootState`. */
    enum class Boot { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED }

    /** Разобранное расширение аттестации (`KeyDescription`). */
    class Description(
        val attestationVersion: Int,
        val attestationLevel: Level,
        val keymasterLevel: Level,
        val challenge: ByteArray,
        /** `null` — `RootOfTrust` в сертификате нет. */
        val boot: Boot?,
        /** `null` — `RootOfTrust` в сертификате нет. */
        val bootloaderLocked: Boolean?,
        val packageNames: List<String>,
        /** SHA-256 сертификатов подписи приложения, как их видит система. */
        val signatureDigests: List<ByteArray>,
    )

    /** Итог проверки, от лучшего к худшему. */
    enum class Outcome {
        /** Аппаратный ключ, корень Google, загрузка проверена, загрузчик заперт. */
        TRUSTED_HARDWARE,

        /** Цепочка до Google, но загрузчик открыт или загрузка не проверена. */
        BOOT_NOT_VERIFIED,

        /** Цепочка до Google, но ключ программный. */
        SOFTWARE_ONLY,

        /** Корень не Google: эмулятор, программная аттестация или подделка. */
        UNTRUSTED_ROOT,

        /** Цепочка не сходится, расширение испорчено или ключ не создался. */
        FAILED,
    }

    class Verdict(
        val outcome: Outcome,
        val description: Description? = null,
        /** Причина для журнала разработчика; на экран не выводится. */
        val reason: String? = null,
    ) {
        val passed: Boolean get() = outcome == Outcome.TRUSTED_HARDWARE

        /**
         * Подписи приложения из аттестации — только если цепочка
         * ведёт к Google. Иначе их мог написать кто угодно.
         */
        val trustedSignatureDigests: List<ByteArray>?
            get() = description?.signatureDigests?.takeIf {
                outcome != Outcome.UNTRUSTED_ROOT && outcome != Outcome.FAILED
            }
    }

    @Volatile
    private var cached: Verdict? = null

    /**
     * Проверка с кешем на время процесса.
     *
     * Создание ключа в StrongBox занимает до секунды, а состояние
     * загрузчика между запусками экрана не меняется. Вызывать
     * не с главного потока.
     */
    fun verdict(): Verdict = cached ?: run().also { cached = it }

    /** Проверка заново: создаёт временный ключ, проверяет и удаляет его. */
    fun run(): Verdict {
        val challenge = ByteArray(CHALLENGE_BYTES).also { SecureRandom().nextBytes(it) }
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }

        return try {
            val publicKey = generate(challenge)

            @Suppress("UNCHECKED_CAST")
            val chain = store.getCertificateChain(ALIAS)?.map { it as X509Certificate }
                ?: return Verdict(Outcome.FAILED, reason = "нет цепочки сертификатов")

            evaluate(chain, challenge, publicKey, Date())
        } catch (failure: Exception) {
            Verdict(Outcome.FAILED, reason = failure.javaClass.simpleName)
        } finally {
            runCatching { store.deleteEntry(ALIAS) }
        }
    }

    /**
     * Проверяет цепочку и её расширение.
     *
     * Отделено от [run], чтобы проверяться на заготовленных цепочках:
     * ошибка в разборе здесь — это «защищено» там, где не защищено.
     */
    fun evaluate(
        chain: List<X509Certificate>,
        challenge: ByteArray,
        publicKey: PublicKey,
        now: Date,
        trustedRoots: List<ByteArray> = GOOGLE_ROOT_KEYS,
    ): Verdict {
        if (chain.isEmpty()) return Verdict(Outcome.FAILED, reason = "пустая цепочка")

        // Лист обязан удостоверять именно наш ключ: иначе чужая
        // настоящая цепочка выдавалась бы за нашу.
        if (!chain[0].publicKey.encoded.contentEquals(publicKey.encoded)) {
            return Verdict(Outcome.FAILED, reason = "лист удостоверяет другой ключ")
        }

        for (i in 0 until chain.size - 1) {
            try {
                chain[i].verify(chain[i + 1].publicKey)
            } catch (failure: Exception) {
                return Verdict(Outcome.FAILED, reason = "подпись звена $i не сходится")
            }

            // Срок листа не проверяется: у ключей Keystore он бывает
            // условным (1970–2048 на части прошивок) и ничего не значит.
            try {
                chain[i + 1].checkValidity(now)
            } catch (failure: Exception) {
                return Verdict(Outcome.FAILED, reason = "звено ${i + 1} вне срока")
            }
        }

        val root = chain.last()

        try {
            root.verify(root.publicKey)
        } catch (failure: Exception) {
            return Verdict(Outcome.FAILED, reason = "корень не самоподписан")
        }

        // 🔐 Расширение доверенно только в листе. Документация Google:
        // доверять можно лишь первому вхождению со стороны корня;
        // вхождение ниже — признак того, что цепочку достроил
        // атакующий, выпустив «аттестацию» от имени настоящего ключа.
        chain.drop(1).forEachIndexed { index, cert ->
            if (cert.getExtensionValue(EXTENSION_OID) != null) {
                return Verdict(Outcome.FAILED, reason = "расширение в звене ${index + 1}")
            }
        }

        val raw = chain[0].getExtensionValue(EXTENSION_OID)
            ?: return Verdict(Outcome.FAILED, reason = "нет расширения аттестации")

        val description = try {
            // getExtensionValue отдаёт OCTET STRING, внутри которого DER расширения.
            parseDescription(Der.parseSingle(raw).asOctets())
        } catch (failure: IllegalArgumentException) {
            return Verdict(Outcome.FAILED, reason = "расширение испорчено: ${failure.message}")
        }

        if (!MessageDigest.isEqual(description.challenge, challenge)) {
            return Verdict(Outcome.FAILED, description, "вызов не совпал — ответ повторён")
        }

        val rootKey = sha256(root.publicKey.encoded)

        val outcome = when {
            trustedRoots.none { it.contentEquals(rootKey) } -> Outcome.UNTRUSTED_ROOT
            description.attestationLevel == Level.SOFTWARE ||
                description.keymasterLevel == Level.SOFTWARE -> Outcome.SOFTWARE_ONLY
            description.boot != Boot.VERIFIED || description.bootloaderLocked != true ->
                Outcome.BOOT_NOT_VERIFIED
            else -> Outcome.TRUSTED_HARDWARE
        }

        return Verdict(outcome, description)
    }

    /**
     * Разбирает `KeyDescription`.
     *
     * ```text
     * KeyDescription ::= SEQUENCE {
     *   attestationVersion        INTEGER,
     *   attestationSecurityLevel  SecurityLevel,
     *   keyMintVersion            INTEGER,
     *   keyMintSecurityLevel      SecurityLevel,
     *   attestationChallenge      OCTET STRING,
     *   uniqueId                  OCTET STRING,
     *   softwareEnforced          AuthorizationList,
     *   hardwareEnforced          AuthorizationList }
     * ```
     *
     * `RootOfTrust` ([704]) ищется в аппаратной части: в программной
     * его ставит система, и верить ему там нельзя. Идентификатор
     * приложения ([709]) — в программной: его заполняет служба
     * Keystore, а подписывает вместе со всем остальным оборудование.
     *
     * @throws IllegalArgumentException при нарушении схемы
     */
    fun parseDescription(der: ByteArray): Description {
        val fields = Der.parseSingle(der).expect(Der.TAG_SEQUENCE).children()

        require(fields.size >= KEY_DESCRIPTION_FIELDS) { "KeyDescription: мало полей" }

        val software = fields[6].expect(Der.TAG_SEQUENCE).children()
        val hardware = fields[7].expect(Der.TAG_SEQUENCE).children()

        val rootOfTrust = hardware.firstOrNull { it.isContext(TAG_ROOT_OF_TRUST) }
            ?.let { explicit(it).expect(Der.TAG_SEQUENCE).children() }

        val appId = software.firstOrNull { it.isContext(TAG_APPLICATION_ID) }
            ?.let { parseApplicationId(explicit(it).asOctets()) }

        return Description(
            attestationVersion = fields[0].asSmallInt(),
            attestationLevel = level(fields[1]),
            keymasterLevel = level(fields[3]),
            challenge = fields[4].asOctets(),
            boot = rootOfTrust?.let {
                require(it.size >= ROOT_OF_TRUST_FIELDS) { "RootOfTrust: мало полей" }
                boot(it[2])
            },
            bootloaderLocked = rootOfTrust?.get(1)?.asBoolean(),
            packageNames = appId?.first.orEmpty(),
            signatureDigests = appId?.second.orEmpty(),
        )
    }

    /**
     * `AttestationApplicationId`:
     *
     * ```text
     * SEQUENCE { packageInfos SET OF SEQUENCE { name OCTET STRING, version INTEGER },
     *            signatureDigests SET OF OCTET STRING }
     * ```
     */
    private fun parseApplicationId(der: ByteArray): Pair<List<String>, List<ByteArray>> {
        val parts = Der.parseSingle(der).expect(Der.TAG_SEQUENCE).children()

        require(parts.size == 2) { "AttestationApplicationId: не два поля" }

        val names = parts[0].expect(Der.TAG_SET).children().map { info ->
            val fields = info.expect(Der.TAG_SEQUENCE).children()

            require(fields.isNotEmpty()) { "AttestationPackageInfo: пусто" }

            String(fields[0].asOctets(), Charsets.UTF_8)
        }

        val digests = parts[1].expect(Der.TAG_SET).children().map { it.asOctets() }

        return names to digests
    }

    /** Содержимое явного тега: ровно один вложенный элемент. */
    private fun explicit(tagged: Der.Element): Der.Element {
        val inner = tagged.children()

        require(inner.size == 1) { "явный тег [${tagged.tagNumber}]: не один элемент" }

        return inner[0]
    }

    private fun level(element: Der.Element): Level = when (element.asSmallInt()) {
        0 -> Level.SOFTWARE
        1 -> Level.TRUSTED_ENVIRONMENT
        2 -> Level.STRONGBOX
        else -> throw IllegalArgumentException("неизвестный уровень защиты")
    }

    private fun boot(element: Der.Element): Boot = when (element.asSmallInt()) {
        0 -> Boot.VERIFIED
        1 -> Boot.SELF_SIGNED
        2 -> Boot.UNVERIFIED
        3 -> Boot.FAILED
        else -> throw IllegalArgumentException("неизвестное состояние загрузки")
    }

    private fun generate(challenge: ByteArray): PublicKey {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)

        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .setIsStrongBoxBacked(strongBox)
            .build()

        return try {
            generator.initialize(spec(strongBox = true))
            generator.generateKeyPair().public
        } catch (absent: StrongBoxUnavailableException) {
            // Тот же откат, что у ключа хранилища (HardwareKey): проверяется
            // то оборудование, в котором ключ хранилища и лежит.
            generator.initialize(spec(strongBox = false))
            generator.generateKeyPair().public
        }
    }

    internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /**
     * SHA-256 открытых ключей (SubjectPublicKeyInfo) корней аттестации Google.
     *
     * Сверяются ключи, а не сертификаты: корень 2022 года перевыпущен
     * на том же ключе RSA-4096, что и корень 2016-го, и старые
     * устройства предъявляют старый сертификат.
     *
     * Источник — developer.android.com/privacy-and-security/security-key-attestation.
     * Сами сертификаты лежат в тестах (`google_attestation_roots.pem`),
     * и `KeyAttestationTest` сверяет с ними эти суммы: опечатка здесь
     * означала бы «корень не Google» на каждом настоящем телефоне.
     */
    internal val GOOGLE_ROOT_KEYS: List<ByteArray> = listOf(
        // RSA-4096, корень с 2016 года (сертификат 2022 года — тот же ключ).
        "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
        // ECDSA P-384, «Key Attestation CA1»: подписывает с 1 февраля 2026.
        "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
    ).map(::hexToBytes)

    internal fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    const val EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_APPLICATION_ID = 709

    private const val KEY_DESCRIPTION_FIELDS = 8
    private const val ROOT_OF_TRUST_FIELDS = 3

    private const val CHALLENGE_BYTES = 32

    /** Временный ключ; удаляется сразу после проверки. */
    private const val ALIAS = "aegis.attestation.probe"

    private const val PROVIDER = "AndroidKeyStore"
}
