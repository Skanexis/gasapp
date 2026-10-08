// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest
import org.gasapp.app.BuildConfig

/**
 * 🔐 Подписан ли установленный APK нашим ключом (MASVS RESILIENCE-2.1).
 *
 * # От чего это защищает
 *
 * От пересобранной копии: GasApp, скачанного с зеркала, из канала
 * «взломанных приложений» или подсунутого вместе с «обновлением».
 * Такая копия выглядит и работает как настоящая, но собрана из
 * изменённого кода — и отправлять переписку может куда угодно.
 * Пересобрать APK можно, только подписав его своим ключом: наш
 * у пересобравшего отсутствует.
 *
 * # Откуда берётся эталон
 *
 * SHA-256 сертификата подписи вписывается в сборку при сборке релиза
 * (`BuildConfig.SIGNING_CERT_SHA256`, см. `app/build.gradle`): Gradle
 * читает его из того же хранилища ключей, которым APK подписывается.
 * Отладочная сборка эталона не имеет — проверять её нечем, и центр
 * безопасности так и говорит.
 *
 * # Два свидетеля
 *
 *  1. `PackageManager` — что система записала при установке.
 *  2. Аттестация ([KeyAttestation]) — что система передала в защищённое
 *     оборудование и что оно подписало. Её подменить труднее: ответ
 *     `PackageManager` перехватывается в процессе, подпись TEE — нет.
 *
 * Расхождение **любого** из них с эталоном — провал.
 *
 * # Чего это не даёт
 *
 * ⚠️ Пересобравший может вырезать и саму проверку — она часть того
 * же кода, который он меняет. Проверка ловит бесхитростную
 * пересборку, а не целенаправленную. Главная мера против подмены
 * сборки — воспроизводимость (ADR-020): любой может собрать APK
 * из исходников и сверить побайтно с опубликованным.
 */
object AppSignature {

    enum class Verdict {
        /** Подпись совпала с эталоном у всех свидетелей. */
        MATCH,

        /** Хотя бы один свидетель видит другую подпись. */
        MISMATCH,

        /** Эталона нет: отладочная сборка. */
        NOT_CONFIGURED,
    }

    /**
     * Проверка на устройстве.
     *
     * @param attested подписи из аттестации — только если её цепочка
     *   ведёт к Google ([KeyAttestation.Verdict.trustedSignatureDigests]);
     *   `null`, если такой нет.
     */
    fun check(context: Context, attested: List<ByteArray>?): Verdict =
        judge(BuildConfig.SIGNING_CERT_SHA256, installedDigests(context), attested)

    /**
     * Решение по уже собранным свидетельствам.
     *
     * 🔐 Подписант обязан быть **ровно один**. Мы подписываем одним
     * ключом; второй подписант рядом с нашим — это APK, который
     * система примет от имени любого из двух.
     */
    fun judge(expectedHex: String, installed: List<ByteArray>, attested: List<ByteArray>?): Verdict {
        if (expectedHex.isBlank()) return Verdict.NOT_CONFIGURED

        val expected = runCatching { KeyAttestation.hexToBytes(normalize(expectedHex)) }.getOrNull()
            ?.takeIf { it.size == SHA256_BYTES }
            ?: return Verdict.MISMATCH

        val installedOk = installed.size == 1 && MessageDigest.isEqual(installed[0], expected)

        // В аттестации — история подписей (ротация ключа по схеме v3
        // оставляет прежние), поэтому достаточно присутствия нашей.
        val attestedOk = attested == null || attested.any { MessageDigest.isEqual(it, expected) }

        return if (installedOk && attestedOk) Verdict.MATCH else Verdict.MISMATCH
    }

    /**
     * SHA-256 сертификатов, которыми подписано содержимое APK.
     *
     * `apkContentsSigners`, а не `signingCertificateHistory`: история
     * включает прежние ключи при ротации, а сверять нужно тот,
     * которым подписан именно этот APK.
     */
    fun installedDigests(context: Context): List<ByteArray> {
        val info = runCatching {
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            ).signingInfo
        }.getOrNull() ?: return emptyList()

        return info.apkContentsSigners.orEmpty().map { KeyAttestation.sha256(it.toByteArray()) }
    }

    private fun normalize(hex: String): String = hex.replace(":", "").trim().lowercase()

    private const val SHA256_BYTES = 32
}
