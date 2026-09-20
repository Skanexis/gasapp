// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 🔐 Разблокировка по биометрии (MASVS AUTH-2.1).
 *
 * # Что здесь происходит и чего здесь не происходит
 *
 * Биометрия **не заменяет** PIN и не выводит из него ключ — отпечаток
 * пальца невозможно превратить в 32 байта, одинаковые от раза к разу.
 * Происходит другое: ключ базы, уже полученный из PIN, кладётся
 * в конверт, который Android Keystore открывает **только после**
 * подтверждения биометрией.
 *
 * ```text
 * включение:  PIN → ключ базы → Cipher(биометрия) → aegis.bio
 * вход:       биометрия → Cipher → aegis.bio → ключ базы → база
 * ```
 *
 * То есть биометрия — это способ не набирать PIN, а не второй способ
 * вывести ключ. PIN остаётся единственным, что знает человек, и без
 * него аккаунт не восстановить.
 *
 * # Почему ключ Keystore помечен обязательной аутентификацией
 *
 * `setUserAuthenticationRequired(true)` — то самое, что оставалось
 * открытым после находки P-5 (раздел 23.6): без биометрического
 * экрана поставить эту пометку было некуда, потому что она заперла бы
 * людей снаружи. Теперь экран есть, и пометка стоит на **отдельном**
 * ключе — не на том, которым обёрнут аппаратный секрет ([HardwareKey]).
 *
 * Разделение существенно: [HardwareKey] обязан открываться без всякого
 * подтверждения, иначе человек без биометрии не войдёт даже по PIN.
 * А этот ключ существует ровно для того, чтобы подтверждения требовать.
 *
 * # ⚠️ Смена набора отпечатков стирает конверт
 *
 * `setInvalidatedByBiometricEnrollment(true)`: добавили в телефон
 * чужой палец — ключ Keystore становится непригоден, и `aegis.bio`
 * больше не открыть ничем. Это защита, а не неудобство: без неё тот,
 * кто получил разблокированный телефон, добавил бы свой отпечаток
 * и вошёл в переписку. Приложение в этом случае молча возвращается
 * к PIN — единственному, что знает владелец.
 *
 * # ⚠️ Что биометрия не защищает
 *
 * От того, кто может приложить палец владельца к датчику. В ряде мест
 * это и правовое различие: код знают, палец — прикладывают. Поэтому
 * биометрия выключена по умолчанию и включается осознанно, а PIN
 * работает всегда.
 *
 * # ⚠️ Проверено сборкой, но не устройством
 *
 * Вне устройства Android Keystore не существует, а биометрического
 * датчика нет и подавно: круговой путь «зашифровать → подтвердить →
 * расшифровать» на этой машине не проверялся. Тестами закреплено
 * то, что можно: политика доступности, стирание конверта и поведение
 * при отключении. Отказ здесь безопасен — не открылось значит
 * «вводите PIN», а не «входите без него».
 */
object BiometricUnlock {

    /** Доступна ли разблокировка по биометрии на этом устройстве. */
    enum class Availability {
        /** Датчик есть и отпечатки заведены. */
        Ready,

        /** Датчик есть, но ни одного отпечатка не заведено. */
        NotEnrolled,

        /** Датчика нет либо он недоступен. */
        Unsupported,
    }

    /**
     * Что умеет это устройство.
     *
     * 🔐 Спрашивается только про **сильную** биометрию
     * (`BIOMETRIC_STRONG`). Класс 2 — распознавание лица, которое
     * обманывается фотографией, — сюда не входит: открывать им
     * переписку значило бы считать фотографию доказательством
     * личности. Устройство с одним лишь слабым датчиком честно
     * отвечает [Availability.Unsupported].
     *
     * Пароль устройства (`DEVICE_CREDENTIAL`) тоже не принимается:
     * у приложения есть собственный PIN, из которого выводится ключ
     * базы, и подменять его кодом разблокировки телефона значило бы
     * свести стойкость к чужой настройке.
     */
    fun availability(context: Context): Availability {
        val manager = androidx.biometric.BiometricManager.from(context)

        return when (
            manager.canAuthenticate(
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG,
            )
        ) {
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS -> Availability.Ready

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                Availability.NotEnrolled

            else -> Availability.Unsupported
        }
    }

    /**
     * Настроена ли разблокировка по биометрии для этого аккаунта.
     *
     * Наличие конверта, а не флаг в настройках: флаг можно потерять
     * при очистке настроек, и приложение предложило бы вход
     * по биометрии, которому нечего расшифровывать.
     */
    fun isEnabled(context: Context): Boolean = envelope(context).exists()

    /**
     * 🔐 Выключает биометрию и стирает конверт.
     *
     * Вызывается при отключении в настройках и при удалении аккаунта.
     * Сам ключ Keystore удаляется тоже: оставленный, он пережил бы
     * аккаунт, ради которого заведён.
     */
    fun disable(context: Context) {
        runCatching { envelope(context).delete() }

        runCatching {
            val store = KeyStore.getInstance(PROVIDER).apply { load(null) }

            if (store.containsAlias(ALIAS)) {
                store.deleteEntry(ALIAS)
            }
        }
    }

    /**
     * Готовит шифрование ключа базы для включения биометрии.
     *
     * Возвращает [Cipher], который вызывающий обязан передать
     * в `BiometricPrompt`: система разрешит им пользоваться только
     * после подтверждения. Ключ Keystore создаётся здесь же.
     *
     * @throws Exception если хранилище недоступно.
     */
    fun cipherForEnabling(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, createKey())

        return cipher
    }

    /**
     * Готовит расшифровку конверта для входа.
     *
     * Возвращает `null`, если конверта нет или ключ Keystore стал
     * непригоден — например, после добавления нового отпечатка.
     * Оба случая означают одно: входить надо по PIN.
     */
    fun cipherForUnlocking(context: Context): Cipher? {
        val record = runCatching { envelope(context).readBytes() }.getOrNull() ?: return null

        if (record.size <= 1) {
            return null
        }

        val ivLength = record[0].toInt()

        if (ivLength !in 1..MAX_IV_BYTES || record.size <= 1 + ivLength) {
            return null
        }

        val iv = record.copyOfRange(1, 1 + ivLength)

        return runCatching {
            val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val key = (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
                ?: return@runCatching null

            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        }.getOrElse { failure ->
            // 🔐 Набор отпечатков изменился: ключ уничтожен системой,
            // конверт открыть нечем. Стираем его, чтобы приложение
            // не предлагало вход, который никогда не пройдёт.
            if (failure is KeyPermanentlyInvalidatedException) {
                disable(context)
            }

            null
        }
    }

    /**
     * Запечатывает ключ базы подтверждённым шифром.
     *
     * Принимается результат подтверждения целиком, а не `Cipher`:
     * шифр достаётся здесь. Экрану знать про `javax.crypto` незачем —
     * ему нужен ключ базы, а не примитив (правило 1, раздел 4.1).
     *
     * Брать какой-то другой шифр нельзя: система разрешает работу
     * только тому экземпляру, который прошёл подтверждение.
     */
    fun seal(
        context: Context,
        result: androidx.biometric.BiometricPrompt.AuthenticationResult,
        storageKey: ByteArray,
    ) {
        val cipher = result.cryptoObject?.cipher
            ?: error("подтверждение без шифра: запечатывать нечем")

        val iv = cipher.iv
        val sealed = cipher.doFinal(storageKey)

        // Длина IV первым байтом: у GCM он 12 байт, но полагаться
        // на это нельзя — значение пришло от платформы.
        val record = ByteArray(1 + iv.size + sealed.size)
        record[0] = iv.size.toByte()
        iv.copyInto(record, 1)
        sealed.copyInto(record, 1 + iv.size)

        envelope(context).writeBytes(record)
    }

    /**
     * Достаёт ключ базы из конверта подтверждённым шифром.
     *
     * Как и [seal], принимает результат подтверждения целиком:
     * `javax.crypto` не выходит за пределы этого файла.
     *
     * Возвращает `null`, если подтверждение пришло без шифра или
     * конверт повреждён. В обоих случаях остаётся PIN.
     */
    fun open(
        context: Context,
        result: androidx.biometric.BiometricPrompt.AuthenticationResult,
    ): ByteArray? {
        val cipher = result.cryptoObject?.cipher ?: return null
        val record = runCatching { envelope(context).readBytes() }.getOrNull() ?: return null

        if (record.isEmpty()) {
            return null
        }

        val ivLength = record[0].toInt()

        if (ivLength !in 1..MAX_IV_BYTES || record.size <= 1 + ivLength) {
            return null
        }

        return runCatching { cipher.doFinal(record, 1 + ivLength, record.size - 1 - ivLength) }
            .getOrNull()
    }

    /** Файл с запечатанным ключом базы. */
    private fun envelope(context: Context): File = File(context.filesDir, ENVELOPE_FILE)

    /**
     * Создаёт ключ, который открывается только после подтверждения.
     *
     * 🔐 `setUserAuthenticationRequired(true)` — суть всей затеи.
     * Без этой пометки ключ отдавался бы приложению просто так,
     * и биометрия была бы рисунком поверх незапертой двери.
     */
    private fun createKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)

        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            // 🔐 Каждое использование — своё подтверждение.
            .setUserAuthenticationRequired(true)
            // 🔐 Новый отпечаток делает ключ непригодным: иначе
            // получивший разблокированный телефон добавил бы свой
            // палец и вошёл в чужую переписку.
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Только сильная биометрия. Распознавание лица класса 2
            // обманывается фотографией, и открывать им переписку
            // значило бы считать фотографию доказательством личности.
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
        }

        generator.init(builder.build())

        return generator.generateKey()
    }

    /** Алиас ключа-конверта в Android Keystore. */
    private const val ALIAS = "aegis.biometric.kek"

    /** Файл с запечатанным ключом базы. */
    private const val ENVELOPE_FILE = "aegis.bio"

    private const val PROVIDER = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_BITS = 256
    private const val GCM_TAG_BITS = 128

    /** Разумный предел длины IV: GCM использует 12 байт, запас на вырост. */
    private const val MAX_IV_BYTES = 16
}
