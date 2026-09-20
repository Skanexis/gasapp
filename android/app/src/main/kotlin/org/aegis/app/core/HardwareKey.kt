// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.aegis.hardwareSecretLen

/**
 * Секрет, который не покидает устройство.
 *
 * Вторая половина ключа хранилища. Первая — растянутый PIN
 * (`deriveStorageKeyBound`); вместе они и составляют схему раздела 7.3
 * и ADR-017.
 *
 * # Что здесь чинится
 *
 * 🔐 Находка P-5 внутреннего пентеста (раздел 23.6): **Android Keystore
 * не использовался нигде**. Ключ базы выводился из одного PIN, а PIN
 * ровно шестизначный — миллион вариантов. `Argon2id` (m=64 МиБ, t=3,
 * p=4) перебор растягивает, но не исключает: он ограничен памятью,
 * и машина с 64 ядрами и 4 ГиБ свободной памяти проходит весь миллион
 * примерно за пару часов. То есть изъятый телефон отдавал переписку
 * за аренду в несколько долларов, при том что план описывал аппаратную
 * защиту ключей как действующую.
 *
 * # Как это устроено
 *
 * В Android Keystore заводится ключ AES-256-GCM с алиасом [ALIAS].
 * Им зашифрован файл [SECRET_FILE] с 32 случайными байтами.
 *
 * 🔐 Ключ Keystore **невынимаем**: система не отдаёт его байты ни
 * приложению, ни root. Скопировав `aegis.db`, `aegis.salt` и
 * `aegis.hw`, атакующий получает зашифрованный секрет, расшифровать
 * который можно только на этом устройстве. Перебирать PIN становится
 * бессмысленно — второй половины входа у него нет.
 *
 * # Чего это не даёт
 *
 * ⚠️ Защита от **снятого файла**, а не от снятого устройства. Тот, у
 * кого в руках разблокированный телефон, получит секрет так же, как
 * приложение. От него защищает PIN, и потому ключ выводится из обоих.
 *
 * ⚠️ Ключ **намеренно не** помечен `setUserAuthenticationRequired`.
 * Пометка требует подтверждения биометрией перед каждым
 * использованием, а этот ключ нужен при **каждом** входе по PIN —
 * в том числе тому, у кого биометрии нет или кто её отключил.
 * Поставить её здесь значило бы запереть таких людей снаружи.
 *
 * Пометка стоит там, где ей место: на конверте биометрии
 * ([BiometricUnlock]), который для того и заведён, чтобы требовать
 * подтверждения. Два ключа, две разные задачи — и объединять их
 * нельзя именно потому, что вход по PIN обязан работать всегда.
 *
 * ⚠️ Ключ Keystore исчезает при сбросе устройства, при удалении
 * приложения и — на части прошивок — при смене экрана блокировки.
 * Вместе с ним становится нечитаемой база. Это не новое ограничение:
 * восстановление и раньше делалось ключом восстановления (M6), и
 * ровно на такой случай он и существует.
 */
object HardwareKey {

    /**
     * Возвращает аппаратный секрет, создавая его при первом обращении.
     *
     * 🔐 Бросает исключение, если аппаратное хранилище недоступно.
     * Молчаливый откат к «ключу из одного PIN» был бы худшим исходом:
     * пользователь видел бы работающее приложение и не знал, что его
     * защита тихо понизилась до перебираемой за часы.
     */
    @Synchronized
    fun secret(context: Context): ByteArray {
        val file = File(context.filesDir, SECRET_FILE)

        if (file.exists()) {
            return decrypt(file.readBytes())
        }

        val fresh = ByteArray(hardwareSecretLen().toInt())
        SecureRandom().nextBytes(fresh)

        // Запись до возврата: секрет, отданный вызывающему и не
        // сохранённый, означал бы базу под ключом, который больше
        // никогда не повторить.
        file.writeBytes(encrypt(fresh))

        return fresh
    }

    /** Заведён ли уже аппаратный секрет на этом устройстве. */
    fun exists(context: Context): Boolean = File(context.filesDir, SECRET_FILE).exists()

    /**
     * Шифрует секрет ключом из Keystore.
     *
     * Формат записи: один байт длины IV, сам IV, затем шифротекст
     * с тегом. Длина IV пишется явно, а не считается константой:
     * GCM допускает разные длины, и реализация вправе менять её
     * между версиями Android.
     */
    private fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())

        val iv = cipher.iv
        val payload = cipher.doFinal(plain)

        return byteArrayOf(iv.size.toByte()) + iv + payload
    }

    private fun decrypt(record: ByteArray): ByteArray {
        // Длина проверяется до чтения: запись короче заголовка означает
        // испорченный файл, и обращение по индексу упало бы с менее
        // понятной ошибкой.
        require(record.isNotEmpty()) { "аппаратный секрет: пустой файл" }

        val ivLength = record[0].toInt()

        require(ivLength in 1..MAX_IV_BYTES && record.size > 1 + ivLength) {
            "аппаратный секрет: испорченный файл"
        }

        val iv = record.copyOfRange(1, 1 + ivLength)
        val payload = record.copyOfRange(1 + ivLength, record.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, iv))

        return cipher.doFinal(payload)
    }

    /**
     * 🔐 Удаляет ключ-обёртку из хранилища устройства.
     *
     * Вызывается при удалении аккаунта. После этого файл [SECRET_FILE]
     * нерасшифровываем **необратимо**: ключ невынимаем, копии его
     * байтов не существует нигде, и восстановить его нечем.
     *
     * Именно это делает стирание настоящим: остатки базы, поднятые
     * с флеш-памяти после удаления файлов, открыть будет нечем —
     * второй половины ключа больше нет ни у кого, включая владельца.
     *
     * Молча ничего не делает, если ключа нет: удаление аккаунта,
     * заведённого до появления аппаратной привязки, — штатный случай.
     */
    fun destroy() {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }

        if (store.containsAlias(ALIAS)) {
            store.deleteEntry(ALIAS)
        }
    }

    /** Возвращает ключ Keystore, создавая его при первом обращении. */
    private fun key(): SecretKey {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }

        (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        return generate()
    }

    /**
     * Создаёт ключ в аппаратном хранилище.
     *
     * 🔐 StrongBox — отдельный защищённый чип, а не TEE на том же
     * кристалле. Он есть не на всех устройствах, поэтому запрос идёт
     * с откатом: при `StrongBoxUnavailableException` ключ создаётся
     * в обычном аппаратном хранилище. Откат именно к нему, а не
     * к программному ключу: последний лежал бы в файлах приложения
     * и уехал бы вместе с ними, то есть не решал бы задачу вовсе.
     */
    private fun generate(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)

        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_BITS)
            // Каждое шифрование со своим IV: повтор пары «ключ, nonce»
            // в GCM раскрывает открытый текст обоих сообщений.
            .setRandomizedEncryptionRequired(true)

        runCatching {
            generator.init(builder.setIsStrongBoxBacked(true).build())

            return generator.generateKey()
        }.onFailure { failure ->
            // Только отсутствие StrongBox: прочие сбои означают
            // неисправное хранилище, и глотать их нельзя.
            if (failure !is StrongBoxUnavailableException) {
                throw failure
            }
        }

        generator.init(builder.build())

        return generator.generateKey()
    }

    /** Алиас ключа в Android Keystore. */
    private const val ALIAS = "aegis.storage.kek"

    /** Имя файла с зашифрованным секретом. */
    private const val SECRET_FILE = "aegis.hw"

    private const val PROVIDER = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_BITS = 256
    private const val GCM_TAG_BITS = 128

    /** Разумный предел длины IV: GCM использует 12 байт, запас на вырост. */
    private const val MAX_IV_BYTES = 16
}
