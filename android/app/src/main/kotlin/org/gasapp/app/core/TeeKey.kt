// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * 🔐 Вторая половина ключа базы — ответ Android Keystore на PIN (схема v3).
 *
 * # Что было не так со схемой v2 ([HardwareKey])
 *
 * Ключ Keystore расшифровывал 32 случайных байта, и дальше они жили
 * в памяти приложения. Ключ не требовал ни подтверждения, ни
 * разблокированного экрана. Кто один раз выполнил код от имени
 * приложения — root, инструмент криминалистики на изъятом телефоне, —
 * получал эти байты и перебирал шестизначный PIN уже **вне** телефона,
 * на видеокартах, за часы. Счётчик неверных попыток в переборе не
 * участвовал вовсе: он живёт в коде приложения.
 *
 * # Как устроено теперь
 *
 * Растянутый `Argon2id` PIN проходит [ROUNDS] раз через HMAC-SHA256
 * ключом, который из Keystore не извлекается. Каждый раунд — отдельная
 * операция внутри защищённого оборудования. Ответ зависит от PIN,
 * поэтому получить его один раз и унести нельзя:
 *
 *  * каждая попытка перебора требует **этого** телефона;
 *  * попытки идут по очереди — оборудование одно, видеокарты не помогут;
 *  * на Android 11+ ключ работает только при разблокированном экране
 *    телефона (`setUnlockedDeviceRequired`): изъятый запертый телефон
 *    не отвечает вовсе.
 *
 * # Сколько это стоит атакующему
 *
 * ⚠️ Честная оценка, а не обещание. Операция Keystore на TEE — единицы
 * миллисекунд; [ROUNDS] раундов — порядка 0,1–0,3 с на попытку при
 * посчитанном заранее `Argon2id`. Миллион вариантов шестизначного PIN —
 * в среднем сутки-трое **на самом телефоне**, разблокированном и под
 * root. Против такого противника шесть цифр — мало; длинный PIN
 * отодвигает перебор на годы. Против снятого файла, запертого телефона
 * и перебора на стороне схема держит полностью.
 *
 * StrongBox здесь не просится намеренно: он медленнее TEE в десятки
 * раз, и [ROUNDS] раундов превратились бы в секунды на каждом входе.
 */
object TeeKey {

    /** Сколько раундов HMAC в оборудовании на одну попытку. */
    const val ROUNDS = 64

    /**
     * Цепочка HMAC над растянутым PIN внутри Keystore.
     *
     * Создаёт ключ при первом обращении.
     *
     * @throws Exception Keystore недоступен или ключ не работает (например,
     *   экран телефона заперт). Молчаливого отката нет: база под более
     *   слабым ключом хуже, чем отказ открыть.
     */
    @Synchronized
    fun respond(stretched: ByteArray): ByteArray {
        val mac = Mac.getInstance(MAC_ALGORITHM)
        mac.init(key())

        var state = mac.doFinal(DOMAIN + stretched)
        repeat(ROUNDS - 1) {
            val next = mac.doFinal(state)
            state.fill(0)
            state = next
        }

        return state
    }

    /** Заведён ли ключ. */
    fun exists(): Boolean = runCatching { keyStore().containsAlias(ALIAS) }.getOrDefault(false)

    /**
     * Где живёт ключ: StrongBox, TEE или программно — ответ системы.
     *
     * 🔐 Для Центра безопасности. Прежде он спрашивал ключ схемы v2
     * ([HardwareKey]), которого после перехода на v3 нет, а у новых
     * аккаунтов не было никогда: проверка «аппаратный ключ» проваливалась
     * у всех, а ключ, на котором держится база, не проверялся вовсе
     * (аудит 2026-10-02, A-7).
     *
     * `null` — ключа нет или спросить не удалось. Ключ здесь не создаётся.
     */
    fun securityLevel(): KeyAttestation.Level? = runCatching {
        val key = keyStore().getKey(ALIAS, null) as? SecretKey ?: return null
        val info = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
            .getKeySpec(key, android.security.keystore.KeyInfo::class.java)
            as android.security.keystore.KeyInfo

        HardwareKey.levelOf(info)
    }.getOrNull()

    /**
     * Удаляет ключ. После этого база схемы v3 не открывается ничем —
     * вызывать только при стирании аккаунта.
     */
    fun destroy() {
        keyStore().deleteEntry(ALIAS)
    }

    private fun key(): SecretKey =
        keyStore().getKey(ALIAS, null) as? SecretKey ?: generate()

    private fun generate(): SecretKey {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setKeySize(KEY_BITS)

        // Android 9–10: у флага были ошибки прошивок, после которых ключ
        // переставал работать и при разблокированном экране, — а без
        // ключа база не открывается. С Android 11 он надёжен.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUnlockedDeviceRequired(true)
        }

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
            .apply { init(builder.build()) }
            .generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "gasapp_storage_tee_v3"
    private const val MAC_ALGORITHM = "HmacSHA256"
    private const val KEY_BITS = 256

    /** Разделитель: этот ключ не отвечает ни на что, кроме схемы v3. */
    private val DOMAIN = "GasApp storage TEE v3".toByteArray()
}
