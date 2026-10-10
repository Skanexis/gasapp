// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.content.Context
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
     * Ключ Keystore не ответил.
     *
     * 🔐 Это не «неверный PIN»: PIN здесь ещё ни с чем не сверялся.
     * Экран входа обязан различать эти случаи — иначе человек с верным
     * PIN видит «Неверный PIN», а счётчик попыток ведёт его к стиранию.
     *
     * @property lost ключ был создан и исчез: база под ним не откроется
     *   уже никогда. `false` — Keystore отказал сейчас (например, экран
     *   телефона заперт) и может ответить позже.
     */
    class KeyUnavailable(val lost: Boolean, cause: Throwable? = null) : Exception(cause)

    /**
     * Цепочка HMAC над растянутым PIN внутри Keystore.
     *
     * Создаёт ключ при первом обращении — и только при первом: отметка
     * о создании лежит рядом с базой. Ключ, который был и пропал,
     * заново **не создаётся**: новый ключ дал бы другой ответ, база
     * «не открылась бы верным PIN», и отличить это от ошибки ввода было
     * бы нечем (проверка на устройстве 2026-10-10).
     *
     * @throws KeyUnavailable Keystore недоступен, ключ не работает либо
     *   утрачен. Молчаливого отката нет: база под более слабым ключом
     *   хуже, чем отказ открыть.
     */
    @Synchronized
    fun respond(context: Context, stretched: ByteArray): ByteArray {
        val key = try {
            existing() ?: run {
                if (marker(context).exists()) throw KeyUnavailable(lost = true)

                generate().also { runCatching { marker(context).createNewFile() } }
            }
        } catch (failure: KeyUnavailable) {
            throw failure
        } catch (failure: Exception) {
            throw KeyUnavailable(lost = false, cause = failure)
        }

        try {
            val mac = Mac.getInstance(MAC_ALGORITHM)
            mac.init(key)

            var state = mac.doFinal(DOMAIN + stretched)
            repeat(ROUNDS - 1) {
                val next = mac.doFinal(state)
                state.fill(0)
                state = next
            }

            return state
        } catch (failure: Exception) {
            throw KeyUnavailable(lost = false, cause = failure)
        }
    }

    /** Отметка «ключ уже создавался» — вне резервных копий, как и база. */
    private fun marker(context: Context) = java.io.File(context.noBackupFilesDir, MARKER)

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
    fun destroy(context: Context) {
        keyStore().deleteEntry(ALIAS)
        marker(context).delete()
    }

    private fun existing(): SecretKey? = keyStore().getKey(ALIAS, null) as? SecretKey

    /**
     * Создаёт ключ.
     *
     * # ⚠️ `setUnlockedDeviceRequired` — только с Android 15
     *
     * На Android 11–14 ключ с этим флагом привязан к блокировке экрана
     * телефона, и проверка на устройстве (API 34, 2026-10-10) показала,
     * чем это кончается:
     *
     *  * на телефоне **без блокировки экрана** ключ не создаётся вовсе —
     *    регистрация падала с «Ошибка ядра»;
     *  * стоит человеку **снять** блокировку экрана — система уничтожает
     *    ключ. База не открывается уже ничем, а приложение отвечало
     *    «Неверный PIN» на верный и считало попытки до стирания.
     *
     * Потерять всю переписку из-за настройки экрана — хуже, чем то, от
     * чего флаг защищал (ответ Keystore на запертом изъятом телефоне;
     * от перебора вне телефона ключ защищает и без флага). С Android 15
     * система держит такие ключи и без блокировки экрана и не
     * уничтожает их при её снятии — там флаг ставится. Не создался
     * с флагом — создаётся без него.
     */
    private fun generate(): SecretKey {
        fun make(unlockedOnly: Boolean): SecretKey {
            val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setKeySize(KEY_BITS)

            if (unlockedOnly) builder.setUnlockedDeviceRequired(true)

            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
                .apply { init(builder.build()) }
                .generateKey()
        }

        if (Build.VERSION.SDK_INT < UNLOCKED_ONLY_SINCE) return make(unlockedOnly = false)

        return runCatching { make(unlockedOnly = true) }.getOrElse {
            runCatching { keyStore().deleteEntry(ALIAS) }
            make(unlockedOnly = false)
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "gasapp_storage_tee_v3"
    private const val MARKER = "storage_tee_v3.created"

    /** Android 15: с него флаг «только при разблокированном экране» безопасен. */
    private const val UNLOCKED_ONLY_SINCE = 35
    private const val MAC_ALGORITHM = "HmacSHA256"
    private const val KEY_BITS = 256

    /** Разделитель: этот ключ не отвечает ни на что, кроме схемы v3. */
    private val DOMAIN = "GasApp storage TEE v3".toByteArray()
}
