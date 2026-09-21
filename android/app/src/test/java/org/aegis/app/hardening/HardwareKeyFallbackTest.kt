// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import java.lang.reflect.InvocationTargetException
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.aegis.app.core.HardwareKey
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 На устройстве без StrongBox ключ создаётся в обычном TEE.
 *
 * # Что здесь проверяется
 *
 * `HardwareKey.generate` обещал откат: при `StrongBoxUnavailableException`
 * ключ создаётся в обычном аппаратном хранилище. Но
 * `builder.setIsStrongBoxBacked(true)` меняет сам построитель, и повторный
 * `builder.build()` снова просил StrongBox.
 *
 * На любом устройстве без StrongBox — эмулятор и многие телефоны —
 * регистрация не проходила вовсе («Core error»), а каждый вход
 * засчитывался как неверный PIN. Нашлось аудитом и подтвердилось
 * первым же запуском на эмуляторе.
 *
 * Здесь `AndroidKeyStore` подменён поставщиком, который ведёт себя
 * как Keystore устройства без StrongBox.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class HardwareKeyFallbackTest {

    @After
    fun restoreProviders() {
        Security.removeProvider(FAKE_KEYSTORE)
    }

    @Test
    fun hardware_key_falls_back_when_strongbox_is_missing() {
        Security.removeProvider(FAKE_KEYSTORE)
        assertEquals(1, Security.insertProviderAt(StrongBoxlessKeyStore(), 1))
        StrongBoxlessKeyGenerator.requests.clear()

        val generate = HardwareKey::class.java.getDeclaredMethod("generate")
            .apply { isAccessible = true }

        try {
            generate.invoke(HardwareKey)
        } catch (failure: InvocationTargetException) {
            fail(
                "откат не сработал: ${failure.cause}; " +
                    "запросы StrongBox по попыткам: ${StrongBoxlessKeyGenerator.requests}",
            )
        }

        assertEquals(
            "вторая попытка обязана идти без StrongBox",
            listOf(true, false),
            StrongBoxlessKeyGenerator.requests,
        )
    }

    private companion object {
        const val FAKE_KEYSTORE = "AndroidKeyStore"
    }
}

/** Keystore устройства без StrongBox. */
class StrongBoxlessKeyStore : Provider("AndroidKeyStore", 1.0, "без StrongBox") {
    init {
        put("KeyGenerator.AES", StrongBoxlessKeyGenerator::class.java.name)
    }
}

class StrongBoxlessKeyGenerator : KeyGeneratorSpi() {

    private var spec: KeyGenParameterSpec? = null

    override fun engineInit(random: SecureRandom?) = Unit

    override fun engineInit(params: AlgorithmParameterSpec?, random: SecureRandom?) {
        spec = params as KeyGenParameterSpec
        requests += params.isStrongBoxBacked
    }

    override fun engineInit(keysize: Int, random: SecureRandom?) = Unit

    override fun engineGenerateKey(): SecretKey {
        if (spec?.isStrongBoxBacked == true) {
            throw StrongBoxUnavailableException()
        }

        return SecretKeySpec(ByteArray(32), "AES")
    }

    companion object {
        val requests = mutableListOf<Boolean>()
    }
}
