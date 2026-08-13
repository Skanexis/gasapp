// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.aegis.FfiException
import uniffi.aegis.coreVersion
import uniffi.aegis.formatSafetyNumber
import uniffi.aegis.protocolVersion

/**
 * Экран проверки моста FFI — задача M1 «Hello from Rust».
 *
 * Показывает три значения, вычисленные Rust-ядром: версию ядра, версию
 * протокола и отформатированный safety number. Заменяется реальными
 * экранами в M4.
 *
 * 🔐 Криптографии здесь нет и быть не может: activity вызывает готовые
 * функции ядра и печатает результат (правило 1, `check-no-crypto-in-ui.sh`).
 */
class MainActivity : AppCompatActivity() {

    private lateinit var coreVersionText: TextView
    private lateinit var protocolVersionText: TextView
    private lateinit var safetyNumberText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        coreVersionText = findViewById(R.id.core_version_text)
        protocolVersionText = findViewById(R.id.protocol_version_text)
        safetyNumberText = findViewById(R.id.safety_number_text)

        loadCoreInfo()
    }

    /**
     * Читает значения из ядра.
     *
     * Вызовы уходят на `Dispatchers.IO`: переход через границу FFI
     * блокирующий, и держать на нём главный поток нельзя. `lifecycleScope`
     * вместо самодельного скоупа — корутина отменяется вместе с activity
     * и не пишет в уже уничтоженные view.
     */
    private fun loadCoreInfo() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    CoreInfo(
                        coreVersion = coreVersion(),
                        protocolVersion = protocolVersion(),
                        // Отпечатки по 30 байт — формат из ADR-022.
                        // Здесь это заглушечные значения: настоящие
                        // появятся вместе с сессиями в M4.
                        safetyNumber = formatSafetyNumber(
                            ByteArray(FINGERPRINT_LEN) { 0x11 },
                            ByteArray(FINGERPRINT_LEN) { 0x22 },
                        ),
                    )
                }
            }

            result
                .onSuccess(::render)
                // FfiException ловится отдельно от прочих: текст ошибки ядра
                // намеренно неинформативен, поэтому в UI показывается
                // собственная строка, а не `e.message`.
                .onFailure { error ->
                    if (error is FfiException) {
                        coreVersionText.text = getString(R.string.ffi_error)
                    } else {
                        throw error
                    }
                }
        }
    }

    private fun render(info: CoreInfo) {
        coreVersionText.text = getString(R.string.ffi_core_version, info.coreVersion)
        protocolVersionText.text =
            getString(R.string.ffi_protocol_version, info.protocolVersion.toInt())
        safetyNumberText.text = getString(R.string.ffi_safety_number, info.safetyNumber)
    }

    private data class CoreInfo(
        val coreVersion: String,
        val protocolVersion: UByte,
        val safetyNumber: String,
    )

    private companion object {
        /** Длина отпечатка identity-ключа в байтах (ADR-022). */
        const val FINGERPRINT_LEN = 30
    }
}
