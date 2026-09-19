// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.QrDrawable
import uniffi.aegis.FfiException
import uniffi.aegis.computeFingerprint
import uniffi.aegis.formatSafetyNumber
import uniffi.aegis.generateIdentityPublicKey
import uniffi.aegis.safetyNumberQr

/**
 * Экран сверки safety number.
 *
 * Единственное место, где криптографическую проверку выполняет
 * **человек**, поэтому форма здесь — решение о безопасности (ADR-022):
 * 60 десятичных цифр, 12 групп по 5, моноширинный шрифт.
 *
 * 🔐 Само число считает ядро: итеративный SHA-512 на 5200 раундов.
 * Повторять вычисление в Kotlin значило бы завести вторую реализацию,
 * которая разойдётся с первой — и пользователь сверил бы не то.
 */
class SafetyNumberActivity : AppCompatActivity() {

    private lateinit var digits: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        // 🔐 Касания через накрывающее окно отбрасываются:
        // отметка «сверено» снимает предупреждение о подмене ключа,
        // то есть подменённое нажатие стоит дороже неудобства
        // (MASVS PLATFORM-3).
        SecureWindow.blockObscuredTouches(this)

        setContentView(R.layout.activity_safety_number)

        digits = findViewById(R.id.safety_number_digits)

        val peerName = intent.getStringExtra(EXTRA_PEER_NAME).orEmpty()
        findViewById<TextView>(R.id.safety_number_peer).text =
            getString(R.string.safety_number_peer, peerName)

        findViewById<AegisButton>(R.id.mark_verified).setOnClickListener {
            // Отметка ставится только вручную: автоматическая обесценила
            // бы верификацию, которая означает «я лично сверил».
            finish()
        }
        findViewById<AegisButton>(R.id.clear_verified).setOnClickListener { finish() }

        loadSafetyNumber()
    }

    /**
     * Считает safety number в ядре.
     *
     * Вызовы уходят на `Dispatchers.IO`: переход через границу FFI
     * блокирующий, а 5200 раундов SHA-512 на слабом телефоне заметны,
     * и держать на них главный поток нельзя.
     */
    private fun loadSafetyNumber() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val local = generateIdentityPublicKey()
                    val remote = generateIdentityPublicKey()

                    formatSafetyNumber(
                        computeFingerprint(local, LOCAL_ID),
                        computeFingerprint(remote, REMOTE_ID),
                    )
                }
            }

            result
                .onSuccess { number ->
                    digits.text = number

                    // QR строится из тех же цифр, что показаны рядом:
                    // разойтись они не могут, потому что источник один.
                    renderQr(number)
                }
                // FfiException ловится отдельно: текст ошибки ядра
                // намеренно неинформативен, поэтому в UI показывается
                // собственная строка, а не `e.message`.
                .onFailure { error ->
                    if (error is FfiException) {
                        digits.text = getString(R.string.ffi_error)
                    } else {
                        throw error
                    }
                }
        }
    }


    /**
     * Рисует QR-код рядом с цифрами.
     *
     * Ошибка построения не показывается: цифры уже на экране, и сверить
     * можно ими. Пустой QR лучше сообщения об ошибке, которое ничего
     * не говорит пользователю о том, что делать.
     */
    private fun renderQr(number: String) {
        val matrix = runCatching { safetyNumberQr(number.filter { it.isDigit() }) }
            .getOrNull()
            ?: return

        val view = findViewById<ImageView>(R.id.safety_number_qr)
        val side = view.width.takeIf { it > 0 } ?: QR_FALLBACK_PX

        view.setImageBitmap(QrDrawable.render(matrix, side))
    }
    companion object {
        /** Имя собеседника для подписи экрана. */
        const val EXTRA_PEER_NAME = "peer_name"

        /** Идентификатор локальной стороны для привязки отпечатка. */
        private val LOCAL_ID = "local".toByteArray()

        /** Идентификатор удалённой стороны. */
        private val REMOTE_ID = "remote".toByteArray()

        /**
         * Сторона QR, если разметка ещё не измерена.
         *
         * Нужна при первой отрисовке: view сообщает ширину только
         * после укладки, а код строится сразу.
         */
        private const val QR_FALLBACK_PX = 660
    }
}
