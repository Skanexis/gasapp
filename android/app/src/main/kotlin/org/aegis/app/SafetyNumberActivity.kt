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
import org.aegis.app.components.AegisToast
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisDialog
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.QrDrawable
import android.view.View
import org.aegis.app.core.Core
import uniffi.aegis.FfiException
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
 *
 * # Что здесь было
 *
 * 🔴 Экран показывал safety number **двух случайных ключей**:
 * `generateIdentityPublicKey()` дважды — две свежие пары на каждое
 * открытие. Цифры менялись от показа к показу, не совпадали
 * у собеседников никогда и не относились ни к одному из них.
 * Кнопка «Отметить сверенным» закрывала экран, и только.
 *
 * Абзац выше при этом уже был — и описывал экран, которого не было.
 *
 * Сверка этих цифр — единственное, что защищает сквозное шифрование
 * от подмены ключей сервером. Её не было, а экран, выглядевший
 * как она, был: хуже, чем отсутствие экрана.
 *
 * # Почему контакт задаётся счётом, а не именем
 *
 * Имя неоднозначно. После смены ключа под одним именем живут две
 * записи (см. `Contact.keyChanged`), и поиск по имени мог бы показать
 * цифры **прежнего** ключа — ровно тогда, когда сверка нужнее всего.
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
        findViewById<android.view.View>(R.id.screen_back).setOnClickListener { finish() }

        digits = findViewById(R.id.safety_number_digits)

        val peerName = intent.getStringExtra(EXTRA_PEER_NAME).orEmpty()
        findViewById<TextView>(R.id.safety_number_peer).text =
            getString(R.string.safety_number_peer, peerName)

        accountId = intent.getStringExtra(EXTRA_ACCOUNT_ID).orEmpty()

        findViewById<AegisButton>(R.id.mark_verified).setOnClickListener {
            // Отметка ставится только вручную: автоматическая обесценила
            // бы верификацию, которая означает «я лично сверил».
            setVerified(true)
        }
        findViewById<AegisButton>(R.id.clear_verified).setOnClickListener { setVerified(false) }

        findViewById<AegisButton>(R.id.scan_safety_number).apply {
            setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.ic_qr, 0, 0, 0)
            compoundDrawablesRelative[0]?.setTint(currentTextColor)
            setOnClickListener {
                scan.launch(ScanActivity.Request(R.string.safety_scan, R.string.scan_hint_safety))
            }
        }

        loadSafetyNumber()
    }

    /** Счёт собеседника: по нему ядро находит его ключ. */
    private var accountId: String = ""

    /** Показанные цифры — с ними сравнивается код собеседника. */
    private var shownDigits: String = ""

    private val scan = registerForActivityResult(ScanActivity.Contract()) { payload ->
        if (payload != null) compareScanned(payload)
    }

    /**
     * 🔐 Сравнивает отсканированный код с показанными цифрами.
     *
     * Safety number у обеих сторон одинаков (он строится из обоих
     * ключей в каноническом порядке), и его QR — те же 60 цифр. Совпадение
     * всех цифр — ровно то, что человек проверял бы глазами, только
     * без пропусков. Несовпадение значит: у собеседника на экране другой
     * ключ — подмена либо не тот человек.
     */
    private fun compareScanned(payload: String) {
        val scanned = payload.filter { it in '0'..'9' }

        if (shownDigits.isNotEmpty() && scanned == shownDigits && payload.length == shownDigits.length) {
            setVerified(true)

            return
        }

        AegisDialog(this)
            .title(R.string.safety_scan_mismatch_title)
            .message(R.string.safety_scan_mismatch_body)
            .primary(R.string.safety_scan_mismatch_ok, AegisDialog.Tone.Danger)
            .show()
    }

    /**
     * 🔐 Ставит или снимает отметку о сверке — в ядре.
     *
     * Экран закрывается только после того, как отметка записана:
     * закрыться при отказе значило бы показать человеку, что сверка
     * засчитана, когда она не засчитана.
     */
    private fun setVerified(verified: Boolean) {
        if (accountId.isEmpty()) {
            return
        }

        lifecycleScope.launch {
            val saved = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().setContactVerified(
                        accountId,
                        verified,
                        System.currentTimeMillis(),
                    )
                }.isSuccess
            }

            if (saved) {
                finish()
            } else {
                AegisToast.show(this@SafetyNumberActivity, R.string.ffi_error, AegisToast.Tone.Error)
            }
        }
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
            // 🔐 Без счёта собеседника цифр нет — и подставлять вместо
            // них нечего. Любое «правдоподобное» число здесь было бы
            // тем самым дефектом, который тут исправлен.
            if (accountId.isEmpty()) {
                showUnavailable()

                return@launch
            }

            val result = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().safetyNumberWith(accountId) }
            }

            result
                .onSuccess { number ->
                    digits.text = number
                    shownDigits = number.filter { it in '0'..'9' }
                    renderMarkButtons()

                    // QR строится из тех же цифр, что показаны рядом:
                    // разойтись они не могут, потому что источник один.
                    renderQr(number)
                }
                // FfiException ловится отдельно: текст ошибки ядра
                // намеренно неинформативен, поэтому в UI показывается
                // собственная строка, а не `e.message`.
                .onFailure { error ->
                    if (error is FfiException || error is IllegalStateException) {
                        showUnavailable()
                    } else {
                        throw error
                    }
                }
        }
    }

    /**
     * Показывает одну кнопку из двух — ту, что меняет текущее состояние.
     *
     * Прежде обе стояли всегда: «Снять отметку» у контакта, который
     * не был отмечен, и «Отметить» у уже отмеченного. По экрану нельзя
     * было понять, сверен ли собеседник.
     */
    private suspend fun renderMarkButtons() {
        val verified = withContext(Dispatchers.IO) {
            runCatching {
                Core.messenger().contacts().firstOrNull { it.accountId == accountId }?.verified
            }.getOrNull()
        } ?: return

        findViewById<AegisButton>(R.id.scan_safety_number).visibility = if (verified) View.GONE else View.VISIBLE
        findViewById<AegisButton>(R.id.mark_verified).visibility = if (verified) View.GONE else View.VISIBLE
        findViewById<AegisButton>(R.id.clear_verified).visibility = if (verified) View.VISIBLE else View.GONE
    }

    /**
     * Цифр нет: контакт неизвестен либо хранилище заперто.
     *
     * 🔐 Кнопки отметки прячутся. Отметить сверенным контакт, цифры
     * которого не показаны, значило бы засчитать сверку, которой
     * не было.
     */
    private fun showUnavailable() {
        digits.text = getString(R.string.ffi_error)
        findViewById<AegisButton>(R.id.scan_safety_number).visibility = View.GONE
        findViewById<AegisButton>(R.id.mark_verified).visibility = View.GONE
        findViewById<AegisButton>(R.id.clear_verified).visibility = View.GONE
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
        /** Имя собеседника — только для подписи экрана. */
        const val EXTRA_PEER_NAME = "peer_name"

        /**
         * Счёт собеседника. По нему, а не по имени, ядро находит ключ:
         * имя после смены ключа неоднозначно.
         */
        const val EXTRA_ACCOUNT_ID = "account_id"

        /**
         * Сторона QR, если разметка ещё не измерена.
         *
         * Нужна при первой отрисовке: view сообщает ширину только
         * после укладки, а код строится сразу.
         */
        private const val QR_FALLBACK_PX = 660
    }
}
