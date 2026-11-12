// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.core.ContactLinks
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureClipboard
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.QrDrawable
import org.gasapp.app.ui.initialsOf

/**
 * Экран собственного профиля: `@имя` и QR-код.
 *
 * # Два способа найти человека
 *
 * **Имя** — чтобы найти через поиск: ключ по нему назовёт сервер,
 * а сверит открытый журнал ключей. **QR** — при встрече: в коде сам
 * identity-ключ, его сканируют встроенным сканером, и ключ приходит
 * мимо сети — это точная сверка.
 *
 * 🔐 Содержимое QR строит ядро (`ownContactLink` → `contactLinkQr`),
 * а не Kotlin: вторая реализация кодирования разошлась бы с первой.
 * Текстом эта строка больше не показывается и не отправляется —
 * «Поделиться» отдаёт только имя.
 */
class ProfileActivity : AppCompatActivity() {

    private lateinit var qrView: ImageView

    /** Содержимое QR — только для отрисовки кода. */
    private var qrPayload: String = ""
    private var username: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_profile)
        findViewById<View>(R.id.profile_back).setOnClickListener { finish() }

        qrView = findViewById(R.id.profile_qr)

        findViewById<GasAppButton>(R.id.profile_copy).setOnClickListener { copyUsername() }
        findViewById<GasAppButton>(R.id.profile_share).setOnClickListener { shareUsername() }
        findViewById<GasAppButton>(R.id.profile_share_link).setOnClickListener { shareContactLink() }

        loadProfile()
    }

    /** 🔐 Код с ключом не остаётся на экране, уходящем в фон. */
    override fun onStop() {
        super.onStop()
        qrView.setImageDrawable(null)
    }

    override fun onStart() {
        super.onStart()

        if (qrPayload.isNotEmpty()) renderQr(qrPayload)
    }

    private fun loadProfile() {
        lifecycleScope.launch {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().ownUsername() to Core.messenger().ownContactLink()
                }
            }

            val (name, payload) = loaded.getOrElse {
                findViewById<TextView>(R.id.profile_username).setText(R.string.ffi_error)
                return@launch
            }

            username = name
            qrPayload = payload

            findViewById<TextView>(R.id.profile_username).text = when (name) {
                null -> getString(R.string.profile_no_username)
                else -> getString(R.string.contact_username, name)
            }
            findViewById<TextView>(R.id.profile_avatar).text = initialsOf(name.orEmpty())

            renderQr(payload)
        }
    }

    /** Рисует QR; ошибка построения не мешает поделиться именем. */
    private fun renderQr(payload: String) {
        val matrix = runCatching { uniffi.gasapp.contactLinkQr(payload) }
            .getOrNull()
            ?: return

        val side = qrView.width.takeIf { it > 0 } ?: QR_FALLBACK_PX

        qrView.setImageBitmap(QrDrawable.render(matrix, side))
    }

    private fun copyUsername() {
        val name = username ?: return

        // Имя — не секрет, но и в буфере обмена, который читает любое
        // приложение на переднем плане, ему незачем жить дольше вставки.
        SecureClipboard.copySensitive(
            context = this,
            label = getString(R.string.profile_title),
            text = getString(R.string.contact_username, name),
        )

        // На Android 13+ подтверждает система (см. SecureClipboard).
        if (!SecureClipboard.systemConfirmsCopy) {
            GasAppToast.show(this, R.string.profile_copied, GasAppToast.Tone.Success)
        }
    }

    /**
     * Отдаёт другому приложению только имя.
     *
     * 🔐 Ни ключа, ни чего-либо ещё: получатель найдёт по имени, а ключ
     * сверит журнал ключей — или QR при встрече.
     */
    /**
     * Отдаёт ссылку-контакт — то же, что в QR-коде, текстом.
     *
     * Для тех, с кем не встретиться: получатель вставляет ссылку в «Новый
     * чат» и может писать сразу. 🔐 Ссылка несёт ключ, и подменивший её
     * по дороге подставил бы свой: верить ей можно настолько, насколько
     * каналу, которым она пришла. Имя из ссылки ядро получателя сверяет
     * с сервером, так что одной подмены ссылки для подлога мало.
     */
    private fun shareContactLink() {
        val link = qrPayload.takeIf { it.isNotEmpty() } ?: return

        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_TEXT, getString(R.string.profile_share_link_text, ContactLinks.webLink(link))),
                getString(R.string.profile_share_link),
            ),
        )
    }

    private fun shareUsername() {
        val name = username ?: return

        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_TEXT, getString(R.string.profile_share_text, name)),
                getString(R.string.profile_share),
            ),
        )
    }

    private companion object {
        /**
         * Сторона QR, если разметка ещё не измерена.
         *
         * View сообщает ширину только после укладки, а код строится сразу.
         */
        const val QR_FALLBACK_PX = 700
    }
}
