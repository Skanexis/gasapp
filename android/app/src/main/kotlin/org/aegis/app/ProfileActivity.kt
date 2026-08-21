// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.QrDrawable
import uniffi.aegis.FfiException

/**
 * Экран собственного профиля: QR и ссылка для обмена контактами.
 *
 * # Зачем это нужно
 *
 * Ключ, полученный от сервера, приходится принимать на веру. Ключ,
 * снятый с экрана человека, стоящего рядом, проверять не нужно —
 * канал доверия проходит мимо сети. Этот экран и есть такой канал.
 *
 * 🔐 Ссылку строит ядро, а не Kotlin. Вторая реализация кодирования
 * разошлась бы с первой, и сканирование давало бы «неверную ссылку»
 * там, где ссылка верна.
 */
class ProfileActivity : AppCompatActivity() {

    private lateinit var linkView: TextView
    private lateinit var qrView: ImageView

    /** Ссылка, показанная на экране; пуста, пока ядро не ответило. */
    private var link: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_profile)

        linkView = findViewById(R.id.profile_link)
        qrView = findViewById(R.id.profile_qr)

        findViewById<AegisButton>(R.id.profile_copy).setOnClickListener { copyLink() }
        findViewById<AegisButton>(R.id.profile_share).setOnClickListener { shareLink() }

        loadProfile()
    }

    /**
     * 🔐 Убирает ссылку при уходе с экрана.
     *
     * Ссылка содержит identity-ключ и имя, то есть отвечает на вопрос
     * «кто пользуется этим телефоном». В снимке для переключателя
     * задач, который система делает при сворачивании, ей не место.
     */
    override fun onStop() {
        super.onStop()

        linkView.text = ""
        qrView.setImageDrawable(null)
    }

    override fun onStart() {
        super.onStart()

        if (link.isNotEmpty()) {
            render(link)
        }
    }

    /**
     * Запрашивает ссылку у ядра.
     *
     * Уходит на `Dispatchers.IO`: переход через границу FFI
     * блокирующий, а внутри — чтение зашифрованного хранилища.
     */
    private fun loadProfile() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().ownContactLink() }
            }

            result
                .onSuccess { uri ->
                    link = uri
                    render(uri)
                }
                // Текст ошибки ядра намеренно неинформативен, поэтому
                // показывается собственная строка, а не `error.message`.
                .onFailure { error ->
                    if (error is FfiException || error is IllegalStateException) {
                        linkView.text = getString(R.string.ffi_error)
                    } else {
                        throw error
                    }
                }
        }
    }

    private fun render(uri: String) {
        linkView.text = uri

        val username = uri.substringAfter(NAME_PARAM, missingDelimiterValue = "")
        findViewById<TextView>(R.id.profile_username).text = when {
            username.isEmpty() -> getString(R.string.profile_no_username)
            else -> getString(R.string.contact_username, decode(username))
        }

        renderQr(uri)
    }

    /**
     * Рисует QR ссылки.
     *
     * Ошибка построения не показывается отдельным сообщением: ссылка
     * уже на экране текстом, и передать контакт можно ею.
     */
    private fun renderQr(uri: String) {
        // Кодируется та же строка, что показана ниже текстом: собери
        // код заново из разобранных частей — и пропущенное поле
        // развело бы QR с тем, что пользователь видит и диктует.
        val matrix = runCatching { uniffi.aegis.contactLinkQr(uri) }
            .getOrNull()
            ?: return

        val side = qrView.width.takeIf { it > 0 } ?: QR_FALLBACK_PX

        qrView.setImageBitmap(QrDrawable.render(matrix, side))
    }

    private fun copyLink() {
        if (link.isEmpty()) {
            return
        }

        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

        clipboard.setPrimaryClip(
            ClipData.newPlainText(getString(R.string.profile_title), link),
        )

        Toast.makeText(this, R.string.profile_copied, Toast.LENGTH_SHORT).show()
    }

    /**
     * Отдаёт ссылку другому приложению.
     *
     * 🔐 Уходит только ссылка — identity-ключ и имя. Ни переписки,
     * ни списка контактов в ней нет, и приложение, которое её примет,
     * не узнаёт о пользователе ничего сверх того, что он сам решил
     * показать.
     */
    private fun shareLink() {
        if (link.isEmpty()) {
            return
        }

        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_TEXT, link),
                getString(R.string.profile_share),
            ),
        )
    }

    /** Разбирает процентное кодирование имени для показа. */
    private fun decode(raw: String): String =
        runCatching { java.net.URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)

    companion object {
        /** Разделитель, после которого в ссылке идёт имя. */
        private const val NAME_PARAM = "?name="

        /**
         * Сторона QR, если разметка ещё не измерена.
         *
         * View сообщает ширину только после укладки, а код строится
         * сразу.
         */
        private const val QR_FALLBACK_PX = 780
    }
}
