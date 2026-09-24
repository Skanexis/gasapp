// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.AlertDialog
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.components.AegisButton
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.showSecure
import org.aegis.app.net.NetworkProxy
import uniffi.aegis.FfiProxy
import uniffi.aegis.validateProxy

/**
 * Сеть: напрямую, через Tor с Orbot или через SOCKS5-прокси (ADR-024).
 *
 * # Что здесь обещается
 *
 * 🔐 Ровно две вещи, и обе написаны рядом с выбором:
 *
 * * при недоступном прокси приложение **не подключится**, а не пойдёт
 *   напрямую — см. [NetworkProxy];
 * * прокси скрывает адрес от сервера, но не всё и не от всех.
 *
 * # Почему без логина и пароля
 *
 * У платформенного транспорта нет проверенного на устройстве пути
 * передачи учётных данных SOCKS5. Поле «пароль», которое молча
 * не применяется, хуже его отсутствия.
 */
class NetworkActivity : AppCompatActivity() {

    private val group by lazy { findViewById<RadioGroup>(R.id.network_mode) }
    private val hostField by lazy { findViewById<EditText>(R.id.network_host) }
    private val portField by lazy { findViewById<EditText>(R.id.network_port) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_network)

        findViewById<ImageView>(R.id.network_back).setOnClickListener { finish() }
        findViewById<AegisButton>(R.id.network_save).setOnClickListener { save() }

        group.setOnCheckedChangeListener { _, checkedId -> renderMode(checkedId) }

        // ⚠️ До Android 7.0 платформа не гарантирует DNS через прокси.
        // Режимы, которые на этой версии закрыли бы сеть, недоступны
        // для выбора — иначе человек включил бы Tor и остался без сети,
        // не понимая почему.
        if (!NetworkProxy.proxySupported) {
            findViewById<RadioButton>(R.id.network_orbot).isEnabled = false
            findViewById<RadioButton>(R.id.network_socks).isEnabled = false
        }

        load()
    }

    private fun load() {
        runCatching { Core.messenger().proxy() }
            .onSuccess { mode ->
                when (mode) {
                    is FfiProxy.Direct -> group.check(R.id.network_direct)
                    is FfiProxy.Orbot -> group.check(R.id.network_orbot)
                    is FfiProxy.Socks5 -> {
                        group.check(R.id.network_socks)
                        hostField.setText(mode.host)
                        portField.setText(mode.port.toString())
                    }
                }
            }
            .onFailure {
                // 🔐 Повреждённая настройка: «напрямую» за пользователя
                // не выбирается. Сеть закрыта, пока он не выберет сам.
                group.clearCheck()
                showStatus(getString(R.string.network_unavailable))
            }

        renderMode(group.checkedRadioButtonId)
    }

    private fun renderMode(checkedId: Int) {
        findViewById<View>(R.id.network_socks_fields).visibility =
            if (checkedId == R.id.network_socks) View.VISIBLE else View.GONE

        val hint = when {
            !NetworkProxy.proxySupported -> R.string.network_requires_android7
            checkedId == R.id.network_orbot -> R.string.network_hint_orbot
            checkedId == R.id.network_socks -> R.string.network_hint_socks
            else -> R.string.network_hint_direct
        }

        findViewById<TextView>(R.id.network_mode_hint).setText(hint)
    }

    /** Режим, выбранный на экране; `null` — выбор неполный или порт неверен. */
    private fun selectedMode(): FfiProxy? = when (group.checkedRadioButtonId) {
        R.id.network_direct -> FfiProxy.Direct
        R.id.network_orbot -> FfiProxy.Orbot
        R.id.network_socks -> portField.text.toString().toIntOrNull()
            ?.takeIf { it in 1..MAX_PORT }
            ?.let { port -> FfiProxy.Socks5(hostField.text.toString().trim(), port.toUShort()) }
        else -> null
    }

    private fun save() {
        val mode = selectedMode()

        // Проверка та же, что в ядре: ошибка в адресе подсвечивается
        // до сохранения, а не обнаруживается отказом сети.
        if (mode == null || !validateProxy(mode)) {
            showStatus(getString(R.string.network_invalid))
            return
        }

        // 🔐 Прямое соединение отдаёт серверу адрес — только явным
        // согласием, после которого человек знает, чем платит.
        if (mode is FfiProxy.Direct) {
            AlertDialog.Builder(this)
                .setTitle(R.string.network_direct_confirm_title)
                .setMessage(R.string.network_direct_confirm_body)
                .setPositiveButton(R.string.network_direct_confirm_ok) { _, _ -> store(mode) }
                .setNegativeButton(R.string.action_cancel, null)
                .showSecure(this)
            return
        }

        store(mode)
    }

    private fun store(mode: FfiProxy) {
        if (runCatching { Core.messenger().setProxy(mode) }.isFailure) {
            showStatus(getString(R.string.network_save_failed))
            return
        }

        // Применяется сразу: следующее соединение уже пойдёт выбранным
        // способом. Открытый сокет уведомлений переподключится через него
        // при ближайшем разрыве.
        NetworkProxy.apply(mode)

        showStatus(getString(R.string.network_saved))
    }

    private fun showStatus(text: String) {
        findViewById<TextView>(R.id.network_status).apply {
            this.text = text
            visibility = View.VISIBLE
        }
    }

    companion object {

        /** Наибольший номер порта. */
        private const val MAX_PORT = 65_535

        /**
         * Подпись режима для строки настроек.
         *
         * `null` — режим прочитать не удалось; показывается как
         * повреждённый, а не как «напрямую».
         */
        fun labelFor(mode: FfiProxy?): Int = when (mode) {
            null -> R.string.network_unavailable_short
            is FfiProxy.Direct -> R.string.network_mode_direct
            is FfiProxy.Orbot -> R.string.network_mode_orbot
            is FfiProxy.Socks5 -> R.string.network_mode_socks
        }
    }
}
