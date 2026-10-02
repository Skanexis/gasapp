// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisDialog
import org.aegis.app.core.Core
import org.aegis.app.core.Reauth
import org.aegis.app.core.SecureWindow
import org.aegis.app.net.EmbeddedTor
import org.aegis.app.net.NetworkProxy
import uniffi.aegis.FfiProxy
import uniffi.aegis.validateProxy
import uniffi.aegis.validateTorBridges

/**
 * Сеть: через встроенный Tor, напрямую или через SOCKS5-прокси (ADR-024).
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
    private val bridgesField by lazy { findViewById<EditText>(R.id.network_bridges) }

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
            findViewById<RadioButton>(R.id.network_tor).isEnabled = false
            findViewById<RadioButton>(R.id.network_socks).isEnabled = false
        }

        load()

        // Ход подключения встроенного Tor — пока экран на виду.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (true) {
                    renderTorStatus()
                    delay(TOR_STATUS_POLL_MS)
                }
            }
        }
    }

    /** Строка состояния встроенного Tor под выбором режима. */
    private fun renderTorStatus() {
        val view = findViewById<TextView>(R.id.network_tor_status)
        val status = EmbeddedTor.status()

        if (group.checkedRadioButtonId != R.id.network_tor || !status.running) {
            view.visibility = View.GONE
            return
        }

        view.text = when {
            status.ready && status.bridges -> getString(R.string.tor_status_ready_bridges)
            status.ready -> getString(R.string.tor_status_ready)
            status.bridges -> getString(R.string.tor_status_via_bridges, status.percent.toInt())
            status.stalled -> getString(R.string.tor_status_stalled, status.percent.toInt())
            else -> getString(R.string.tor_status_connecting, status.percent.toInt())
        }
        view.visibility = View.VISIBLE
    }

    private fun load() {
        runCatching { Core.messenger().torBridges() }
            .onSuccess { bridges -> bridgesField.setText(bridges.joinToString("\n")) }

        runCatching { Core.messenger().proxy() }
            .onSuccess { mode ->
                when (mode) {
                    is FfiProxy.Direct -> group.check(R.id.network_direct)
                    is FfiProxy.Tor -> group.check(R.id.network_tor)
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
        findViewById<View>(R.id.network_bridges_fields).visibility =
            if (checkedId == R.id.network_tor) View.VISIBLE else View.GONE

        val hint = when {
            !NetworkProxy.proxySupported -> R.string.network_requires_android7
            checkedId == R.id.network_tor -> R.string.network_hint_tor
            checkedId == R.id.network_socks -> R.string.network_hint_socks
            else -> R.string.network_hint_direct
        }

        findViewById<TextView>(R.id.network_mode_hint).setText(hint)
    }

    /** Режим, выбранный на экране; `null` — выбор неполный или порт неверен. */
    private fun selectedMode(): FfiProxy? = when (group.checkedRadioButtonId) {
        R.id.network_direct -> FfiProxy.Direct
        R.id.network_tor -> FfiProxy.Tor
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

        // Мосты проверяются так же, как в ядре, — до сохранения.
        if (mode is FfiProxy.Tor && !validateTorBridges(bridgesField.text.toString())) {
            showStatus(getString(R.string.network_bridges_invalid))
            return
        }

        if (mode is FfiProxy.Tor) {
            store(mode)
            return
        }

        // 🔐 Сеть мимо Tor — только владельцу (аудит 2026-10-02, A-3):
        // свой SOCKS-прокси, тихо вписанный тем, кому дали подержать
        // телефон, узнавал бы адрес и время каждого соединения.
        Reauth.require(this, R.string.reauth_network) {
            // 🔐 Прямое соединение отдаёт серверу адрес — только явным
            // согласием, после которого человек знает, чем платит.
            if (mode is FfiProxy.Direct) {
                AegisDialog(this)
                    .title(R.string.network_direct_confirm_title)
                    .message(R.string.network_direct_confirm_body)
                    .secondary()
                    .primary(R.string.network_direct_confirm_ok) { store(mode) }
                    .show()
            } else {
                store(mode)
            }
        }
    }

    private fun store(mode: FfiProxy) {
        val bridgesText = bridgesField.text.toString()

        // В фоне: смена мостов перезапускает Tor, а это до пары секунд.
        lifecycleScope.launch {
            val saved = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()
                    val bridges = if (mode is FfiProxy.Tor) {
                        messenger.setTorBridges(bridgesText)
                    } else {
                        messenger.torBridges()
                    }
                    messenger.setProxy(mode)

                    // Применяется сразу: следующее соединение уже пойдёт
                    // выбранным способом. Открытый сокет уведомлений
                    // переподключится через него при ближайшем разрыве.
                    NetworkProxy.apply(this@NetworkActivity, mode, bridges)
                    bridges
                }
            }

            saved
                .onSuccess { bridges ->
                    bridgesField.setText(bridges.joinToString("\n"))
                    renderTorStatus()
                    showStatus(getString(R.string.network_saved))
                }
                .onFailure { showStatus(getString(R.string.network_save_failed)) }
        }
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

        /** Как часто обновлять строку состояния Tor. */
        private const val TOR_STATUS_POLL_MS = 1_000L

        /**
         * Подпись режима для строки настроек.
         *
         * `null` — режим прочитать не удалось; показывается как
         * повреждённый, а не как «напрямую».
         */
        fun labelFor(mode: FfiProxy?): Int = when (mode) {
            null -> R.string.network_unavailable_short
            is FfiProxy.Direct -> R.string.network_mode_direct
            is FfiProxy.Tor -> R.string.network_mode_tor
            is FfiProxy.Socks5 -> R.string.network_mode_socks
        }
    }
}
