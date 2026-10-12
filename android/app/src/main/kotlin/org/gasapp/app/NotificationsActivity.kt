// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.provider.Settings as SystemSettings
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppButton
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.notify.NotifyPrefs
import org.gasapp.app.notify.NotifySetup
import org.gasapp.app.notify.Notifier
import org.gasapp.app.ui.SettingsToggle

/**
 * Настройки уведомлений (ADR-040).
 *
 * # Что здесь на самом деле настраивается
 *
 * Приходит ли уведомление «есть новые сообщения» вообще. 🔐 В нём нет
 * ни текста, ни отправителя: оно показывается, пока приложение заперто,
 * и расшифровать ему нечего. Поэтому переключателей «показывать текст»
 * здесь нет — обещать их значило бы обещать то, чего нет.
 *
 * Звук и вибрация — настройки канала в системе: Android хранит их сам,
 * и второй, приложенческий, выключатель только расходился бы с ними.
 */
class NotificationsActivity : AppCompatActivity() {

    private lateinit var toggle: SettingsToggle

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)
        setContentView(R.layout.activity_notifications)

        findViewById<ImageView>(R.id.notifications_back).setOnClickListener { finish() }

        val prefs = NotifyPrefs(this)

        toggle = SettingsToggle.bind(
            root = findViewById(R.id.notifications_enabled),
            label = R.string.notifications_enabled,
            hint = R.string.notifications_enabled_hint,
            icon = R.drawable.ic_bell,
            checked = prefs.enabled,
        ) { wanted ->
            prefs.enabled = wanted
            if (wanted && !Notifier.permitted(this)) openSystemSettings()
            resync()
            true
        }

        findViewById<View>(R.id.notifications_sound).apply {
            findViewById<ImageView>(R.id.row_icon).setImageResource(R.drawable.ic_settings)
            findViewById<TextView>(R.id.row_label).setText(R.string.notifications_sound_system)
            findViewById<TextView>(R.id.row_value).visibility = View.GONE
            setOnClickListener {
                Notifier.ensureChannel(this@NotificationsActivity)
                runCatching {
                    startActivity(
                        Intent(SystemSettings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                            .putExtra(SystemSettings.EXTRA_APP_PACKAGE, packageName)
                            .putExtra(SystemSettings.EXTRA_CHANNEL_ID, Notifier.CHANNEL),
                    )
                }
            }
        }

        findViewById<GasAppButton>(R.id.notifications_allow).setOnClickListener { openSystemSettings() }
    }

    override fun onResume() {
        super.onResume()
        // Разрешение могли выдать или забрать в системных настройках.
        resync()
    }

    private fun resync() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { NotifySetup.sync(this@NotificationsActivity, Core.messenger()) }
            }
            renderState()
        }
    }

    /** Почему уведомлений сейчас не будет — если не будет. */
    private fun renderState() {
        val prefs = NotifyPrefs(this)
        val permitted = Notifier.permitted(this)
        val state = findViewById<TextView>(R.id.notifications_state)
        val allow = findViewById<View>(R.id.notifications_allow)

        val reason = when {
            !prefs.enabled -> null
            !permitted -> R.string.notifications_blocked
            !prefs.direct -> R.string.notifications_tor
            else -> null
        }

        state.visibility = if (reason == null) View.GONE else View.VISIBLE
        reason?.let(state::setText)
        allow.visibility = if (prefs.enabled && !permitted) View.VISIBLE else View.GONE
    }

    private fun openSystemSettings() {
        runCatching {
            startActivity(
                Intent(SystemSettings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(SystemSettings.EXTRA_APP_PACKAGE, packageName),
            )
        }
    }
}
