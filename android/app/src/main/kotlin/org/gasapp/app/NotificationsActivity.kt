// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.os.Bundle
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.core.Settings
import org.gasapp.app.ui.SettingsToggle

/**
 * Настройки уведомлений.
 *
 * # Что здесь на самом деле настраивается
 *
 * 🔐 Не то, что присылает сервер, а то, что подставляет приложение.
 * Уведомление приходит без содержимого: сервер отправляет флаг
 * «есть новое», и ни текста, ни отправителя, ни чата в нём нет
 * (ADR-014). Иначе Apple и Google видели бы, кто с кем переписывается,
 * — а мессенджер, отдающий это посреднику, перестаёт быть тем,
 * за что его выбрали.
 *
 * Приложение расшифровывает сообщение на устройстве и решает, сколько
 * из него показать на заблокированном экране. Это решение и живёт
 * здесь.
 */
class NotificationsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_notifications)

        findViewById<ImageView>(R.id.notifications_back).setOnClickListener { finish() }

        SettingsToggle.bind(
            root = findViewById(R.id.notifications_preview),
            label = R.string.notifications_preview,
            hint = R.string.notifications_preview_hint,
            icon = R.drawable.ic_chat,
            checked = readBool(Settings.NOTIFICATION_PREVIEW, default = false),
        ) { wanted -> writeBool(Settings.NOTIFICATION_PREVIEW, wanted) }

        SettingsToggle.bind(
            root = findViewById(R.id.notifications_sender),
            label = R.string.notifications_sender,
            hint = R.string.notifications_sender_hint,
            icon = R.drawable.ic_users,
            checked = readBool(NOTIFICATION_SENDER, default = false),
        ) { wanted -> writeBool(NOTIFICATION_SENDER, wanted) }

        SettingsToggle.bind(
            root = findViewById(R.id.notifications_sound),
            label = R.string.notifications_sound,
            icon = R.drawable.ic_bell,
            checked = readBool(Settings.NOTIFICATION_SOUND, default = true),
        ) { wanted -> writeBool(Settings.NOTIFICATION_SOUND, wanted) }

        SettingsToggle.bind(
            root = findViewById(R.id.notifications_vibrate),
            label = R.string.notifications_vibrate,
            icon = R.drawable.ic_mobile,
            checked = readBool(NOTIFICATION_VIBRATE, default = true),
        ) { wanted -> writeBool(NOTIFICATION_VIBRATE, wanted) }
    }

    private fun readBool(key: String, default: Boolean): Boolean =
        runCatching { Core.messenger().settingBool(key, default) }.getOrDefault(default)

    private fun writeBool(key: String, enabled: Boolean): Boolean =
        runCatching { Core.messenger().setSettingBool(key, enabled) }.isSuccess

    private companion object {
        /**
         * Показывать ли имя отправителя в уведомлении.
         *
         * 🔐 Выключено по умолчанию: имя на заблокированном экране
         * видно любому, кто рядом, и выдаёт круг общения, даже когда
         * текст скрыт.
         */
        const val NOTIFICATION_SENDER = "notification_sender"

        /** Вибрация уведомлений. */
        const val NOTIFICATION_VIBRATE = "notification_vibrate"
    }
}
