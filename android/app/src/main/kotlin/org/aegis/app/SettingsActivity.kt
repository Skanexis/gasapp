// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

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
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.BottomNav

/**
 * Настройки.
 *
 * 🔐 Раздел «Безопасность» выделен цветом акцента: он ведёт в
 * [SecurityCenterActivity], где живут проверки, от которых зависит
 * защита переписки. Остальные разделы нейтральны — выделение всего
 * подряд перестаёт что-либо значить.
 */
class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_settings)

        renderProfile()
        renderRows()
        bindNavigation()
        BottomNav.highlight(this, BottomNav.Tab.Settings)
    }

    /**
     * Показывает собственное имя и открывает экран профиля.
     *
     * Имя читается из ядра: держать вторую копию в настройках значило
     * бы показывать устаревшее после смены.
     */
    private fun renderProfile() {
        findViewById<View>(R.id.profile_row).setOnClickListener {
            startActivity(Intent(this, ProfileActivity::class.java))
        }
        findViewById<View>(R.id.profile_qr).setOnClickListener {
            startActivity(Intent(this, ProfileActivity::class.java))
        }

        lifecycleScope.launch {
            val username = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().ownUsername() }.getOrNull()
            }

            findViewById<TextView>(R.id.profile_name).text =
                username ?: getString(R.string.profile_no_username)
            findViewById<TextView>(R.id.profile_username).text = when (username) {
                null -> ""
                else -> getString(R.string.contact_username, username)
            }

            // Инициал для кружка аватара. Пустая строка, а не заглушка
            // с буквами: чужие инициалы в своём профиле сбивают с толку.
            findViewById<TextView>(R.id.profile_avatar).text =
                username?.take(1)?.uppercase().orEmpty()
        }
    }

    /**
     * Заполняет разделы настроек.
     *
     * Каждая строка ведёт на свой экран. Раньше пять из шести были
     * нарисованы, но не нажимались, а у «Устройств» стояло значение
     * «3» — число, взятое из макета и не имеющее отношения к тому,
     * сколько устройств связано на самом деле. 🔐 Ложное число рядом
     * с настройкой безопасности хуже отсутствия числа: пользователь
     * искал бы два лишних устройства, которых нет, — или не искал бы
     * настоящее.
     */
    private fun renderRows() {
        // Безопасность выделена акцентом: там живут проверки, от
        // которых зависит защита переписки. Выделение всего подряд
        // перестаёт что-либо значить.
        bindRow(
            R.id.settings_security,
            R.drawable.ic_shield,
            R.string.settings_security,
            value = null,
            accent = true,
        )
        bindRow(R.id.settings_privacy, R.drawable.ic_lock, R.string.settings_privacy, null)
        bindRow(
            R.id.settings_notifications,
            R.drawable.ic_alert,
            R.string.settings_notifications,
            getString(R.string.notifications_private),
        )
        bindRow(
            R.id.settings_appearance,
            R.drawable.ic_settings,
            R.string.settings_appearance,
            getString(R.string.appearance_theme_value),
        )
        bindRow(
            R.id.settings_storage,
            R.drawable.ic_file,
            R.string.settings_storage,
            null,
        )

        // Устройство ровно одно, пока нет связывания: показывать
        // выдуманное число рядом с настройкой безопасности нельзя.
        bindRow(R.id.settings_devices, R.drawable.ic_users, R.string.settings_devices, "1")
        bindRow(R.id.settings_about, R.drawable.ic_key, R.string.settings_about, null)

        open(R.id.settings_security, SecurityCenterActivity::class.java)
        open(R.id.settings_privacy, PrivacyActivity::class.java)
        open(R.id.settings_notifications, NotificationsActivity::class.java)
        open(R.id.settings_appearance, AppearanceActivity::class.java)
        open(R.id.settings_storage, StorageActivity::class.java)
        open(R.id.settings_devices, DevicesActivity::class.java)
        open(R.id.settings_about, AboutActivity::class.java)
    }

    /** Связывает строку с экраном, который она открывает. */
    private fun open(rowId: Int, screen: Class<*>) {
        findViewById<View>(rowId).setOnClickListener {
            startActivity(Intent(this, screen))
        }
    }

    private fun bindRow(
        rowId: Int,
        iconRes: Int,
        labelRes: Int,
        value: String?,
        accent: Boolean = false,
    ) {
        val row: View = findViewById(rowId)

        row.findViewById<ImageView>(R.id.row_icon).apply {
            setImageResource(iconRes)
            if (accent) {
                setColorFilter(getColor(R.color.accent_base))
            }
        }
        row.findViewById<TextView>(R.id.row_label).setText(labelRes)
        row.findViewById<TextView>(R.id.row_value).apply {
            if (value == null) {
                visibility = View.GONE
            } else {
                visibility = View.VISIBLE
                text = value
            }
        }
    }

    private fun bindNavigation() {
        findViewById<View>(R.id.nav_chats).setOnClickListener {
            startActivity(Intent(this, ChatListActivity::class.java))
            finish()
        }
        findViewById<View>(R.id.nav_calls).setOnClickListener {
            startActivity(Intent(this, CallsActivity::class.java))
            finish()
        }
    }
}
