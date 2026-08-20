// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

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
        setContentView(R.layout.activity_settings)

        renderProfile()
        renderRows()
        bindNavigation()
    }

    private fun renderProfile() {
        // Имя и username придут из ядра вместе с оркестрацией.
        findViewById<TextView>(R.id.profile_avatar).text = "MK"
        findViewById<TextView>(R.id.profile_name).text = "Maria Keller"
        findViewById<TextView>(R.id.profile_username).text = "@maria.k"
    }

    private fun renderRows() {
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
        bindRow(R.id.settings_devices, R.drawable.ic_users, R.string.settings_devices, "3")
        bindRow(R.id.settings_about, R.drawable.ic_key, R.string.settings_about, null)

        findViewById<View>(R.id.settings_security).setOnClickListener {
            startActivity(Intent(this, SecurityCenterActivity::class.java))
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
    }
}
