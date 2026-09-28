// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.SettingsRow

/**
 * Связанные устройства.
 *
 * 🔐 Каждое связанное устройство читает переписку целиком. Список
 * показывает, сколько их: устройство, о котором пользователь
 * не помнит, — повод для тревоги, и увидеть его он должен без усилий.
 *
 * Связывание появится в M7 вместе с протоколом из раздела 13.2.
 * До тех пор здесь только текущее устройство — честное состояние,
 * а не заглушка «скоро».
 */
class DevicesActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_devices)

        findViewById<ImageView>(R.id.devices_back).setOnClickListener { finish() }

        // Как в UI kit (Devices): модель — названием, отметка «это
        // устройство» — пилюлей, идентификатор — строкой под названием.
        // Модель видна только здесь и на сервер не уходит.
        val row = findViewById<android.view.View>(R.id.devices_this)
        SettingsRow.bind(
            root = row,
            title = android.os.Build.MODEL,
            value = getString(R.string.devices_this_pill),
            icon = R.drawable.ic_mobile,
        )
        row.findViewById<TextView>(R.id.row_detail).apply {
            text = getString(R.string.devices_this_id, shortDeviceId())
            visibility = android.view.View.VISIBLE
        }
        row.findViewById<TextView>(R.id.row_value).apply {
            setBackgroundResource(R.drawable.bg_pill_ok)
            setTextColor(getColor(R.color.status_ok))
            textSize = 11f
            setPadding(dp(10), dp(4), dp(10), dp(4))
        }
        row.findViewById<android.view.View>(R.id.row_chevron).visibility = android.view.View.GONE
        row.findViewById<ImageView>(R.id.row_icon).imageTintList =
            android.content.res.ColorStateList.valueOf(getColor(R.color.accent_base))
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    /**
     * Начало идентификатора устройства.
     *
     * Полный UUID занимает строку целиком и ничего не добавляет:
     * его сверяют при связывании, а здесь он служит признаком того,
     * что устройство зарегистрировано.
     */
    private fun shortDeviceId(): String =
        Core.deviceId?.take(ID_CHARS) ?: getString(R.string.contact_no_username)

    private companion object {
        const val ID_CHARS = 8
    }
}
