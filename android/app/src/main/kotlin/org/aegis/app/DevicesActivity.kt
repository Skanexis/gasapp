// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.widget.ImageView
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

        SettingsRow.bind(
            root = findViewById(R.id.devices_this),
            label = R.string.devices_this,
            value = shortDeviceId(),
            icon = R.drawable.ic_phone,
        )
    }

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
