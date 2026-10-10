// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.os.Bundle
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.SettingsRow
import uniffi.gasapp.coreVersion
import uniffi.gasapp.protocolVersion

/**
 * О программе.
 *
 * Версии ядра и протокола показаны, потому что от них зависит
 * совместимость: собеседник со старой версией протокола не прочитает
 * сообщение, и знать номер полезно раньше, чем начнётся разбирательство
 * о том, почему переписка не идёт.
 */
class AboutActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_about)

        findViewById<ImageView>(R.id.about_back).setOnClickListener { finish() }

        SettingsRow.bind(
            root = findViewById(R.id.about_app_version),
            label = R.string.about_app_version,
            value = BuildConfig.VERSION_NAME,
            icon = R.drawable.ic_shield,
        )

        SettingsRow.bind(
            root = findViewById(R.id.about_core_version),
            label = R.string.about_core_version,
            value = runCatching { coreVersion() }.getOrDefault("—"),
            icon = R.drawable.ic_key,
        )

        SettingsRow.bind(
            root = findViewById(R.id.about_protocol_version),
            label = R.string.about_protocol_version,
            value = runCatching { protocolVersion().toString() }.getOrDefault("—"),
            icon = R.drawable.ic_lock,
        )

        SettingsRow.bind(
            root = findViewById(R.id.about_license),
            label = R.string.about_license,
            value = getString(R.string.about_license_value),
            icon = R.drawable.ic_file,
        )

        SettingsRow.bind(
            root = findViewById(R.id.about_source),
            label = R.string.about_source,
            value = getString(R.string.about_source_value),
            icon = R.drawable.ic_globe,
        )

        // Условия, политика, правила сообщества, удаление аккаунта.
        SettingsRow.bind(
            root = findViewById(R.id.about_documents),
            label = R.string.legal_title,
            value = null,
            icon = R.drawable.ic_file,
        )
        findViewById<android.view.View>(R.id.about_documents).setOnClickListener {
            org.gasapp.app.core.Legal.show(this)
        }
    }
}
