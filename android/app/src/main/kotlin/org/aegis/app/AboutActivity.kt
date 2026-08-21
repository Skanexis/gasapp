// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.SettingsRow
import uniffi.aegis.coreVersion
import uniffi.aegis.protocolVersion

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
        )

        SettingsRow.bind(
            root = findViewById(R.id.about_source),
            label = R.string.about_source,
            value = getString(R.string.about_source_value),
        )
    }
}
