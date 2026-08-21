// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.view.View
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.Settings
import org.aegis.app.ui.SettingsToggle

/**
 * Настройки приватности.
 *
 * # Что здесь решается
 *
 * 🔐 Каждая настройка меняет то, что узнаёт о пользователе кто-то
 * другой: собеседник, система, человек рядом с телефоном. Поэтому
 * у каждой есть пояснение — название вроде «Индикаторы присутствия»
 * не говорит, что именно станет видно.
 *
 * # Про умолчания
 *
 * Они разные и заданы в [Settings] рядом с ключами: присутствие
 * выключено, блокировка снимков включена. Функция, требующая
 * отключения, защищает только тех, кто нашёл настройку; требующая
 * включения — всех остальных.
 */
class PrivacyActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_privacy)

        findViewById<ImageView>(R.id.privacy_back).setOnClickListener { finish() }

        bindPresence()
        bindLastSeen()
        bindScreenshots()
        bindNotificationPreview()
    }

    private fun bindPresence() {
        SettingsToggle.bind(
            root = findViewById(R.id.privacy_presence),
            label = R.string.privacy_presence,
            hint = R.string.privacy_presence_hint,
            icon = R.drawable.ic_edit,
            checked = readBool(Settings.PRESENCE, default = false),
        ) { wanted -> writeBool(Settings.PRESENCE, wanted) }
    }

    private fun bindLastSeen() {
        SettingsToggle.bind(
            root = findViewById(R.id.privacy_last_seen),
            label = R.string.privacy_last_seen,
            hint = R.string.privacy_last_seen_hint,
            icon = R.drawable.ic_clock,
            checked = readBool(Settings.LAST_SEEN, default = false),
        ) { wanted -> writeBool(Settings.LAST_SEEN, wanted) }
    }

    /**
     * Блокировка снимков экрана.
     *
     * 🔐 Флаг применяется при следующем открытии экранов: снять его
     * с уже показанного окна платформа позволяет, но тогда снимок,
     * сделанный между двумя состояниями, попал бы в систему. Проще
     * и честнее — применять при создании экрана.
     */
    private fun bindScreenshots() {
        SettingsToggle.bind(
            root = findViewById(R.id.privacy_screenshots),
            label = R.string.privacy_screenshots,
            hint = R.string.privacy_screenshots_hint,
            icon = R.drawable.ic_shield,
            checked = readBool(Settings.BLOCK_SCREENSHOTS, default = true),
        ) { wanted -> writeBool(Settings.BLOCK_SCREENSHOTS, wanted) }
    }

    private fun bindNotificationPreview() {
        SettingsToggle.bind(
            root = findViewById(R.id.privacy_preview),
            label = R.string.privacy_preview,
            hint = R.string.privacy_preview_hint,
            icon = R.drawable.ic_alert,
            checked = readBool(Settings.NOTIFICATION_PREVIEW, default = false),
        ) { wanted -> writeBool(Settings.NOTIFICATION_PREVIEW, wanted) }
    }

    /**
     * Читает настройку.
     *
     * Чтение синхронное: это одна строка из уже открытой базы,
     * и переносить её в фон значило бы показать экран с пустыми
     * переключателями, которые дёрнутся через миг.
     */
    private fun readBool(key: String, default: Boolean): Boolean =
        runCatching { Core.messenger().settingBool(key, default) }.getOrDefault(default)

    /**
     * Записывает настройку.
     *
     * Возвращает `false`, если запись не удалась: переключатель тогда
     * остаётся в прежнем положении. 🔐 Настройка, которая выглядит
     * включённой, но не сохранилась, опаснее выключенной — пользователь
     * считает, что защита работает.
     */
    private fun writeBool(key: String, enabled: Boolean): Boolean =
        runCatching { Core.messenger().setSettingBool(key, enabled) }.isSuccess
}
