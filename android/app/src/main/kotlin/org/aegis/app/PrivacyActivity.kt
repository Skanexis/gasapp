// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.Core
import org.aegis.app.core.DeleteAccount
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.Settings
import org.aegis.app.ui.SettingsRow
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
        bindDeleteAccount()
    }

    /**
     * Строка сети пересчитывается при возвращении: человек уходит
     * на экран «Сеть» менять способ подключения и возвращается сюда.
     */
    override fun onStart() {
        super.onStart()
        bindNetwork()
    }

    /**
     * Способ подключения к серверу (ADR-024).
     *
     * 🔐 Нечитаемая настройка показывается как повреждённая, а не как
     * «напрямую»: подпись не должна обещать то, чего нет.
     */
    private fun bindNetwork() {
        val mode = runCatching { Core.messenger().proxy() }.getOrNull()

        SettingsRow.bind(
            root = findViewById(R.id.privacy_network),
            label = R.string.privacy_network,
            value = getString(NetworkActivity.labelFor(mode)),
            icon = R.drawable.ic_shield,
            onClick = { startActivity(Intent(this, NetworkActivity::class.java)) },
        )
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
     * 🔐 Удаление аккаунта (MASVS PRIVACY-3.2).
     *
     * # Почему подтверждений два
     *
     * Первое называет последствия, второе требует нажать кнопку
     * с явным словом. Одно подтверждение здесь мало: диалог с «ОК»
     * закрывают не читая, а вернуть удалённый аккаунт нельзя —
     * ни нам, ни человеку, ни оператору сервера.
     *
     * # Что говорится честно
     *
     * Что имя освободится и его сможет занять кто-то другой; что
     * сообщения, уже доставленные собеседникам, останутся у них; что
     * присланные вложения доживут на сервере свой тридцатидневный
     * срок. Всё это — правда о том, чего удаление **не** делает,
     * и узнать её человек должен до нажатия, а не после.
     */
    private fun bindDeleteAccount() {
        SettingsRow.bind(
            root = findViewById(R.id.privacy_delete_account),
            label = R.string.privacy_delete_account,
            icon = R.drawable.ic_alert,
            destructive = true,
            onClick = { confirmDeleteAccount() },
        )
    }

    /** Первое подтверждение: что именно произойдёт. */
    private fun confirmDeleteAccount() {
        androidx.appcompat.app.AlertDialog.Builder(this, R.style.AegisDialog)
            .setTitle(R.string.privacy_delete_account_title)
            .setMessage(R.string.privacy_delete_account_warning)
            .setPositiveButton(R.string.privacy_delete_account_continue) { _, _ ->
                confirmDeleteAccountFinally()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Второе подтверждение: последняя возможность отказаться. */
    private fun confirmDeleteAccountFinally() {
        androidx.appcompat.app.AlertDialog.Builder(this, R.style.AegisDialog)
            .setTitle(R.string.privacy_delete_account_final_title)
            .setMessage(R.string.privacy_delete_account_final)
            .setPositiveButton(R.string.privacy_delete_account_confirm) { _, _ ->
                runDeleteAccount()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Выполняет удаление.
     *
     * Порядок «сначала сервер, потом устройство» держит
     * [DeleteAccount], а не этот экран: перепутать его можно ровно
     * один раз, и стоить это будет переписки.
     *
     * 🔐 Отказ сервера показывается как отказ. Экран, сообщивший
     * «аккаунт удалён» там, где удаления не было, научил бы доверять
     * этому сообщению и в следующий раз.
     */
    private fun runDeleteAccount() {
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { DeleteAccount.run(applicationContext) }
            }

            outcome
                .onSuccess { result ->
                    if (!result.wiped) {
                        // Сервер очищен, устройство — не до конца.
                        // Умолчать значило бы оставить человека
                        // с файлами, о которых он не знает.
                        android.widget.Toast.makeText(
                            this@PrivacyActivity,
                            R.string.privacy_delete_account_partial,
                            android.widget.Toast.LENGTH_LONG,
                        ).show()
                    }

                    // Хранилище закрыто, аккаунта нет: любой экран,
                    // кроме начального, обратился бы к закрытому ядру.
                    startActivity(
                        Intent(this@PrivacyActivity, OnboardingActivity::class.java).apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                                Intent.FLAG_ACTIVITY_CLEAR_TASK
                        },
                    )
                    finish()
                }
                .onFailure {
                    android.widget.Toast.makeText(
                        this@PrivacyActivity,
                        R.string.privacy_delete_account_failed,
                        android.widget.Toast.LENGTH_LONG,
                    ).show()
                }
        }
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
