// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.Settings
import org.aegis.app.ui.SettingsRow
import uniffi.aegis.Messenger

/**
 * Центр безопасности.
 *
 * 🔐 Смысл экрана — показать, **что именно** проверено, а не выставить
 * оценку. Одна цифра без разбивки создаёт ложное чувство защищённости,
 * поэтому под кольцом стоит список проверок, и непройденные — первыми.
 *
 * # Что было не так
 *
 * Счёт был константой «9 из 10», строка устройств показывала «2» при
 * одном устройстве, а строка заблокированных — «1», хотя по нажатию
 * экран честно отвечал «заблокированных нет». Экран, выдумывающий
 * состояние защиты, опаснее отсутствия экрана: человек перестаёт
 * проверять то, что считает проверенным.
 *
 * # Откуда берутся проверки
 *
 * Пять считает ядро (`securityReport`) — ключ восстановления, свежесть
 * копии, сверка контактов, sealed sender, скрытый адрес. Три — настройки
 * устройства, которые хранит и применяет само приложение: блокировка
 * снимков, скрытый текст уведомлений, автоблокировка. Если состояние
 * прочитать нельзя, проверка считается **не пройденной**: не подтверждённая
 * защита не засчитывается.
 */
class SecurityCenterActivity : AppCompatActivity() {

    /**
     * Одна проверка.
     *
     * @param target экран, где проверку можно исправить; `null` — такого
     *   экрана нет, и строка не обещает перехода.
     */
    private data class Check(
        val label: Int,
        val passed: Boolean,
        val detail: String? = null,
        val target: Class<*>? = null,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_security_center)

        findViewById<ImageView>(R.id.security_back).setOnClickListener { finish() }

        bindActions()
    }

    /**
     * Проверки пересчитываются при каждом возвращении на экран: человек
     * уходит отсюда исправлять пункт и возвращается посмотреть, исправился ли.
     */
    override fun onStart() {
        super.onStart()

        val checks = collectChecks()

        renderScore(checks)
        renderChecks(checks)
        renderRows()
    }

    private fun bindActions() {
        // Ключи шифрования: свой профиль показывает identity-ключ
        // и QR для передачи его собеседнику.
        findViewById<View>(R.id.security_keys).setOnClickListener {
            startActivity(Intent(this, ProfileActivity::class.java))
        }

        findViewById<View>(R.id.security_devices).setOnClickListener {
            startActivity(Intent(this, DevicesActivity::class.java))
        }

        findViewById<View>(R.id.security_recovery).setOnClickListener {
            startActivity(Intent(this, RecoveryCenterActivity::class.java))
        }

        // Блокировка контактов появится вместе с Report/Block (ADR-025).
        // Пустой список — честный ответ, а не заглушка.
        findViewById<View>(R.id.security_blocked).setOnClickListener {
            Toast.makeText(this, R.string.security_blocked_empty, Toast.LENGTH_SHORT).show()
        }
    }

    private fun collectChecks(): List<Check> {
        val messenger = runCatching { Core.messenger() }.getOrNull()
        val report = messenger?.let {
            runCatching { it.securityReport(System.currentTimeMillis()) }.getOrNull()
        }

        val unverified = report?.unverifiedContacts?.toInt()

        return listOf(
            Check(
                label = R.string.security_check_recovery,
                passed = report?.recoveryKeyCreated == true,
                target = RecoveryCenterActivity::class.java,
            ),
            Check(
                label = R.string.security_check_backup,
                passed = report?.backupRecent == true,
                target = RecoveryCenterActivity::class.java,
            ),
            Check(
                label = R.string.security_check_contacts,
                passed = unverified == 0,
                detail = unverified?.takeIf { it > 0 }?.let {
                    getString(R.string.security_check_unverified, it)
                },
                target = ContactsActivity::class.java,
            ),
            Check(
                label = R.string.security_check_sealed,
                passed = report?.sealedSenderEnabled == true,
            ),
            Check(
                label = R.string.security_check_address,
                passed = report?.addressHidden == true,
                target = PrivacyActivity::class.java,
            ),
            Check(
                label = R.string.security_check_screenshots,
                passed = readBool(messenger, Settings.BLOCK_SCREENSHOTS, default = true) == true,
                target = PrivacyActivity::class.java,
            ),
            Check(
                label = R.string.security_check_preview,
                passed = readBool(messenger, Settings.NOTIFICATION_PREVIEW, default = false) == false,
                target = PrivacyActivity::class.java,
            ),
            Check(
                label = R.string.security_check_autolock,
                passed = autoLockWithinLimit(messenger),
            ),
        )
    }

    /**
     * Читает настройку; `null` — прочитать не удалось.
     *
     * Умолчание здесь не подставляется вместо ошибки: для блокировки
     * снимков умолчание «включено», и сбой чтения выглядел бы как
     * пройденная проверка.
     */
    private fun readBool(messenger: Messenger?, key: String, default: Boolean): Boolean? =
        messenger?.let { runCatching { it.settingBool(key, default) }.getOrNull() }

    /**
     * Автоблокировка не дольше пяти минут.
     *
     * Ноль — блокировка сразу после ухода, самый строгий режим, поэтому
     * он проверку проходит.
     */
    private fun autoLockWithinLimit(messenger: Messenger?): Boolean {
        val seconds = messenger?.let {
            runCatching {
                it.settingInt(Settings.AUTO_LOCK_SECONDS, Settings.AUTO_LOCK_DEFAULT)
            }.getOrNull()
        } ?: return false

        return seconds in 0L..AUTO_LOCK_LIMIT_SECONDS
    }

    /**
     * Показывает счёт и заполняет кольцо.
     *
     * Уровень drawable задаётся в десятитысячных долях — это единица
     * измерения `ClipDrawable`/`ring`, а не проценты.
     */
    private fun renderScore(checks: List<Check>) {
        val total = checks.size
        val passed = checks.count { it.passed }
        val pending = total - passed

        findViewById<TextView>(R.id.score_value).apply {
            text = getString(R.string.security_score, passed, total)
            setTextColor(statusColor(pending == 0))
        }

        findViewById<ImageView>(R.id.score_ring).drawable?.let { ring ->
            ring.level = passed * MAX_LEVEL / total
        }

        // «Защищено» — только когда это правда. Заголовок, не зависящий
        // от счёта, успокаивал бы человека при любом его значении.
        findViewById<TextView>(R.id.score_title).setText(
            if (pending == 0) R.string.security_protected else R.string.security_attention_title,
        )

        findViewById<TextView>(R.id.score_subtitle).text = if (pending == 0) {
            getString(R.string.security_all_clear)
        } else {
            resources.getQuantityString(R.plurals.security_attention, pending, pending)
        }
    }

    /** Заполняет список проверок: непройденные — первыми. */
    private fun renderChecks(checks: List<Check>) {
        val list = findViewById<LinearLayout>(R.id.security_checks)
        list.removeAllViews()

        checks.sortedBy { it.passed }.forEach { check ->
            val row = layoutInflater.inflate(R.layout.item_settings_row, list, false)

            SettingsRow.bind(
                root = row,
                label = check.label,
                value = check.detail ?: getString(
                    if (check.passed) R.string.security_check_passed else R.string.security_check_failed,
                ),
                icon = if (check.passed) R.drawable.ic_shield else R.drawable.ic_alert,
                // Переход предлагается только к непройденной проверке:
                // исправлять пройденную незачем.
                onClick = check.target
                    ?.takeUnless { check.passed }
                    ?.let { screen -> { startActivity(Intent(this, screen)) } },
            )

            row.findViewById<TextView>(R.id.row_value).setTextColor(statusColor(check.passed))

            list.addView(row)
        }
    }

    /** Строки навигации под списком проверок. */
    private fun renderRows() {
        bindRow(R.id.security_keys, R.drawable.ic_key, R.string.security_keys, null)

        // Устройство ровно одно: связывание устройств отложено (M7 без
        // мульти-девайса). Число показывается, только когда устройство
        // действительно зарегистрировано.
        bindRow(
            R.id.security_devices,
            R.drawable.ic_users,
            R.string.security_devices,
            Core.deviceId?.let { "1" },
        )

        bindRow(
            R.id.security_recovery,
            R.drawable.ic_shield,
            R.string.security_recovery,
            recoveryState(),
        )

        // Блокировки ещё нет, значит и заблокированных нет. Число здесь
        // было бы выдумкой.
        bindRow(R.id.security_blocked, R.drawable.ic_alert, R.string.security_blocked, null)
    }

    /**
     * Состояние резервного копирования для строки навигации.
     *
     * 🔐 «Ключ не создан» — не украшение списка, а предупреждение:
     * при таком состоянии потеря телефона означает потерю всей
     * переписки, и восстановить её будет неоткуда.
     */
    private fun recoveryState(): String {
        val configured = runCatching {
            Core.messenger().backupStatus().configured
        }.getOrDefault(false)

        return getString(
            if (configured) R.string.recovery_pill_configured
            else R.string.recovery_pill_not_configured,
        )
    }

    /**
     * Заполняет строку навигации, не трогая её обработчик нажатия.
     *
     * Не через [SettingsRow]: тот снимает обработчик у строки без
     * действия, а обработчики здесь назначены в [bindActions].
     */
    private fun bindRow(rowId: Int, iconRes: Int, labelRes: Int, value: String?) {
        val row: View = findViewById(rowId)

        row.findViewById<ImageView>(R.id.row_icon).setImageResource(iconRes)
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

    private fun statusColor(ok: Boolean): Int =
        ContextCompat.getColor(this, if (ok) R.color.status_ok else R.color.status_warn)

    private companion object {
        /** Максимальный уровень drawable. */
        const val MAX_LEVEL = 10_000

        /** Предел автоблокировки, при котором проверка пройдена: пять минут. */
        const val AUTO_LOCK_LIMIT_SECONDS = 300L
    }
}
