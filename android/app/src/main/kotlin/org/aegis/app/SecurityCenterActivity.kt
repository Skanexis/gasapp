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
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.AppSignature
import org.aegis.app.core.Core
import org.aegis.app.core.DeviceIntegrity
import org.aegis.app.core.HardwareKey
import org.aegis.app.core.KeyAttestation
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.SecurityEvents
import org.aegis.app.core.Settings
import org.aegis.app.core.TouchTarget
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
 * снимков, скрытый текст уведомлений, автоблокировка. Остальные —
 * состояние самого устройства и сборки: экран блокировки, признаки root
 * ([org.aegis.app.core.DeviceIntegrity]), где лежит ключ хранилища
 * ([HardwareKey.securityLevel]), что об этом говорит само оборудование
 * ([KeyAttestation]) и чьим ключом подписан APK ([AppSignature]).
 * Если состояние прочитать
 * нельзя, проверка считается **не пройденной**: не подтверждённая
 * защита не засчитывается.
 *
 * # Почему проверки устройства здесь, а не в запрете запуска
 *
 * 🔐 Ни отсутствие экрана блокировки, ни найденный root не мешают
 * пользоваться приложением. Довод записан в
 * [org.aegis.app.core.DeviceIntegrity]; короче всего он звучит так:
 * детект root обходится, и защита, которую тривиально обходят,
 * не должна принимать решений за пользователя.
 */
class SecurityCenterActivity : AppCompatActivity() {

    /**
     * Одна проверка.
     *
     * @param fix что делать, чтобы её исправить; `null` — исправлять
     *   нечем, и строка не обещает перехода.
     *
     * Действие, а не класс экрана: экран блокировки устройства ставится
     * в системных настройках, а туда переходят намерением, а не
     * `Intent(this, Класс::class.java)`.
     */
    private data class Check(
        val label: Int,
        val passed: Boolean,
        val detail: String? = null,
        val fix: (() -> Unit)? = null,
    )

    /** Переход к экрану приложения — самый частый вид [Check.fix]. */
    private fun screen(target: Class<*>): () -> Unit =
        { startActivity(Intent(this, target)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_security_center)

        findViewById<ImageView>(R.id.security_back).setOnClickListener { finish() }

        // 🔐 Иконка 24dp, область нажатия — 48dp (WCAG 2.5.5).
        // Вид не меняется: увеличивается только то, куда можно
        // попасть. Подробности — в TouchTarget.
        TouchTarget.expand(findViewById(R.id.security_back))

        bindActions()
    }

    /**
     * Проверки пересчитываются при каждом возвращении на экран: человек
     * уходит отсюда исправлять пункт и возвращается посмотреть, исправился ли.
     */
    override fun onStart() {
        super.onStart()

        // Проверки считаются не на главном потоке: аттестация создаёт
        // ключ в Keystore, а в StrongBox это до секунды. Счёт рисуется
        // только целиком — частичный показал бы «всё в порядке»
        // до того, как досчитались непройденные.
        findViewById<TextView>(R.id.score_subtitle).setText(R.string.security_check_pending)

        lifecycleScope.launch {
            val checks = withContext(Dispatchers.IO) { collectChecks() }

            renderScore(checks)
            renderChecks(checks)
        }

        renderRows()
        renderLog()
    }

    /**
     * 🔐 Последние события журнала безопасности.
     *
     * Журнал писался, но прочитать его было негде (см. [SecurityEvents]).
     * Событие неизвестного экрану типа показывается сырым, а не
     * прячется.
     */
    private fun renderLog() {
        val list = findViewById<LinearLayout>(R.id.security_log)
        list.removeAllViews()

        val events = runCatching { Core.messenger().securityEvents(LOG_LIMIT) }
            .getOrDefault(emptyList())

        if (events.isEmpty()) {
            val row = layoutInflater.inflate(R.layout.item_settings_row, list, false)
            SettingsRow.bind(root = row, label = R.string.security_log_empty, icon = R.drawable.ic_shield)
            list.addView(row)

            return
        }

        val format = java.text.DateFormat.getDateTimeInstance(
            java.text.DateFormat.SHORT,
            java.text.DateFormat.SHORT,
        )

        events.forEach { event ->
            val row = layoutInflater.inflate(R.layout.item_settings_row, list, false)
            val label = SecurityEvents.labelFor(event.eventType)

            SettingsRow.bind(
                root = row,
                title = label?.let(::getString) ?: event.eventType,
                value = format.format(java.util.Date(event.timestampMillis)),
                icon = R.drawable.ic_alert,
            )

            list.addView(row)
        }
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

        // Считается один раз: обращение ходит по файловой системе,
        // а список проверок перестраивается при каждом возвращении
        // на экран.
        val rooted = DeviceIntegrity.looksRooted()
        val hasScreenLock = DeviceIntegrity.hasScreenLock(this)
        val attestation = KeyAttestation.verdict()

        return listOf(
            Check(
                label = R.string.security_check_recovery,
                passed = report?.recoveryKeyCreated == true,
                fix = screen(RecoveryCenterActivity::class.java),
            ),
            Check(
                label = R.string.security_check_backup,
                passed = report?.backupRecent == true,
                fix = screen(RecoveryCenterActivity::class.java),
            ),
            Check(
                label = R.string.security_check_contacts,
                passed = unverified == 0,
                detail = unverified?.takeIf { it > 0 }?.let {
                    getString(R.string.security_check_unverified, it)
                },
                fix = screen(ContactsActivity::class.java),
            ),
            Check(
                label = R.string.security_check_sealed,
                passed = report?.sealedSenderEnabled == true,
            ),
            Check(
                label = R.string.security_check_address,
                passed = report?.addressHidden == true,
                fix = screen(PrivacyActivity::class.java),
            ),
            Check(
                label = R.string.security_check_screenshots,
                passed = readBool(messenger, Settings.BLOCK_SCREENSHOTS, default = true) == true,
                fix = screen(PrivacyActivity::class.java),
            ),
            // ⚠️ Проверки «текст скрыт в уведомлениях» нет, пока нет
            // уведомлений: приложение их не показывает вовсе (см.
            // `Settings.NOTIFICATION_PREVIEW`). Прежде она засчитывалась
            // по настройке, которую никто не читает, — и «проваливалась»
            // у того, кто её включил, хотя показывать было нечего.
            Check(
                label = R.string.security_check_autolock,
                passed = autoLockWithinLimit(messenger),
            ),

            // 🔐 Экран блокировки устройства. Без него файлы приложения
            // на диске не защищены учётными данными: шифрование Android
            // (FBE) привязывает ключ хранилища к экрану блокировки, и без
            // него база, соль и обёрнутый секрет лежат доступными любому,
            // кто снял образ. Остаётся только PIN. Без экрана блокировки
            // не работает и вход по отпечатку: конверт биометрии требует
            // подтверждения, а его Android даёт только при экране
            // блокировки.
            //
            // ⚠️ Прежде здесь было сказано, что KEK в Keystore «привязан
            // к аутентификации». Ключ HardwareKey намеренно не привязан
            // (иначе вход по PIN без биометрии был бы невозможен) —
            // привязан только конверт биометрии.
            //
            // Экрана в приложении, который это чинит, нет и быть не
            // может: настройка системная, поэтому строка ведёт в
            // системные настройки безопасности.
            Check(
                label = R.string.security_check_screen_lock,
                passed = hasScreenLock,
                detail = if (hasScreenLock) {
                    null
                } else {
                    getString(R.string.security_check_screen_lock_hint)
                },
                fix = { openSystemSecuritySettings() },
            ),

            // ⚠️ Признаки root. Проверка эвристическая, и её
            // отрицательный ответ ничего не гарантирует — так и
            // написано в подписи строки.
            Check(
                label = R.string.security_check_root,
                passed = !rooted,
                detail = if (rooted) getString(R.string.security_check_root_hint) else null,
            ),

            // 🔐 Раздел 7.3: «Нет StrongBox/TEE → предупреждение
            // в Security Center». Без аппаратного ключа снятая копия
            // файлов приложения защищена одним PIN.
            hardwareKeyCheck(),

            // 🔐 Ответ самого оборудования, а не системы (RESILIENCE-1.3).
            // Заодно — заперт ли загрузчик.
            attestationCheck(attestation),

            // 🔐 Подпись APK (RESILIENCE-2.1): пересобранная копия
            // подписана чужим ключом.
            signatureCheck(attestation),
        )
    }

    private fun hardwareKeyCheck(): Check {
        val level = HardwareKey.securityLevel()

        return Check(
            label = R.string.security_check_hardware_key,
            passed = level == KeyAttestation.Level.STRONGBOX ||
                level == KeyAttestation.Level.TRUSTED_ENVIRONMENT,
            detail = when (level) {
                KeyAttestation.Level.STRONGBOX -> getString(R.string.security_check_hardware_key_strongbox)
                KeyAttestation.Level.TRUSTED_ENVIRONMENT -> getString(R.string.security_check_hardware_key_tee)
                KeyAttestation.Level.SOFTWARE -> getString(R.string.security_check_hardware_key_software)
                // Ключа ещё нет или спросить не удалось: непройдено,
                // но без выдуманного объяснения.
                null -> null
            },
        )
    }

    private fun attestationCheck(verdict: KeyAttestation.Verdict): Check = Check(
        label = R.string.security_check_attestation,
        passed = verdict.passed,
        detail = when (verdict.outcome) {
            KeyAttestation.Outcome.TRUSTED_HARDWARE -> null
            KeyAttestation.Outcome.BOOT_NOT_VERIFIED -> getString(R.string.security_check_attestation_boot)
            KeyAttestation.Outcome.SOFTWARE_ONLY -> getString(R.string.security_check_attestation_software)
            KeyAttestation.Outcome.UNTRUSTED_ROOT -> getString(R.string.security_check_attestation_untrusted)
            KeyAttestation.Outcome.FAILED -> getString(R.string.security_check_attestation_failed)
        },
    )

    private fun signatureCheck(attestation: KeyAttestation.Verdict): Check {
        val verdict = AppSignature.check(this, attestation.trustedSignatureDigests)

        return Check(
            label = R.string.security_check_signature,
            passed = verdict == AppSignature.Verdict.MATCH,
            detail = when (verdict) {
                AppSignature.Verdict.MATCH -> null
                AppSignature.Verdict.MISMATCH -> getString(R.string.security_check_signature_mismatch)
                AppSignature.Verdict.NOT_CONFIGURED -> getString(R.string.security_check_signature_unchecked)
            },
        )
    }

    /**
     * Открывает системные настройки безопасности.
     *
     * Экран блокировки ставится в системе, а не в приложении, поэтому
     * строка проверки ведёт туда. Намерение может не разрешиться
     * (производители переносят этот экран), и тогда строка просто
     * не реагирует — это лучше падения.
     */
    private fun openSystemSecuritySettings() {
        runCatching {
            startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
        }
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

        return seconds in 0L..Settings.AUTO_LOCK_RECOMMENDED_MAX
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
                onClick = check.fix?.takeUnless { check.passed },
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

        /** Сколько последних событий журнала показывается. */
        const val LOG_LIMIT = 20u

    }
}
