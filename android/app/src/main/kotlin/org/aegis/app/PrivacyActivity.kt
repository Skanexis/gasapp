// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisToast
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisSheet
import org.aegis.app.components.PinPad
import org.aegis.app.core.BiometricUnlock
import org.aegis.app.core.Core
import org.aegis.app.core.DeleteAccount
import org.aegis.app.core.PinAttempts
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
        bindBiometric()
        bindWipe()
        bindAutoLock()
        bindExport()
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
            icon = R.drawable.ic_globe,
            onClick = { startActivity(Intent(this, NetworkActivity::class.java)) },
        )
    }

    private fun bindPresence() {
        SettingsToggle.bind(
            root = findViewById(R.id.privacy_presence),
            label = R.string.privacy_presence,
            hint = R.string.privacy_presence_hint,
            icon = R.drawable.ic_check,
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
            icon = R.drawable.ic_eye_off,
            checked = readBool(Settings.BLOCK_SCREENSHOTS, default = true),
        ) { wanted -> writeBool(Settings.BLOCK_SCREENSHOTS, wanted) }
    }

    private fun bindNotificationPreview() {
        SettingsToggle.bind(
            root = findViewById(R.id.privacy_preview),
            label = R.string.privacy_preview,
            hint = R.string.privacy_preview_hint,
            icon = R.drawable.ic_bell,
            checked = readBool(Settings.NOTIFICATION_PREVIEW, default = false),
        ) { wanted -> writeBool(Settings.NOTIFICATION_PREVIEW, wanted) }
    }

    /**
     * 🔐 Вход по отпечатку (MASVS AUTH-2.1).
     *
     * # Что переключатель на самом деле делает
     *
     * Включение: спрашивает PIN, собирает из него ключ базы
     * и запечатывает его в конверт, который Android Keystore откроет
     * только после подтверждения биометрией. Выключение: стирает
     * конверт и его ключ.
     *
     * Биометрия здесь — способ не набирать PIN, а не второй способ
     * получить доступ. Подпись под переключателем говорит это прямо:
     * иначе человек решит, что отпечаток защищает переписку **вместо**
     * PIN, и выберет PIN попроще.
     *
     * # Почему PIN спрашивается заново
     *
     * Ключ базы живёт в ядре и наружу не отдаётся. Чтобы его
     * запечатать, его надо собрать, а собрать его без PIN нельзя —
     * в этом и смысл. Экран не хранит PIN между экранами и не может
     * взять его «откуда-то».
     */
    private fun bindBiometric() {
        val row = findViewById<View>(R.id.privacy_biometric)
        val availability = BiometricUnlock.availability(this)

        SettingsToggle.bind(
            root = row,
            label = R.string.privacy_biometric,
            hint = R.string.privacy_biometric_hint,
            icon = R.drawable.ic_key,
            checked = BiometricUnlock.isEnabled(this),
        ) { wanted ->
            if (!wanted) {
                BiometricUnlock.disable(this)
                toast(R.string.privacy_biometric_disabled, AegisToast.Tone.Info)

                return@bind true
            }

            when (availability) {
                BiometricUnlock.Availability.Ready -> {
                    askPinThenEnableBiometric()

                    // Переключатель встанет в нужное положение после
                    // подтверждения, а не по нажатию: пока человек
                    // не приложил палец, ничего не включено.
                    false
                }

                BiometricUnlock.Availability.NotEnrolled -> {
                    toast(R.string.privacy_biometric_not_enrolled)

                    false
                }

                BiometricUnlock.Availability.Unsupported -> {
                    toast(R.string.privacy_biometric_unsupported)

                    false
                }
            }
        }
    }

    /**
     * Спрашивает PIN и запечатывает ключ базы.
     *
     * 🔐 PIN — своей клавиатурой, не системной (см. [PinPad]): прежде здесь
     * было текстовое поле, и каждую цифру получала системная клавиатура.
     * Окно защищено от снимков всегда, а не по настройке: на записи экрана
     * видно, какие клавиши нажаты.
     */
    private fun askPinThenEnableBiometric() {
        val view = layoutInflater.inflate(R.layout.dialog_pin, null)
        var dialog: AegisDialog.Shown? = null

        PinPad(view) { pad ->
            val pin = pad.take()
            dialog?.dismiss()
            enableBiometric(pin)
        }

        dialog = AegisDialog(this)
            .title(R.string.privacy_biometric_pin_title)
            .content(view)
            .secondary()
            .alwaysSecure()
            .show()
    }

    /**
     * Показывает подтверждение и запечатывает ключ.
     *
     * 🔐 Ключ базы затирается сразу после запечатывания: массив
     * остаётся в куче до сборки мусора, и дамп памяти, снятый
     * в этот момент, отдал бы его целиком.
     */
    private fun enableBiometric(pin: ByteArray) {
        val cipher = runCatching { BiometricUnlock.cipherForEnabling() }.getOrNull()

        if (cipher == null) {
            pin.fill(0)
            toast(R.string.privacy_biometric_failed)

            return
        }

        val prompt = androidx.biometric.BiometricPrompt(
            this,
            androidx.core.content.ContextCompat.getMainExecutor(this),
            object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: androidx.biometric.BiometricPrompt.AuthenticationResult,
                ) {
                    sealStorageKey(pin, result)
                }

                // 🔐 Отказ и отмена — тоже конец жизни PIN.
                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    pin.fill(0)
                }
            },
        )

        prompt.authenticate(
            androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.lock_biometric_title))
                .setSubtitle(getString(R.string.privacy_biometric))
                .setNegativeButtonText(getString(android.R.string.cancel))
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG,
                )
                .build(),
            androidx.biometric.BiometricPrompt.CryptoObject(cipher),
        )
    }

    private fun sealStorageKey(
        pin: ByteArray,
        result: androidx.biometric.BiometricPrompt.AuthenticationResult,
    ) {
        lifecycleScope.launch {
            val sealed = withContext(Dispatchers.IO) {
                runCatching {
                    // Argon2id: около секунды, главный поток не переживёт.
                    val key = Core.deriveKey(applicationContext, pin)

                    try {
                        // 🔐 Запечатывается только ключ, который открывает
                        // базу. Прежде PIN не проверялся: опечатка давала
                        // «включённую» биометрию, которая не открывала
                        // базу никогда, — а человек узнавал об этом, уже
                        // забыв PIN в расчёте на отпечаток.
                        if (Core.keyOpensStorage(key)) {
                            BiometricUnlock.seal(applicationContext, result, key)
                            true
                        } else {
                            false
                        }
                    } finally {
                        key.fill(0)
                    }
                }
            }

            pin.fill(0)

            when (sealed.getOrNull()) {
                true -> toast(R.string.privacy_biometric_enabled, AegisToast.Tone.Success)
                false -> {
                    BiometricUnlock.disable(applicationContext)
                    toast(R.string.privacy_biometric_wrong_pin)
                }
                null -> {
                    BiometricUnlock.disable(applicationContext)
                    toast(R.string.privacy_biometric_failed)
                }
            }

            bindBiometric()
        }
    }

    private fun toast(
        @androidx.annotation.StringRes message: Int,
        tone: AegisToast.Tone = AegisToast.Tone.Warning,
    ) {
        AegisToast.show(this, message, tone)
    }

    /**
     * 🔐 Выгрузка данных (MASVS PRIVACY-3.1).
     *
     * # Почему через системный выбор файла
     *
     * `CreateDocument` отдаёт приложению ровно тот файл, который
     * человек указал, и не требует ни одного разрешения на хранилище.
     * Запись в «Загрузки» своими руками потребовала бы доступа
     * ко всему хранилищу — ради одного файла, который человек и так
     * выбирает сам.
     *
     * # Почему предупреждение обязательно
     *
     * ⚠️ Файл **не зашифрован**. Это не недоработка: зашифрованная
     * выгрузка не переносима, а смысл выгрузки — унести данные туда,
     * где их прочтут другой программой. Но получивший этот файл
     * получил всю переписку, и узнать об этом человек должен
     * до того, как выберет, куда сохранять, — а не после.
     */
    /**
     * 🔐 Срок автоблокировки.
     *
     * Настройку читали [AutoLock] и центр безопасности, но ни один
     * экран её не записывал: срок был минутой навсегда, а комментарии
     * в `Settings` обещали, что его можно поменять.
     */
    /**
     * 🔐 Opt-in стирание после десяти неверных PIN (раздел 19.3).
     *
     * Включение — через подтверждение, выключение — сразу: включённое
     * по ошибке стирание уничтожает данные, выключенное по ошибке —
     * нет. Флаг лежит вне базы (см. [PinAttempts.wipeEnabled]).
     */
    private fun bindWipe() {
        lateinit var toggle: org.aegis.app.ui.SettingsToggle

        toggle = SettingsToggle.bind(
            root = findViewById(R.id.privacy_wipe),
            label = R.string.privacy_wipe,
            hint = R.string.privacy_wipe_hint,
            icon = R.drawable.ic_trash,
            checked = PinAttempts.wipeEnabled(this),
        ) { wanted ->
            if (!wanted) {
                PinAttempts.setWipeEnabled(this, false)

                return@bind true
            }

            AegisDialog(this)
                .title(R.string.privacy_wipe_confirm_title)
                .message(R.string.privacy_wipe_confirm_body)
                .secondary()
                .primary(R.string.privacy_wipe_confirm, AegisDialog.Tone.Danger) {
                    PinAttempts.setWipeEnabled(this, true)
                    toggle.isChecked = true
                }
                .show()

            // Переключатель встанет после подтверждения, а не по нажатию.
            false
        }
    }

    private fun bindAutoLock() {
        val current = runCatching {
            Core.messenger().settingInt(Settings.AUTO_LOCK_SECONDS, Settings.AUTO_LOCK_DEFAULT)
        }.getOrDefault(Settings.AUTO_LOCK_DEFAULT)

        SettingsRow.bind(
            root = findViewById(R.id.privacy_autolock),
            title = getString(R.string.privacy_autolock),
            value = autoLockLabel(current),
            icon = R.drawable.ic_clock,
            onClick = { chooseAutoLock() },
        )
    }

    private fun chooseAutoLock() {
        val sheet = AegisSheet.on(this, R.string.privacy_autolock)

        Settings.AUTO_LOCK_CHOICES.forEach { seconds ->
            sheet.action(autoLockLabel(seconds)) {
                // Запись в зашифрованную базу; отказ оставляет прежний срок,
                // и строка покажет его, а не выбранный.
                runCatching { Core.messenger().setSettingInt(Settings.AUTO_LOCK_SECONDS, seconds) }
                bindAutoLock()
            }
        }

        sheet.show()
    }

    private fun autoLockLabel(seconds: Long): String = when {
        seconds < 60L -> resources.getQuantityString(R.plurals.autolock_seconds, seconds.toInt(), seconds.toInt())
        else -> resources.getQuantityString(R.plurals.autolock_minutes, (seconds / 60L).toInt(), (seconds / 60L).toInt())
    }

    private fun bindExport() {
        SettingsRow.bind(
            root = findViewById(R.id.privacy_export),
            label = R.string.privacy_export,
            icon = R.drawable.ic_file,
            onClick = { confirmExport() },
        )
    }

    /** Предупреждение до выбора места. */
    private fun confirmExport() {
        AegisDialog(this)
            .title(R.string.privacy_export_title)
            .message(R.string.privacy_export_warning)
            .secondary()
            .primary(R.string.privacy_export_continue) { createExportFile.launch(exportFileName()) }
            .show()
    }

    /**
     * Принимает выбранное место и пишет туда выгрузку.
     *
     * 🔐 Выгрузка строится **после** выбора места, а не до: иначе вся
     * переписка открытым текстом лежала бы в памяти процесса всё
     * время, пока человек ходит по системному выбору файлов, — в том
     * числе если он оттуда просто уйдёт.
     */
    private val createExportFile = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri == null) {
            return@registerForActivityResult
        }

        lifecycleScope.launch {
            val written = withContext(Dispatchers.IO) {
                runCatching {
                    val json = Core.messenger().exportData(System.currentTimeMillis())

                    contentResolver.openOutputStream(uri)?.use { stream ->
                        stream.write(json.toByteArray(Charsets.UTF_8))
                    } ?: error("поток не открылся")
                }
            }

            AegisToast.show(
                this@PrivacyActivity,
                if (written.isSuccess) R.string.privacy_export_done else R.string.privacy_export_failed,
                if (written.isSuccess) AegisToast.Tone.Success else AegisToast.Tone.Error,
            )
        }
    }

    /**
     * Имя файла с датой.
     *
     * 🔐 Имени пользователя в нём нет: файл попадает в «Загрузки»,
     * в облако и в список недавних, а эти места видят другие
     * приложения. Имя аккаунта внутри файла — там ему и место.
     */
    private fun exportFileName(): String {
        val date = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
            .format(java.util.Date())

        return "aegis-export-$date.json"
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
        AegisDialog(this)
            .title(R.string.privacy_delete_account_title)
            .message(R.string.privacy_delete_account_warning)
            .secondary()
            .primary(R.string.privacy_delete_account_continue, AegisDialog.Tone.Danger) {
                confirmDeleteAccountFinally()
            }
            .show()
    }

    /** Второе подтверждение: последняя возможность отказаться. */
    private fun confirmDeleteAccountFinally() {
        AegisDialog(this)
            .title(R.string.privacy_delete_account_final_title)
            .message(R.string.privacy_delete_account_final)
            .secondary()
            .primary(R.string.privacy_delete_account_confirm, AegisDialog.Tone.Danger) { runDeleteAccount() }
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
                        //
                        // Системный тост, а не AegisToast: следом открывается
                        // другой экран, и тост внутри этого окна исчез бы с ним.
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
                    AegisToast.show(
                        this@PrivacyActivity,
                        R.string.privacy_delete_account_failed,
                        AegisToast.Tone.Error,
                    )
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
