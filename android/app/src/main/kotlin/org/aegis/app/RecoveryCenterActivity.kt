// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisTextField
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.SettingsRow
import uniffi.aegis.validateRecoveryKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Recovery Center (раздел 12.4 плана).
 *
 * # Что здесь можно сделать
 *
 * Создать ключ восстановления, сделать копию, восстановиться из копии
 * и сменить ключ. Всё, кроме первого, требует уже созданного ключа —
 * поэтому кнопки включаются по состоянию, а не показываются всегда.
 *
 * # 🔐 Чего здесь нет и не будет
 *
 * Показа существующего ключа. Ключ показывается **один раз**, в момент
 * создания, и нигде не хранится — ни в базе, ни в файле. Кнопка
 * «показать ключ» потребовала бы его хранить, а хранимый ключ
 * означает, что изъятое устройство отдаёт вместе с собой и все копии.
 *
 * Поэтому «проверить ключ» здесь — это ввести его заново на экране
 * восстановления, а не посмотреть.
 */
class RecoveryCenterActivity : AppCompatActivity() {

    /**
     * Ключ, показанный пользователю в этой сессии.
     *
     * 🔐 Живёт в памяти экрана и только до его закрытия: нужен, чтобы
     * сделать первую копию сразу после создания ключа, не заставляя
     * человека набирать 52 символа. Обнуляется в [onDestroy].
     */
    private var pendingKey: String? = null

    /** Куда сохранить собранный файл копии. */
    private var pendingArchive: ByteArray? = null

    /**
     * Диалог сохранения файла копии.
     *
     * Файл пишет система через SAF: приложение не просит доступа
     * ко всему хранилищу ради одного файла, который выбирает
     * пользователь.
     */
    private val saveArchive = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts
            .StartActivityForResult(),
    ) { result ->
        val uri = result.data?.data

        if (result.resultCode == Activity.RESULT_OK && uri != null) {
            writeArchive(uri)
        } else {
            // Отказ от сохранения — не ошибка, но копия при этом
            // никуда не делась: сказать об этом надо, иначе человек
            // решит, что копия есть.
            pendingArchive = null
            showStatus(getString(R.string.recovery_not_saved))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_recovery_center)

        findViewById<ImageView>(R.id.recovery_back).setOnClickListener { finish() }

        findViewById<AegisButton>(R.id.recovery_create).setOnClickListener {
            startActivity(Intent(this, RecoveryKeyActivity::class.java))
        }
        findViewById<AegisButton>(R.id.recovery_backup_now).setOnClickListener { backupNow() }
        SettingsRow.bind(
            root = findViewById(R.id.recovery_restore),
            label = R.string.recovery_restore,
            icon = R.drawable.ic_database,
            onClick = { startActivity(Intent(this, RestoreActivity::class.java)) },
        )
        SettingsRow.bind(
            root = findViewById(R.id.recovery_new_key),
            label = R.string.recovery_new_key,
            icon = R.drawable.ic_key,
            onClick = ::newKey,
        )
    }

    override fun onStart() {
        super.onStart()

        // Ключ, только что созданный на соседнем экране, приезжает сюда
        // через intent: держать его в статическом поле значило бы
        // оставить его в памяти процесса после закрытия экрана.
        intent?.getStringExtra(EXTRA_RECOVERY_KEY)?.let {
            pendingKey = it
            intent.removeExtra(EXTRA_RECOVERY_KEY)
        }

        render()
    }

    /**
     * 🔐 Ключ не переживает экран.
     *
     * Строка Kotlin не обнуляется явно — сборщик мусора делает это
     * когда захочет, — но ссылка снимается сразу, и после этого ключ
     * недостижим. Это предел того, что даёт JVM; настоящее обнуление
     * секретов живёт в Rust, где для этого есть `Secret<T>`.
     */
    override fun onDestroy() {
        pendingKey = null
        pendingArchive = null

        super.onDestroy()
    }

    private fun render() {
        val status = runCatching { Core.messenger().backupStatus() }.getOrNull()

        val configured = status?.configured == true

        // Состояние не только цветом (раздел 20.5): значок и слова
        // тоже разные — щит с галочкой у настроенной копии, ключ
        // у ненастроенной.
        val stateColor = androidx.core.content.ContextCompat.getColor(
            this,
            if (configured) R.color.status_ok else R.color.status_warn,
        )
        findViewById<ImageView>(R.id.recovery_state_icon).apply {
            setImageResource(if (configured) R.drawable.ic_shield_check else R.drawable.ic_key)
            imageTintList = android.content.res.ColorStateList.valueOf(stateColor)
            backgroundTintList = android.content.res.ColorStateList.valueOf(
                androidx.core.content.ContextCompat.getColor(
                    this@RecoveryCenterActivity,
                    if (configured) R.color.status_ok_dim else R.color.status_warn_dim,
                ),
            )
        }
        findViewById<TextView>(R.id.recovery_state_title).setText(
            if (configured) R.string.recovery_state_on else R.string.recovery_state_off,
        )

        findViewById<TextView>(R.id.recovery_last).text = when (val at = status?.lastBackupAtMillis) {
            null -> getString(R.string.recovery_never)
            else -> getString(R.string.recovery_last, formatMoment(at))
        }

        // Копию можно сделать, только когда есть чем её зашифровать:
        // либо ключ создан прямо сейчас, либо цепочка уже начата и
        // ключ надо ввести.
        val hasKey = pendingKey != null || configured
        // Главное действие — одно на экран (UI kit): пока ключа нет —
        // создать его, когда есть — сделать копию. Погашенная кнопка
        // «Сделать копию» рядом с «Создать ключ» только мешала.
        findViewById<AegisButton>(R.id.recovery_backup_now).visibility = if (hasKey) View.VISIBLE else View.GONE
        findViewById<AegisButton>(R.id.recovery_create).visibility = if (hasKey) View.GONE else View.VISIBLE
        // Сменить можно только существующий ключ.
        findViewById<View>(R.id.recovery_new_key).visibility = if (configured) View.VISIBLE else View.GONE
    }

    /**
     * Собирает резервную копию и предлагает сохранить её файлом.
     *
     * Ключ берётся из этой сессии, если он только что создан; иначе
     * пользователя просят ввести его. Второго пути нет — ключ нигде
     * не хранится.
     */
    private fun backupNow() {
        // Ключа под рукой нет — значит, его надо спросить: приложение
        // его не хранит и достать неоткуда.
        val key = pendingKey ?: return askForKey(::runBackup)

        runBackup(key)
    }

    /**
     * Спрашивает ключ восстановления для очередной копии.
     *
     * 🔐 Введённый ключ не запоминается дальше одной операции:
     * поле [pendingKey] заполняется только тем ключом, который
     * приложение само что создало и ещё не дало забыть.
     */
    private fun askForKey(onEntered: (String) -> Unit) {
        val input = AegisTextField(this).apply {
            setHint(R.string.restore_key_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setTextColor(androidx.core.content.ContextCompat.getColor(context, R.color.text_primary))

            // 🔐 Клавиатура не учится на ключе восстановления, а поле
            // не сохраняет его в состоянии экрана. Прежде поле создавалось
            // без этих флагов: запрет подсказок (NO_SUGGESTIONS) клавиатура
            // вправе не считать запретом обучения, и ключ, открывающий всю
            // копию переписки, мог попасть в её словарь. KeyboardLearningTest
            // этого не видел — он проверяет только поля из разметки.
            imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            isSaveEnabled = false
        }

        AegisDialog(this)
            .title(R.string.recovery_key_needed)
            .content(input)
            .secondary()
            .primary(R.string.recovery_backup_now, closeOnClick = false) { dialog ->
                val entered = input.text.toString()

                // Контрольная сумма проверяется до дорогого Argon2id:
                // опечатку видно мгновенно — в самом диалоге, не теряя
                // набранного.
                if (validateRecoveryKey(entered)) {
                    dialog.dismiss()
                    onEntered(entered)
                } else {
                    input.hasError = true
                    dialog.showError(R.string.restore_key_invalid)
                }
            }
            // 🔐 Всегда, а не по настройке: здесь вводится ключ,
            // открывающий всю копию переписки.
            .alwaysSecure()
            .show()
    }

    private fun runBackup(key: String) {
        val button = findViewById<AegisButton>(R.id.recovery_backup_now)
        button.isLoading = true

        lifecycleScope.launch {
            // Argon2id с 256 МиБ памяти и чтение всей базы: главный
            // поток такое не переживёт.
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().createBackup(
                        recoveryKey = key,
                        deviceLabel = android.os.Build.MODEL,
                        nowMillis = System.currentTimeMillis(),
                    )
                }
            }

            button.isLoading = false

            outcome.onSuccess { backup ->
                pendingArchive = backup.archive
                showStatus(
                    getString(
                        R.string.recovery_created,
                        backup.recordCount.toInt(),
                        backup.generation.toInt(),
                    ),
                )
                askWhereToSave(backup.generation.toInt())
            }.onFailure {
                button.isError = true
                showStatus(getString(R.string.recovery_failed))
            }

            render()
        }
    }

    /** Спрашивает у системы, куда положить файл копии. */
    private fun askWhereToSave(generation: Int) {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = ARCHIVE_MIME
            putExtra(Intent.EXTRA_TITLE, archiveName(generation))
        }

        saveArchive.launch(intent)
    }

    /**
     * Пишет файл копии по выбранному пути.
     *
     * 🔐 Содержимое зашифровано: файл можно класть в любое облако.
     * Именно это свойство и есть смысл zero-knowledge backup —
     * хранилищу не нужно доверять.
     */
    private fun writeArchive(uri: Uri) {
        val archive = pendingArchive ?: return

        lifecycleScope.launch {
            val written = withContext(Dispatchers.IO) {
                runCatching {
                    contentResolver.openOutputStream(uri)?.use { it.write(archive) }
                        ?: error("поток не открылся")
                }
            }

            pendingArchive = null

            showStatus(
                if (written.isSuccess) {
                    getString(R.string.recovery_saved)
                } else {
                    getString(R.string.recovery_save_failed)
                },
            )
        }
    }

    /**
     * Смена ключа восстановления.
     *
     * ⚠️ Прежние копии остаются зашифрованными **старым** ключом:
     * перешифровать их приложение не может — они лежат в чужом
     * хранилище. Сказать это надо до, а не после.
     */
    private fun newKey() {
        AegisDialog(this)
            .title(R.string.recovery_new_key)
            .message(R.string.recovery_new_key_warning)
            .secondary()
            .primary(R.string.recovery_new_key_confirm) {
                runCatching { Core.messenger().forgetBackupChain() }
                    .onSuccess {
                        pendingKey = null
                        startActivity(Intent(this, RecoveryKeyActivity::class.java))
                    }
                    .onFailure { showStatus(getString(R.string.recovery_failed)) }

                render()
            }
            .show()
    }

    private fun showStatus(text: String) {
        findViewById<TextView>(R.id.recovery_status).apply {
            this.text = text
            visibility = View.VISIBLE
        }
    }

    private fun formatMoment(millis: Long): String =
        SimpleDateFormat("d MMMM, HH:mm", Locale.getDefault()).format(Date(millis))

    private fun archiveName(generation: Int): String {
        val stamp = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())

        return "aegis-backup-$stamp-$generation.aegisbk"
    }

    companion object {

        /** Ключ восстановления, переданный с экрана его создания. */
        const val EXTRA_RECOVERY_KEY: String = "recovery_key"

        /**
         * Тип файла копии.
         *
         * `application/octet-stream`, а не свой тип: файл — это шум,
         * и объявлять для него отдельный MIME значило бы помечать
         * его как «резервная копия AEGIS» для всякого, кто смотрит
         * на хранилище.
         */
        private const val ARCHIVE_MIME = "application/octet-stream"
    }
}
