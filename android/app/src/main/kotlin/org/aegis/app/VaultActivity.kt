// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.Core
import org.aegis.app.ui.SettingsRow
import uniffi.aegis.FfiVaultFile
import java.io.File

/**
 * File Vault: файлы под вторым фактором (раздел 11.4 плана).
 *
 * # Два состояния экрана
 *
 * Закрытое — рабочее, а не заглушка: на нём видно только число
 * файлов. Имена уже говорят достаточно («паспорт.pdf», «результаты
 * анализов.jpg»), поэтому список появляется лишь после повторной
 * аутентификации.
 *
 * # 🔐 Почему PIN спрашивается заново
 *
 * Разблокированного приложения недостаточно. Сценарий, ради которого
 * vault существует, — «телефон разблокирован и отдан в чужие руки»:
 * показать переписку не жалко, показать паспорт — жалко. Ключ vault
 * выводится в Rust из введённого PIN и живёт только пока vault
 * открыт: через 60 секунд бездействия или при уходе в фон он
 * обнуляется.
 *
 * # 🔐 Про превью и системные кэши
 *
 * Задача раздела 11.4: миниатюры файлов vault не должны попадать
 * в системный кэш изображений. Здесь это обеспечивается тем, что
 * приложение **не отдаёт файлы системе**:
 *
 * * список рисуется текстовыми строками, без миниатюр — значит,
 *   декодировать и кэшировать нечего;
 * * расшифрованный файл пишется во временный каталог, из которого
 *   удаляется сразу после закрытия экрана;
 * * `FLAG_SECURE` стоит всегда, поэтому окно не попадает и в снимок
 *   переключателя задач.
 *
 * Просмотр содержимого сторонним приложением сознательно не сделан:
 * отданный по `content://` файл попадает в кэш того приложения,
 * и вернуть его оттуда нельзя. Это ограничение, а не недоделка,
 * и оно отмечено в плане.
 */
class VaultActivity : AppCompatActivity() {

    /**
     * Временные файлы, созданные при просмотре.
     *
     * 🔐 Удаляются в [onStop]: расшифрованный файл на диске — ровно
     * то, чего vault должен не допускать.
     */
    private val temporary = mutableListOf<File>()

    /** Выбор файла для добавления в vault. */
    private val pickFile = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts
            .StartActivityForResult(),
    ) { result ->
        val uri = result.data?.data

        if (result.resultCode == Activity.RESULT_OK && uri != null) {
            addFile(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Всегда, независимо от общей настройки: содержимое vault
        // не должно попасть ни в скриншот, ни в снимок переключателя
        // задач. Человек, выключивший блокировку снимков ради чатов,
        // не имел в виду «показывать паспорт в переключателе задач».
        // Заодно отбрасываются касания через накрывающее окно:
        // подтверждение на этом экране необратимо (MASVS PLATFORM-3).
        SecureWindow.applyAlways(this)

        setContentView(R.layout.activity_vault)

        findViewById<ImageView>(R.id.vault_back).setOnClickListener { finish() }
        findViewById<ImageView>(R.id.vault_seal).setOnClickListener { seal() }
        findViewById<AegisButton>(R.id.vault_unlock).setOnClickListener { unlock() }
        findViewById<AegisButton>(R.id.vault_add).setOnClickListener { pickFileToAdd() }

        render()
    }

    override fun onStart() {
        super.onStart()
        render()
    }

    /**
     * 🔐 Уход с экрана закрывает vault и стирает временные файлы.
     *
     * Ядро закрывает vault и по таймауту, но таймаут вычисляется
     * при обращении: пока никто не спрашивает, ключ лежит в памяти.
     * Явный вызов при уходе в фон — то, на что ядро рассчитывает.
     */
    override fun onStop() {
        runCatching { Core.messenger().onBackground() }

        temporary.forEach { file -> runCatching { file.delete() } }
        temporary.clear()

        super.onStop()
    }

    private fun render() {
        val open = runCatching {
            Core.messenger().isVaultOpen(System.currentTimeMillis())
        }.getOrDefault(false)

        findViewById<View>(R.id.vault_sealed_panel).visibility =
            if (open) View.GONE else View.VISIBLE
        findViewById<View>(R.id.vault_open_panel).visibility =
            if (open) View.VISIBLE else View.GONE
        findViewById<View>(R.id.vault_seal).visibility =
            if (open) View.VISIBLE else View.GONE

        val count = runCatching { Core.messenger().vaultFileCount() }.getOrDefault(0u).toInt()

        findViewById<TextView>(R.id.vault_count).text =
            resources.getQuantityString(R.plurals.vault_file_count, count, count)

        if (open) {
            renderFiles()
        }
    }

    private fun renderFiles() {
        val files = runCatching {
            Core.messenger().vaultFiles(FILE_LIMIT, System.currentTimeMillis())
        }.getOrDefault(emptyList())

        val list = findViewById<LinearLayout>(R.id.vault_list)
        list.removeAllViews()

        findViewById<View>(R.id.vault_empty).visibility =
            if (files.isEmpty()) View.VISIBLE else View.GONE

        // 🔐 Строки текстовые, без миниатюр: нечего декодировать —
        // нечего и кэшировать в системном кэше изображений.
        files.forEach { file ->
            val row = layoutInflater.inflate(R.layout.item_settings_row, list, false)

            SettingsRow.bind(
                root = row,
                title = file.name,
                value = formatSize(file.size),
                icon = R.drawable.ic_file,
                onClick = { openFile(file) },
            )

            list.addView(row)
        }
    }

    /**
     * Открывает vault по повторно введённому PIN.
     *
     * 🔐 PIN уходит в ядро, ключ обратно не возвращается: вывод
     * `K_vault` целиком в Rust, и в памяти Kotlin его нет никогда.
     */
    private fun unlock() {
        val field = findViewById<EditText>(R.id.vault_pin)
        val pin = field.text.toString()
        val button = findViewById<AegisButton>(R.id.vault_unlock)

        button.isLoading = true

        lifecycleScope.launch {
            // Argon2id: секунда на телефоне, и это норма, а не
            // проблема производительности.
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().unlockVault(
                        pin = pin,
                        salt = Core.salt(this@VaultActivity),
                        nowMillis = System.currentTimeMillis(),
                    )
                }
            }

            button.isLoading = false
            // 🔐 Поле очищается в любом случае: PIN не должен остаться
            // на экране, к которому вернутся через переключатель задач.
            field.setText("")

            if (outcome.isFailure) {
                button.isError = true
                showStatus(getString(R.string.vault_unlock_failed))
            }

            render()
        }
    }

    private fun seal() {
        runCatching { Core.messenger().sealVault() }
        showStatus(getString(R.string.vault_sealed))
        render()
    }

    private fun pickFileToAdd() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }

        pickFile.launch(intent)
    }

    /**
     * Кладёт файл в vault.
     *
     * Шифрует ядро, записывает на диск платформа: файловой системы
     * ядро не касается — так же, как со вложениями.
     */
    private fun addFile(uri: Uri) {
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: error("файл не читается")
                    val name = displayName(uri)
                    val blob = File(vaultDir(), "${System.nanoTime()}.enc")

                    val sealed = Core.messenger().addVaultFile(
                        name = name,
                        contents = bytes,
                        location = blob.absolutePath,
                        nowMillis = System.currentTimeMillis(),
                    )

                    blob.writeBytes(sealed.ciphertext)
                }
            }

            showStatus(
                if (outcome.isSuccess) {
                    getString(R.string.vault_added)
                } else {
                    getString(R.string.vault_add_failed)
                },
            )

            render()
        }
    }

    /**
     * Расшифровывает файл во временный каталог и показывает путь.
     *
     * 🔐 Файл кладётся в `cacheDir/vault-open`, откуда удаляется
     * в [onStop]. Наружу он не отдаётся: `content://` для стороннего
     * приложения означал бы копию в его кэше, до которой приложению
     * уже не дотянуться.
     */
    private fun openFile(file: FfiVaultFile) {
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val blob = File(file.location).readBytes()
                    val plaintext = Core.messenger().openVaultFile(
                        fileId = file.fileId,
                        ciphertext = blob,
                        nowMillis = System.currentTimeMillis(),
                    )

                    val opened = File(openDir(), file.name)
                    opened.writeBytes(plaintext)

                    opened
                }
            }

            outcome.onSuccess { opened ->
                temporary.add(opened)
                showStatus(getString(R.string.vault_opened, opened.name))
            }.onFailure {
                // Отказ здесь означает либо закрывшийся по таймауту
                // vault, либо подменённый блоб. Обе причины —
                // «попробуйте открыть заново».
                showStatus(getString(R.string.vault_open_failed))
                render()
            }
        }
    }

    private fun displayName(uri: Uri): String {
        val cursor = contentResolver.query(uri, null, null, null, null)

        cursor?.use {
            val index = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)

            if (index >= 0 && it.moveToFirst()) {
                return it.getString(index)
            }
        }

        return getString(R.string.vault_unnamed)
    }

    /** Каталог шифроблобов vault. */
    private fun vaultDir(): File = File(filesDir, "vault").apply { mkdirs() }

    /**
     * Каталог временно расшифрованных файлов.
     *
     * Определён в [org.aegis.app.core.VaultTemp]: там же лежит
     * подметание, которое убирает пережившее гибель процесса.
     */
    private fun openDir(): File = org.aegis.app.core.VaultTemp.directory(this)

    private fun showStatus(text: String) {
        findViewById<TextView>(R.id.vault_status).apply {
            this.text = text
            visibility = View.VISIBLE
        }
    }

    /** Размер файла в том же виде, что на экране хранилища. */
    private fun formatSize(bytes: Long): String = when {
        bytes >= 1024L * 1024L -> String.format(
            java.util.Locale.getDefault(),
            "%.1f МБ",
            bytes / (1024.0 * 1024.0),
        )

        bytes >= 1024L -> "${bytes / 1024} КБ"
        else -> "$bytes Б"
    }

    private companion object {

        /** Сколько файлов показывать: список vault не бывает длинным. */
        const val FILE_LIMIT = 200u
    }
}
