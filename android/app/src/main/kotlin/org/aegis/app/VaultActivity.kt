// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisSheet
import org.aegis.app.components.PinPad
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.VaultBlob
import org.aegis.app.core.showSecure
import org.aegis.app.ui.FileSize
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

    /** Клавиатура PIN хранилища. */
    private lateinit var vaultPin: PinPad

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

        // 🔐 PIN — своей клавиатурой, не системной (см. [PinPad]);
        // набранные шесть цифр открывают хранилище сразу, как на экране
        // входа.
        vaultPin = PinPad(findViewById(android.R.id.content)) { unlock() }
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
                value = FileSize.format(this, file.size),
                icon = R.drawable.ic_file,
                onClick = { showFileActions(file) },
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
        if (!vaultPin.isComplete) {
            showStatus(getString(R.string.vault_pin_incomplete))

            return
        }

        // 🔐 Забирается с затиранием: PIN не остаётся на экране,
        // к которому вернутся через переключатель задач.
        val pin = vaultPin.take()
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

            if (outcome.isFailure) {
                button.isError = true
                showStatus(getString(R.string.vault_unlock_failed))
            } else {
                // Отказ прошлой попытки не должен висеть над открытым
                // хранилищем: «не удалось открыть» при открытом vault
                // заставляет усомниться, что он открыт своим PIN.
                button.isError = false
                findViewById<TextView>(R.id.vault_status).visibility = View.GONE
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
            // Запись — чтобы после добавления можно было удалить
            // оригинал (offerToDeleteOriginal). Только этот документ,
            // только на время процесса: разрешение не сохраняется.
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
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

                    // Атомарно: обрезанный блоб — файл, который уже
                    // не расшифровать, при живой записи о нём в базе.
                    org.aegis.app.core.DurableFile.write(blob, sealed.ciphertext)
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

            if (outcome.isSuccess) {
                offerToDeleteOriginal(uri)
            }
        }
    }

    /**
     * 🔐 Предлагает удалить исходный файл после добавления в хранилище.
     *
     * # Что здесь чинится
     *
     * Добавление шифровало **копию**. Исходник оставался в общей
     * памяти телефона: его видели галерея, любое приложение с доступом
     * к файлам и облачная копия, — а человек считал, что спрятал файл.
     * Хранилище, рядом с которым лежит открытый оригинал, не хранит
     * ничего.
     *
     * # Почему вопрос, а не молчаливое удаление
     *
     * Удалить чужой файл без спроса — потерять его, если шифрование
     * копии пойдёт не так в следующий раз. Вопрос задаётся после
     * успешной записи, и по умолчанию ничего не удаляется.
     *
     * ⚠️ Удаление не затирает флеш-память, и облачная копия, если она
     * уже сделана, остаётся. Диалог об этом говорит.
     */
    private fun offerToDeleteOriginal(uri: Uri) {
        AlertDialog.Builder(this)
            .setTitle(R.string.vault_original_title)
            .setMessage(R.string.vault_original_body)
            .setNegativeButton(R.string.vault_original_keep, null)
            .setPositiveButton(R.string.vault_original_delete) { _, _ -> deleteOriginal(uri) }
            .showSecure(this)
    }

    private fun deleteOriginal(uri: Uri) {
        lifecycleScope.launch {
            val deleted = withContext(Dispatchers.IO) {
                runCatching { DocumentsContract.deleteDocument(contentResolver, uri) }
                    .getOrDefault(false)
            }

            // Поставщик вправе не уметь удалять (облачные папки, чужие
            // приложения): тогда человек должен знать, что оригинал цел.
            Toast.makeText(
                this@VaultActivity,
                if (deleted) R.string.vault_original_deleted else R.string.vault_original_manual,
                Toast.LENGTH_LONG,
            ).show()
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
    /**
     * Действия с файлом: открыть или удалить.
     *
     * 🔐 Удаление стоит рядом с открытием, а не прячется за долгим
     * нажатием. Прежде удалить файл из хранилища было нельзя вовсе:
     * ядро и FFI это умели, экран не звал, а документ о сроках
     * хранения обещал «до удаления пользователем». Действие, которое
     * надо угадать, для такого обещания почти так же плохо.
     */
    private fun showFileActions(file: FfiVaultFile) {
        AegisSheet.on(this, file.name)
            .action(getString(R.string.vault_open), R.drawable.ic_file) { openFile(file) }
            .action(getString(R.string.vault_delete), R.drawable.ic_trash, destructive = true) {
                confirmDelete(file)
            }
            .show()
    }

    /** Подтверждение: удаление необратимо, копии нет нигде. */
    private fun confirmDelete(file: FfiVaultFile) {
        AegisSheet.on(this, getString(R.string.vault_delete_confirm_title, file.name))
            .action(getString(R.string.vault_delete_forever), R.drawable.ic_trash, destructive = true) {
                deleteFile(file)
            }
            .show()
    }

    /**
     * 🔐 Удаляет файл: запись в базе — ядром, блоб на диске — здесь.
     *
     * Порядок именно такой. Сначала ядро убирает запись (и переносит
     * журнал WAL, чтобы имя и ключ блоба не остались в файле базы),
     * потом стирается блоб. Обратный порядок при сбое оставил бы запись
     * без блоба — файл, который числится в хранилище и не открывается.
     */
    private fun deleteFile(file: FfiVaultFile) {
        lifecycleScope.launch {
            val deleted = withContext(Dispatchers.IO) {
                runCatching {
                    val location = Core.messenger().deleteVaultFile(
                        file.fileId,
                        System.currentTimeMillis(),
                    )

                    location?.let { VaultBlob.deleteInside(vaultDir(), it) }
                }.isSuccess
            }

            showStatus(
                getString(if (deleted) R.string.vault_deleted else R.string.vault_delete_failed),
            )

            render()
        }
    }

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
    // Имя каталога — одно на приложение: его же стирает AccountWipe.
    private fun vaultDir(): File =
        File(filesDir, org.aegis.app.core.AccountWipe.VAULT_DIRECTORY).apply { mkdirs() }

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


    private companion object {

        /** Сколько файлов показывать: список vault не бывает длинным. */
        const val FILE_LIMIT = 200u
    }
}
