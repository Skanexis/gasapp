// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.os.Bundle
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.FileSize
import org.gasapp.app.ui.SettingsRow
import java.io.File

/**
 * Хранилище.
 *
 * 🔐 Всё, что показано здесь, лежит в зашифрованной базе на устройстве.
 * Освобождение места удаляет данные безвозвратно: сервер копий
 * не хранит, и восстановить стёртое будет неоткуда.
 */
class StorageActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_storage)

        findViewById<ImageView>(R.id.storage_back).setOnClickListener { finish() }

        render()
    }

    override fun onStart() {
        super.onStart()
        render()
    }

    private fun render() {
        SettingsRow.bind(
            root = findViewById(R.id.storage_messages),
            label = R.string.storage_messages,
            value = FileSize.format(this, databaseSize()),
            icon = R.drawable.ic_chat,
        )

        SettingsRow.bind(
            root = findViewById(R.id.storage_attachments),
            label = R.string.storage_attachments,
            value = FileSize.format(this, cacheSize()),
            icon = R.drawable.ic_file,
        )

        // 🔐 Удаление истёкших помечено разрушительным: оно необратимо,
        // и отличаться от обычного перехода должно до нажатия.
        SettingsRow.bind(
            root = findViewById(R.id.storage_purge_expired),
            label = R.string.storage_purge_expired,
            icon = R.drawable.ic_clock,
            destructive = true,
            onClick = ::purgeExpired,
        )

        SettingsRow.bind(
            root = findViewById(R.id.storage_clear_cache),
            label = R.string.storage_clear_cache,
            icon = R.drawable.ic_trash,
            destructive = true,
            onClick = ::clearCache,
        )
    }

    /**
     * Удаляет сообщения с истёкшим сроком.
     *
     * Отдельным действием, хотя чистка идёт и при открытии базы:
     * пользователь, включивший исчезающие сообщения, вправе убедиться,
     * что они действительно исчезли, не дожидаясь перезапуска.
     */
    private fun purgeExpired() {
        lifecycleScope.launch {
            val removed = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().purgeExpired(System.currentTimeMillis())
                }.getOrDefault(0u)
            }

            GasAppToast.show(
                this@StorageActivity,
                getString(R.string.storage_purged, removed.toInt()),
                GasAppToast.Tone.Success,
            )

            render()
        }
    }

    /**
     * Удаляет скачанные вложения.
     *
     * 🔐 Кеш — единственное место, где расшифрованный файл лежит
     * на диске. Он появляется, когда пользователь сохраняет вложение,
     * и удаляется отсюда.
     */
    private fun clearCache() {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { cacheDir.deleteRecursively() }
            }

            GasAppToast.show(this@StorageActivity, R.string.storage_cleared, GasAppToast.Tone.Success)

            render()
        }
    }

    private fun databaseSize(): Long =
        runCatching { File(filesDir, DATABASE_NAME).length() }.getOrDefault(0L)

    private fun cacheSize(): Long =
        runCatching {
            cacheDir.walkTopDown().filter { it.isFile }.sumOf { it.length() }
        }.getOrDefault(0L)


    private companion object {
        /** Имя файла базы: то же, что в Core. */
        const val DATABASE_NAME = "gasapp.db"
    }
}
