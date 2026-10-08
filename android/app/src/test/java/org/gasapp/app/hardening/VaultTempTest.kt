// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import java.io.File
import org.gasapp.app.core.AccountWipe
import org.gasapp.app.core.VaultTemp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Расшифрованные файлы хранилища не переживают процесс.
 *
 * # Что здесь проверяется
 *
 * Чтобы показать файл из хранилища, его приходится расшифровать
 * на диск. `VaultActivity.onStop` копию удаляет — но по списку
 * в памяти, а `onStop` вызывается не всегда: процесс, убитый
 * системой по памяти или снятый из недавних, его не выполнит.
 *
 * Тогда расшифрованный файл остаётся лежать открытым текстом —
 * в хранилище, которое существует ровно затем, чтобы такого
 * не было.
 *
 * Поэтому чистить надо **по каталогу** и тогда, когда список
 * заведомо пуст: при открытии базы и при удалении аккаунта.
 *
 * # Чего тест не проверяет
 *
 * Невосстановимость. Удаление файла не затирает ячейки флеш-памяти;
 * здесь закрывается другое — файл перестаёт лежать на виду.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultTempTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun leftover(name: String): File =
        File(VaultTemp.directory(context), name).apply {
            writeBytes("расшифрованное содержимое".toByteArray())
        }

    /** 🔐 Пережившее прошлый сеанс подметается. */
    @Test
    fun leftovers_from_a_previous_run_are_swept() {
        val first = leftover("договор.pdf")
        val second = leftover("снимок.jpg")

        assertTrue("тест не подготовил файлы", first.exists() && second.exists())

        val removed = VaultTemp.sweep(context)

        assertEquals("подметено не всё", 2, removed)
        assertFalse("файл пережил подметание", first.exists())
        assertFalse("файл пережил подметание", second.exists())
    }

    /**
     * Подметание не падает, когда каталога нет.
     *
     * Первый запуск после установки — самый обычный случай,
     * и исключение здесь помешало бы открыть хранилище вообще.
     */
    @Test
    fun sweeping_a_missing_directory_is_harmless() {
        VaultTemp.directory(context).deleteRecursively()

        assertEquals(0, VaultTemp.sweep(context))
    }

    /**
     * 🔐 Удаление аккаунта уносит и расшифрованные файлы.
     *
     * Они лежат в кэше, а не в `filesDir`, и прежним списком
     * не покрывались: аккаунт удалялся, а файлы оставались.
     */
    @Test
    fun deleting_the_account_removes_decrypted_files() {
        val opened = leftover("паспорт.pdf")

        assertTrue("тест не подготовил файл", opened.exists())

        AccountWipe.wipe(context)

        assertFalse("расшифрованный файл пережил удаление аккаунта", opened.exists())
    }

    /**
     * 🔐 Удаление аккаунта уносит и шифроблобы File Vault.
     *
     * Они лежат каталогом в `filesDir/vault` и прежним списком файлов
     * не покрывались: экран обещал удалить «файлы», а блобы оставались.
     * Нашёл аудитор.
     */
    @Test
    fun deleting_the_account_removes_vault_blobs() {
        val vault = File(context.filesDir, AccountWipe.VAULT_DIRECTORY).apply { mkdirs() }
        val blob = File(vault, "123.enc").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        assertTrue("тест не подготовил блоб", blob.exists())

        AccountWipe.wipe(context)

        assertFalse("шифроблоб хранилища пережил удаление аккаунта", blob.exists())
        assertFalse("каталог хранилища пережил удаление аккаунта", vault.exists())
    }

    /**
     * Подметание не трогает остальной кэш.
     *
     * Кэш — общий для приложения, и удаление аккаунта не должно
     * превращаться в сброс всего подряд.
     */
    @Test
    fun the_sweep_leaves_the_rest_of_the_cache_alone() {
        val foreign = File(context.cacheDir, "не-наше.bin").apply {
            writeBytes(byteArrayOf(1, 2, 3))
        }

        leftover("наше.pdf")
        VaultTemp.sweep(context)

        assertTrue("подметание вынесло чужой файл из кэша", foreign.exists())
    }
}
