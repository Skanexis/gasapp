// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.core.VaultTemp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Имя файла от чужого провайдера не выводит за каталог.
 *
 * Имя расшифрованной копии приходило из `DISPLAY_NAME` провайдера,
 * из которого человек выбрал файл, и шло в путь как есть. Вредоносный
 * провайдер отдавал `../../databases/gasapp.db` — и при открытии
 * файла из хранилища расшифрованное содержимое ложилось поверх
 * собственных файлов приложения.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultFileNameTest {

    private val hostile = listOf(
        "../../databases/gasapp.db",
        "../shared_prefs/x.xml",
        "/data/data/org.gasapp.app/files/gasapp.db",
        "..\\..\\files\\gasapp.db",
        "..",
        ".",
        "",
        "name\u0000.pdf",
        "\n\r",
    )

    @Test
    fun hostile_names_lose_their_path() {
        assertEquals("gasapp.db", VaultTemp.safeName("../../databases/gasapp.db"))
        assertEquals("gasapp.db", VaultTemp.safeName("..\\..\\files\\gasapp.db"))
        assertEquals("file", VaultTemp.safeName(".."))
        assertEquals("file", VaultTemp.safeName(""))
        assertEquals("name.pdf", VaultTemp.safeName("name\u0000.pdf"))
        assertEquals("Отчёт за март.pdf", VaultTemp.safeName("Отчёт за март.pdf"))
        // Смена направления текста: «счёт‮fdp.exe» выглядел бы документом.
        assertEquals("счётfdp.exe", VaultTemp.safeName("счёт‮fdp.exe"))
    }

    @Test
    fun the_decrypted_copy_always_lands_inside_its_directory() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val root = VaultTemp.directory(context).canonicalFile

        for (name in hostile) {
            val file = VaultTemp.fileFor(context, name)
            assertEquals("«$name» вывел за каталог", root, file.parentFile)
        }

        assertTrue(VaultTemp.safeName("x".repeat(1000)).length <= 120)
    }
}
