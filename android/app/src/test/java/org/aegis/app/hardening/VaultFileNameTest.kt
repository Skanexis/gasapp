// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import androidx.test.core.app.ApplicationProvider
import org.aegis.app.core.VaultTemp
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
 * провайдер отдавал `../../databases/aegis.db` — и при открытии
 * файла из хранилища расшифрованное содержимое ложилось поверх
 * собственных файлов приложения.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultFileNameTest {

    private val hostile = listOf(
        "../../databases/aegis.db",
        "../shared_prefs/x.xml",
        "/data/data/org.aegis.app/files/aegis.db",
        "..\\..\\files\\aegis.db",
        "..",
        ".",
        "",
        "name\u0000.pdf",
        "\n\r",
    )

    @Test
    fun hostile_names_lose_their_path() {
        assertEquals("aegis.db", VaultTemp.safeName("../../databases/aegis.db"))
        assertEquals("aegis.db", VaultTemp.safeName("..\\..\\files\\aegis.db"))
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
