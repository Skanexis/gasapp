// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import java.io.File
import org.gasapp.app.core.VaultBlob
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * 🔐 Удаление файла из хранилища стирает его блоб — и только его.
 *
 * # Что здесь проверяется
 *
 * Удалить файл из хранилища было нельзя вовсе: ядро и FFI это умели,
 * а экран не звал. Документ о сроках хранения при этом обещал
 * «до удаления пользователем».
 *
 * Путь к блобу возвращает ядро, беря его из базы. Стирается он,
 * только если лежит внутри каталога хранилища: запись, указывающая
 * наружу, не должна превращать удаление файла в удаление чего угодно.
 */
class VaultBlobTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun vault(): File = temp.newFolder("vault")

    /** 🔐 Блоб внутри хранилища стирается. */
    @Test
    fun a_blob_inside_the_vault_is_deleted() {
        val dir = vault()
        val blob = File(dir, "123.enc").apply { writeBytes(byteArrayOf(1, 2, 3)) }

        assertTrue("блоб не удалён", VaultBlob.deleteInside(dir, blob.absolutePath))
        assertFalse("блоб пережил удаление", blob.exists())
    }

    /** 🔐 Путь, выходящий из хранилища через `..`, не трогается. */
    @Test
    fun a_path_escaping_the_vault_is_left_alone() {
        val dir = vault()
        val outside = temp.newFile("gasapp.db").apply { writeBytes(byteArrayOf(9)) }

        val escaping = File(dir, "../gasapp.db").path

        assertFalse("удалён файл вне хранилища", VaultBlob.deleteInside(dir, escaping))
        assertTrue("файл вне хранилища стёрт", outside.exists())
    }

    /** 🔐 Чужой абсолютный путь не трогается. */
    @Test
    fun an_absolute_path_elsewhere_is_left_alone() {
        val dir = vault()
        val elsewhere = temp.newFile("contacts.db").apply { writeBytes(byteArrayOf(7)) }

        assertFalse(VaultBlob.deleteInside(dir, elsewhere.absolutePath))
        assertTrue("чужой файл стёрт", elsewhere.exists())
    }

    /**
     * 🔐 Соседний каталог с похожим именем — не хранилище.
     *
     * `…/vault-old/x` начинается со строки `…/vault`, но внутри него
     * не лежит. Сравнение по префиксу строки это пропустило бы.
     */
    @Test
    fun a_sibling_with_a_similar_name_is_not_the_vault() {
        val dir = vault()
        val sibling = temp.newFolder("vault-old")
        val blob = File(sibling, "x.enc").apply { writeBytes(byteArrayOf(5)) }

        assertFalse(VaultBlob.deleteInside(dir, blob.absolutePath))
        assertTrue("стёрт файл из соседнего каталога", blob.exists())
    }

    /** Отсутствующий блоб — не ошибка: удалять нечего. */
    @Test
    fun a_missing_blob_is_harmless() {
        val dir = vault()

        assertFalse(VaultBlob.deleteInside(dir, File(dir, "gone.enc").absolutePath))
    }
}
