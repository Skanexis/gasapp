// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.aegis.app.core.DurableFile
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * 🔐 Соль и аппаратная половина ключа не остаются пустыми после сбоя.
 *
 * После аварийной остановки эмулятора на диске оказались база и пустые
 * `aegis.salt` и `aegis.hw`: база записалась, половина её ключа — нет.
 * Такую базу не открыть ничем. Здесь проверяются свойства замены,
 * которая это исключает: либо прежнее содержимое целиком, либо новое
 * целиком, и никаких хвостов.
 *
 * ⚠️ Сам сбой питания в модульном тесте не воспроизвести; проверяется
 * то, от чего его последствия зависят, — порядок «временный файл →
 * fsync → атомарная замена» и то, что провал записи прежний файл
 * не трогает.
 */
class DurableFileTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Test
    fun writes_the_bytes() {
        val target = File(folder.root, "aegis.salt")

        DurableFile.write(target, byteArrayOf(1, 2, 3))

        assertArrayEquals(byteArrayOf(1, 2, 3), target.readBytes())
    }

    @Test
    fun replaces_existing_contents_whole() {
        val target = File(folder.root, "aegis.hw")
        target.writeBytes(ByteArray(64) { 7 })

        DurableFile.write(target, byteArrayOf(9))

        assertArrayEquals(byteArrayOf(9), target.readBytes())
    }

    /** Временный файл не остаётся рядом: он содержал бы ту же тайну. */
    @Test
    fun leaves_no_temporary_file_behind() {
        val target = File(folder.root, "aegis.hw")

        DurableFile.write(target, byteArrayOf(1))
        DurableFile.write(target, byteArrayOf(2))

        assertEquals(listOf("aegis.hw"), folder.root.list()!!.sorted())
    }

    /** 🔐 Провал записи прежний файл не трогает. */
    @Test
    fun a_failed_write_keeps_the_old_file() {
        val target = File(folder.root, "aegis.salt")
        target.writeBytes(byteArrayOf(4, 2))

        // Временный файл не создать: на его месте каталог.
        Files.createDirectory(File(folder.root, ".aegis.salt.tmp").toPath())

        try {
            DurableFile.write(target, byteArrayOf(1, 1, 1))
            fail("запись поверх каталога прошла")
        } catch (expected: IOException) {
            // ожидаемо
        }

        assertArrayEquals("прежний файл испорчен неудачной записью", byteArrayOf(4, 2), target.readBytes())
    }
}
