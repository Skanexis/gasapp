// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import org.aegis.app.core.AttachmentPrep
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 HEIC/AVIF узнаются и уходят на перекодирование в JPEG.
 *
 * Ядро такие файлы отвергает (`aegis_media::scrub`): их метаданные —
 * часть структуры изображения. Если интерфейс их не узнает, фото
 * с камеры по умолчанию не отправится вовсе.
 */
class AttachmentPrepTest {

    private fun ftyp(major: String, vararg compatible: String): ByteArray {
        val brands = (listOf(major, "\u0000\u0000\u0000\u0000") + compatible).joinToString("")
        val size = 8 + brands.length
        return byteArrayOf(0, 0, 0, size.toByte()) + "ftyp".toByteArray() + brands.toByteArray(Charsets.ISO_8859_1)
    }

    @Test
    fun heic_and_avif_are_recognised() {
        assertTrue(AttachmentPrep.isHeif(ftyp("heic", "mif1", "heic")))
        assertTrue(AttachmentPrep.isHeif(ftyp("avif", "avif", "mif1")))
        // Бренд только среди совместимых.
        assertTrue(AttachmentPrep.isHeif(ftyp("isom", "mif1")))
    }

    @Test
    fun video_and_other_files_are_left_alone() {
        assertFalse(AttachmentPrep.isHeif(ftyp("isom", "isom", "mp42")))
        assertFalse(AttachmentPrep.isHeif(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte())))
        assertFalse(AttachmentPrep.isHeif(ByteArray(0)))
    }

    /** Предупреждение о метаданных — для всего, кроме фото, видео и звука. */
    @Test
    fun documents_are_not_media() {
        assertTrue(AttachmentPrep.isMediaMime("image/jpeg"))
        assertTrue(AttachmentPrep.isMediaMime("video/mp4"))
        assertTrue(AttachmentPrep.isMediaMime("audio/mpeg"))
        assertFalse(AttachmentPrep.isMediaMime("application/pdf"))
        assertFalse(AttachmentPrep.isMediaMime(null))
    }
}
