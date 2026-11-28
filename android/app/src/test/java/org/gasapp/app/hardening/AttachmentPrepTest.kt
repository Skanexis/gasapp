// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import org.gasapp.app.core.AttachmentPrep
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 HEIC/AVIF узнаются и уходят на перекодирование в JPEG.
 *
 * Ядро такие файлы отвергает (`gasapp_media::scrub`): их метаданные —
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

    /**
     * Предупреждение о метаданных — для всего, что ядро не чистит само.
     *
     * Аудит 2026-11-28: «чистым» считался любой MIME вида image, audio или
     * video, и TIFF, FLAC, WebM уходили с метаданными без вопроса.
     */
    @Test
    fun only_formats_the_core_scrubs_count_as_cleaned() {
        assertTrue(AttachmentPrep.isCleanedMime("image/jpeg"))
        assertTrue(AttachmentPrep.isCleanedMime("image/png"))
        assertTrue(AttachmentPrep.isCleanedMime("image/webp"))
        assertTrue(AttachmentPrep.isCleanedMime("image/gif"))
        // HEIC/AVIF перекодируются в JPEG.
        assertTrue(AttachmentPrep.isCleanedMime("image/heic"))
        assertTrue(AttachmentPrep.isCleanedMime("video/mp4"))
        assertTrue(AttachmentPrep.isCleanedMime("video/quicktime"))
        assertTrue(AttachmentPrep.isCleanedMime("audio/mpeg"))
        assertTrue(AttachmentPrep.isCleanedMime("audio/mp4"))
        assertTrue(AttachmentPrep.isCleanedMime("Image/JPEG"))

        // Медиа, которые ядро оставляет как есть.
        assertFalse(AttachmentPrep.isCleanedMime("image/tiff"))
        assertFalse(AttachmentPrep.isCleanedMime("image/x-adobe-dng"))
        assertFalse(AttachmentPrep.isCleanedMime("image/svg+xml"))
        assertFalse(AttachmentPrep.isCleanedMime("audio/flac"))
        assertFalse(AttachmentPrep.isCleanedMime("audio/ogg"))
        assertFalse(AttachmentPrep.isCleanedMime("audio/wav"))
        assertFalse(AttachmentPrep.isCleanedMime("video/x-matroska"))
        assertFalse(AttachmentPrep.isCleanedMime("video/webm"))
    }

    @Test
    fun documents_are_not_cleaned() {
        // PDF ядро чистит лишь отчасти: сжатые потоки объектов и XMP остаются.
        assertFalse(AttachmentPrep.isCleanedMime("application/pdf"))
        assertFalse(AttachmentPrep.isCleanedMime("application/vnd.openxmlformats-officedocument.wordprocessingml.document"))
        assertFalse(AttachmentPrep.isCleanedMime("application/octet-stream"))
        assertFalse(AttachmentPrep.isCleanedMime(null))
    }
}
