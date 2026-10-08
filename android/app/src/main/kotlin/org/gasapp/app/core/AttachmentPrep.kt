// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.graphics.Bitmap
import android.graphics.ImageDecoder
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * 🔐 Подготовка вложения к очистке метаданных.
 *
 * # Зачем
 *
 * Метаданные удаляет ядро (`gasapp_media::scrub`) — без перекодирования,
 * разбором контейнера. HEIC и AVIF так очистить нельзя: их EXIF и
 * геометка — элементы внутри структуры самого изображения, и ядро
 * такие файлы отвергает, чтобы они не ушли с метаданными.
 *
 * Поэтому HEIC/AVIF (формат камеры по умолчанию на многих телефонах)
 * перекодируются здесь в JPEG. Системный декодер берёт только пиксели:
 * в новый файл не переходит ничего, кроме изображения. Поворот
 * `ImageDecoder` применяет сам, поэтому кадр не ляжет на бок.
 *
 * ⚠️ Перекодирование — потеря качества, пусть и небольшая (JPEG 92).
 * Это цена: иначе фото с геометкой ушло бы как есть, либо не ушло бы
 * вовсе.
 */
object AttachmentPrep {

    /** HEIC/HEIF/AVIF по бренду в `ftyp` — теми же брендами, что в ядре. */
    fun isHeif(bytes: ByteArray): Boolean {
        if (bytes.size < 12 || String(bytes, 4, 4, Charsets.US_ASCII) != "ftyp") return false

        val size = ((bytes[0].toInt() and 0xFF) shl 24) or ((bytes[1].toInt() and 0xFF) shl 16) or
            ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
        val end = size.coerceIn(12, bytes.size)

        // основной бренд (8..12) и совместимые (16..end)
        val brands = buildList {
            add(String(bytes, 8, 4, Charsets.US_ASCII))
            var at = 16
            while (at + 4 <= end) {
                add(String(bytes, at, 4, Charsets.US_ASCII))
                at += 4
            }
        }

        return brands.any { it in HEIF_BRANDS }
    }

    /**
     * Содержимое, готовое к отправке: HEIC/AVIF — в JPEG, прочее как есть.
     *
     * @throws Exception изображение не декодируется — отправлять нечего
     */
    fun prepare(bytes: ByteArray): ByteArray = if (isHeif(bytes)) toJpeg(bytes) else bytes

    /**
     * Метаданные удаляет ядро только у фото, видео и звука. У документов
     * (PDF, Word) они — часть формата, и интерфейс должен это сказать.
     */
    fun isMediaMime(mime: String?): Boolean =
        mime != null && (mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("audio/"))

    private fun toJpeg(bytes: ByteArray): ByteArray {
        val bitmap = ImageDecoder.decodeBitmap(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) { decoder, _, _ ->
            // Программный декодер: аппаратный Bitmap нельзя сжать в JPEG.
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
        }

        return ByteArrayOutputStream().use { out ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, out)
            bitmap.recycle()
            out.toByteArray()
        }
    }

    private val HEIF_BRANDS = setOf("heic", "heix", "hevc", "heim", "heis", "hevm", "mif1", "msf1", "avif")

    private const val JPEG_QUALITY = 92
}
