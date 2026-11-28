// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory

/**
 * Фото профиля: из байтов собеседника — в маленькую картинку для аватара.
 *
 * # 🔐 Что здесь важно
 *
 * Фото прислал собеседник, а он может быть недружественным (аудит
 * 2026-11-28). PNG в 96 КБ может заявить 30000×30000 точек: декодер
 * без уменьшения попросит под него гигабайты, и чат или список чатов
 * падал бы на каждом запуске. Поэтому:
 *
 * * сначала читаются только размеры (`inJustDecodeBounds`), и картинка
 *   больше [MAX_SOURCE_SIDE] по любой стороне — это просто «фото нет»;
 * * декодирование идёт с уменьшением (`inSampleSize`) до размера
 *   аватара — не больше [PHOTO_SIDE] точек;
 * * любой сбой декодера — тоже «фото нет», а не падение экрана.
 */
object ProfilePhotos {

    /** Наибольшая сторона фото в приложении: больше аватару не нужно. */
    const val PHOTO_SIDE = 384

    /** Картинка крупнее этого по любой стороне не декодируется вовсе. */
    const val MAX_SOURCE_SIDE = 4096

    /**
     * Декодирует фото не крупнее [targetSide] по большей стороне
     * (с точностью до степени двойки). `null` — если фото нет, оно
     * испорчено или заявляет нелепый размер.
     */
    fun decode(bytes: ByteArray, targetSide: Int = PHOTO_SIDE): Bitmap? = runCatching<Bitmap?> {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        val width = bounds.outWidth
        val height = bounds.outHeight
        if (width <= 0 || height <= 0) return@runCatching null
        if (width > MAX_SOURCE_SIDE || height > MAX_SOURCE_SIDE) return@runCatching null

        // Уменьшение при декодировании: целиком в памяти фото не бывает;
        // по большей стороне — и узкая полоса 4096×700 не займёт 11 МБ.
        var sample = 1
        while (maxOf(width, height) / (sample * 2) >= targetSide) sample *= 2

        BitmapFactory.decodeByteArray(
            bytes,
            0,
            bytes.size,
            BitmapFactory.Options().apply { inSampleSize = sample },
        )
    }.getOrNull()
}
