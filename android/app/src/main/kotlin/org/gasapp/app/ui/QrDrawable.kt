// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.graphics.Bitmap
import android.graphics.Color
import uniffi.gasapp.FfiQrMatrix

/**
 * Превращает матрицу QR из ядра в картинку.
 *
 * 🔐 Матрицу строит ядро, а не Android: генератор на каждой платформе
 * дал бы два разных кода, и устройства не смогли бы сверить друг
 * друга. Здесь только отрисовка.
 */
object QrDrawable {

    /**
     * Рисует матрицу в bitmap.
     *
     * @param matrix матрица из ядра
     * @param sizePx желаемая сторона картинки в пикселях
     */
    fun render(matrix: FfiQrMatrix, sizePx: Int): Bitmap {
        val modules = matrix.size.toInt()

        // Тихая зона в четыре модуля — требование стандарта. Без неё
        // сканеры не находят код на светлом фоне, и сверка срывается
        // там, где всё остальное работает.
        val total = modules + QUIET_ZONE * 2

        // Целочисленный масштаб: дробный даёт модули разной ширины
        // после округления, и код перестаёт читаться под углом.
        val scale = (sizePx / total).coerceAtLeast(1)
        val side = total * scale

        val pixels = IntArray(side * side) { Color.WHITE }

        for (y in 0 until modules) {
            for (x in 0 until modules) {
                if (!matrix.modules[y * modules + x]) {
                    continue
                }

                fillModule(pixels, side, (x + QUIET_ZONE) * scale, (y + QUIET_ZONE) * scale, scale)
            }
        }

        return Bitmap.createBitmap(pixels, side, side, Bitmap.Config.ARGB_8888)
    }

    private fun fillModule(pixels: IntArray, side: Int, left: Int, top: Int, scale: Int) {
        for (dy in 0 until scale) {
            val row = (top + dy) * side

            for (dx in 0 until scale) {
                pixels[row + left + dx] = Color.BLACK
            }
        }
    }

    /** Тихая зона по краям кода, в модулях. */
    private const val QUIET_ZONE = 4
}
