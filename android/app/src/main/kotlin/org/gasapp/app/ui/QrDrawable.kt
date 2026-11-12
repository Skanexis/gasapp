// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import uniffi.gasapp.FfiQrMatrix

/**
 * Превращает матрицу QR из ядра в картинку.
 *
 * 🔐 Матрицу строит ядро, а не Android: генератор на каждой платформе
 * дал бы два разных кода, и устройства не смогли бы сверить друг
 * друга. Здесь только отрисовка — та же, что на iPhone (`QRView`):
 * скруглённые модули цвета ночного неба и угловые «глаза» с зрачком
 * цвета контура логотипа. Оба цвета тёмные: сканеру нужен контраст с
 * белым, а не именно чёрный.
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
        // сканеры не находят код на светлом фоне.
        val total = modules + QUIET_ZONE * 2
        val side = sizePx.coerceAtLeast(total)
        val cell = side.toFloat() / total

        val bitmap = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        canvas.drawColor(Color.WHITE)

        val ink = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = INK }
        val eye = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = EYE }

        fun isFinder(x: Int, y: Int) =
            (x < 7 && y < 7) || (x >= modules - 7 && y < 7) || (x < 7 && y >= modules - 7)

        val inset = cell * 0.06f
        val radius = cell * 0.32f
        val rect = RectF()

        for (y in 0 until modules) {
            for (x in 0 until modules) {
                if (!matrix.modules[y * modules + x] || isFinder(x, y)) {
                    continue
                }

                rect.set(
                    (x + QUIET_ZONE) * cell + inset,
                    (y + QUIET_ZONE) * cell + inset,
                    (x + QUIET_ZONE + 1) * cell - inset,
                    (y + QUIET_ZONE + 1) * cell - inset,
                )
                canvas.drawRoundRect(rect, radius, radius, ink)
            }
        }

        for ((fx, fy) in listOf(0 to 0, modules - 7 to 0, 0 to modules - 7)) {
            val left = (fx + QUIET_ZONE) * cell
            val top = (fy + QUIET_ZONE) * cell
            val outer = RectF(left, top, left + cell * 7, top + cell * 7)
            val inner = RectF(outer).apply { inset(cell, cell) }

            val ring = Path().apply {
                fillType = Path.FillType.EVEN_ODD
                addRoundRect(outer, cell * 2f, cell * 2f, Path.Direction.CW)
                addRoundRect(inner, cell * 1.3f, cell * 1.3f, Path.Direction.CW)
            }
            canvas.drawPath(ring, ink)

            val pupil = RectF(outer).apply { inset(cell * 2, cell * 2) }
            canvas.drawRoundRect(pupil, cell * 0.9f, cell * 0.9f, eye)
        }

        return bitmap
    }

    /** Тихая зона по краям кода, в модулях. */
    private const val QUIET_ZONE = 4

    /** Ночное небо GasApp — `#0E1238`. */
    private val INK = Color.rgb(0x0E, 0x12, 0x38)

    /** Коричневый контур логотипа — `#8A3414`. */
    private val EYE = Color.rgb(0x8A, 0x34, 0x14)
}
