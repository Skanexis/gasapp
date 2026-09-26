// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Распознаёт QR в кадре камеры (яркостная плоскость Y).
 *
 * Отдельно от экрана, чтобы проверяться без камеры. Только QR и только
 * на устройстве: ZXing — чистая Java, сети не касается.
 */
object QrDecoder {

    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )

    /**
     * @param luminance яркость построчно, строка — [rowStride] байт.
     * @return текст кода или `null`, если кода в кадре нет.
     */
    fun decode(luminance: ByteArray, rowStride: Int, width: Int, height: Int): String? {
        if (width <= 0 || height <= 0 || rowStride < width || luminance.size < rowStride * (height - 1) + width) {
            return null
        }

        val source = PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false)

        return try {
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: ReaderException) {
            null
        }
    }
}
