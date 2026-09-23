// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.content.Context
import org.aegis.app.R

/**
 * Размер файла в привычных единицах: Б / КБ / МБ, по 1024.
 *
 * Единицы берутся из ресурсов, а не зашиты в код: иначе английский
 * интерфейс показывал бы «2,4 МБ» посреди английского текста.
 */
object FileSize {

    fun format(context: Context, bytes: Long): String = when {
        bytes >= MEGABYTE -> context.getString(R.string.size_mb, bytes / MEGABYTE.toDouble())
        bytes >= KILOBYTE -> context.getString(R.string.size_kb, bytes / KILOBYTE)
        else -> context.getString(R.string.size_bytes, bytes)
    }

    private const val KILOBYTE = 1024L

    private const val MEGABYTE = 1024L * 1024L
}
