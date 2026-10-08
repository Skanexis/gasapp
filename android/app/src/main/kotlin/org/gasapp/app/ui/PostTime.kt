// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.content.Context
import android.text.format.DateFormat
import android.text.format.DateUtils
import java.util.Date

/**
 * Время записи канала — на языке и в формате системы.
 *
 * Время берётся из самой записи: его поставил автор, и оно лежит
 * внутри шифротекста. Сервер знает только час публикации.
 */
object PostTime {

    /** Для списка каналов: сегодня — часы и минуты, иначе — число и месяц. */
    fun short(context: Context, millis: Long): String =
        if (DateUtils.isToday(millis)) {
            DateFormat.getTimeFormat(context).format(Date(millis))
        } else {
            DateUtils.formatDateTime(context, millis, DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_MONTH)
        }

    /** Для ленты: число, месяц и время; год — если не текущий. */
    fun full(context: Context, millis: Long): String =
        DateUtils.formatDateTime(
            context,
            millis,
            DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_TIME or DateUtils.FORMAT_ABBREV_MONTH,
        )
}
