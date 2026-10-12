// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.notify

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.gasapp.app.LockActivity
import org.gasapp.app.R

/**
 * Системное уведомление «есть новые сообщения».
 *
 * 🔐 Без текста и без отправителя — и не потому, что так настроено:
 * уведомление показывается, пока приложение заперто, и расшифровать
 * ему нечего. Поэтому и на экране блокировки оно не выдаёт ничего,
 * кроме того, что пришло что-то.
 */
object Notifier {

    /** Канал сообщений: звук и вибрацию человек настраивает в системе. */
    const val CHANNEL = "messages"

    private const val ID = 1

    /** Заводит канал (Android 8+ без канала уведомление не покажется). */
    fun ensureChannel(context: Context) {
        val channel = NotificationChannel(
            CHANNEL,
            context.getString(R.string.notify_channel),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.notify_channel_hint)
            lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
        }

        context.getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    /** Можно ли показывать уведомления: разрешение и системный выключатель. */
    fun permitted(context: Context): Boolean {
        val granted = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

        return granted && NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    /** Показывает «есть новые сообщения». Нажатие открывает экран входа. */
    @android.annotation.SuppressLint("MissingPermission")
    fun showNewMessages(context: Context) {
        if (!permitted(context)) return

        ensureChannel(context)

        // 🔐 Явный экран и неизменяемое намерение: подменить, что откроет
        // нажатие, другому приложению нечем.
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, LockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_bell)
            .setContentTitle(context.getString(R.string.notify_title))
            .setContentText(context.getString(R.string.notify_body))
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context).notify(ID, notification)
    }

    /** Убирает уведомление: человек открыл приложение. */
    fun cancel(context: Context) {
        NotificationManagerCompat.from(context).cancel(ID)
    }
}
