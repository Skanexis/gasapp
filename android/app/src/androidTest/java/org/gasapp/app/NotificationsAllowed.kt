// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.Manifest
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry

/**
 * Разрешение на уведомления — до того, как откроется список чатов.
 *
 * С Android 13 список чатов один раз спрашивает разрешение
 * (`ChatListActivity.offerNotifications`). Системный диалог встаёт
 * поверх экрана, и тот остаётся в `STARTED`, а не `RESUMED`: тест
 * автоблокировки на API 36 падал на «список чатов не открылся», хотя
 * приложение работало верно. Человек этот вопрос видит и отвечает
 * на него сам — проверяется он не здесь.
 */
object NotificationsAllowed {
    fun grant() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.uiAutomation.grantRuntimePermission(
            instrumentation.targetContext.packageName,
            Manifest.permission.POST_NOTIFICATIONS,
        )
    }
}
