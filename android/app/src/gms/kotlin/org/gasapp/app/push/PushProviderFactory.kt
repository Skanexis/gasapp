// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.push

import android.content.Context
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailabilityLight
import com.google.android.gms.tasks.Tasks
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import java.util.concurrent.TimeUnit
import org.gasapp.app.BuildConfig
import uniffi.gasapp.FfiPushProvider
import uniffi.gasapp.Messenger

/** Сборка для Google Play: пустые пуши через Firebase Cloud Messaging. */
object PushProviderFactory {
    fun create(): PushProvider = FcmPushProvider
}

/**
 * 🔐 Firebase подключается вручную, из настроек сборки
 * (`-PgasappFcmProjectId` и др.), а не файлом `google-services.json`
 * с автозапуском: без этих настроек он не стартует вовсе, а с ними —
 * только когда человек включил уведомления. Аналитика и выгрузка
 * метрик доставки выключены в манифесте (`src/gms/AndroidManifest.xml`).
 */
internal object FcmPushProvider : PushProvider {
    override val displayName: String = "Firebase Cloud Messaging"

    private const val TIMEOUT_SECONDS = 30L

    override fun isAvailable(context: Context): Boolean =
        BuildConfig.GASAPP_FCM_PROJECT_ID.isNotEmpty() &&
            GoogleApiAvailabilityLight.getInstance()
                .isGooglePlayServicesAvailable(context) == ConnectionResult.SUCCESS

    override fun register(context: Context, messenger: Messenger) {
        val token = Tasks.await(messaging(context).token, TIMEOUT_SECONDS, TimeUnit.SECONDS)

        messenger.registerPushToken(FfiPushProvider.FCM, token, System.currentTimeMillis())
    }

    override fun unregister(context: Context, messenger: Messenger) {
        // Сначала сервер: он перестанет будить. Потом провайдер.
        runCatching { messenger.unregisterPushToken(System.currentTimeMillis()) }
        if (FirebaseApp.getApps(context).isNotEmpty()) {
            runCatching {
                Tasks.await(FirebaseMessaging.getInstance().deleteToken(), TIMEOUT_SECONDS, TimeUnit.SECONDS)
            }
        }
    }

    @Synchronized
    private fun messaging(context: Context): FirebaseMessaging {
        if (FirebaseApp.getApps(context).isEmpty()) {
            FirebaseApp.initializeApp(
                context.applicationContext,
                FirebaseOptions.Builder()
                    .setProjectId(BuildConfig.GASAPP_FCM_PROJECT_ID)
                    .setApplicationId(BuildConfig.GASAPP_FCM_APP_ID)
                    .setApiKey(BuildConfig.GASAPP_FCM_API_KEY)
                    .setGcmSenderId(BuildConfig.GASAPP_FCM_SENDER_ID)
                    .build(),
            )
        }

        return FirebaseMessaging.getInstance()
    }
}
