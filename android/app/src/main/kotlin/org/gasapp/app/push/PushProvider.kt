// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.push

import android.content.Context
import uniffi.gasapp.Messenger

/**
 * Способ доставки уведомлений о новых сообщениях.
 *
 * Реализация выбирается на этапе сборки flavor'ом, а не условием в коде:
 *
 * * `gms`  — пустой пуш Firebase Cloud Messaging (Google Play);
 * * `foss` — без сервисов Google: опрос сервера по токену (ADR-040).
 *
 * Разделение по flavor'ам, а не по `if`, — требование раздела 18.2 плана:
 * сборка для F-Droid обязана **физически не содержать** классов Google Play
 * Services, иначе она не проходит проверку на отсутствие проприетарных
 * зависимостей. Условие в общем коде оставило бы их в APK.
 *
 * 🔐 Пуш всегда пустой (ADR-014): Google показывает «Новые сообщения»
 * ключами строк самого приложения — без текста, имени и чата. Сервер
 * отправляет его не с узлов API, а отдельной службой на машине базы
 * (`gasapp-server-admin push`).
 */
interface PushProvider {

    /** Человекочитаемое имя механизма доставки — для экрана диагностики. */
    val displayName: String

    /**
     * Можно ли будить телефон через провайдера: сборка знает проект
     * Firebase и на телефоне есть сервисы Google. Нет — остаётся опрос
     * по токену (`NotifyJob`).
     */
    fun isAvailable(context: Context): Boolean

    /**
     * Получает токен у провайдера и называет его серверу за подписью
     * устройства. Сеть — только из фонового потока, база открыта.
     */
    fun register(context: Context, messenger: Messenger)

    /** Отзывает токен у сервера и у провайдера. Фоновый поток. */
    fun unregister(context: Context, messenger: Messenger)
}
