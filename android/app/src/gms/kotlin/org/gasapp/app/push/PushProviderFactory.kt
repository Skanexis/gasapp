// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.push

/**
 * Фабрика провайдера доставки для сборки **gms** (Google Play).
 *
 * Здесь ссылки на Firebase допустимы — в отличие от flavor'а `foss`.
 */
object PushProviderFactory {

    /** Возвращает провайдер доставки для этой сборки. */
    fun create(): PushProvider = FcmPushProvider()
}

/**
 * Доставка через Firebase Cloud Messaging.
 *
 * ⚠️ FCM видит факт и время доставки уведомления — это метаданные, которые
 * мы честно **не** скрываем (раздел 15.5 плана). Содержимое push при этом
 * всегда пустое (ADR-014): в нём нет ни текста, ни отправителя, ни чата.
 * Клиент, получив сигнал, сам идёт на сервер за шифроблобом.
 *
 * Если Play Services на устройстве нет (частый случай на прошивках без GMS),
 * [isAvailable] возвращает `false`, и приложение переходит на постоянное
 * соединение — тот же механизм, что в flavor'е `foss`.
 */
internal class FcmPushProvider : PushProvider {

    override val displayName: String = "Firebase Cloud Messaging"

    override fun isAvailable(): Boolean {
        // Проверка наличия Play Services — M4, вместе с подключением FCM.
        return false
    }

    override fun start() {
        // Реализация — M4 (доставка сообщений). Здесь фиксируется только
        // граница между flavor'ами, чтобы её проверял CI начиная с M1.
        TODO("Подключение FCM реализуется в M4")
    }

    override fun stop() {
        TODO("Подключение FCM реализуется в M4")
    }
}
