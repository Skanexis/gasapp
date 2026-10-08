// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.push

/**
 * Фабрика провайдера доставки для сборки **foss** (F-Droid).
 *
 * Во всём каталоге `src/foss` не должно быть ни одной ссылки на сервисы
 * Google — ни на Play Services, ни на Firebase. За этим следит
 * `tools/check-no-telemetry.sh` (джоб `no-telemetry` в CI): он ищет
 * соответствующие имена пакетов по подстроке, поэтому упоминать их здесь
 * нельзя даже в комментарии.
 */
object PushProviderFactory {

    /** Возвращает провайдер доставки для этой сборки. */
    fun create(): PushProvider = SocketPushProvider()
}

/**
 * Доставка через собственный постоянный сокет.
 *
 * Компромисс задокументирован в разделе 18.2 плана: без сервисов Google
 * приложение вынуждено держать фоновое соединение, что заметнее расходует
 * батарею. Пользователь F-Droid-сборки выбирает это сознательно в обмен
 * на отсутствие проприетарных зависимостей.
 */
internal class SocketPushProvider : PushProvider {

    override val displayName: String = "Постоянное соединение"

    // Сокет доступен всегда: он не зависит от наличия сторонних сервисов.
    override fun isAvailable(): Boolean = true

    override fun start() {
        // Реализация — M4 (доставка сообщений). Здесь фиксируется только
        // граница между flavor'ами, чтобы её проверял CI начиная с M1.
        TODO("Фоновое соединение реализуется в M4")
    }

    override fun stop() {
        TODO("Фоновое соединение реализуется в M4")
    }
}
