// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Application
import org.aegis.app.core.AutoLock

/**
 * Класс приложения.
 *
 * Появился ради одной вещи: автоматическое запирание нужно наблюдать
 * за всем процессом, а не за отдельным экраном. Отслеживание в базовой
 * Activity не годится — переход между двумя экранами выглядел бы уходом
 * в фон, и приложение запиралось бы на каждом нажатии.
 *
 * Больше здесь ничего не делается намеренно. 🔐 Работа в `onCreate`
 * приложения выполняется до ввода PIN, то есть на закрытом хранилище:
 * всё, что потребовало бы данных, пришлось бы либо откладывать, либо
 * открывать базу раньше времени.
 */
class AegisApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        AutoLock.install(this)
    }
}
