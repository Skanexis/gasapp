// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.Application
import org.aegis.app.core.AutoLock
import org.aegis.app.core.Language
import org.aegis.app.net.EmbeddedTor
import org.aegis.app.ui.SafeArea

/**
 * Класс приложения.
 *
 * Третье — безопасная область экранов ([SafeArea]): отступы по системным
 * панелям и клавиатуре нужны каждому экрану, и ставятся они в одном месте.
 *
 * Появился ради автоматического запирания: оно наблюдает за всем
 * процессом, а не за отдельным экраном. Отслеживание в базовой
 * Activity не годится — переход между двумя экранами выглядел бы уходом
 * в фон, и приложение запиралось бы на каждом нажатии.
 *
 * Второе — язык интерфейса: он должен быть выбран до первого экрана,
 * включая экран блокировки. Выбор хранится вне базы (см. [Language]),
 * так что данных для этого не требуется.
 *
 * Четвёртое — прогрев встроенного Tor ([EmbeddedTor.prewarmIfChosen]):
 * пока человек вводит PIN, Tor уже подключается. Данных для этого
 * не нужно — только признак «в прошлый раз выбран Tor без мостов».
 *
 * Больше здесь ничего не делается намеренно. 🔐 Работа в `onCreate`
 * приложения выполняется до ввода PIN, то есть на закрытом хранилище:
 * всё, что потребовало бы данных, пришлось бы либо откладывать, либо
 * открывать базу раньше времени.
 */
class AegisApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        Language.applyStored(this)
        AutoLock.install(this)
        SafeArea.install(this)

        // В фоне: запуск Tor читает каталог состояния с диска.
        Thread({ EmbeddedTor.prewarmIfChosen(this) }, "aegis-tor-prewarm").start()
    }
}
