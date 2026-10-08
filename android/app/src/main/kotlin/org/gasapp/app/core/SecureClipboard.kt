// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Копирование в буфер обмена с пометкой и сроком.
 *
 * Закрывает два пункта раздела 19.2 и MASVS STORAGE-2:
 * «`ClipboardManager` — помечать `EXTRA_IS_SENSITIVE` (API 33+)»
 * и «нет данных в буфере обмена дольше 60 сек».
 *
 * # Что было не так
 *
 * Оба места, откуда приложение копирует, — текст сообщения
 * ([org.gasapp.app.ChatActivity]) и ссылка на профиль с identity-ключом
 * ([org.gasapp.app.ProfileActivity]) — звали `setPrimaryClip` напрямую.
 * Из этого следовало два разных следа:
 *
 *  * начиная с Android 13 система показывает всплывающее окно
 *    с **содержимым** скопированного. Текст сообщения оказывался
 *    на экране поверх приложения, которое этот же текст прячет
 *    от снимка экрана (`FLAG_SECURE`);
 *  * буфер обмена читает любое приложение, оказавшееся на переднем
 *    плане, и он переживает блокировку. Скопированное утром
 *    сообщение доставалось оттуда вечером.
 *
 * # Чего эта защита не даёт
 *
 * 🔐 Пометка `EXTRA_IS_SENSITIVE` — просьба к системному интерфейсу
 * не показывать содержимое, а не запрет на чтение. Приложение,
 * которому пользователь оставил доступ к буферу, прочитает текст
 * как обычно. Смысл пометки в том, чтобы содержимое не показывалось
 * тому, кто просто смотрит на экран через плечо.
 *
 * Срок в минуту тоже не гарантия: очистка выполняется таймером
 * в процессе приложения, и убитый системой процесс её не выполнит.
 * Именно поэтому очистка вдобавок делается при блокировке
 * (см. [org.gasapp.app.core.Core.close] — там вызывается [clear]),
 * а не только по таймеру.
 */
object SecureClipboard {

    /**
     * Срок жизни скопированного — 60 секунд.
     *
     * Значение из раздела 25 (MASVS STORAGE-2). Оно подобрано под
     * сценарий «скопировал и тут же вставил в другом приложении»:
     * меньше — и вставка не успевает, больше — и содержимое переживает
     * тот момент, ради которого его копировали.
     */
    const val TTL_MILLIS = 60_000L

    private val handler = Handler(Looper.getMainLooper())

    /**
     * Показывает ли система своё подтверждение копирования.
     *
     * С Android 13 система сама показывает всплывающее окно буфера;
     * своё уведомление поверх него — дубль, который к тому же ложится
     * на то же место внизу экрана.
     */
    val systemConfirmsCopy: Boolean
        get() = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU

    /** Что именно сейчас лежит в буфере по нашей вине. */
    private var pending: Runnable? = null

    /**
     * Копирует [text], помечая содержимое как чувствительное и заводя
     * таймер очистки.
     *
     * @param label подпись для системного интерфейса. 🔐 Не должна
     *   содержать самого секрета: на Android 13+ подпись показывается
     *   во всплывающем окне даже тогда, когда содержимое скрыто.
     */
    fun copySensitive(context: Context, label: CharSequence, text: CharSequence) {
        val manager = manager(context) ?: return

        val clip = ClipData.newPlainText(label, text).apply {
            // API 33+ — константа появилась в Android 13. На более
            // ранних система всплывающего окна с содержимым не
            // показывает вовсе, поэтому и помечать нечего.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }

        manager.setPrimaryClip(clip)

        // Прежний таймер снимается: второе копирование подряд иначе
        // унесло бы свежее содержимое по сроку первого.
        pending?.let(handler::removeCallbacks)

        val task = Runnable { clearIfOurs(context, text) }
        pending = task
        handler.postDelayed(task, TTL_MILLIS)
    }

    /**
     * Очищает буфер немедленно, если в нём всё ещё наше содержимое.
     *
     * Вызывается при блокировке хранилища: таймер к этому моменту мог
     * не сработать, а блокировка — это ровно тот момент, после которого
     * ничего из переписки на устройстве быть не должно.
     */
    fun clear(context: Context) {
        pending?.let(handler::removeCallbacks)
        pending = null

        val manager = manager(context) ?: return

        // 🔐 Чужое содержимое не трогаем даже при блокировке: человек
        // мог скопировать что-то в другом приложении, и стирать это
        // приложению-мессенджеру не за чем.
        if (!isOurs(manager)) {
            return
        }

        wipe(manager)
    }

    /**
     * Очистка по таймеру.
     *
     * Сверяется с тем, что лежит в буфере сейчас: за минуту человек мог
     * скопировать что-то ещё, и стирать чужое приложение не вправе.
     */
    private fun clearIfOurs(context: Context, copied: CharSequence) {
        pending = null

        val manager = manager(context) ?: return
        val current = manager.primaryClip ?: return

        if (current.itemCount == 0) {
            return
        }

        val text = runCatching { current.getItemAt(0).coerceToText(context) }.getOrNull()

        if (text?.toString() != copied.toString()) {
            return
        }

        wipe(manager)
    }

    /**
     * Лежит ли в буфере то, что клали мы.
     *
     * Определяется по пометке чувствительности: свой ярлык
     * в `ClipDescription` проверять надёжнее нечем, а содержимое
     * сверять здесь нельзя — [clear] вызывается уже после того, как
     * ключ хранилища забыт.
     */
    private fun isOurs(manager: ClipboardManager): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            // До Android 13 пометки нет, и отличить своё от чужого
            // нечем. Ждём таймера: он единственный знает содержимое.
            return false
        }

        val extras = manager.primaryClipDescription?.extras ?: return false

        return extras.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE, false)
    }

    /**
     * Стирает буфер.
     *
     * `clearPrimaryClip` появился в API 28 — то есть доступен на всём
     * поддерживаемом диапазоне (minSdk = 28). Подмена пустой строкой,
     * как делают на старых версиях, оставила бы в буфере запись нашего
     * приложения; здесь она не нужна.
     */
    private fun wipe(manager: ClipboardManager) {
        runCatching { manager.clearPrimaryClip() }
    }

    private fun manager(context: Context): ClipboardManager? =
        context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
}
