// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import org.aegis.app.LockActivity
import org.aegis.app.OnboardingActivity

/**
 * Автоматическое запирание приложения после ухода в фон.
 *
 * Раздел 19.3 («Auto-lock: 1 мин по умолчанию, настраивается»,
 * «при уходе в фон — zeroize LSMK через N секунд») и MASVS AUTH-2.
 *
 * # Что было не так
 *
 * Настройка [Settings.AUTO_LOCK_SECONDS] существовала, экран настроек
 * её показывал, а центр безопасности засчитывал проверку «автоблокировка
 * не дольше пяти минут» как пройденную. Запирать при этом было некому:
 * `Core.close()` не вызывался ниоткуда. Приложение, открытое однажды,
 * оставалось открытым до того, как систему заставят убить процесс.
 *
 * Это худший вид расхождения: пользователь видел подтверждение защиты,
 * которой не было, и полагался на него.
 *
 * # Как считается время
 *
 * По [SystemClock.elapsedRealtime], а не по настенным часам.
 * 🔐 Настенное время переводится — и переводом назад срок отодвигался бы
 * на столько, на сколько сдвинули часы. `elapsedRealtime` считает от
 * загрузки, идёт в глубоком сне и не настраивается ничем.
 *
 * Обратная сторона: после перезагрузки счёт начинается заново. Здесь
 * это безвредно — перезагрузка и так убивает процесс вместе с ключом
 * хранилища, то есть запирает приложение вернее любого таймера.
 *
 * # Почему счёт по числу видимых экранов
 *
 * Отследить «ушёл в фон» одним экраном нельзя: переход между двумя
 * экранами приложения — это `onStop` первого и `onStart` второго,
 * и любая навигация выглядела бы уходом. Считается количество
 * показанных экранов; фон — это ноль.
 *
 * Поворот экрана тоже даёт ноль на мгновение, но пройденное время
 * при этом близко к нулю, и порог не срабатывает.
 *
 * # Два рубежа, а не один
 *
 * Ключ забывается по таймеру, заведённому в момент ухода в фон, —
 * то есть пока приложение в фоне, а не в момент возвращения.
 * 🔐 Разница существенна: телефон, изъятый через час после того, как
 * его положили на стол, не должен содержать ключ хранилища в памяти
 * процесса. Ожидание возвращения оставляло бы ключ там ровно до него.
 *
 * Таймер, однако, не гарантия: начиная с Android 14 система замораживает
 * фоновые процессы, и отложенная задача в замороженном процессе не
 * выполняется. Поэтому при возвращении порог проверяется заново
 * по пройденному времени.
 *
 * ⚠️ У второго рубежа есть заметный глазу побочный эффект. Платформа
 * вызывает `onActivityStarted` **после** `onStart` самого экрана, так что
 * при возвращении экран успевает один раз обратиться к уже закрытому
 * хранилищу. Обращение безвредно — все вызовы ядра на экранах обёрнуты
 * в `runCatching`, — но видно: перед экраном блокировки мелькает пустой
 * список. Это цена того, что запирание не зависит от порядка,
 * в котором платформа рассылает события жизненного цикла.
 */
object AutoLock : Application.ActivityLifecycleCallbacks {

    /** Сколько экранов приложения сейчас показано. */
    private var visible = 0

    /**
     * Момент ухода в фон, `0` — приложение на переднем плане.
     *
     * По [SystemClock.elapsedRealtime].
     */
    private var backgroundedAt = 0L

    /**
     * Порог, прочитанный **до** ухода в фон.
     *
     * 🔐 Читать его в момент возврата нельзя: настройка лежит
     * в зашифрованной базе, и к этому моменту база может быть уже
     * закрыта — тогда чтение упало бы, и подставлять пришлось бы
     * умолчание. Значение снимается, пока хранилище заведомо открыто.
     */
    private var thresholdMillis = Settings.AUTO_LOCK_DEFAULT * 1000L

    private val handler = Handler(Looper.getMainLooper())

    /** Отложенное забывание ключа; `null` — приложение на переднем плане. */
    private var scheduled: Runnable? = null

    fun install(application: Application) {
        application.registerActivityLifecycleCallbacks(this)
    }

    override fun onActivityStarted(activity: Activity) {
        visible++

        // Возвращение раньше срока отменяет отложенное забывание.
        scheduled?.let(handler::removeCallbacks)
        scheduled = null

        if (visible > 1 || backgroundedAt == 0L) {
            return
        }

        val away = SystemClock.elapsedRealtime() - backgroundedAt
        backgroundedAt = 0L

        if (away < thresholdMillis) {
            return
        }

        lock(activity)
    }

    override fun onActivityStopped(activity: Activity) {
        visible--

        if (visible > 0) {
            return
        }

        backgroundedAt = SystemClock.elapsedRealtime()
        thresholdMillis = readThreshold()

        // 🔐 Ключ забывается в фоне, не дожидаясь возвращения.
        //
        // Контекст берётся у приложения, а не у экрана: экран к моменту
        // срабатывания может быть уничтожен, и ссылка на него всё это
        // время держала бы его в памяти.
        val application = activity.applicationContext

        val task = Runnable {
            scheduled = null

            Core.close()
            SecureClipboard.clear(application)
        }

        scheduled = task
        handler.postDelayed(task, thresholdMillis)
    }

    /**
     * Запирает приложение и возвращает пользователя на экран PIN.
     *
     * Порядок не произволен: сначала забывается ключ, потом строится
     * переход. 🔐 При обратном порядке экран блокировки успевает
     * появиться поверх ещё открытого хранилища, и приложение,
     * свёрнутое в эту секунду, останется открытым.
     */
    private fun lock(activity: Activity) {
        Core.close()

        // Буфер обмена — часть того же состояния: скопированное
        // сообщение переживает запирание, и вынуть его оттуда может
        // любое приложение на переднем плане.
        SecureClipboard.clear(activity)

        // Экран блокировки бесполезен без аккаунта: расшифровывать
        // нечего, и человек упёрся бы в запрос, который не проходит.
        val target = if (Core.hasAccount(activity)) {
            LockActivity::class.java
        } else {
            OnboardingActivity::class.java
        }

        // CLEAR_TASK убирает из стека всё, что было открыто до запирания.
        // Без него кнопка «назад» с экрана блокировки возвращала бы
        // в переписку — на экран, который просто нарисован и не имеет
        // доступа к данным, но выглядит как открытый.
        activity.startActivity(
            Intent(activity, target)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
    }

    /**
     * Читает порог из зашифрованной базы.
     *
     * 🔐 Нечитаемая настройка даёт умолчание, а не «не запирать»:
     * неизвестное состояние трактуется в пользу защиты — то же правило,
     * что в [SecureWindow].
     */
    private fun readThreshold(): Long {
        val seconds = runCatching {
            Core.messenger().settingInt(Settings.AUTO_LOCK_SECONDS, Settings.AUTO_LOCK_DEFAULT)
        }.getOrDefault(Settings.AUTO_LOCK_DEFAULT)

        return seconds.coerceAtLeast(0L) * 1000L
    }

    override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit

    override fun onActivityResumed(activity: Activity) = Unit

    override fun onActivityPaused(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(activity: Activity, out: Bundle) = Unit

    override fun onActivityDestroyed(activity: Activity) = Unit
}
