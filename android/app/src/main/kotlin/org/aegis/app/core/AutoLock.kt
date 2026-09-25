// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import java.lang.ref.WeakReference
import android.os.Looper
import android.os.SystemClock
import org.aegis.app.LockActivity
import org.aegis.app.OnboardingActivity
import org.aegis.app.RestoreActivity

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

    /**
     * Забывает отлучку: «приложение на переднем плане, в фон не уходило».
     *
     * Только для проверок на устройстве. Сторож живёт весь процесс,
     * и отлучка, заведённая одним тестом (`AutoLockOnDeviceTest`
     * ставит порог «запирать сразу» и уходит в фон), запирала экран
     * следующего теста того же прогона. Для приложения это верное
     * поведение; для соседнего теста — помеха, которую надо снять явно.
     *
     * Вызывать с главного потока.
     */
    @androidx.annotation.VisibleForTesting
    fun forgetAbsenceForTests() {
        scheduled?.let(handler::removeCallbacks)
        scheduled = null
        backgroundedAt = 0L
        thresholdMillis = Settings.AUTO_LOCK_DEFAULT * 1000L
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

            // 🔐 Экраны с данными закрываются тут же, в фоне.
            //
            // Прежде они жили до возвращения человека: хранилище
            // закрыто, но расшифрованные превью переписки, имена
            // собеседников и тексты сообщений оставались в памяти
            // процесса — в адаптерах экранов из стека. Дамп памяти
            // запертого приложения (эмулятор, 2026-09-25) их показывал.
            // Возвращение всё равно начинается с экрана блокировки.
            finishDataScreens()
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

    /**
     * 🔐 Экран с перепиской не создаётся при закрытом хранилище.
     *
     * # Что здесь чинится
     *
     * Система, убившая процесс по памяти, при возвращении восстанавливает
     * **верхний экран задачи** — например, открытую переписку. В новом
     * процессе хранилище закрыто, а у [AutoLock] `backgroundedAt == 0`:
     * отлучки он не видел и запирать не стал. Экран переписки показывал
     * имя собеседника из extras и черновик из сохранённого состояния —
     * без PIN.
     *
     * # Почему список разрешённых, а не запрещённых
     *
     * Без хранилища имеют право открываться только экраны, которые его
     * и открывают: блокировка, регистрация, восстановление из копии.
     * Новый экран, добавленный завтра, защищён по умолчанию; при списке
     * запрещённых его пришлось бы не забыть туда вписать.
     *
     * # Почему только экраны приложения
     *
     * Чужая активность в этом процессе (системный выбор файла, экран
     * библиотеки) хранилища не касается, и закрывать её незачем.
     *
     * Экран закрывается в `onCreate`, то есть до `onStart`: он не успевает
     * ни отрисоваться, ни восстановить поля из сохранённого состояния.
     */
    override fun onActivityCreated(activity: Activity, state: Bundle?) {
        if (!activity.javaClass.name.startsWith(APP_PACKAGE)) {
            return
        }

        if (activity.javaClass !in OPEN_WHILE_LOCKED) {
            dataScreens += WeakReference(activity)
        }

        if (activity.javaClass in OPEN_WHILE_LOCKED || Core.isUnlocked) {
            return
        }

        lock(activity)
        activity.finish()
    }

    /** Экраны, которые сами открывают хранилище и потому работают без него. */
    private val OPEN_WHILE_LOCKED: Set<Class<out Activity>> = setOf(
        LockActivity::class.java,
        OnboardingActivity::class.java,
        RestoreActivity::class.java,
    )

    private const val APP_PACKAGE = "org.aegis.app."

    override fun onActivityResumed(activity: Activity) = Unit

    override fun onActivityPaused(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(activity: Activity, out: Bundle) = Unit

    override fun onActivityDestroyed(activity: Activity) {
        dataScreens.removeAll { it.get().let { screen -> screen == null || screen === activity } }
    }

    /**
     * Экраны приложения, работающие с открытым хранилищем.
     *
     * Слабые ссылки: список не должен держать экран в памяти дольше,
     * чем его держит система, — ровно этого он и призван избежать.
     */
    private val dataScreens = mutableListOf<WeakReference<Activity>>()

    /** Закрывает экраны с данными — при запирании в фоне. */
    private fun finishDataScreens() {
        dataScreens.mapNotNull { it.get() }
            .filterNot { it.isFinishing }
            .forEach { it.finish() }
        dataScreens.clear()
    }
}
