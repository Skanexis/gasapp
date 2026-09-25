// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.app.Activity
import android.app.Application
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import java.time.Duration
import org.aegis.app.core.AutoLock
import org.aegis.app.core.Settings
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock

/**
 * 🔐 Приложение запирается после ухода в фон.
 *
 * Раздел 19.3 («Auto-lock: 1 мин по умолчанию») и MASVS AUTH-2.
 *
 * # Почему тест понадобился
 *
 * До M8 запирания не существовало вовсе: настройка была, экран её
 * показывал, центр безопасности засчитывал проверку — а `Core.close()`
 * не вызывался ниоткуда (раздел 23.5). Дефект такого рода не виден
 * ни компилятору, ни глазу: отсутствие вызова нечем заметить.
 * Поэтому проверяется не «есть ли код», а «происходит ли переход».
 *
 * # ⚠️ Почему события подаются вручную
 *
 * `AegisApplication` регистрирует [AutoLock] как
 * `ActivityLifecycleCallbacks`, и очевидный тест водил бы экран
 * контроллером Robolectric. Так не выходит: **Robolectric не рассылает
 * `onActivityStopped` во второй раз** для одного контроллера. После
 * пары `stop()` → `start()` следующий `stop()` молча не доходит
 * до слушателей.
 *
 * Последствие — не ложное падение, а кое-что хуже: счётчик видимых
 * экранов не возвращался к нулю после теста, следующий тест начинал
 * с единицы, уход в фон у него не засчитывался, и падал он с
 * «приложение не заперлось». То есть красным становился **исправный**
 * код, а причина лежала в тестовом инструменте.
 *
 * Поэтому штатная регистрация снимается, а события подаются парами
 * вручную. Проверяется та же логика — она не знает, кто её позвал, —
 * но состояние между тестами остаётся сбалансированным.
 *
 * # Что здесь проверяется, а что нет
 *
 * Проверяется решение: сколько времени прошло и надо ли запирать.
 * Не проверяется, что ключ действительно забыт, — это делает
 * `Core.close()`, а хранилище в юнит-тесте не открыто.
 *
 * # Про часы
 *
 * [AutoLock] считает по `SystemClock.elapsedRealtime`, потому что
 * настенное время переводится. Тест двигает именно его.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AutoLockTest {

    private lateinit var activity: Activity

    @Before
    fun setUp() {
        val application: Application = ApplicationProvider.getApplicationContext()

        // Снимается штатная регистрация из AegisApplication: иначе
        // каждое событие пришло бы дважды — от Robolectric и от теста.
        application.unregisterActivityLifecycleCallbacks(AutoLock)

        resetAutoLock()

        activity =Robolectric.buildActivity(Activity::class.java).setup().get()
        shadowOf(activity).clearNextStartedActivities()

        // Приложение на переднем плане: один видимый экран.
        AutoLock.onActivityStarted(activity)
        shadowOf(activity).clearNextStartedActivities()
    }

    /** Парное закрытие: счётчик обязан вернуться к нулю. */
    @After
    fun tearDown() {
        AutoLock.onActivityStopped(activity)
    }

    /**
     * Короткая отлучка не запирает.
     *
     * Запирание на каждом сворачивании — не строгость, а причина
     * выключить автоблокировку совсем.
     */
    @Test
    fun a_short_absence_does_not_lock() {
        AutoLock.onActivityStopped(activity)

        advance(thresholdMillis() - 1_000L)

        AutoLock.onActivityStarted(activity)

        assertNull(
            "приложение заперто раньше срока",
            shadowOf(activity).peekNextStartedActivity(),
        )
    }

    /** 🔐 Отлучка дольше порога запирает. */
    @Test
    fun an_absence_past_the_threshold_locks() {
        AutoLock.onActivityStopped(activity)

        advance(thresholdMillis())

        AutoLock.onActivityStarted(activity)

        assertNotNull(
            "приложение не заперлось после порога",
            shadowOf(activity).peekNextStartedActivity(),
        )
    }

    /**
     * 🔐 Экран блокировки открывается поверх всего, а не поверх чата.
     *
     * Без `CLEAR_TASK` кнопка «назад» возвращала бы на экран переписки:
     * данных там уже нет, но выглядит он как открытый, и человек решил
     * бы, что приложение не заперто.
     */
    @Test
    fun locking_clears_the_task() {
        AutoLock.onActivityStopped(activity)

        advance(thresholdMillis())

        AutoLock.onActivityStarted(activity)

        val started = shadowOf(activity).peekNextStartedActivity()
        assertNotNull("приложение не заперлось", started)

        val flags = started.flags

        assertTrue(
            "нет FLAG_ACTIVITY_CLEAR_TASK: назад вернёт в переписку",
            flags and Intent.FLAG_ACTIVITY_CLEAR_TASK != 0,
        )
        assertTrue(
            "нет FLAG_ACTIVITY_NEW_TASK: CLEAR_TASK без него не действует",
            flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0,
        )
    }

    /**
     * Переход между экранами приложения не считается уходом в фон.
     *
     * 🔐 Самая вероятная ошибка в такой схеме: отслеживать один экран
     * вместо счёта всех. Тогда любое открытие чата выглядело бы уходом,
     * и приложение запиралось бы на каждом нажатии — то есть
     * автоблокировку выключили бы в первый же день.
     */
    @Test
    fun navigating_between_screens_is_not_a_departure() {
        val next = Robolectric.buildActivity(Activity::class.java).setup().get()

        // Порядок как у платформы: новый экран стартует до того,
        // как остановится прежний.
        AutoLock.onActivityStarted(next)
        AutoLock.onActivityStopped(activity)

        advance(thresholdMillis() * 2)

        AutoLock.onActivityStarted(activity)

        assertNull(
            "переход между экранами засчитан уходом в фон",
            shadowOf(activity).peekNextStartedActivity(),
        )

        AutoLock.onActivityStopped(next)
    }

    /** Умолчание порога — минута, как в разделе 19.3. */
    @Test
    fun default_threshold_matches_the_plan() {
        assertEquals(60L, Settings.AUTO_LOCK_DEFAULT)
    }

    /**
     * Порог в миллисекундах.
     *
     * Хранилище в тесте закрыто, поэтому [AutoLock] читает умолчание —
     * то же, что проверяет [default_threshold_matches_the_plan].
     */
    /**
     * 🔐 Запирание в фоне закрывает экраны с данными, не дожидаясь
     * возвращения.
     *
     * Иначе расшифрованные превью и имена собеседников оставались
     * в памяти запертого процесса — их показал дамп памяти на эмуляторе.
     */
    @Test
    fun locking_in_the_background_finishes_data_screens() {
        val dataScreen = Robolectric.buildActivity(Activity::class.java).setup().get()
        trackAsDataScreen(dataScreen)

        AutoLock.onActivityStopped(activity)
        advance(thresholdMillis())
        shadowOf(android.os.Looper.getMainLooper()).idleFor(Duration.ofMillis(thresholdMillis()))

        assertTrue("экран с данными пережил запирание в фоне", dataScreen.isFinishing)

        // Возвращение для tearDown: счётчик видимых экранов парный.
        AutoLock.onActivityStarted(activity)
    }

    /**
     * Регистрирует экран как экран с данными.
     *
     * AutoLock отбирает их по пакету приложения, а тестовый экран —
     * `android.app.Activity`; список пополняется отражением, чтобы
     * не заводить в защитном коде ручку для тестов (как [resetAutoLock]).
     */
    @Suppress("UNCHECKED_CAST")
    private fun trackAsDataScreen(screen: Activity) {
        val field = AutoLock::class.java.getDeclaredField("dataScreens").apply { isAccessible = true }
        (field.get(null) as MutableList<java.lang.ref.WeakReference<Activity>>) +=
            java.lang.ref.WeakReference(screen)
    }

    private fun thresholdMillis(): Long = Settings.AUTO_LOCK_DEFAULT * 1_000L

    private fun advance(millis: Long) {
        ShadowSystemClock.advanceBy(Duration.ofMillis(millis))
    }

    /**
     * Сбрасывает состояние [AutoLock] перед тестом.
     *
     * [AutoLock] — объект, и Robolectric держит его между тестами одной
     * песочницы. Экран, запущенный другим тестом и не остановленный,
     * оставлял счётчик видимых экранов ненулевым, и здесь уход в фон
     * не распознавался: тесты зависели от порядка и упали, когда перед
     * ними по алфавиту встал ActionSheetOpensTest. Сброс — отражением,
     * чтобы не заводить в защитном коде ручку «обнулить счётчик».
     */
    private fun resetAutoLock() {
        for ((name, value) in listOf("visible" to 0, "backgroundedAt" to 0L)) {
            AutoLock::class.java.getDeclaredField(name).apply { isAccessible = true }.set(null, value)
        }
    }
}
