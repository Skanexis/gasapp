// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.core

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock

/**
 * Счётчик неверных попыток PIN и экспоненциальные задержки.
 *
 * Политика — таблица раздела 19.3, целиком и без настроек:
 *
 * | Неверных подряд | Задержка перед следующей попыткой |
 * |---|---|
 * | 1–3 | нет |
 * | 4 | 5 секунд |
 * | 5 | 30 секунд |
 * | 6 | 5 минут |
 * | 7 | 30 минут |
 * | 8 и далее | 1 час с удвоением |
 *
 * 🔐 Задержки неотключаемы намеренно. Настраиваемая защита от перебора
 * защищает только тех, кто её нашёл и включил; а выключить её захочет
 * ровно тот, кому надоело ждать после своих же опечаток — то есть тот,
 * кому она нужнее всего.
 *
 * Считает **все** проверки PIN: экран входа, повторное подтверждение
 * перед опасными действиями ([Reauth]), хранилище файлов, включение
 * отпечатка. Любая из них отвечает на вопрос «верен ли PIN», и
 * незасчитанная превращалась бы в обход задержек.
 *
 * # Попытка засчитывается до проверки (аудит 2026-10-02, A-1)
 *
 * Прежде неверная попытка записывалась **после** проверки, в области
 * жизни экрана. Поворот телефона во время проверки (около секунды)
 * пересоздавал экран, корутина отменялась — и запись не происходила:
 * перебор без задержек, по попытке в секунду. Теперь [beginAttempt]
 * записывает попытку на диск до вывода ключа, а [recordSuccess] снимает
 * её, только если PIN подошёл. Прерванная проверка остаётся неверной.
 *
 * # Время — монотонное (аудит 2026-10-02, A-2)
 *
 * Прежде срок считался по настенным часам, а перевод их **вперёд**
 * снимал любую задержку из настроек даты — без root, одним движением.
 * Теперь срок считается по `SystemClock.elapsedRealtime`: от загрузки,
 * идёт во сне, не настраивается ничем. После перезагрузки этот счёт
 * начинается заново, и пройденное до неё время узнать честно нельзя —
 * поэтому перезагрузка начинает ожидание сначала. Владельцу это стоит
 * лишнего ожидания в редком случае; перебирающему отнимает способ
 * его обойти.
 *
 * # Почему счётчик не в зашифрованной базе
 *
 * База открывается ключом, выведенным из PIN: пока PIN не подошёл,
 * читать счётчик неоткуда. Счётчик, который нельзя прочитать до
 * проверки, не ограничивает проверку. Поэтому он лежит в приватных
 * `SharedPreferences` приложения: не уходят в облачную копию
 * (`allowBackup="false"`) и переживают перезапуск.
 *
 * # Чего этот счётчик не даёт
 *
 * ⚠️ Он не мешает перебору **вне** приложения. От перебора по снятому
 * файлу защищает аппаратная половина ключа ([TeeKey], схема v3): каждая
 * попытка требует этого телефона. Под root на разблокированном телефоне
 * Keystore можно звать в обход этого счётчика — против такого противника
 * держит только длина PIN.
 *
 * ⚠️ Он обнуляется при переустановке приложения — вместе с данными
 * приложения и ключами Keystore, так что перебирать после неё нечего.
 */
object PinAttempts {

    /**
     * Момент по монотонным часам: время от загрузки и номер загрузки.
     *
     * [boot] — `Settings.Global.BOOT_COUNT`, `-1`, если система его
     * не отдала; тогда перезагрузку выдаёт время, пошедшее назад.
     */
    data class Moment(val elapsed: Long, val boot: Int) {
        companion object {
            /** Сейчас. */
            fun now(context: Context): Moment = Moment(SystemClock.elapsedRealtime(), bootCount(context))
        }
    }

    /**
     * Сколько неверных попыток подряд уже сделано.
     *
     * Ноль после последнего успешного ввода. Прерванная проверка
     * считается неверной.
     */
    fun failures(context: Context): Int = prefs(context).getInt(KEY_FAILURES, 0)

    /**
     * Сколько миллисекунд осталось ждать до следующей попытки.
     *
     * Ноль — можно пробовать.
     *
     * 🔐 После перезагрузки (или если монотонное время пошло назад)
     * отсчёт начинается сначала: отметка переносится на [at] и
     * записывается, так что ждать придётся полный срок.
     */
    fun remainingMillis(context: Context, at: Moment = Moment.now(context)): Long {
        val store = prefs(context)
        val required = delayMillis(store.getInt(KEY_FAILURES, 0))

        if (required == 0L) {
            return 0L
        }

        val lastElapsed = store.getLong(KEY_LAST_ELAPSED, NEVER)
        val lastBoot = store.getInt(KEY_LAST_BOOT, UNKNOWN_BOOT)
        val rebooted = lastElapsed == NEVER ||
            at.elapsed < lastElapsed ||
            (at.boot != UNKNOWN_BOOT && lastBoot != UNKNOWN_BOOT && at.boot != lastBoot)

        if (rebooted) {
            store.edit()
                .putLong(KEY_LAST_ELAPSED, at.elapsed)
                .putInt(KEY_LAST_BOOT, at.boot)
                .commitOrThrow()

            return required
        }

        return (required - (at.elapsed - lastElapsed)).coerceAtLeast(0L)
    }

    /**
     * 🔐 Засчитывает попытку **до** проверки PIN.
     *
     * Вызывать перед выводом ключа, а не после неудачи: проверка,
     * прерванная поворотом экрана или убитым процессом, должна остаться
     * неверной. Верный PIN снимает попытку через [recordSuccess].
     *
     * @return число неверных попыток подряд, считая эту.
     * @throws IllegalStateException запись не удалась — проверять PIN
     *   без записанной попытки нельзя.
     */
    fun beginAttempt(context: Context, at: Moment = Moment.now(context)): Int {
        val failures = failures(context).let { if (it == Int.MAX_VALUE) it else it + 1 }

        prefs(context).edit()
            .putInt(KEY_FAILURES, failures)
            .putLong(KEY_LAST_ELAPSED, at.elapsed)
            .putInt(KEY_LAST_BOOT, at.boot)
            // commit, а не apply: apply пишет на диск асинхронно, и
            // убитый сразу после ввода процесс унёс бы запись с собой.
            .commitOrThrow()

        return failures
    }

    /**
     * Сбрасывает счётчик после верного PIN.
     *
     * Вызывается только тогда, когда хранилище действительно
     * открылось: «верный PIN» здесь не отдельная проверка, а факт
     * успешной расшифровки.
     */
    @SuppressLint("ApplySharedPref")
    fun recordSuccess(context: Context) {
        prefs(context).edit()
            .remove(KEY_FAILURES)
            .remove(KEY_LAST_ELAPSED)
            .remove(KEY_LAST_BOOT)
            .remove(LEGACY_LAST_ATTEMPT)
            .commit()
    }

    /**
     * Задержка после [failures] неверных попыток подряд.
     *
     * Вынесена отдельно и открыта для теста: таблица задержек — это
     * и есть политика.
     */
    fun delayMillis(failures: Int): Long = when {
        failures <= FREE_ATTEMPTS -> 0L
        failures == 4 -> 5_000L
        failures == 5 -> 30_000L
        failures == 6 -> 5 * 60_000L
        failures == 7 -> 30 * 60_000L
        else -> {
            // 8 → час, 9 → два, 10 → четыре и так далее. Сдвиг ограничен:
            // переполнение сделало бы задержку отрицательной, то есть
            // защиту — своей противоположностью.
            val steps = (failures - 8).coerceAtMost(MAX_DOUBLINGS)

            HOUR_MILLIS shl steps
        }
    }

    /**
     * 🔐 Стирать ли данные после [WIPE_AFTER] неверных попыток подряд.
     *
     * Раздел 19.3: opt-in, по умолчанию **выключено**. Случайное
     * стирание ребёнком или в кармане — частый сценарий, а вернуть
     * данные можно только ключом восстановления.
     *
     * Флаг лежит рядом со счётчиком, а не в базе: до верного PIN
     * прочитать из неё нечего.
     */
    fun wipeEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_WIPE, false)

    @SuppressLint("ApplySharedPref")
    fun setWipeEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_WIPE, enabled).commit()
    }

    /** Пора ли стирать после [failures] неверных попыток подряд. */
    fun shouldWipe(failures: Int, enabled: Boolean): Boolean = enabled && failures >= WIPE_AFTER

    /** Порог стирания — раздел 19.3. */
    const val WIPE_AFTER = 10

    /**
     * 🔐 Забывает историю попыток — при удалении аккаунта: «последняя
     * попытка входа — вчера» после удаления удалением не является.
     */
    @SuppressLint("ApplySharedPref")
    fun forget(context: Context) {
        prefs(context).edit().clear().commit()
    }

    private fun prefs(context: Context): SharedPreferences =
        context.applicationContext.getSharedPreferences(STORE, Context.MODE_PRIVATE)

    @SuppressLint("ApplySharedPref")
    private fun SharedPreferences.Editor.commitOrThrow() {
        check(commit()) { "счётчик попыток PIN не записан" }
    }

    /** Номер загрузки устройства (API 24+); `-1` — неизвестен. */
    private fun bootCount(context: Context): Int = runCatching {
        android.provider.Settings.Global.getInt(
            context.contentResolver,
            android.provider.Settings.Global.BOOT_COUNT,
            UNKNOWN_BOOT,
        )
    }.getOrDefault(UNKNOWN_BOOT)

    /** Сколько попыток проходит без задержки. */
    private const val FREE_ATTEMPTS = 3

    private const val HOUR_MILLIS = 60 * 60_000L

    /** Предел удвоений: 20 удвоений часа — больше ста лет. */
    private const val MAX_DOUBLINGS = 20

    private const val NEVER = -1L
    private const val UNKNOWN_BOOT = -1

    private const val STORE = "aegis_pin_attempts"
    private const val KEY_FAILURES = "failures"
    private const val KEY_LAST_ELAPSED = "last_attempt_elapsed"
    private const val KEY_LAST_BOOT = "last_attempt_boot"

    /** Отметка прежних версий по настенным часам — только убирается. */
    private const val LEGACY_LAST_ATTEMPT = "last_attempt"
    private const val KEY_WIPE = "wipe_after_failures"
}
