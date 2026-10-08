// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.content.Context
import org.gasapp.app.R

/**
 * 🔐 Проверка PIN при открытом хранилище — с тем же счётом попыток,
 * что на экране входа.
 *
 * # Зачем
 *
 * PIN спрашивается не только на экране входа: перед опасными действиями
 * ([Reauth]), в хранилище файлов, при включении отпечатка. Прежде эти
 * проверки попыток не считали вовсе (аудит 2026-10-02, A-4): тот, кому
 * достался разблокированный телефон, подбирал PIN в диалоге «включить
 * отпечаток» по попытке в секунду, без задержек и без стирания после
 * десяти. Узнав PIN, он получал и всё, что за ним заперто.
 *
 * Теперь любая проверка идёт через [PinAttempts]: попытка засчитывается
 * до вывода ключа, задержки общие с экраном входа, стирание после
 * десяти — тоже.
 *
 * # Как проверяется
 *
 * PIN верен, если выведенный из него ключ ([Core.deriveKey], схема v3
 * с Keystore) и есть ключ открытой базы ([Core.keyOpensStorage]).
 * Признака «верный PIN» нигде не хранится.
 */
object PinCheck {

    /** Чем кончилась проверка. */
    sealed class Outcome {
        /** PIN верен. */
        object Correct : Outcome()

        /** PIN неверен; [failures] — неверных подряд, [waitMillis] — до следующей попытки. */
        data class Wrong(val failures: Int, val waitMillis: Long) : Outcome()

        /** Попытки сейчас нельзя: идёт задержка. */
        data class Wait(val millis: Long) : Outcome()

        /** Десятая неверная при включённом стирании: аккаунт стёрт на устройстве. */
        object Wiped : Outcome()
    }

    /**
     * Проверяет PIN. Долго (Argon2id и Keystore) — звать не с главного потока.
     *
     * [pin] затирается здесь же, чем бы ни кончилось.
     */
    fun verify(context: Context, pin: ByteArray): Outcome {
        val app = context.applicationContext

        try {
            val remaining = PinAttempts.remainingMillis(app)
            if (remaining > 0L) {
                return Outcome.Wait(remaining)
            }

            // 🔐 До вывода ключа: прерванная проверка остаётся неверной.
            val failures = PinAttempts.beginAttempt(app)

            val correct = runCatching {
                val key = Core.deriveKey(app, pin)
                try {
                    Core.keyOpensStorage(key)
                } finally {
                    key.fill(0)
                }
            }.getOrDefault(false)

            if (correct) {
                PinAttempts.recordSuccess(app)
                return Outcome.Correct
            }

            if (PinAttempts.shouldWipe(failures, PinAttempts.wipeEnabled(app))) {
                AccountWipe.wipe(app)
                return Outcome.Wiped
            }

            return Outcome.Wrong(failures, PinAttempts.delayMillis(failures))
        } finally {
            pin.fill(0)
        }
    }

    /** Остаток ожидания словами: «через 5 минут». */
    fun waitText(context: Context, millis: Long): String {
        val seconds = (millis + 999L) / 1000L
        val resources = context.resources
        val left = when {
            seconds >= SECONDS_IN_HOUR -> (seconds / SECONDS_IN_HOUR).toInt().let {
                resources.getQuantityString(R.plurals.lock_left_hours, it, it)
            }
            seconds >= SECONDS_IN_MINUTE -> (seconds / SECONDS_IN_MINUTE).toInt().let {
                resources.getQuantityString(R.plurals.lock_left_minutes, it, it)
            }
            else -> seconds.toInt().let {
                resources.getQuantityString(R.plurals.lock_left_seconds, it, it)
            }
        }

        return context.getString(R.string.lock_locked_for, left)
    }

    private const val SECONDS_IN_MINUTE = 60L
    private const val SECONDS_IN_HOUR = 3600L
}
