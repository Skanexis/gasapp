// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import java.io.File
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.BiometricUnlock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Разблокировка по биометрии: то, что можно проверить без устройства.
 *
 * MASVS AUTH-2.1.
 *
 * # ⚠️ Чего этот файл НЕ проверяет
 *
 * Главного: кругового пути «ключ базы → конверт → подтверждение →
 * ключ базы». Вне устройства Android Keystore не существует, а
 * биометрического датчика нет и подавно. Эта часть проверена только
 * сборкой, и в плане записана как непроверенная — выдавать её
 * за проверенную значило бы повторить находку P-5 (раздел 23.6),
 * где документ описывал защиту, которой не было.
 *
 * # Что проверяется
 *
 * Поведение **вокруг** крипто: когда биометрия считается включённой,
 * что остаётся на диске после выключения и переживает ли конверт
 * удаление аккаунта. Здесь и живут ошибки, которые не видны глазом:
 * забытый файл выглядит как отсутствие файла.
 *
 * # Почему отказ безопасен
 *
 * Все пути здесь ведут к «вводите PIN». Не открылся конверт, не нашёлся
 * ключ, сменился набор отпечатков — во всех случаях остаётся PIN,
 * из которого и выводится ключ базы. Открыть базу «без ключа»
 * нельзя ни одним из этих путей.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BiometricUnlockTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val envelope: File
        get() = File(context.filesDir, "aegis.bio")

    /**
     * Без конверта биометрия выключена.
     *
     * Состояние определяется наличием файла, а не флагом в настройках:
     * флаг переживает очистку данных, и приложение предлагало бы вход
     * по биометрии, которому нечего расшифровывать.
     */
    @Test
    fun biometrics_are_off_when_there_is_no_envelope() {
        envelope.delete()

        assertFalse(
            "биометрия считается включённой без конверта",
            BiometricUnlock.isEnabled(context),
        )
    }

    /** С конвертом — включена. */
    @Test
    fun biometrics_are_on_when_the_envelope_exists() {
        envelope.writeBytes(byteArrayOf(12, 1, 2, 3))

        assertTrue(
            "конверт есть, а биометрия считается выключенной",
            BiometricUnlock.isEnabled(context),
        )
    }

    /** 🔐 Выключение стирает конверт. */
    @Test
    fun disabling_removes_the_envelope() {
        envelope.writeBytes(byteArrayOf(12, 1, 2, 3))

        BiometricUnlock.disable(context)

        assertFalse("конверт пережил выключение биометрии", envelope.exists())
        assertFalse(
            "биометрия осталась включённой после выключения",
            BiometricUnlock.isEnabled(context),
        )
    }

    /**
     * 🔐 Удаление аккаунта уносит конверт.
     *
     * В конверте лежит ключ базы. Оставить его — значит оставить вход
     * в удалённый аккаунт: база стёрта, а ключ от неё пережил удаление.
     */
    @Test
    fun deleting_the_account_removes_the_envelope() {
        envelope.writeBytes(byteArrayOf(12, 1, 2, 3))

        assertTrue("тест не подготовил конверт", envelope.exists())

        AccountWipe.wipe(context)

        assertFalse("конверт пережил удаление аккаунта", envelope.exists())
    }

    /**
     * 🔐 Повреждённый конверт не открывают — предлагают PIN.
     *
     * Обрезанный файл, файл с невозможной длиной IV, пустой файл:
     * каждый обязан дать `null`, а не исключение и не попытку
     * расшифровать мусор.
     */
    @Test
    fun a_damaged_envelope_yields_no_cipher() {
        val damaged = listOf(
            byteArrayOf(),
            byteArrayOf(12),
            byteArrayOf(0, 1, 2, 3),
            byteArrayOf(99, 1, 2, 3),
            byteArrayOf(-1, 1, 2, 3),
            byteArrayOf(12, 1, 2),
        )

        for (record in damaged) {
            envelope.writeBytes(record)

            assertNull(
                "повреждённый конверт (${record.size} байт) дал шифр",
                BiometricUnlock.cipherForUnlocking(context),
            )
        }
    }

    /** Отсутствующий конверт тоже не даёт шифра. */
    @Test
    fun a_missing_envelope_yields_no_cipher() {
        envelope.delete()

        assertNull(
            "отсутствующий конверт дал шифр",
            BiometricUnlock.cipherForUnlocking(context),
        )
    }

    /**
     * Доступность отвечает одним из трёх состояний и не падает.
     *
     * ⚠️ Какое именно — зависит от устройства, и закреплять его здесь
     * бессмысленно: у Robolectric датчика нет. Проверяется, что вызов
     * безопасен на устройстве без биометрии, — то есть что экран
     * настроек откроется и там.
     */
    @Test
    fun availability_is_answered_without_a_sensor() {
        val answer = BiometricUnlock.availability(context)

        assertTrue(
            "неожиданное состояние доступности: $answer",
            answer in BiometricUnlock.Availability.entries,
        )
    }
}
