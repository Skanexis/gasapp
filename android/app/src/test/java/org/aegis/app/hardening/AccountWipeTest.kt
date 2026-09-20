// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import java.io.File
import org.aegis.app.core.AccountWipe
import org.aegis.app.core.PinAttempts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Удаление аккаунта не оставляет следов на устройстве.
 *
 * MASVS PRIVACY-3.2. До M8 удаления не существовало вовсе: политика
 * приватности прямо писала, что права на удаление у пользователя нет.
 *
 * # Почему проверяется списком файлов, а не «вызвался ли метод»
 *
 * Забытый файл — самая вероятная ошибка в такой задаче, и она
 * невидима: приложение после удаления выглядит чистым, потому что
 * показывать ему нечего. Заметить `aegis.db-wal`, в котором лежат
 * страницы базы, можно только заглянув в каталог.
 *
 * # Чего этот тест не проверяет
 *
 * Удаление ключа из Android Keystore: вне устройства хранилища
 * не существует, и [AccountWipe] честно засчитывает его сбой как
 * «убрано не всё». Поэтому проверяется не возвращённый признак,
 * а само отсутствие файлов — то, что на этой машине проверить можно.
 *
 * Не проверяется и невосстановимость: удаление файла не затирает
 * ячейки флеш-памяти, и обещать иное было бы неправдой. Гарантия
 * здесь другая — содержимое зашифровано, а вторая половина ключа
 * уходит вместе с записью Keystore.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AccountWipeTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Before
    fun createAccountFiles() {
        for (name in ACCOUNT_FILES) {
            File(context.filesDir, name).writeBytes(byteArrayOf(1, 2, 3))
        }
    }

    /** 🔐 Ни одного файла аккаунта не остаётся. */
    @Test
    fun wipe_removes_every_account_file() {
        AccountWipe.wipe(context)

        for (name in ACCOUNT_FILES) {
            assertFalse(
                "после удаления остался $name",
                File(context.filesDir, name).exists(),
            )
        }
    }

    /**
     * 🔐 Журнал опережающей записи уходит вместе с базой.
     *
     * Отдельный тест, потому что это и есть та самая забываемая
     * строка: в `aegis.db-wal` лежат страницы базы, ещё не влитые
     * в основной файл. Удалить `aegis.db`, оставив журнал, значит
     * оставить часть переписки — зашифрованную, но оставить.
     */
    @Test
    fun wipe_removes_the_write_ahead_log() {
        AccountWipe.wipe(context)

        assertFalse(
            "журнал SQLite пережил удаление аккаунта",
            File(context.filesDir, "aegis.db-wal").exists(),
        )
        assertFalse(
            "файл разделяемой памяти SQLite пережил удаление",
            File(context.filesDir, "aegis.db-shm").exists(),
        )
    }

    /**
     * 🔐 Соль и аппаратный секрет уходят тоже.
     *
     * Соль без базы безобидна, но её присутствие — признак того, что
     * аккаунт был. Удаление, оставляющее следы существования аккаунта,
     * удалением не является.
     */
    @Test
    fun wipe_removes_the_salt_and_the_hardware_secret() {
        AccountWipe.wipe(context)

        assertFalse(
            "соль пережила удаление",
            File(context.filesDir, "aegis.salt").exists(),
        )
        assertFalse(
            "зашифрованный аппаратный секрет пережил удаление",
            File(context.filesDir, "aegis.hw").exists(),
        )
    }

    /**
     * 🔐 История неверных попыток PIN забывается.
     *
     * «Последняя попытка входа — вчера в 23:40» говорит о том, что
     * телефоном пользовались и когда. После удаления аккаунта этого
     * следа быть не должно.
     */
    @Test
    fun wipe_forgets_the_pin_attempt_history() {
        PinAttempts.recordFailure(context, now = 1_000L)
        PinAttempts.recordFailure(context, now = 2_000L)

        assertEquals(
            "тест не подготовил историю — проверять будет нечего",
            2,
            PinAttempts.failures(context),
        )

        AccountWipe.wipe(context)

        assertEquals(
            "счётчик неверных попыток пережил удаление аккаунта",
            0,
            PinAttempts.failures(context),
        )
    }

    /**
     * Чужие файлы не трогаются.
     *
     * Удаление аккаунта — не сброс приложения. Кэш изображений,
     * файлы библиотек и всё прочее к аккаунту не относится, и стирать
     * их значило бы делать больше, чем человек просил.
     */
    @Test
    fun wipe_leaves_unrelated_files_alone() {
        val other = File(context.filesDir, "not-ours.bin")
        other.writeBytes(byteArrayOf(9))

        AccountWipe.wipe(context)

        assertTrue("удалён файл, не относящийся к аккаунту", other.exists())
    }

    private companion object {
        val ACCOUNT_FILES = listOf(
            "aegis.db",
            "aegis.db-wal",
            "aegis.db-shm",
            "aegis.salt",
            "aegis.hw",
        )
    }
}
