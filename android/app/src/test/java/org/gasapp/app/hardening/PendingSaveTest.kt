// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import org.gasapp.app.core.PendingSave
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 🔐 Сохранение вложения переживает диалог выбора места.
 *
 * # Что здесь проверяется
 *
 * Сохранение вложения не работало вовсе и не сообщало об этом.
 *
 * Порядок был такой: скачать файл, расшифровать, положить байты
 * в поле экрана, открыть системный выбор места. Выбор места —
 * полноэкранная активность, то есть `ChatActivity.onStop`, а `onStop`
 * это поле обнулял: расшифрованное не должно переживать сворачивание.
 *
 * К возвращению из диалога байтов не было никогда. Обработчик
 * результата видел `null` и выходил молча — ни файла, ни ошибки.
 *
 * Оба решения по отдельности верны: `onStop` правильно стирает
 * расшифрованное, диалог правильно спрашивает место до записи.
 * Не работала связка.
 *
 * # Чего тест не проверяет
 *
 * Что диалог выбора места действительно вызывает `onStop`, —
 * это поведение платформы, а не приложения. Проверяется решение,
 * принятое в ответ: уход экрана в фон сохранение не отменяет.
 */
class PendingSaveTest {

    /**
     * 🔐 Уход экрана в фон не отменяет сохранение.
     *
     * Ровно тот случай, в котором всё и ломалось: диалог выбора
     * места — это и есть ушедший в фон экран.
     */
    @Test
    fun a_pending_save_survives_the_screen_going_away() {
        val save = PendingSave<String>()

        save.begin("договор.pdf")
        save.onScreenStopped()

        assertEquals(
            "сохранение отменилось уходом экрана в фон",
            "договор.pdf",
            save.take(),
        )
    }

    /**
     * 🔐 Забранное не остаётся в памяти.
     *
     * В задаче лежит описание вложения вместе с ключом расшифровки;
     * после того как им воспользовались или отказались, держать
     * его незачем.
     */
    @Test
    fun what_was_taken_is_not_kept() {
        val save = PendingSave<String>()

        save.begin("паспорт.pdf")

        assertEquals("паспорт.pdf", save.take())
        assertNull("описание осталось в памяти после того, как его забрали", save.take())
        assertFalse(save.isPending())
    }

    /** Пока не забрали — задача числится незавершённой. */
    @Test
    fun a_task_is_pending_until_it_is_taken() {
        val save = PendingSave<String>()

        assertFalse("пустой держатель числится занятым", save.isPending())

        save.begin("снимок.jpg")

        assertTrue("поставленная задача не числится", save.isPending())

        save.onScreenStopped()

        assertTrue("уход экрана в фон снял задачу", save.isPending())
    }

    /** У пустого держателя забирать нечего. */
    @Test
    fun taking_from_an_empty_holder_is_harmless() {
        assertNull(PendingSave<String>().take())
    }
}
