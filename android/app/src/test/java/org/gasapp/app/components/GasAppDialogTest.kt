// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.app.Activity
import android.view.View
import android.widget.TextView
import org.gasapp.app.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Диалог дизайн-системы: раскладка UI kit и поведение действий.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class GasAppDialogTest {

    private fun host(): Activity =
        Robolectric.buildActivity(Activity::class.java).setup().get().apply {
            setTheme(R.style.Theme_GasApp)
        }

    private fun GasAppDialog.Shown.view(id: Int): View = requireNotNull(dialog.findViewById(id))

    /** Заголовок, текст и обе кнопки на месте; без текста — поле скрыто. */
    @Test
    fun title_message_and_actions_are_shown() {
        val shown = GasAppDialog(host())
            .title("Удалить у всех?")
            .message("Сообщение удалится со всех устройств.")
            .secondary()
            .primary(R.string.action_delete, GasAppDialog.Tone.Danger)
            .show()

        assertEquals("Удалить у всех?", (shown.view(R.id.dialog_title) as TextView).text.toString())
        assertEquals(View.VISIBLE, shown.view(R.id.dialog_message).visibility)
        assertEquals(View.VISIBLE, shown.view(R.id.dialog_primary).visibility)
        assertEquals(View.VISIBLE, shown.view(R.id.dialog_secondary).visibility)
        assertEquals(View.GONE, shown.view(R.id.dialog_error).visibility)
    }

    /**
     * 🔐 Необратимое действие — красной кнопкой, обычное — акцентной.
     *
     * Красный в GasApp означает только ошибку или необратимое (раздел
     * 20.1): кнопка «Удалить» того же цвета, что «Открыть», учит
     * нажимать не глядя.
     */
    @Test
    fun a_destructive_action_is_the_danger_variant() {
        val danger = GasAppDialog(host()).primary(R.string.action_delete, GasAppDialog.Tone.Danger).show()
        val plain = GasAppDialog(host()).primary(R.string.action_save).show()

        assertEquals(GasAppButton.Variant.Danger, (danger.view(R.id.dialog_primary) as GasAppButton).variant)
        assertEquals(GasAppButton.Variant.Primary, (plain.view(R.id.dialog_primary) as GasAppButton).variant)
    }

    /**
     * 🔐 Диалог и панель отбрасывают касания сквозь чужое наложение.
     *
     * Это отдельные окна, и флаг экрана на них не переходил: чужое
     * наложение могло подвести к нажатию «Стереть и восстановить»,
     * которого человек не видел.
     */
    @Test
    fun dialogs_and_sheets_drop_touches_through_overlays() {
        val activity = host()
        val plain = GasAppDialog(activity).primary(R.string.action_save).show()
        val secure = GasAppDialog(activity).primary(R.string.action_delete).alwaysSecure().show()
        GasAppSheet.on(activity, "Меню").action("Действие") {}.show()
        val sheet = org.robolectric.shadows.ShadowDialog.getLatestDialog()

        assertTrue(plain.dialog.window!!.decorView.filterTouchesWhenObscured)
        assertTrue(secure.dialog.window!!.decorView.filterTouchesWhenObscured)
        assertTrue(sheet.window!!.decorView.filterTouchesWhenObscured)
    }

    /** Основное действие по умолчанию закрывает диалог и выполняется. */
    @Test
    fun the_primary_action_runs_and_closes() {
        var ran = false
        val shown = GasAppDialog(host()).primary(R.string.action_save) { ran = true }.show()

        shown.view(R.id.dialog_primary).performClick()

        assertTrue(ran)
        assertFalse(shown.dialog.isShowing)
    }

    /**
     * С проверкой ввода диалог остаётся открытым и показывает ошибку:
     * набранное не теряется, опечатку можно поправить.
     */
    @Test
    fun a_validating_action_keeps_the_dialog_open_with_an_error() {
        val shown = GasAppDialog(host())
            .primary(R.string.action_save, closeOnClick = false) { it.showError("Неверный ключ") }
            .show()

        shown.view(R.id.dialog_primary).performClick()

        assertTrue(shown.dialog.isShowing)
        assertEquals(View.VISIBLE, shown.view(R.id.dialog_error).visibility)
        assertEquals("Неверный ключ", (shown.view(R.id.dialog_error) as TextView).text.toString())
    }

    /** Занятая кнопка не запускает действие второй раз. */
    @Test
    fun a_busy_primary_action_does_not_run_twice() {
        var runs = 0
        val shown = GasAppDialog(host())
            .primary(R.string.action_save, closeOnClick = false) { dialog ->
                runs++
                dialog.setBusy(true)
            }
            .show()

        shown.view(R.id.dialog_primary).performClick()
        shown.view(R.id.dialog_primary).performClick()

        assertEquals(1, runs)
    }
}
