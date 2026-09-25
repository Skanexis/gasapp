// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import org.aegis.app.R
import org.aegis.app.RecoveryCenterActivity
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisSheet
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog

/**
 * 🔐 Диалоги не снимаются, когда не снимается экран.
 *
 * # Что здесь проверяется
 *
 * Диалог — отдельное окно, и `FLAG_SECURE` экрана на него не переходит.
 * Прежде ни один диалог приложения флага не ставил: снимок экрана
 * и превью в переключателе задач показывали их содержимое — имена
 * файлов хранилища, имена собеседников, поля ввода. Поле ключа
 * восстановления вдобавок учило клавиатуру. Нашёл аудитор; последняя
 * проверка перенесена из его рабочей копии.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DialogScreenshotTest {

    private fun secure(flags: Int): Boolean = flags and WindowManager.LayoutParams.FLAG_SECURE != 0

    private fun hostActivity(secureHost: Boolean): Activity =
        Robolectric.buildActivity(Activity::class.java).setup().get().apply {
            setTheme(R.style.Theme_AEGIS)
            if (secureHost) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }

    /** 🔐 Диалог защищённого экрана не снимается. */
    @Test
    fun a_dialog_of_a_secure_screen_is_secure() {
        val host = hostActivity(secureHost = true)

        val dialog = AegisDialog(host)
            .message("имя файла хранилища")
            .show()
            .dialog

        assertTrue("диалог защищённого экрана снимается", secure(dialog.window!!.attributes.flags))
    }

    /** Экран, где снимки разрешены, не превращает диалоги в запрещённые. */
    @Test
    fun a_dialog_follows_the_screen_when_screenshots_are_allowed() {
        val host = hostActivity(secureHost = false)

        val dialog = AegisDialog(host)
            .message("что угодно")
            .show()
            .dialog

        assertFalse(secure(dialog.window!!.attributes.flags))
    }

    /** 🔐 Панель действий тоже наследует запрет. */
    @Test
    fun the_action_sheet_of_a_secure_screen_is_secure() {
        val host = hostActivity(secureHost = true)

        AegisSheet.on(host, "договор.pdf").action("Удалить") {}.show()

        val dialog = requireNotNull(ShadowDialog.getLatestDialog()) { "панель не показана" }
        assertTrue("панель действий защищённого экрана снимается", secure(dialog.window!!.attributes.flags))
    }

    /**
     * 🔐 Поле ключа восстановления не учит клавиатуру, а окно не снимается —
     * даже если на экране снимки разрешены.
     */
    @Test
    fun the_recovery_key_field_is_never_captured_or_learned() {
        val activity = Robolectric.buildActivity(RecoveryCenterActivity::class.java).get()

        RecoveryCenterActivity::class.java
            .getDeclaredMethod("askForKey", Function1::class.java)
            .apply { isAccessible = true }
            .invoke(activity, { _: String -> })

        val dialog = requireNotNull(ShadowDialog.getLatestDialog()) { "диалог не показан" }
        val field = requireNotNull(findEditText(dialog.window!!.decorView)) { "поля нет" }

        val learns = field.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING == 0
        val capturable = !secure(dialog.window!!.attributes.flags)

        assertTrue(
            "ключ восстановления: клавиатура учится=$learns, окно снимается=$capturable",
            !learns && !capturable,
        )
    }

    /**
     * 🔐 В коде приложения нет системных диалогов в обход [AegisDialog].
     *
     * `AlertDialog` запрет снимков от экрана не наследует: его надо
     * ставить руками при каждом показе, и новый диалог, где об этом
     * забыли, снимался бы на защищённом экране. AegisDialog ставит флаг
     * сам — поэтому все диалоги идут через него.
     */
    @Test
    fun app_code_shows_no_bare_alert_dialogs() {
        val sources = java.io.File("src/main/kotlin")
        assertTrue("исходники не найдены: ${sources.absolutePath}", sources.isDirectory)

        val offenders = sources.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { "AlertDialog.Builder(" in it.readText() }
            .map { it.name }
            .toList()

        assertTrue("системный AlertDialog вместо AegisDialog: $offenders", offenders.isEmpty())
    }

    private fun findEditText(view: View): EditText? {
        if (view is EditText) return view
        if (view is ViewGroup) {
            for (index in 0 until view.childCount) {
                findEditText(view.getChildAt(index))?.let { return it }
            }
        }
        return null
    }
}
