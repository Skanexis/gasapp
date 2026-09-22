// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import org.aegis.app.R
import org.aegis.app.components.AegisSheet
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog

/**
 * Панель действий открывается.
 *
 * # Что здесь проверяется
 *
 * `AegisSheet.show()` вызывал `requestFeature(FEATURE_NO_TITLE)` после
 * `setContentView`, и платформа отвечала `AndroidRuntimeException`
 * («requestFeature() must be called before adding content»). Каждая
 * панель приложения — меню чата, вложения, действия над сообщением,
 * реакции, таймер исчезновения, выбор автоблокировки, «открыть/удалить»
 * в хранилище — роняла приложение при открытии. Ни один тест панель
 * не показывал; падение воспроизведено на эмуляторе (меню чата,
 * `AegisSheet.kt:112`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ActionSheetOpensTest {

    @Test
    fun an_action_sheet_opens_and_shows_its_actions() {
        val host = Robolectric.buildActivity(Activity::class.java).setup().get().apply {
            setTheme(R.style.Theme_AEGIS)
        }

        AegisSheet.on(host, "Меню чата").action("Удалить переписку") {}.show()

        val dialog = requireNotNull(ShadowDialog.getLatestDialog()) { "панель не показана" }

        assertTrue("панель не показана", dialog.isShowing)
        assertTrue(
            "в панели нет её действия",
            texts(dialog.window!!.decorView).contains("Удалить переписку"),
        )
    }

    private fun texts(view: View): List<String> = when (view) {
        is TextView -> listOf(view.text.toString())
        is ViewGroup -> (0 until view.childCount).flatMap { texts(view.getChildAt(it)) }
        else -> emptyList()
    }
}
