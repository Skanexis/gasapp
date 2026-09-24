// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.app.Activity
import android.app.AlertDialog
import org.aegis.app.core.SecureWindow
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * 🔐 Экраны скрыты от служб специальных возможностей, не являющихся
 * инструментами доступности (Android 14+).
 *
 * Банковские трояны читают чужие экраны через такие службы: дерево
 * элементов, а не пиксели, так что `FLAG_SECURE` от них не спасает.
 * Пометка `accessibilityDataSensitive` оставляет содержимое только
 * инструментам доступности вроде TalkBack.
 *
 * Здесь — механизм; на настоящем окне каждого экрана пометку
 * проверяет `EveryScreenSecureOnDeviceTest`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AccessibilitySpyingTest {

    /** Экран с общей настройкой снимков — пометка ставится независимо от неё. */
    @Test
    fun screens_are_hidden_from_non_tool_services() {
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()

        SecureWindow.apply(activity)

        assertTrue(
            "окно экрана открыто службам, не являющимся инструментами доступности",
            activity.window.decorView.isAccessibilityDataSensitive,
        )
    }

    @Test
    fun key_and_file_screens_are_hidden_too() {
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()

        SecureWindow.applyAlways(activity)

        assertTrue(activity.window.decorView.isAccessibilityDataSensitive)
    }

    /** Диалог — отдельное окно, и пометку экрана он не наследует сам. */
    @Test
    fun dialogs_are_hidden_too() {
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()
        val dialog = AlertDialog.Builder(activity).setMessage("x").create()

        SecureWindow.inherit(dialog, activity)

        assertTrue(
            "окно диалога открыто службам, не являющимся инструментами доступности",
            dialog.window!!.decorView.isAccessibilityDataSensitive,
        )
    }

    /** На Android 13 пометки нет — и вызов не должен падать. */
    @Test
    @Config(sdk = [33])
    fun older_android_is_left_alone() {
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()

        SecureWindow.applyAlways(activity)
    }
}
