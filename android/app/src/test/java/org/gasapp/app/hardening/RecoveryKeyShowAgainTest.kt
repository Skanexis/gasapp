// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.content.Context
import android.content.Intent
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import org.gasapp.app.R
import org.gasapp.app.RecoveryConfirmActivity
import org.gasapp.app.RecoveryKeyActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 🔐 «Показать ключ ещё раз» показывает тот же ключ.
 *
 * # Что здесь проверяется
 *
 * Прежде кнопка открывала экран ключа без ключа, и он выпускал новый.
 * Человек, переписавший половину групп, дописывал вторую половину
 * от другого ключа — и бумажная копия не восстанавливала ничего.
 * Нашёл аудитор; первая проверка перенесена из его рабочей копии.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecoveryKeyShowAgainTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    /** Подтверждение возвращает к показу именно тот ключ, что переписывается. */
    @Test
    fun show_again_passes_the_same_key_back() {
        val intent = Intent(context, RecoveryConfirmActivity::class.java)
            .putExtra(RecoveryConfirmActivity.EXTRA_KEY, KEY)

        val activity = Robolectric.buildActivity(RecoveryConfirmActivity::class.java, intent).get()

        RecoveryConfirmActivity::class.java.getDeclaredMethod("showAgain")
            .apply { isAccessible = true }
            .invoke(activity)

        val next = shadowOf(activity).nextStartedActivity

        assertEquals(
            "повторный показ открыт без ключа — экран выпустит новый",
            KEY,
            next?.getStringExtra(RecoveryKeyActivity.EXTRA_EXISTING_KEY),
        )
    }

    /** Экран ключа с переданным ключом показывает его, а не выпускает новый. */
    @Test
    fun the_key_screen_shows_the_key_it_was_given() {
        val intent = Intent(context, RecoveryKeyActivity::class.java)
            .putExtra(RecoveryKeyActivity.EXTRA_EXISTING_KEY, KEY)

        val controller = Robolectric.buildActivity(RecoveryKeyActivity::class.java, intent).setup()

        try {
            val shown = controller.get().findViewById<TextView>(R.id.key_value).text.toString()

            assertTrue(
                "показан не тот ключ: «$shown»",
                shown.replace("\n", "-").contains("ABCDE-FGHJK"),
            )
        } finally {
            // AutoLock считает экраны счётчиком на процесс (см. PinLengthTest).
            controller.pause().stop().destroy()
        }
    }

    private companion object {
        const val KEY = "GASAPP-ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567-89ABC-DEFGH-JKLMN-PQRST"
    }
}
