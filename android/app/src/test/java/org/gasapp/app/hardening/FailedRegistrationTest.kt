// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.hardening

import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.io.File
import org.gasapp.app.OnboardingActivity
import org.gasapp.app.R
import org.gasapp.app.core.Core
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * 🔐 Неудавшаяся регистрация не оставляет базы.
 *
 * # Что здесь проверяется
 *
 * Регистрация открывает базу под ключом из PIN и только потом идёт
 * на сервер. Сбой на сервере (имя занято, сети нет) оставлял базу
 * на месте — открытой и под первым PIN:
 *
 * * повторная попытка с другим PIN получала тот же открытый мессенджер,
 *   и база так и оставалась под первым PIN, который человек считал
 *   сменённым. После блокировки новый PIN её не открывал;
 * * после перезапуска существующий файл выглядел аккаунтом
 *   (`Core.hasAccount`), и вместо регистрации открывался экран входа —
 *   в базу, где аккаунта нет.
 *
 * В тесте регистрация падает сама: нативной библиотеки нет. Этого
 * достаточно — проверяется, что делает экран после сбоя.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FailedRegistrationTest {

    @Test
    fun a_failed_registration_leaves_no_database_behind() {
        val controller = Robolectric.buildActivity(OnboardingActivity::class.java).setup()
        val activity = controller.get()

        // База от прежней попытки: открыта и под другим PIN.
        val database = File(activity.filesDir, "gasapp.db").apply { writeText("прежняя попытка") }
        assertTrue("заготовка теста: базы нет", Core.hasAccount(activity))

        // Шаги как у человека: приветствие → имя → PIN.
        activity.findViewById<Button>(R.id.onboarding_start).performClick()
        activity.findViewById<EditText>(R.id.onboarding_username).setText("alice")
        activity.findViewById<EditText>(R.id.onboarding_email).setText("alice@example.org")
        activity.findViewById<Button>(R.id.onboarding_next).performClick()
        for (key in listOf(R.id.key_4, R.id.key_8, R.id.key_2, R.id.key_9, R.id.key_1, R.id.key_5)) {
            activity.findViewById<View>(key).performClick()
        }
        activity.findViewById<Button>(R.id.onboarding_create).performClick()

        val error = activity.findViewById<TextView>(R.id.onboarding_error)
        val deadline = System.currentTimeMillis() + 10_000L
        while (error.visibility != View.VISIBLE && System.currentTimeMillis() < deadline) {
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(20)
        }

        assertTrue("заготовка теста: регистрация не завершилась сбоем", error.visibility == View.VISIBLE)
        assertFalse("база неудавшейся регистрации осталась", database.exists())
        assertFalse(
            "после сбоя приложение считает, что аккаунт есть, — откроется вход вместо регистрации",
            Core.hasAccount(activity),
        )
    }
}
