// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 🔐 Safety number на настоящем устройстве набран моноширинным.
 *
 * Модульный тест (MonospaceKeysTest) проверяет разметку в Robolectric;
 * здесь — шрифты и инфлейтер самой системы.
 *
 * Проверка — после того, как главный поток выполнит отложенное: AppCompat
 * догружал Inter из темы асинхронно и перезаписывал поле уже после
 * раздувания. Сразу после inflate поле было моноширинным, на экране — нет.
 */
@RunWith(AndroidJUnit4::class)
class MonospaceOnDeviceTest {

    @Test
    fun the_safety_number_digits_are_monospace() {
        // Экран сверки без открытой базы сразу закрывается, поэтому
        // разметка раздувается инфлейтером живого экрана регистрации —
        // тем же, что у экрана сверки (AppCompat + Material).
        ActivityScenario.launch(OnboardingActivity::class.java).use { scenario ->
            lateinit var digits: TextView

            scenario.onActivity { activity ->
                val root = activity.layoutInflater.inflate(R.layout.activity_safety_number, null)
                digits = root.findViewById(R.id.safety_number_digits)
                // Как на экране: строки по три группы, по центру.
                digits.text = "68085 49475 81425\n70798 15919 17116"
            }

            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            scenario.onActivity {
                val paint = digits.paint

                assertEquals(
                    "safety number на устройстве — пропорциональным шрифтом",
                    paint.measureText("1111"),
                    paint.measureText("WWWW"),
                    0.01f,
                )

                digits.measure(
                    View.MeasureSpec.makeMeasureSpec(WIDTH_PX, View.MeasureSpec.EXACTLY),
                    View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED),
                )
                val layout = digits.layout
                assertEquals(
                    "строки safety number разной ширины",
                    layout.getLineWidth(0),
                    layout.getLineWidth(1),
                    0.5f,
                )
            }
        }
    }

    private companion object {
        const val WIDTH_PX = 1000
    }
}
