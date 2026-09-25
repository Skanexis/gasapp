// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.content.Context
import android.os.Looper
import android.view.View
import android.widget.FrameLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.GraphicsMode

/**
 * 🔐 Ключи, safety number и ключ восстановления набраны моноширинным.
 *
 * # Что здесь проверяется
 *
 * Моноширинный шрифт здесь — не оформление (раздел 20.1 плана):
 * сверяя два отпечатка, человек сравнивает символы по позициям,
 * а пропорциональный шрифт сдвигает колонки и сливает похожие знаки.
 *
 * Разметка просила `android:fontFamily="monospace"`, но тема задаёт
 * атрибут AppCompat `fontFamily` = Inter, и AppCompatTextView брал
 * его первым: все эти поля на устройстве были набраны Inter. Заметно
 * это было только на снимке экрана — строки safety number разной
 * длины.
 *
 * Проверка по ширине, а не по имени шрифта: у моноширинного «1111»
 * и «WWWW» одной ширины, у пропорционального — нет. Нужна настоящая
 * отрисовка текста, отсюда нативная графика Robolectric.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34, 36])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class MonospaceKeysTest {

    /**
     * Раздувает как экран приложения — инфлейтером AppCompat.
     *
     * Именно он подменяет TextView на AppCompatTextView, который и брал
     * Inter из темы. Платформенный инфлейтер эту ошибку не показывает:
     * первая версия теста на нём проходила там, где телефон ошибался.
     */
    private val activity: AppCompatActivity =
        Robolectric.buildActivity(AppCompatActivity::class.java)
            .also { it.get().setTheme(R.style.Theme_AEGIS) }
            .setup()
            .get()

    private val context: Context get() = activity

    private fun field(layout: Int, id: Int): TextView {
        val root: View = activity.layoutInflater.inflate(layout, FrameLayout(activity), false)
        val view: TextView = requireNotNull(root.findViewById(id)) { "поля нет в разметке" }

        // Шрифт темы AppCompat догружал отложенно и перезаписывал поле
        // уже после раздувания: сразу после inflate поле было
        // моноширинным, через кадр — нет. Поэтому проверка — после
        // того, как главный поток выполнит всё отложенное.
        view.text = "68085 49475 81425"
        shadowOf(Looper.getMainLooper()).idle()

        return view
    }

    private fun isMonospace(view: TextView): Boolean =
        view.paint.measureText("1111") == view.paint.measureText("WWWW")

    /** Контроль: обычный текст приложения — пропорциональный. */
    @Test
    fun the_body_text_is_proportional_so_the_check_can_tell() {
        val body = field(R.layout.activity_contact_profile, R.id.contact_profile_hint)

        assertNotEquals(
            "проверка не различает шрифты — остальные тесты ничего не доказывают",
            body.paint.measureText("1111"),
            body.paint.measureText("WWWW"),
        )
    }

    @Test
    fun the_safety_number_is_monospace() {
        assertMonospace(field(R.layout.activity_safety_number, R.id.safety_number_digits))
    }

    @Test
    fun the_contact_key_is_monospace() {
        assertMonospace(field(R.layout.activity_contact_profile, R.id.contact_profile_key))
    }

    @Test
    fun the_recovery_key_is_monospace() {
        assertMonospace(field(R.layout.activity_recovery_key, R.id.key_value))
    }

    @Test
    fun the_recovery_key_inputs_are_monospace() {
        assertMonospace(field(R.layout.activity_restore, R.id.restore_key))
        assertMonospace(field(R.layout.activity_recovery_confirm, R.id.confirm_input_first))
    }

    private fun assertMonospace(view: TextView) {
        assertEquals(
            "${context.resources.getResourceEntryName(view.id)} набран пропорциональным шрифтом",
            true,
            isMonospace(view),
        )
    }
}
