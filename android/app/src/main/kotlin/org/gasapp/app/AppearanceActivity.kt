// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.os.Bundle
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import org.gasapp.app.components.GasAppSheet
import org.gasapp.app.core.Language
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.ui.SettingsRow

/**
 * Внешний вид.
 *
 * # Почему выбора темы нет
 *
 * Приложение нарисовано под тёмный фон. Светлая тема означала бы
 * вторую палитру, вторую проверку контраста и вторую возможность
 * ошибиться в том, каким цветом показано состояние безопасности:
 * зелёный «проверено человеком» и красный «сменился ключ» должны
 * читаться одинаково надёжно, а на светлом фоне те же цвета ведут
 * себя иначе.
 *
 * Пункт при этом показан и объяснён, а не убран: отсутствие настройки
 * без объяснения читается как недоделка, и пользователь ищет её снова
 * и снова.
 */
class AppearanceActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SecureWindow.apply(this)

        setContentView(R.layout.activity_appearance)

        findViewById<ImageView>(R.id.appearance_back).setOnClickListener { finish() }

        // Тема справочная: значение не меняется, поэтому шеврона у неё
        // нет — стрелка обещала бы переход, которого не будет.
        SettingsRow.bind(
            root = findViewById(R.id.appearance_theme),
            label = R.string.appearance_theme,
            value = getString(R.string.appearance_theme_value),
            icon = R.drawable.ic_moon,
        )

        SettingsRow.bind(
            root = findViewById(R.id.appearance_language),
            label = R.string.appearance_language,
            value = Language.displayName(Language.current(this)),
            icon = R.drawable.ic_globe,
            onClick = ::chooseLanguage,
        )
    }

    private fun chooseLanguage() {
        val sheet = GasAppSheet.on(this, R.string.appearance_language)

        // Выбранный язык отмечен галочкой: иначе по панели не понять,
        // какой сейчас стоит.
        val current = Language.current(this)

        for (tag in Language.CHOICES) {
            sheet.action(Language.displayName(tag), icon = if (tag == current) R.drawable.ic_check else null) {
                if (tag != Language.current(this)) {
                    Language.set(this, tag)
                }
            }
        }

        sheet.show()
    }
}
