// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.os.Bundle
import android.widget.ImageView
import androidx.appcompat.app.AppCompatActivity
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.SettingsRow

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

        // Строки справочные: значения не меняются, поэтому шеврона
        // у них нет — стрелка обещала бы переход, которого не будет.
        SettingsRow.bind(
            root = findViewById(R.id.appearance_theme),
            label = R.string.appearance_theme,
            value = getString(R.string.appearance_theme_value),
            icon = R.drawable.ic_settings,
        )

        SettingsRow.bind(
            root = findViewById(R.id.appearance_language),
            label = R.string.appearance_language,
            value = getString(R.string.appearance_language_value),
            icon = R.drawable.ic_chat,
        )
    }
}
