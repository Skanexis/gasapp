// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.core

import android.app.LocaleManager
import android.content.Context
import android.os.Build
import android.os.LocaleList
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import java.util.Locale

/**
 * Язык интерфейса.
 *
 * # Почему английский по умолчанию, а не язык системы
 *
 * Интерфейс переведён на английский и русский. Раньше язык шёл за
 * системой, и телефон с русской локалью показывал русский интерфейс
 * без возможности это изменить. Теперь умолчание — английский,
 * а русский выбирается явно в «Внешнем виде».
 *
 * # Где хранится выбор
 *
 * В обычных `SharedPreferences`, а не в зашифрованной базе: язык нужен
 * до ввода PIN — экран блокировки уже должен говорить на выбранном
 * языке. Секрета в выборе языка нет.
 *
 * # Как применяется
 *
 * - API 33+: системный `LocaleManager` — он же источник истины, так что
 *   выбор в системных настройках «Язык приложения» тоже работает.
 * - Ниже: `AppCompatDelegate` — все экраны наследуют
 *   `AppCompatActivity` и подхватывают язык при создании.
 */
object Language {

    const val ENGLISH = "en"

    const val RUSSIAN = "ru"

    /** Поддерживаемые языки в порядке показа. */
    val CHOICES: List<String> = listOf(ENGLISH, RUSSIAN)

    /** Выбранный язык; `en`, если выбора не было. */
    fun current(context: Context): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val system = localeManager(context).applicationLocales

            if (!system.isEmpty) {
                val tag = system[0].language

                if (tag in CHOICES) {
                    return tag
                }
            }
        }

        return prefs(context).getString(KEY, ENGLISH)?.takeIf { it in CHOICES } ?: ENGLISH
    }

    /** Применяет сохранённый выбор. Вызывается из `Application.onCreate`. */
    fun applyStored(context: Context) {
        apply(context, current(context))
    }

    /** Сохраняет и применяет новый язык; открытые экраны пересоздаются. */
    fun set(context: Context, tag: String) {
        require(tag in CHOICES) { "unsupported language: $tag" }

        prefs(context).edit().putString(KEY, tag).apply()
        apply(context, tag)
    }

    /** Название языка на нём самом: так его узнают, не зная текущего. */
    fun displayName(tag: String): String = when (tag) {
        RUSSIAN -> "Русский"
        else -> "English"
    }

    private fun apply(context: Context, tag: String) {
        Locale.setDefault(Locale.forLanguageTag(tag))

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val manager = localeManager(context)
            val wanted = LocaleList.forLanguageTags(tag)

            if (manager.applicationLocales != wanted) {
                manager.applicationLocales = wanted
            }
        } else {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
        }
    }

    // Вызывается только в ветках для Android 13+: ниже этого класса нет.
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun localeManager(context: Context): LocaleManager =
        context.getSystemService(LocaleManager::class.java)

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(STORE, Context.MODE_PRIVATE)

    private const val STORE = "gasapp_ui"

    private const val KEY = "language"
}
