// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.hardening

import android.app.Activity
import android.content.res.XmlResourceParser
import android.view.inputmethod.EditorInfo
import org.aegis.app.R
import org.aegis.app.components.AegisTextField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.xmlpull.v1.XmlPullParser

/**
 * 🔐 Ни одно поле ввода не обучает клавиатуру.
 *
 * Раздел 19.2 («`imeOptions="flagNoPersonalizedLearning"` — не обучать
 * клавиатуру на тексте») и MASVS STORAGE-2 («нет данных в кэше
 * клавиатуры»).
 *
 * # Что происходит без флага
 *
 * Клавиатура — Gboard и почти все прочие — добавляет набранные слова
 * в персональный словарь. Словарь живёт вне приложения, переживает его
 * удаление и синхронизируется в облако учётной записи. Имена, адреса
 * и редкие слова из переписки после этого всплывают подсказками
 * в других приложениях и попадают в ту самую резервную копию, которую
 * приложение у себя запретило (`allowBackup="false"`).
 *
 * Отсутствие флага ничем не проявляется: поле работает, ничего не
 * падает. Поэтому проверка, а не пункт в списке ревью.
 *
 * # Почему разметка читается, а не разворачивается
 *
 * Очевидный тест — развернуть разметку и посмотреть на `imeOptions`
 * готового поля. Он не работает: четыре экрана задают `layout_height`
 * через стиль (`@style/AegisPanel` и соседние), а Robolectric не
 * разрешает `layout_*` из стиля в `generateLayoutParams` и падает на
 * «You must supply a layout_height attribute». На устройстве эти экраны
 * разворачиваются нормально — то есть падал бы тест, а не приложение.
 *
 * Чтение скомпилированной разметки той же проблемы не имеет и вдобавок
 * даёт главное: перебор идёт по **всем** полям `R.layout`, а не по
 * списку. Разметка, добавленная завтра, попадает под проверку без правки
 * теста.
 *
 * # Что тест не проверяет
 *
 * Клавиатура вправе флаг проигнорировать — это просьба, а не запрет,
 * и сторонняя клавиатура видит ввод целиком независимо от него
 * (отдельное предупреждение раздела 19.1). Проверяется наша сторона
 * договора.
 */
@RunWith(RobolectricTestRunner::class)
class KeyboardLearningTest {

    /**
     * Каждый плоский `<EditText>` в разметке объявляет флаг.
     *
     * Поля дизайн-системы сюда не попадают: они получают флаг
     * в конструкторе, что закреплено отдельным тестом ниже.
     */
    @Test
    fun every_plain_edit_text_declares_no_personalized_learning() {
        val resources = Robolectric.buildActivity(Activity::class.java).get().resources
        val offenders = mutableListOf<String>()
        var checked = 0

        layoutIds().forEach { (name, id) ->
            resources.getLayout(id).use { parser ->
                forEachTag(parser) { tag ->
                    if (!tag.endsWith("EditText")) return@forEachTag

                    checked++

                    val options = parser.getAttributeIntValue(ANDROID_NS, "imeOptions", 0)

                    if (options and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING == 0) {
                        offenders += "$name:${parser.lineNumber} <$tag>"
                    }
                }
            }
        }

        // Ноль найденных полей означал бы, что тест перестал что-либо
        // проверять — например, после переименования тега. Такой
        // «зелёный» хуже красного.
        assertTrue("плоских EditText в разметке не найдено", checked > 0)

        assertTrue(
            "поля обучают клавиатуру: ${offenders.joinToString()}",
            offenders.isEmpty(),
        )
    }

    /**
     * Поле дизайн-системы выставляет флаг само, без атрибута в разметке.
     *
     * Так закрыт разрыв, который иначе пришлось бы закрывать дисциплиной:
     * разметок с полями девять, и следующая забыла бы атрибут молча.
     */
    @Test
    fun design_system_field_disables_personalized_learning_without_xml() {
        val field = AegisTextField(themedActivity())

        assertTrue(
            "AegisTextField не выставил flagNoPersonalizedLearning",
            field.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0,
        )
    }

    /**
     * Флаг добавляется к значению из разметки, а не вместо него.
     *
     * Отдельный случай: присваивание вместо `or` стёрло бы `actionSearch`
     * у поля поиска, и запустить поиск с клавиатуры стало бы нечем.
     * Ошибка тихая — поле продолжает работать, — поэтому проверяется явно.
     */
    @Test
    fun design_system_field_keeps_ime_action_from_xml() {
        val attrs = Robolectric.buildAttributeSet()
            .addAttribute(android.R.attr.imeOptions, "actionSearch")
            .build()

        val field = AegisTextField(themedActivity(), attrs)

        assertEquals(
            "потеряно действие actionSearch",
            EditorInfo.IME_ACTION_SEARCH,
            field.imeOptions and EditorInfo.IME_MASK_ACTION,
        )
        assertTrue(
            "не выставлен flagNoPersonalizedLearning",
            field.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0,
        )
    }

    private fun themedActivity(): Activity =
        Robolectric.buildActivity(Activity::class.java).get().apply {
            setTheme(R.style.Theme_AEGIS)
        }

    /** Все разметки приложения — по полям сгенерированного `R.layout`. */
    private fun layoutIds(): List<Pair<String, Int>> =
        R.layout::class.java.fields
            .filter { it.type == Int::class.javaPrimitiveType }
            .map { it.name to it.getInt(null) }

    private inline fun forEachTag(parser: XmlResourceParser, body: (String) -> Unit) {
        var event = parser.eventType

        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.START_TAG) {
                body(parser.name)
            }
            event = parser.next()
        }
    }

    private companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    }
}
