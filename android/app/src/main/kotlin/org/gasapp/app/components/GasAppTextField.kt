// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.content.Context
import android.util.AttributeSet
import android.view.inputmethod.EditorInfo
import android.graphics.drawable.Drawable
import androidx.appcompat.widget.AppCompatEditText
import androidx.core.content.ContextCompat
import androidx.core.content.res.use
import androidx.core.graphics.drawable.DrawableCompat
import org.gasapp.app.R

/**
 * Поле ввода дизайн-системы GasApp.
 *
 * Состояния `enabled`, `focused` и `pressed` обрабатывает платформа через
 * селектор `res/drawable/bg_gasapp_text_field.xml`. Прикладное состояние
 * «ошибка» добавляется через [onCreateDrawableState].
 *
 * # Про имя свойства
 *
 * Флаг ошибки называется [hasError], а не `error`: у `EditText` уже есть
 * свойство `error` (текст всплывающей подсказки валидации). Прежняя версия
 * объявляла своё `getError` и получала конфликт с методом супертипа.
 *
 * # 🔐 Почему запрет обучения клавиатуры стоит здесь
 *
 * Раздел 19.2 требует `imeOptions="flagNoPersonalizedLearning"`. Флаг
 * можно было проставить в каждой разметке, но разметок восемь, а полей
 * в них больше, и следующее добавленное поле флага не получило бы —
 * молча, потому что его отсутствие ничем не проявляется.
 *
 * Что происходит без флага: клавиатура (Gboard и подавляющее
 * большинство остальных) добавляет набранные слова в персональный
 * словарь. Словарь живёт вне приложения, переживает его удаление и
 * синхронизируется в облако учётной записи. Имена, адреса и редкие
 * слова из переписки после этого всплывают подсказками в других
 * приложениях — и попадают в резервную копию, которую само приложение
 * у себя запретило (`allowBackup="false"`).
 *
 * Флаг именно добавляется к значению из разметки, а не заменяет его:
 * у поля поиска в разметке стоит `actionSearch`, и присваивание
 * стёрло бы кнопку «Искать» на клавиатуре.
 */
class GasAppTextField @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = androidx.appcompat.R.attr.editTextStyle,
) : AppCompatEditText(context, attrs, defStyleAttr) {

    /** Содержимое поля не прошло валидацию. */
    var hasError: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            refreshDrawableState()
        }

    init {
        // Фон поля kit — если разметка не задала свой. Прежде он ставился
        // всегда и молча затирал заданный: поле сообщения в переписке
        // выходило прямоугольником вместо «таблетки» из kit.
        val ownBackground = attrs?.getAttributeResourceValue(ANDROID_NS, "background", 0) ?: 0
        if (ownBackground == 0) {
            setBackgroundResource(R.drawable.bg_gasapp_text_field)
        }

        // 🔐 Порядок важен: суперконструктор уже разобрал атрибуты
        // разметки, поэтому `imeOptions` здесь содержит заданное в XML
        // значение, и `or` его дополняет.
        imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING

        context.obtainStyledAttributes(attrs, R.styleable.GasAppTextField).use { typed ->
            typed.getDrawable(R.styleable.GasAppTextField_fieldIcon)?.let(::setFieldIcon)
        }
    }

    /**
     * Значок слева в поле: 20dp, приглушённый цвет, отступ 12 до текста
     * (UI kit, Inputs).
     */
    fun setFieldIcon(icon: Drawable) {
        val size = resources.getDimensionPixelSize(R.dimen.icon_s)
        val tinted = DrawableCompat.wrap(icon.mutate()).apply {
            setBounds(0, 0, size, size)
            DrawableCompat.setTint(this, ContextCompat.getColor(context, R.color.text_muted))
        }

        setCompoundDrawablesRelative(tinted, null, null, null)
        compoundDrawablePadding = resources.getDimensionPixelSize(R.dimen.field_icon_gap)
    }

    override fun onCreateDrawableState(extraSpace: Int): IntArray {
        val state = super.onCreateDrawableState(extraSpace + EXTRA_STATES)

        if (hasError) {
            mergeDrawableStates(state, STATE_ERROR)
        }

        return state
    }

    private companion object {
        const val EXTRA_STATES = 1

        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

        val STATE_ERROR = intArrayOf(R.attr.state_error)
    }
}
