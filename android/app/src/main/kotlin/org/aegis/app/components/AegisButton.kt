// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import androidx.appcompat.widget.AppCompatButton
import androidx.core.content.res.use
import org.aegis.app.R

/**
 * Кнопка дизайн-системы AEGIS с семью состояниями (раздел 20.4 плана).
 *
 * Состояния делятся на две группы:
 *
 * * **системные** — `enabled`, `pressed`, `focused`, `hovered`: ими управляет
 *   сама платформа, и перехватывать их сеттерами не нужно. Реакция задаётся
 *   селектором в `res/drawable/bg_aegis_button.xml`;
 * * **прикладные** — `loading` и `error`: платформа о них не знает, поэтому
 *   они хранятся здесь и подмешиваются в состояние через
 *   [onCreateDrawableState].
 *
 * # Почему не сеттеры
 *
 * Прежняя версия пыталась переопределить `setFocused` (такого метода в
 * `View` нет — фокус меняется через `requestFocus`/`clearFocus`) и читала
 * несуществующее свойство `isNotEnabled`. Из-за этого модуль не
 * компилировался. Здесь вместо перехвата состояний используется штатный
 * механизм Android — расширение набора состояний drawable.
 */
class AegisButton @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = android.R.attr.buttonStyle,
) : AppCompatButton(context, attrs, defStyleAttr) {

    /** Идёт длительная операция: кнопка недоступна и показывает подпись загрузки. */
    var isLoading: Boolean = false
        set(value) {
            if (field == value) return
            field = value

            if (value) {
                textBeforeLoading = text
                setText(R.string.button_loading)
            } else {
                text = textBeforeLoading
            }

            // Во время загрузки нажатие не должно проходить повторно.
            isEnabled = !value
            refreshDrawableState()
        }

    /** Последняя операция завершилась ошибкой. */
    var isError: Boolean = false
        set(value) {
            if (field == value) return
            field = value
            refreshDrawableState()
        }

    private var textBeforeLoading: CharSequence = ""

    /**
     * Вариант кнопки из UI kit.
     *
     * Задаёт фон и цвет подписи. Размер и шрифт приходят из стиля,
     * потому что они одинаковы у всех вариантов: меняется вес
     * действия, а не его типографика.
     */
    var variant: Variant = Variant.Primary
        set(value) {
            if (field == value) return
            field = value
            applyVariant()
        }

    init {
        context.theme.obtainStyledAttributes(attrs, R.styleable.AegisButton, defStyleAttr, 0)
            .use { typed ->
                variant = Variant.entries.getOrElse(
                    typed.getInt(R.styleable.AegisButton_buttonVariant, 0),
                ) { Variant.Primary }

                applySize(typed.getInt(R.styleable.AegisButton_buttonSize, 0))
            }

        applyVariant()

        // Метрики из UI kit (.btn): 48dp, отступы 24, шрифт 600/15.
        // Заданы здесь, а не только в стиле: кнопка, поставленная
        // в раскладку без стиля, всё равно обязана выглядеть кнопкой
        // AEGIS, а не системной.
        val padding = resources.getDimensionPixelSize(R.dimen.space_l)
        setPaddingRelative(padding, 0, padding, 0)

        minHeight = resources.getDimensionPixelSize(R.dimen.button_medium)
        minimumHeight = minHeight
        minWidth = 0
        minimumWidth = 0

        isAllCaps = false
        gravity = android.view.Gravity.CENTER
        stateListAnimator = null

        typeface = androidx.core.content.res.ResourcesCompat.getFont(
            context,
            R.font.inter_semibold,
        )
        setTextSize(
            android.util.TypedValue.COMPLEX_UNIT_PX,
            resources.getDimension(R.dimen.text_button),
        )

        isFocusable = true
        isClickable = true
    }

    /** Применяет фон и цвет подписи выбранного варианта. */
    private fun applyVariant() {
        setBackgroundResource(
            when (variant) {
                Variant.Primary -> R.drawable.bg_btn_primary
                Variant.Secondary -> R.drawable.bg_btn_secondary
                Variant.Outline -> R.drawable.bg_btn_outline
                Variant.Ghost -> R.drawable.bg_btn_ghost
                Variant.Danger -> R.drawable.bg_btn_danger
                Variant.Ok -> R.drawable.bg_btn_ok
            },
        )

        setTextColor(
            androidx.core.content.ContextCompat.getColorStateList(
                context,
                when (variant) {
                    Variant.Primary -> R.color.button_text_on_accent
                    Variant.Secondary, Variant.Outline -> R.color.button_text_default
                    Variant.Ghost -> R.color.button_text_accent
                    Variant.Danger -> R.color.button_text_on_danger
                    Variant.Ok -> R.color.button_text_on_ok
                },
            ),
        )

        // Опасное и подтверждающее действия набраны жирнее: на шаг,
        // который нельзя отменить, смотрят дольше.
        if (variant == Variant.Danger || variant == Variant.Ok) {
            typeface = androidx.core.content.res.ResourcesCompat.getFont(
                context,
                R.font.inter_bold,
            )
        }
    }

    /** Применяет размер: medium по умолчанию, large и small — из макета. */
    private fun applySize(size: Int) {
        val (heightRes, paddingRes, textSp) = when (size) {
            1 -> Triple(R.dimen.button_large, R.dimen.space_xl, 16f)
            2 -> Triple(R.dimen.button_small, R.dimen.space_m, 14f)
            else -> Triple(R.dimen.button_medium, R.dimen.space_l, 15f)
        }

        minHeight = resources.getDimensionPixelSize(heightRes)
        minimumHeight = minHeight

        val padding = resources.getDimensionPixelSize(paddingRes)
        setPaddingRelative(padding, 0, padding, 0)

        textSize = textSp
    }

    /** Варианты кнопки из UI kit. */
    enum class Variant {
        /** Основное действие экрана. */
        Primary,

        /** Второстепенное действие рядом с основным. */
        Secondary,

        /** Действие, равное по весу отказу. */
        Outline,

        /** Действие в ряду других. */
        Ghost,

        /** 🔐 Необратимое действие: удалить, сбросить, отозвать. */
        Danger,

        /** 🔐 Подтверждение проверки: сверка прошла. */
        Ok,
    }

    override fun onCreateDrawableState(extraSpace: Int): IntArray {
        val state = super.onCreateDrawableState(extraSpace + EXTRA_STATES)

        if (isLoading) {
            mergeDrawableStates(state, STATE_LOADING)
        }
        if (isError) {
            mergeDrawableStates(state, STATE_ERROR)
        }

        return state
    }

    private companion object {
        /** Сколько дополнительных состояний может добавить эта вью. */
        const val EXTRA_STATES = 2

        val STATE_LOADING = intArrayOf(R.attr.state_loading)
        val STATE_ERROR = intArrayOf(R.attr.state_error)
    }
}
