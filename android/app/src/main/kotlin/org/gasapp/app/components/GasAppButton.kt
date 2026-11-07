// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.content.Context
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.util.AttributeSet
import android.view.Gravity
import androidx.appcompat.widget.AppCompatButton
import androidx.core.content.res.use
import com.google.android.material.progressindicator.CircularProgressIndicatorSpec
import com.google.android.material.progressindicator.IndeterminateDrawable
import org.gasapp.app.R

/**
 * Кнопка дизайн-системы GasApp с семью состояниями (раздел 20.4 плана).
 *
 * Состояния делятся на две группы:
 *
 * * **системные** — `enabled`, `pressed`, `focused`, `hovered`: ими управляет
 *   сама платформа, и перехватывать их сеттерами не нужно. Реакция задаётся
 *   селектором в `res/drawable/bg_gasapp_button.xml`;
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
class GasAppButton @JvmOverloads constructor(
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
                showSpinner()
            } else {
                text = textBeforeLoading
                hideSpinner()
            }

            // Во время загрузки нажатие не проходит повторно (см.
            // [performClick]), но кнопка не гаснет: в UI kit идущее
            // действие — та же кнопка со спиннером, а не недоступная.
            isClickable = !value
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

    /**
     * Размер кнопки из UI kit: 40, 48 или 56dp.
     *
     * Задаётся атрибутом `gasappButtonSize` в разметке или из кода (кнопки
     * диалога — [Size.Small]).
     */
    var size: Size = Size.Medium
        set(value) {
            field = value
            applySize()
        }

    init {
        var variantAttr = Variant.Primary
        var sizeAttr = Size.Medium

        context.theme.obtainStyledAttributes(attrs, R.styleable.GasAppButton, defStyleAttr, 0)
            .use { typed ->
                variantAttr = Variant.entries.getOrElse(
                    typed.getInt(R.styleable.GasAppButton_buttonVariant, 0),
                ) { Variant.Primary }

                sizeAttr = Size.entries.getOrElse(
                    typed.getInt(R.styleable.GasAppButton_gasappButtonSize, 0),
                ) { Size.Medium }
            }

        // Метрики из UI kit (.btn), общие для всех вариантов и размеров.
        // Заданы здесь, а не только в стиле: кнопка, поставленная
        // в раскладку без стиля, всё равно обязана выглядеть кнопкой
        // GasApp, а не системной.
        //
        // ⚠️ Порядок важен: сначала общее, потом вариант и размер.
        // Прежде общие метрики ставились последними и затирали
        // выбранное — `gasappButtonSize="small"` и жирный шрифт опасной
        // кнопки не действовали нигде.
        minWidth = 0
        minimumWidth = 0

        isAllCaps = false
        letterSpacing = 0f
        // Значок из разметки уже стоит: тогда группа центрируется в onDraw.
        gravity = if (compoundDrawablesRelative[0] != null) {
            Gravity.START or Gravity.CENTER_VERTICAL
        } else {
            Gravity.CENTER
        }
        stateListAnimator = null

        isFocusable = true
        isClickable = true

        variant = variantAttr
        applyVariant()

        size = sizeAttr
    }

    private var spinner: IndeterminateDrawable<CircularProgressIndicatorSpec>? = null

    /**
     * Спиннер загрузки перед подписью (UI kit, .spin: 18dp, цвет подписи).
     *
     * Одна подпись «Загрузка…» не отличает идущую операцию от зависшей
     * кнопки; вращение отличает.
     */
    private fun showSpinner() {
        val size = resources.getDimensionPixelSize(R.dimen.button_spinner)
        val spec = CircularProgressIndicatorSpec(context, null).apply {
            indicatorSize = size
            trackThickness = resources.getDimensionPixelSize(R.dimen.button_spinner_stroke)
            indicatorInset = 0
            indicatorColors = intArrayOf(currentTextColor)
        }

        spinner = IndeterminateDrawable.createCircularDrawable(context, spec).apply {
            setBounds(0, 0, size, size)
        }

        setCompoundDrawablesRelative(spinner, null, null, null)
        compoundDrawablePadding = resources.getDimensionPixelSize(R.dimen.space_s)
        spinner?.setVisible(true, true)
    }

    private fun hideSpinner() {
        spinner?.setVisible(false, false)
        spinner = null
        setCompoundDrawablesRelative(null, null, null, null)
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
        //
        // Подписи кнопок — шрифтом вывески (DESIGN.md, «Night Camp»):
        // плотный Rubik держит вес рядом с объёмной гранью.
        typeface = androidx.core.content.res.ResourcesCompat.getFont(context, R.font.rubik_bold)

        // Грань основной кнопки короче самой кнопки на кромку.
        applySize()
    }

    /** Применяет размер: высоту, боковые отступы и кегль. */
    private fun applySize() {
        val (heightRes, paddingRes, textSp) = when (size) {
            Size.Large -> Triple(R.dimen.button_large, R.dimen.space_xl, 16f)
            Size.Small -> Triple(R.dimen.button_small, R.dimen.space_m, 14f)
            Size.Medium -> Triple(R.dimen.button_medium, R.dimen.space_l, 15f)
        }

        minHeight = resources.getDimensionPixelSize(heightRes)
        minimumHeight = minHeight

        val padding = resources.getDimensionPixelSize(paddingRes)
        // У основной кнопки снизу кромка: подпись центрируется по грани,
        // а не по всей высоте.
        val edge = if (variant == Variant.Primary) resources.getDimensionPixelSize(R.dimen.button_edge) else 0
        setPaddingRelative(padding, 0, padding, edge)

        textSize = textSp
    }

    /** Размеры кнопки; порядок совпадает с enum `gasappButtonSize` в attrs.xml. */
    enum class Size { Medium, Large, Small }

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

    /** Во время загрузки нажатие — и касанием, и из TalkBack — не проходит. */
    override fun performClick(): Boolean = if (isLoading) false else super.performClick()

    /**
     * Значок и подпись — одной группой по центру.
     *
     * Штатно TextView прижимает значок к краю, а подпись центрирует
     * в оставшемся месте: на широкой кнопке значок («Сканировать
     * QR-код», спиннер загрузки) оказывался у самого края, далеко
     * от своей подписи. Здесь при значке содержимое прижимается
     * к началу и сдвигается на половину свободного места.
     */
    override fun onDraw(canvas: Canvas) {
        val icon = compoundDrawablesRelative[0]
        if (icon == null) {
            super.onDraw(canvas)
            return
        }

        val label = layout?.let { layout ->
            (0 until layout.lineCount).maxOfOrNull { layout.getLineWidth(it) } ?: 0f
        } ?: 0f
        val content = icon.bounds.width() + compoundDrawablePadding + label
        val free = (width - paddingLeft - paddingRight - content).coerceAtLeast(0f)
        val shift = free / 2 * if (layoutDirection == LAYOUT_DIRECTION_RTL) -1 else 1

        canvas.save()
        canvas.translate(shift, 0f)
        super.onDraw(canvas)
        canvas.restore()
    }

    override fun setCompoundDrawablesRelative(start: Drawable?, top: Drawable?, end: Drawable?, bottom: Drawable?) {
        super.setCompoundDrawablesRelative(start, top, end, bottom)
        // С значком — от начала (сдвиг в onDraw), без — по центру.
        gravity = if (start != null) Gravity.START or Gravity.CENTER_VERTICAL else Gravity.CENTER
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
