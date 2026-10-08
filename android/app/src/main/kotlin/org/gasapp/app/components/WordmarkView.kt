// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Shader
import android.util.AttributeSet
import android.util.TypedValue
import android.view.View
import androidx.core.content.res.ResourcesCompat
import androidx.core.content.withStyledAttributes
import org.gasapp.app.R
import kotlin.math.ceil

/**
 * Логотип GasApp объёмными буквами: золото с тёмной обводкой и
 * «выдавленной» вниз кромкой — как вывеска (DESIGN.md, «Night Camp»).
 *
 * Рисуется кодом из шрифта заголовков, поэтому остаётся резким на
 * любой плотности и переводится вместе со строкой. Градиент в буквах —
 * часть знака, а не приём для обычного текста: в интерфейсе он стоит
 * только здесь.
 *
 * Для чтения с экрана это обычный заголовок с названием приложения.
 */
class WordmarkView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    /** Надпись. */
    var text: String = context.getString(R.string.app_name)
        set(value) {
            field = value
            contentDescription = value
            requestLayout()
            invalidate()
        }

    private val density = resources.displayMetrics.density

    private val face = ResourcesCompat.getFont(context, R.font.rubik_black)

    private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { typeface = face }

    private val outline = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = face
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        color = OUTLINE
    }

    private val edge = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = face
        style = Paint.Style.FILL_AND_STROKE
        strokeJoin = Paint.Join.ROUND
        color = EDGE
    }

    private val bounds = Rect()

    /** Толщина обводки и глубина кромки — доли кегля. */
    private var stroke = 0f
    private var depth = 0f

    init {
        var size = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, DEFAULT_SIZE_SP, resources.displayMetrics)

        context.withStyledAttributes(attrs, R.styleable.WordmarkView) {
            size = getDimension(R.styleable.WordmarkView_wordmarkSize, size)
            getString(R.styleable.WordmarkView_wordmarkText)?.let { text = it }
        }

        setTextSize(size)
        contentDescription = text
        isFocusable = false
        accessibilityHeading(true)
    }

    private fun accessibilityHeading(heading: Boolean) {
        isAccessibilityHeading = heading
    }

    private fun setTextSize(size: Float) {
        stroke = size * STROKE_RATIO
        depth = size * DEPTH_RATIO

        for (paint in arrayOf(fill, outline, edge)) {
            paint.textSize = size
            // Лёгкая разрядка: обводка съедает просветы между буквами.
            paint.letterSpacing = LETTER_SPACING
        }
        outline.strokeWidth = stroke
        edge.strokeWidth = stroke
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        fill.getTextBounds(text, 0, text.length, bounds)

        val wanted = ceil(fill.measureText(text) + stroke * 2f + paddingLeft + paddingRight).toInt()
        val metrics = fill.fontMetrics
        val tall = ceil(metrics.descent - metrics.ascent + depth + stroke * 2f + paddingTop + paddingBottom).toInt()

        setMeasuredDimension(resolveSize(wanted, widthMeasureSpec), resolveSize(tall, heightMeasureSpec))
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)

        val metrics = fill.fontMetrics
        val top = paddingTop + stroke
        fill.shader = LinearGradient(
            0f, top, 0f, top + (metrics.descent - metrics.ascent),
            intArrayOf(FILL_TOP, FILL_MID, FILL_BOTTOM),
            floatArrayOf(0.15f, 0.55f, 0.9f),
            Shader.TileMode.CLAMP,
        )
    }

    override fun onDraw(canvas: Canvas) {
        val metrics = fill.fontMetrics
        val x = (width - fill.measureText(text)) / 2f
        val baseline = paddingTop + stroke - metrics.ascent

        // Кромка: буквы «выдавлены» вниз на [depth] — несколько слоёв
        // дают сплошную стенку, а не тень со ступеньками.
        val layers = (depth / density).toInt().coerceAtLeast(1)
        for (layer in layers downTo 1) {
            canvas.drawText(text, x, baseline + depth * layer / layers, edge)
        }

        canvas.drawText(text, x, baseline, outline)
        canvas.drawText(text, x, baseline, fill)
    }

    private companion object {
        const val DEFAULT_SIZE_SP = 48f
        const val STROKE_RATIO = 0.13f
        const val DEPTH_RATIO = 0.12f
        const val LETTER_SPACING = 0.02f

        val FILL_TOP = Color.rgb(0xFF, 0xEE, 0x7A)
        val FILL_MID = Color.rgb(0xFF, 0xCB, 0x2E)
        val FILL_BOTTOM = Color.rgb(0xFF, 0x9A, 0x1F)
        val OUTLINE = Color.rgb(0x4A, 0x16, 0x00)
        val EDGE = Color.rgb(0x7A, 0x2E, 0x00)
    }
}
