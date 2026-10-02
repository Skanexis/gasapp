// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import androidx.core.content.ContextCompat
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin
import org.aegis.app.R

/**
 * Гильоширная розетка — знак AEGIS.
 *
 * Тонкие переплетённые линии, как на защищённой полиграфии паспортов
 * и банкнот: приложение — документ, который человек носит с собой,
 * а не терминал. Розетка стоит на экране входа, приветствии, пустом
 * списке чатов и в Центре безопасности; на прочих экранах её нет.
 *
 * Каждое кольцо — несколько волнистых нитей со сдвигом фазы. Кольца
 * [inked] из [rings] прорисованы «чернилами» акцента, остальные —
 * едва видны: в Центре безопасности кольцо — это проверка, и
 * прорисованное кольцо значит «пройдена».
 *
 * # Производительность
 *
 * Пути считаются один раз при смене размера и хранятся. Поворот —
 * свойство вида (`rotation`): его применяет GPU к готовому списку
 * отрисовки, без перерисовки. Перерисовка нужна только для смены
 * цвета (ошибка PIN, ~0,4 с) и смены числа прорисованных колец.
 *
 * Движение пропускается, когда система отключила анимации
 * («Удалить анимации» в специальных возможностях).
 */
class GuillocheView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    /** Сколько колец в розетке. */
    var rings: Int = DEFAULT_RINGS
        set(value) {
            field = value.coerceIn(1, MAX_RINGS)
            rebuild()
        }

    /** Сколько колец прорисовано «чернилами» (снаружи внутрь). */
    var inked: Int = DEFAULT_RINGS
        set(value) {
            field = value.coerceIn(0, rings)
            invalidate()
        }

    /**
     * Доля радиуса под окно в середине: там стоят точки PIN или итог
     * проверок.
     */
    var window: Float = DEFAULT_WINDOW
        set(value) {
            field = value.coerceIn(0.2f, 0.9f)
            rebuild()
        }

    /** Нитей в кольце: три — розетка знака, одна — счётная печать. */
    var strands: Int = DEFAULT_STRANDS
        set(value) {
            field = value.coerceIn(1, 4)
            rebuild()
        }

    /**
     * Доля полосы кольца под зазор: у счётной печати кольца разделены,
     * чтобы их можно было сосчитать.
     */
    var gap: Float = 0f
        set(value) {
            field = value.coerceIn(0f, 0.7f)
            rebuild()
        }

    private var inkColor = ContextCompat.getColor(context, R.color.accent_base)
    private val faintColor = ContextCompat.getColor(context, R.color.line)
    private val errorColor = ContextCompat.getColor(context, R.color.status_error)

    /** Текущий цвет прорисованных колец — меняется при ошибке. */
    private var currentInk = inkColor

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = STROKE_DP * resources.displayMetrics.density
        strokeCap = Paint.Cap.ROUND
    }

    private var paths: List<Path> = emptyList()
    private var colorAnimator: ValueAnimator? = null

    init {
        // Украшение: читалке экрана здесь нечего сообщить.
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        rebuild()
    }

    private fun rebuild() {
        if (width == 0 || height == 0) return

        val cx = width / 2f
        val cy = height / 2f
        val outer = min(width, height) / 2f - paint.strokeWidth * 2
        val inner = outer * window
        val band = (outer - inner) / rings

        paths = (0 until rings).map { ring ->
            // Снаружи внутрь: кольцо 0 — внешнее.
            val radius = outer - band * (ring + 0.5f)
            val amplitude = band * AMPLITUDE_FRACTION * (1f - gap)
            // Число волн растёт к краю: рисунок «дышит», как настоящая розетка.
            val waves = BASE_WAVES + (rings - ring) * 2

            Path().apply {
                for (strand in 0 until strands) {
                    val phase = (2 * PI * strand / strands).toFloat()
                    for (step in 0..SEGMENTS) {
                        val t = (2 * PI * step / SEGMENTS).toFloat()
                        val r = radius + amplitude * sin(waves * t + phase)
                        val x = cx + r * cos(t)
                        val y = cy + r * sin(t)
                        if (step == 0) moveTo(x, y) else lineTo(x, y)
                    }
                    close()
                }
            }
        }

        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        paths.forEachIndexed { ring, path ->
            val isInked = ring < inked
            paint.color = if (isInked) currentInk else faintColor
            paint.alpha = if (isInked) INK_ALPHA else FAINT_ALPHA
            canvas.drawPath(path, paint)
        }
    }

    /** Цвет прорисованных колец — например, цвет итога проверок. */
    fun setInkColor(color: Int) {
        inkColor = color
        currentInk = color
        invalidate()
    }

    /**
     * Прорисовывает кольца по одному до [target] — «печать» знака.
     *
     * Без анимаций — сразу итог.
     */
    fun inkTo(target: Int) {
        val goal = target.coerceIn(0, rings)
        inkAnimator?.cancel()

        if (!motionAllowed() || goal == 0) {
            inked = goal
            return
        }

        inked = 0
        inkAnimator = ValueAnimator.ofInt(0, goal).apply {
            duration = INK_STEP_MS * goal
            interpolator = DecelerateInterpolator()
            addUpdateListener { inked = it.animatedValue as Int }
            start()
        }
    }

    private var inkAnimator: ValueAnimator? = null

    /** Поворачивает розетку на одну насечку — отклик на цифру PIN. */
    fun turn() {
        if (!motionAllowed()) return

        // withLayer: розетка — тысячи отрезков со сглаживанием; на время
        // движения она живёт текстурой GPU, а не перерисовывается кадр
        // за кадром на слабом телефоне.
        animate()
            .rotationBy(TURN_DEGREES)
            .setDuration(TURN_MS)
            .setInterpolator(OvershootInterpolator(OVERSHOOT))
            .withLayer()
            .start()
    }

    /** Возвращает розетку в исходное положение — PIN стёрт. */
    fun settle() {
        if (!motionAllowed()) {
            rotation = 0f
            return
        }

        animate().rotation(0f).setDuration(SETTLE_MS).setInterpolator(DecelerateInterpolator()).withLayer().start()
    }

    /** Розетка «раскрывается» — PIN верен; [onEnd] — когда раскрылась. */
    fun open(onEnd: () -> Unit) {
        if (!motionAllowed()) {
            onEnd()
            return
        }

        animate()
            .scaleX(OPEN_SCALE)
            .scaleY(OPEN_SCALE)
            .alpha(0f)
            .rotationBy(OPEN_DEGREES)
            .setDuration(OPEN_MS)
            .setInterpolator(DecelerateInterpolator(2f))
            .withLayer()
            .withEndAction(onEnd)
            .start()
    }

    /** Розетка вспыхивает цветом ошибки и возвращается — PIN неверен. */
    fun reject() {
        colorAnimator?.cancel()

        if (!motionAllowed()) {
            settle()
            return
        }

        colorAnimator = ValueAnimator.ofObject(ArgbEvaluator(), inkColor, errorColor, inkColor).apply {
            duration = REJECT_MS
            addUpdateListener {
                currentInk = it.animatedValue as Int
                invalidate()
            }
            addListener(
                object : AnimatorListenerAdapter() {
                    override fun onAnimationEnd(animation: Animator) {
                        currentInk = inkColor
                        invalidate()
                    }
                },
            )
            start()
        }

        // Встряска — «нет», понятное без слов; затем розетка
        // возвращается в исходное положение.
        val shift = SHAKE_DP * resources.displayMetrics.density
        android.animation.ObjectAnimator.ofFloat(
            this,
            TRANSLATION_X,
            0f, -shift, shift, -shift * 0.6f, shift * 0.6f, -shift * 0.3f, shift * 0.3f, 0f,
        ).apply {
            duration = SHAKE_MS
            start()
        }
        settle()
    }

    /** Возвращает вид после [open] — экран переиспользуется. */
    fun reset() {
        animate().cancel()
        rotation = 0f
        scaleX = 1f
        scaleY = 1f
        alpha = 1f
    }

    override fun onDetachedFromWindow() {
        colorAnimator?.cancel()
        inkAnimator?.cancel()
        animate().cancel()
        super.onDetachedFromWindow()
    }

    private fun motionAllowed(): Boolean = ValueAnimator.areAnimatorsEnabled()

    private companion object {
        const val DEFAULT_RINGS = 4
        const val MAX_RINGS = 16
        const val DEFAULT_STRANDS = 3
        const val SEGMENTS = 360
        const val BASE_WAVES = 11
        const val DEFAULT_WINDOW = 0.70f
        const val AMPLITUDE_FRACTION = 0.55f
        const val STROKE_DP = 0.9f
        const val INK_ALPHA = 128
        const val FAINT_ALPHA = 200

        const val TURN_DEGREES = 15f
        const val TURN_MS = 320L
        const val OVERSHOOT = 2.2f
        const val SETTLE_MS = 420L
        const val OPEN_SCALE = 1.7f
        const val OPEN_DEGREES = 60f
        const val OPEN_MS = 380L
        const val REJECT_MS = 520L
        const val INK_STEP_MS = 70L
        const val SHAKE_DP = 8f
        const val SHAKE_MS = 380L
    }
}
