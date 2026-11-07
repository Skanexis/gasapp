// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.components

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.Shader
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import androidx.core.content.withStyledAttributes
import org.gasapp.app.R
import kotlin.math.PI
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin

/**
 * Ночная поляна GasApp: звёздное небо, луна и ельник — сцена, в которой
 * живёт приложение (DESIGN.md, «Night Camp»).
 *
 * # Почему кодом, а не картинкой
 *
 * Сцена тянется на любую ширину и высоту без потери резкости, весит
 * ноль байт в APK и перекрашивается из палитры. Растровая иллюстрация
 * владельца (персонаж, фон) кладётся **поверх** — см. `design/art/`.
 *
 * # Где стоит
 *
 * На приветствии, экране блокировки и пустых списках — и нигде больше:
 * переписка и настройки остаются спокойными. Сцена — декорация:
 * от чтения с экрана она скрыта, и ничего, кроме настроения, не несёт.
 *
 * # Производительность
 *
 * Геометрия считается один раз на размер; кадр — это заливка, полсотни
 * кружков и три готовых контура. Мерцают только несколько звёзд, и
 * перерисовка идёт не чаще [TWINKLE_FPS] раз в секунду. Без анимаций
 * в системе сцена неподвижна.
 */
class NightSceneView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    /** Рисовать ли луну. */
    var showMoon: Boolean = true
        set(value) {
            field = value
            invalidate()
        }

    /** Рисовать ли ельник и поляну; без них — только небо. */
    var showForest: Boolean = true
        set(value) {
            field = value
            invalidate()
        }

    /**
     * Растворять ли низ сцены в фоне экрана: так шапка-сцена переходит
     * в содержимое без шва.
     */
    var fadeToGround: Boolean = true
        set(value) {
            field = value
            rebuild(width, height)
            invalidate()
        }

    private val density = resources.displayMetrics.density

    private val skyPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val starPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = STAR }
    private val moonPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val craterPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = MOON_CRATER }
    private val farPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = FOREST_FAR }
    private val nearPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = FOREST_NEAR }
    private val groundPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val fadePaint = Paint(Paint.ANTI_ALIAS_FLAG)

    private val farForest = Path()
    private val nearForest = Path()
    private val ground = Path()

    /** Звёзды: x, y, радиус, фаза мерцания (отрицательная — не мерцает). */
    private var stars = FloatArray(0)

    private var moonX = 0f
    private var moonY = 0f
    private var moonRadius = 0f

    /** Ход мерцания, 0..1 по кругу. */
    private var twinkle = 0f
    private var lastFrame = 0L

    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = TWINKLE_PERIOD_MS
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener {
            twinkle = it.animatedValue as Float

            // Мерцанию хватает редких кадров: сцена не должна тратить
            // батарею на то, чего человек не различает.
            val now = System.nanoTime()
            if (now - lastFrame >= FRAME_NANOS) {
                lastFrame = now
                invalidate()
            }
        }
    }

    init {
        // Декорация: ни фокуса, ни озвучивания.
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO

        context.withStyledAttributes(attrs, R.styleable.NightSceneView) {
            showMoon = getBoolean(R.styleable.NightSceneView_sceneMoon, true)
            showForest = getBoolean(R.styleable.NightSceneView_sceneForest, true)
            fadeToGround = getBoolean(R.styleable.NightSceneView_sceneFade, true)

            // Сцена-карточка: скругление обрезает и небо, и ельник.
            val radius = getDimension(R.styleable.NightSceneView_sceneRadius, 0f)
            if (radius > 0f) {
                outlineProvider = object : android.view.ViewOutlineProvider() {
                    override fun getOutline(view: View, outline: android.graphics.Outline) {
                        outline.setRoundRect(0, 0, view.width, view.height, radius)
                    }
                }
                clipToOutline = true
            }
        }
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        rebuild(w, h)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (ValueAnimator.areAnimatorsEnabled()) animator.start()
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        super.onDetachedFromWindow()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)

        // Невидимая сцена не анимируется.
        if (isShown && isAttachedToWindow && ValueAnimator.areAnimatorsEnabled()) {
            if (!animator.isStarted) animator.start()
        } else {
            animator.cancel()
        }
    }

    private fun rebuild(w: Int, h: Int) {
        if (w <= 0 || h <= 0) return

        val width = w.toFloat()
        val height = h.toFloat()

        val base = ContextCompat.getColor(context, R.color.bg_base)

        skyPaint.shader = if (showForest) {
            LinearGradient(
                0f, 0f, 0f, height,
                intArrayOf(SKY_TOP, SKY_MID, SKY_HORIZON),
                floatArrayOf(0f, 0.55f, 1f),
                Shader.TileMode.CLAMP,
            )
        } else {
            // Только небо: без светлого горизонта — ночь уходит прямо в фон
            // экрана, и то, что стоит поверх (PIN), не теряет контраста.
            LinearGradient(
                0f, 0f, 0f, height,
                intArrayOf(SKY_TOP, SKY_DEEP, base),
                floatArrayOf(0f, 0.45f, 1f),
                Shader.TileMode.CLAMP,
            )
        }

        placeStars(width, height)
        placeMoon(width, height)
        growForest(width, height)

        fadePaint.shader = if (fadeToGround && showForest) {
            LinearGradient(
                0f, height * FADE_START, 0f, height,
                Color.argb(0, Color.red(base), Color.green(base), Color.blue(base)),
                base,
                Shader.TileMode.CLAMP,
            )
        } else {
            null
        }
    }

    /**
     * Расставляет звёзды. Генератор детерминированный: небо одно и то
     * же при каждом открытии экрана, а не случайное.
     */
    private fun placeStars(width: Float, height: Float) {
        val count = ((width * height) / (density * density) / STAR_AREA_DP).toInt().coerceIn(18, 90)
        val random = Lcg(STAR_SEED)
        val sky = if (showForest) height * 0.72f else height

        stars = FloatArray(count * STAR_FIELDS)
        for (index in 0 until count) {
            val offset = index * STAR_FIELDS
            stars[offset] = random.next() * width
            // К горизонту звёзд меньше: квадрат сдвигает их вверх.
            stars[offset + 1] = random.next().let { it * it } * sky
            stars[offset + 2] = (0.6f + random.next() * 1.3f) * density
            // Каждая шестая мерцает.
            stars[offset + 3] = if (index % TWINKLE_EVERY == 0) random.next() else NO_TWINKLE
        }
    }

    private fun placeMoon(width: Float, height: Float) {
        moonRadius = min(width, height) * 0.11f
        moonX = width * 0.82f
        moonY = max(moonRadius * 1.9f, height * 0.24f)

        moonPaint.shader = RadialGradient(
            moonX - moonRadius * 0.35f, moonY - moonRadius * 0.35f, moonRadius * 1.6f,
            MOON_LIGHT, MOON_SHADE, Shader.TileMode.CLAMP,
        )
        glowPaint.shader = RadialGradient(
            moonX, moonY, moonRadius * 3.2f,
            intArrayOf(MOON_GLOW, Color.TRANSPARENT),
            null,
            Shader.TileMode.CLAMP,
        )
    }

    private fun growForest(width: Float, height: Float) {
        val random = Lcg(FOREST_SEED)
        val horizon = height * 0.78f

        farForest.rewind()
        var x = -width * 0.04f
        while (x < width * 1.04f) {
            val treeHeight = height * (0.20f + random.next() * 0.12f)
            val treeWidth = treeHeight * 0.52f
            addPine(farForest, x, horizon + height * 0.03f, treeWidth, treeHeight)
            x += treeWidth * (0.55f + random.next() * 0.35f)
        }

        nearForest.rewind()
        // Ближний ряд — по краям: середина остаётся поляной.
        for (side in intArrayOf(-1, 1)) {
            var offset = 0f
            var size = 0.46f
            repeat(NEAR_TREES_PER_SIDE) {
                val treeHeight = height * size
                val treeWidth = treeHeight * 0.5f
                val centre = if (side < 0) offset else width - offset
                addPine(nearForest, centre - treeWidth / 2f, height * 0.93f, treeWidth, treeHeight)
                offset += treeWidth * 0.62f
                size *= 0.74f
            }
        }

        ground.rewind()
        ground.moveTo(0f, height)
        ground.lineTo(0f, horizon + height * 0.06f)
        ground.quadTo(width * 0.5f, horizon - height * 0.04f, width, horizon + height * 0.06f)
        ground.lineTo(width, height)
        ground.close()

        groundPaint.shader = LinearGradient(
            0f, horizon, 0f, height,
            GROUND_LIT, GROUND_DARK, Shader.TileMode.CLAMP,
        )
    }

    /** Ель: ствол не рисуется, крона — четыре яруса с зубчатым краем. */
    private fun addPine(path: Path, left: Float, bottom: Float, width: Float, height: Float) {
        val centre = left + width / 2f
        val tier = height / PINE_TIERS

        path.moveTo(centre, bottom - height)
        // Правая сторона сверху вниз.
        for (level in 1..PINE_TIERS) {
            val reach = width / 2f * level / PINE_TIERS
            val y = bottom - height + tier * level
            path.lineTo(centre + reach, y)
            if (level < PINE_TIERS) path.lineTo(centre + reach * 0.55f, y - tier * 0.12f)
        }
        // Левая — снизу вверх.
        for (level in PINE_TIERS downTo 1) {
            val reach = width / 2f * level / PINE_TIERS
            val y = bottom - height + tier * level
            if (level < PINE_TIERS) path.lineTo(centre - reach * 0.55f, y - tier * 0.12f)
            path.lineTo(centre - reach, y)
        }
        path.close()
    }

    override fun onDraw(canvas: Canvas) {
        val width = width.toFloat()
        val height = height.toFloat()

        canvas.drawRect(0f, 0f, width, height, skyPaint)

        for (index in 0 until stars.size / STAR_FIELDS) {
            val offset = index * STAR_FIELDS
            val phase = stars[offset + 3]

            starPaint.alpha = if (phase < 0f) {
                STEADY_ALPHA
            } else {
                // Плавное мерцание: от трети до полной яркости.
                val wave = (sin((twinkle + phase) * 2.0 * PI).toFloat() + 1f) / 2f
                (TWINKLE_MIN_ALPHA + wave * (255 - TWINKLE_MIN_ALPHA)).toInt()
            }
            canvas.drawCircle(stars[offset], stars[offset + 1], stars[offset + 2], starPaint)
        }

        if (showMoon) {
            canvas.drawCircle(moonX, moonY, moonRadius * 3.2f, glowPaint)
            canvas.drawCircle(moonX, moonY, moonRadius, moonPaint)
            canvas.drawCircle(moonX - moonRadius * 0.28f, moonY + moonRadius * 0.22f, moonRadius * 0.2f, craterPaint)
            canvas.drawCircle(moonX + moonRadius * 0.36f, moonY - moonRadius * 0.12f, moonRadius * 0.13f, craterPaint)
            canvas.drawCircle(moonX + moonRadius * 0.08f, moonY + moonRadius * 0.52f, moonRadius * 0.1f, craterPaint)
        }

        if (showForest) {
            canvas.drawPath(farForest, farPaint)
            canvas.drawPath(ground, groundPaint)
            canvas.drawPath(nearForest, nearPaint)
        }

        if (fadePaint.shader != null) {
            canvas.drawRect(0f, height * FADE_START, width, height, fadePaint)
        }
    }

    /** Линейный конгруэнтный генератор: воспроизводимая «случайность». */
    private class Lcg(seed: Int) {
        private var state = seed

        /** Число в [0, 1). */
        fun next(): Float {
            state = state * 1_103_515_245 + 12_345
            return ((state ushr 8) and 0xFFFF) / 65_536f
        }
    }

    private companion object {
        // Краски сцены. Заданы здесь, а не в палитре: это краски
        // иллюстрации, а не интерфейса, и в токены они не входят.
        // Фиолетовое небо — как на иллюстрации приветствия и логотипе GAS
        // (2026-11-07); прежде небо было синим индиго.
        val SKY_TOP = Color.rgb(0x0B, 0x06, 0x26)
        val SKY_MID = Color.rgb(0x22, 0x10, 0x5C)
        val SKY_DEEP = Color.rgb(0x18, 0x0C, 0x48)
        val SKY_HORIZON = Color.rgb(0x48, 0x2A, 0xA0)
        val STAR = Color.rgb(0xF7, 0xF2, 0xFF)
        val MOON_LIGHT = Color.rgb(0xF4, 0xF7, 0xFF)
        val MOON_SHADE = Color.rgb(0xA9, 0xB8, 0xE8)
        val MOON_CRATER = Color.argb(0x38, 0x5C, 0x6E, 0xB0)
        val MOON_GLOW = Color.argb(0x3D, 0xD4, 0xC2, 0xFF)
        val FOREST_FAR = Color.rgb(0x1A, 0x2E, 0x3C)
        val FOREST_NEAR = Color.rgb(0x0C, 0x18, 0x24)
        val GROUND_LIT = Color.rgb(0x2C, 0x7A, 0x2F)
        val GROUND_DARK = Color.rgb(0x0F, 0x33, 0x1C)

        const val STAR_SEED = 20_261_007
        const val FOREST_SEED = 4_815
        const val STAR_FIELDS = 4
        const val STAR_AREA_DP = 2_600f
        const val TWINKLE_EVERY = 6
        const val NO_TWINKLE = -1f
        const val STEADY_ALPHA = 200
        const val TWINKLE_MIN_ALPHA = 80
        const val PINE_TIERS = 4
        const val NEAR_TREES_PER_SIDE = 3
        const val FADE_START = 0.8f

        const val TWINKLE_PERIOD_MS = 5_200L
        const val TWINKLE_FPS = 15
        const val FRAME_NANOS = 1_000_000_000L / TWINKLE_FPS
    }
}
