// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.components

import android.app.Activity
import android.graphics.Outline
import android.provider.Settings
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.ViewOutlineProvider
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.StringRes
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import org.aegis.app.R

/**
 * Тост дизайн-системы (UI kit, Notifications & Toasts).
 *
 * Карточка с цветной полосой слева и значком тона, живёт три секунды.
 * Тон — не только цвет (раздел 20.5): у каждого свой значок.
 *
 * # 🔐 Почему не `android.widget.Toast`
 *
 * Системный тост рисует система в собственном окне, и `FLAG_SECURE`
 * экрана на него не распространяется: текст тоста — «Файл сохранён»,
 * «Ссылка скопирована», имя собеседника в будущем — попадал бы
 * в снимки и запись экрана, которые приложение у себя запретило.
 * Этот тост — вид внутри окна приложения и защищён вместе с ним.
 * Заодно он выглядит как остальное приложение, а не как белая
 * плашка системы.
 */
object AegisToast {

    /** Тон сообщения. */
    enum class Tone(val color: Int, val icon: Int) {
        /** Готово: сохранено, скопировано, удалено. */
        Success(R.color.status_ok, R.drawable.ic_check),

        /** Нейтральное: идёт загрузка, отправляется. */
        Info(R.color.status_info, R.drawable.ic_info),

        /** Требует внимания, но не сбой: удалите вручную, ключ сменился. */
        Warning(R.color.status_warn, R.drawable.ic_alert),

        /** Не получилось. */
        Error(R.color.status_error, R.drawable.ic_block),
    }

    /** Время жизни, как в kit. */
    private const val LIFETIME_MS = 3_000L

    /** Появление и исчезновение — motion.base. */
    private const val FADE_MS = 200L

    /** Метка, по которой тост находится в окне. */
    private val TAG = AegisToast::class.java.name

    fun show(activity: Activity, @StringRes text: Int, tone: Tone = Tone.Info) =
        show(activity, activity.getString(text), tone)

    fun show(activity: Activity, text: CharSequence, tone: Tone = Tone.Info) {
        if (activity.isFinishing || activity.isDestroyed) return

        val host = activity.findViewById<FrameLayout>(android.R.id.content) ?: return

        // Один тост за раз: новый заменяет прежний, а не встаёт в очередь.
        host.findViewWithTag<View>(TAG)?.let(host::removeView)

        val toast = LayoutInflater.from(activity).inflate(R.layout.view_toast, host, false)
        toast.tag = TAG

        val color = activity.getColor(tone.color)
        toast.findViewById<View>(R.id.toast_spine).setBackgroundColor(color)
        toast.findViewById<ImageView>(R.id.toast_icon).apply {
            setImageResource(tone.icon)
            setColorFilter(color)
        }
        toast.findViewById<TextView>(R.id.toast_text).text = text

        // Полоса слева обрезается по скруглению карточки.
        toast.outlineProvider = object : ViewOutlineProvider() {
            override fun getOutline(view: View, outline: Outline) {
                outline.setRoundRect(0, 0, view.width, view.height, activity.resources.displayMetrics.density * 12)
            }
        }
        toast.clipToOutline = true

        val margin = activity.resources.getDimensionPixelSize(R.dimen.space_m)
        val params = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL,
        )
        // Над системной навигацией и над нижней панелью экрана.
        val bottomInset = ViewCompat.getRootWindowInsets(host)
            ?.getInsets(WindowInsetsCompat.Type.systemBars())?.bottom ?: 0
        params.setMargins(margin, margin, margin, bottomInset + activity.resources.getDimensionPixelSize(R.dimen.toast_bottom))

        host.addView(toast, params)
        toast.announceForAccessibility(text)

        val animate = animationsEnabled(activity)
        if (animate) {
            toast.alpha = 0f
            toast.translationY = margin.toFloat()
            toast.animate().alpha(1f).translationY(0f).setDuration(FADE_MS).start()
        }

        toast.postDelayed({
            if (!animate) {
                host.removeView(toast)
            } else {
                toast.animate().alpha(0f).setDuration(FADE_MS).withEndAction { host.removeView(toast) }.start()
            }
        }, LIFETIME_MS)
    }

    /** `prefers-reduced-motion`: при выключенных анимациях — без них (раздел 20.1). */
    private fun animationsEnabled(activity: Activity): Boolean =
        Settings.Global.getFloat(activity.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f
}
