// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ObjectAnimator
import android.os.Build
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import org.aegis.app.R

/**
 * Отклик на неверный PIN: точки краснеют, вздрагивают и гаснут.
 *
 * Прежде ошибку говорила только мелкая красная строка под точками —
 * её легко не заметить, глядя на клавиатуру. Движение и вибрация
 * видны и ощутимы сразу; строка остаётся — для экранного чтеца
 * и для тех, у кого анимации выключены.
 *
 * 🔐 Отклик один и тот же при любой ошибке: он не говорит, сколько
 * цифр совпало.
 */
object PinFeedback {

    /** Показывает ошибку на ряду точек [dots]; [onEnd] — когда точки снова пустые. */
    fun wrong(dots: ViewGroup, onEnd: () -> Unit = {}) {
        for (index in 0 until dots.childCount) {
            dots.getChildAt(index).setBackgroundResource(R.drawable.bg_pin_dot_error)
        }

        dots.performHapticFeedback(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                HapticFeedbackConstants.REJECT
            } else {
                HapticFeedbackConstants.LONG_PRESS
            },
        )

        val shift = SHAKE_DP * dots.resources.displayMetrics.density
        ObjectAnimator.ofFloat(
            dots,
            View.TRANSLATION_X,
            0f, -shift, shift, -shift * 0.66f, shift * 0.66f, -shift * 0.33f, shift * 0.33f, 0f,
        ).apply {
            duration = SHAKE_MS
            addListener(
                object : AnimatorListenerAdapter() {
                    override fun onAnimationEnd(animation: Animator) {
                        dots.translationX = 0f
                        dots.postDelayed({
                            for (index in 0 until dots.childCount) {
                                dots.getChildAt(index).setBackgroundResource(R.drawable.bg_pin_dot)
                            }
                            onEnd()
                        }, HOLD_MS)
                    }
                },
            )
            start()
        }
    }

    private const val SHAKE_DP = 10f
    private const val SHAKE_MS = 360L
    private const val HOLD_MS = 180L
}
