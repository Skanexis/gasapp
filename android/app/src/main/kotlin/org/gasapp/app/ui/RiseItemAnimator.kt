// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.view.animation.DecelerateInterpolator
import androidx.recyclerview.widget.DefaultItemAnimator
import androidx.recyclerview.widget.RecyclerView

/**
 * Новое сообщение поднимается на место и проявляется.
 *
 * Стандартный аниматор только проявляет добавленное. Подъём на
 * несколько dp связывает сообщение с полем ввода, откуда оно ушло,
 * и отличает пришедшее от того, что уже было на экране.
 *
 * Движение — только свойства вида (сдвиг и прозрачность), их считает
 * GPU; длительность умножается на системный масштаб анимаций, так что
 * «Удалить анимации» снимает и его.
 */
class RiseItemAnimator : DefaultItemAnimator() {

    init {
        addDuration = ADD_MS

        // Изменённая строка перерисовывается на месте. Со стандартной
        // анимацией смена галочки «отправлено → доставлено» растворяла
        // и проявляла весь пузырь — сообщение мигало на каждый статус.
        supportsChangeAnimations = false
    }

    override fun animateAdd(holder: RecyclerView.ViewHolder): Boolean {
        holder.itemView.translationY = RISE_DP * holder.itemView.resources.displayMetrics.density
        return super.animateAdd(holder)
    }

    override fun onAddStarting(item: RecyclerView.ViewHolder) {
        item.itemView.animate()
            .translationY(0f)
            .setDuration(addDuration)
            .setInterpolator(DecelerateInterpolator(DECELERATION))
            .start()
    }

    override fun onAddFinished(item: RecyclerView.ViewHolder) {
        item.itemView.translationY = 0f
    }

    override fun endAnimation(item: RecyclerView.ViewHolder) {
        item.itemView.animate().cancel()
        item.itemView.translationY = 0f
        super.endAnimation(item)
    }

    private companion object {
        const val ADD_MS = 240L
        const val RISE_DP = 14f
        const val DECELERATION = 2f
    }
}
