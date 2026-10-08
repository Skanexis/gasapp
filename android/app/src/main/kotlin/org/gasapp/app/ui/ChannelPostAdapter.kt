// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import org.gasapp.app.R

/** Запись канала в ленте. */
data class ChannelPostRow(
    val seq: Long,
    val text: String,
    val time: String,
)

/**
 * Лента записей канала — от старых к новым, новые внизу.
 *
 * 🔐 Тексты расшифрованы: экран очищает адаптер при уходе ([clear]).
 */
class ChannelPostAdapter : RecyclerView.Adapter<ChannelPostAdapter.ViewHolder>() {

    private val posts = mutableListOf<ChannelPostRow>()

    fun submit(items: List<ChannelPostRow>) {
        val old = posts.toList()
        val diff = DiffUtil.calculateDiff(
            object : DiffUtil.Callback() {
                override fun getOldListSize() = old.size

                override fun getNewListSize() = items.size

                override fun areItemsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition].seq == items[newPosition].seq

                override fun areContentsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition] == items[newPosition]
            },
        )

        posts.clear()
        posts.addAll(items)
        diff.dispatchUpdatesTo(this)
    }

    fun clear() {
        val removed = posts.size
        posts.clear()
        notifyItemRangeRemoved(0, removed)
    }

    /** Номер последней записи в ленте или `null`, если она пуста. */
    fun lastSeq(): Long? = posts.lastOrNull()?.seq

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
        ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_channel_post, parent, false))

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        posts.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = posts.size

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {

        private val text: TextView = view.findViewById(R.id.post_text)
        private val time: TextView = view.findViewById(R.id.post_time)

        fun bind(post: ChannelPostRow) {
            text.text = post.text
            time.text = post.time
        }
    }
}
