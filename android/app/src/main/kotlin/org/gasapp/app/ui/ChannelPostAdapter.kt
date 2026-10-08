// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.isVisible
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import org.gasapp.app.R
import uniffi.gasapp.FfiAttachmentKind

/** Вложение записи канала. */
class ChannelAttachmentRow(
    /** Описание как есть — им ядро скачивает и расшифровывает файл. */
    val descriptor: ByteArray,
    val kind: FfiAttachmentKind,
    /** 🔐 Имя назвал автор канала: показывать можно, доверять — нет. */
    val name: String?,
    val size: Long,
) {
    override fun equals(other: Any?): Boolean =
        other is ChannelAttachmentRow && descriptor.contentEquals(other.descriptor)

    override fun hashCode(): Int = descriptor.contentHashCode()
}

/** Реакция со счётчиком. */
data class ChannelReactionRow(val emoji: String, val count: Long)

/** Запись канала в ленте. */
data class ChannelPostRow(
    val seq: Long,
    val text: String,
    val time: String,
    val edited: Boolean = false,
    val views: Long = 0,
    val reactions: List<ChannelReactionRow> = emptyList(),
    val myReaction: String? = null,
    val attachments: List<ChannelAttachmentRow> = emptyList(),
    val pinned: Boolean = false,
)

/**
 * Лента записей канала — от старых к новым, новые внизу.
 *
 * 🔐 Тексты и картинки расшифрованы: экран очищает адаптер при уходе
 * ([clear]). Картинки адаптер не скачивает и не хранит — их по
 * описанию ставит [loadImage].
 */
class ChannelPostAdapter(
    private val onLongPress: (ChannelPostRow) -> Unit = {},
    private val onReaction: (ChannelPostRow, String) -> Unit = { _, _ -> },
    private val onAttachment: (ChannelAttachmentRow) -> Unit = {},
    private val loadImage: (ChannelAttachmentRow, ImageView) -> Unit = { _, _ -> },
) : RecyclerView.Adapter<ChannelPostAdapter.ViewHolder>() {

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

    /** Номер самой старой записи в ленте или `null`, если она пуста. */
    fun firstSeq(): Long? = posts.firstOrNull()?.seq

    /** Место записи в ленте или `-1`, если её здесь нет. */
    fun positionOf(seq: Long): Int = posts.indexOfFirst { it.seq == seq }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
        ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_channel_post, parent, false))

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        posts.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = posts.size

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {

        private val pinned: View = view.findViewById(R.id.post_pinned)
        private val media: LinearLayout = view.findViewById(R.id.post_media)
        private val text: TextView = view.findViewById(R.id.post_text)
        private val reactionsScroll: View = view.findViewById(R.id.post_reactions_scroll)
        private val reactions: LinearLayout = view.findViewById(R.id.post_reactions)
        private val views: TextView = view.findViewById(R.id.post_views)
        private val edited: View = view.findViewById(R.id.post_edited)
        private val time: TextView = view.findViewById(R.id.post_time)

        fun bind(post: ChannelPostRow) {
            pinned.isVisible = post.pinned

            text.text = post.text
            text.isVisible = post.text.isNotEmpty()

            time.text = post.time
            edited.isVisible = post.edited

            views.isVisible = post.views > 0
            views.text = Counts.compact(post.views)
            views.contentDescription =
                itemView.resources.getQuantityString(R.plurals.channel_views, countForPlural(post.views), post.views)

            bindMedia(post)
            bindReactions(post)

            val open = View.OnLongClickListener {
                onLongPress(post)
                true
            }
            itemView.setOnLongClickListener(open)
            text.setOnLongClickListener(open)
        }

        private fun bindMedia(post: ChannelPostRow) {
            media.removeAllViews()
            media.isVisible = post.attachments.isNotEmpty()

            val inflater = LayoutInflater.from(itemView.context)

            for (attachment in post.attachments) {
                if (attachment.kind == FfiAttachmentKind.IMAGE && attachment.size <= ChannelImages.AUTO_LOAD_BYTES) {
                    media.addView(imageFor(attachment))
                } else {
                    val row = inflater.inflate(R.layout.item_channel_attachment, media, false)
                    ChannelAttachmentView.bind(row, attachment.kind, attachment.name, attachment.size)
                    row.setOnClickListener { onAttachment(attachment) }
                    media.addView(row)
                }
            }
        }

        /** Картинка записи: место под неё занято сразу, содержимое приезжает позже. */
        private fun imageFor(attachment: ChannelAttachmentRow): ImageView {
            val context = itemView.context
            val height = context.resources.getDimensionPixelSize(R.dimen.channel_image_height)

            return ImageView(context).apply {
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, height).apply {
                    bottomMargin = context.resources.getDimensionPixelSize(R.dimen.space_s)
                }
                setBackgroundResource(R.drawable.bg_composer_field)
                clipToOutline = true
                scaleType = ImageView.ScaleType.CENTER_CROP
                contentDescription = context.getString(R.string.attachment_image)
                setOnClickListener { onAttachment(attachment) }
                setOnLongClickListener {
                    posts.getOrNull(bindingAdapterPosition)?.let(onLongPress)
                    true
                }
                loadImage(attachment, this)
            }
        }

        private fun bindReactions(post: ChannelPostRow) {
            reactions.removeAllViews()
            reactionsScroll.isVisible = post.reactions.isNotEmpty()

            val context = itemView.context
            val gap = context.resources.getDimensionPixelSize(R.dimen.space_s)
            val padding = context.resources.getDimensionPixelSize(R.dimen.channel_reaction_padding)
            val height = context.resources.getDimensionPixelSize(R.dimen.channel_reaction_height)

            for (reaction in post.reactions) {
                val mine = reaction.emoji == post.myReaction

                reactions.addView(
                    TextView(context, null, 0, R.style.GasAppText_Caption_Muted).apply {
                        text = context.getString(R.string.channel_reaction_chip, reaction.emoji, Counts.compact(reaction.count))
                        gravity = android.view.Gravity.CENTER
                        minHeight = height
                        setPadding(padding, 0, padding, 0)
                        setBackgroundResource(if (mine) R.drawable.bg_pill_accent else R.drawable.bg_pill_neutral)
                        setTextColor(context.getColor(if (mine) R.color.accent_base else R.color.text_secondary))
                        contentDescription = context.resources.getQuantityString(
                            if (mine) R.plurals.channel_reaction_mine else R.plurals.channel_reaction_count,
                            countForPlural(reaction.count),
                            reaction.emoji,
                            reaction.count,
                        )
                        setOnClickListener { onReaction(post, reaction.emoji) }
                    },
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { marginEnd = gap },
                )
            }
        }
    }

    private companion object {
        /** Число для выбора формы множественного числа. */
        fun countForPlural(count: Long): Int = count.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
    }
}

/** Строка файла: значок по типу, имя, размер. */
object ChannelAttachmentView {

    fun bind(row: View, kind: FfiAttachmentKind, name: String?, size: Long) {
        val context = row.context

        row.findViewById<ImageView>(R.id.attachment_icon).setImageResource(
            when (kind) {
                FfiAttachmentKind.IMAGE, FfiAttachmentKind.VIDEO -> R.drawable.ic_image
                FfiAttachmentKind.VOICE -> R.drawable.ic_mic
                FfiAttachmentKind.DOCUMENT -> R.drawable.ic_file
            },
        )
        row.findViewById<TextView>(R.id.attachment_name).text = name ?: context.getString(
            when (kind) {
                FfiAttachmentKind.IMAGE -> R.string.attachment_image
                FfiAttachmentKind.VIDEO -> R.string.attachment_video
                FfiAttachmentKind.VOICE -> R.string.attachment_voice
                FfiAttachmentKind.DOCUMENT -> R.string.attachment_document
            },
        )
        row.findViewById<TextView>(R.id.attachment_size).text = FileSize.format(context, size)
    }
}

/** Короткая запись счётчика: 950, 1,2 тыс., 3,4 млн. */
object Counts {

    fun compact(count: Long): String = when {
        count < THOUSAND -> count.toString()
        count < MILLION -> String.format(java.util.Locale.getDefault(), "%.1fK", count / THOUSAND.toDouble())
        else -> String.format(java.util.Locale.getDefault(), "%.1fM", count / MILLION.toDouble())
    }

    private const val THOUSAND = 1_000L
    private const val MILLION = 1_000_000L
}
