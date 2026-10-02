// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.AbsoluteSizeSpan
import android.text.style.ForegroundColorSpan
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.R

/**
 * Статус доставки сообщения.
 *
 * Повторяет `DeliveryStatus` из `aegis-core`, но живёт отдельно: ядро
 * знает про состояние отправки, UI — про то, какую галочку рисовать.
 * Совпадение вариантов сегодня не повод связывать слои навсегда.
 */
enum class DeliveryMark {
    /** Ждёт отправки: сеть недоступна либо очередь ещё не дошла. */
    Pending,

    /** Ушло на сервер. */
    Sent,

    /** Доставлено на устройство получателя. */
    Delivered,

    /** Прочитано. */
    Read,

    /** Отправить не удалось: попытки исчерпаны. */
    Failed,
}

/** Сообщение в том виде, в каком его показывает UI. */
data class MessageItem(
    /** Идентификатор сообщения. */
    val messageId: String,
    /** Расшифрованный текст. */
    val text: String,
    /** Время в формате для показа. */
    val time: String,
    /** Наше это сообщение или входящее. */
    val outgoing: Boolean,
    /** Статус доставки. Имеет смысл только для исходящих. */
    val status: DeliveryMark,
    /**
     * Вложение, если оно есть.
     *
     * Само содержимое файла сюда не попадает: он лежит на сервере
     * зашифрованным и загружается по нажатию.
     */
    val attachment: AttachmentPreview? = null,

    /**
     * Правлено ли сообщение после отправки.
     *
     * 🔐 Пометка обязательна: правка не скрывает исходный текст —
     * получатель уже видел его, — но без пометки отправитель мог бы
     * переписать разговор задним числом, и собеседник не заметил бы
     * подмены.
     */
    val edited: Boolean = false,

    /** Время сообщения — для группировки и плашки дня. */
    val timestampMillis: Long = 0L,
)

/**
 * Строка переписки: сообщение и его место в группе.
 *
 * Считается один раз на весь список в [MessageAdapter.submit], и разница
 * строится по строкам: новое сообщение меняет форму предыдущего пузыря
 * (он перестаёт быть последним в группе), и DiffUtil перерисует его сам.
 */
data class MessageRow(
    val item: MessageItem,
    /** Предыдущее сообщение — той же стороны и рядом по времени. */
    val joinsPrevious: Boolean,
    /** Следующее сообщение — той же стороны и рядом по времени. */
    val joinsNext: Boolean,
    /** Плашка дня над сообщением, если с него начинается день. */
    val day: String?,
)

/**
 * То, что видно о вложении до загрузки.
 *
 * 🔐 Имя и размер приходят из описания, то есть из-под сквозного
 * шифрования. Сервер их не знает.
 */
data class AttachmentPreview(
    /** Сериализованное описание: по нему файл скачивается. */
    val descriptor: ByteArray,
    /** Имя файла, если отправитель его передал. */
    val name: String?,
    /** Размер в байтах. */
    val size: Long,
    /** Тип вложения. */
    val kind: AttachmentKindMark,
) {
    // equals и hashCode переопределены, потому что data class сравнил
    // бы описание по ссылке.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttachmentPreview) return false

        return descriptor.contentEquals(other.descriptor) &&
            name == other.name &&
            size == other.size &&
            kind == other.kind
    }

    override fun hashCode(): Int {
        var result = descriptor.contentHashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + size.hashCode()
        result = 31 * result + kind.hashCode()

        return result
    }
}

/** Тип вложения для выбора значка и подписи. */
enum class AttachmentKindMark {
    Image,
    Video,
    Document,
}

/**
 * Адаптер переписки.
 *
 * 🔐 Держит расшифрованный текст, поэтому очищается при блокировке —
 * см. [MessageAdapter.clear].
 */
class MessageAdapter(
    /**
     * Нажатие на вложение.
     *
     * 🔐 Загрузка идёт только по нажатию: автоматическая подтвердила бы
     * отправителю, что сообщение открыли, ещё до того как человек
     * решил его открывать.
     */
    private val onAttachmentClick: ((AttachmentPreview) -> Unit)? = null,

    /**
     * Долгое нажатие на сообщение: открывает меню действий.
     *
     * Долгое, а не обычное: обычное нажатие в переписке ничего
     * не делает, и превращать его в меню значило бы открывать список
     * каждый раз, когда человек промахнулся мимо прокрутки.
     */
    private val onMessageLongClick: ((MessageItem) -> Unit)? = null,

    /** Подпись дня для плашки: «Сегодня», «Вчера», дата. */
    private val dayLabel: (Long) -> String = { "" },
) : RecyclerView.Adapter<MessageAdapter.ViewHolder>() {

    private val rows = mutableListOf<MessageRow>()

    /** Сообщения в порядке показа. */
    private val messages: List<MessageItem>
        get() = rows.map { it.item }

    /** Заменяет содержимое переписки. */
    fun submit(items: List<MessageItem>) {
        // Разница, а не перерисовка всего списка: обновление приходит
        // на каждое событие сокета, и полная перерисовка мигала строками
        // и сбивала прокрутку.
        val old = rows.toList()
        val new = rowsOf(items)
        val diff = DiffUtil.calculateDiff(
            object : DiffUtil.Callback() {
                override fun getOldListSize() = old.size

                override fun getNewListSize() = new.size

                override fun areItemsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition].item.messageId == new[newPosition].item.messageId

                override fun areContentsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition] == new[newPosition]
            },
        )

        rows.clear()
        rows.addAll(new)
        diff.dispatchUpdatesTo(this)
    }

    /** Добавляет одно сообщение в конец. */
    fun append(item: MessageItem) {
        submit(messages + item)
    }

    /** Группы и плашки дня: считаются по соседям. */
    private fun rowsOf(items: List<MessageItem>): List<MessageRow> {
        val days = items.map { if (it.timestampMillis > 0) dayLabel(it.timestampMillis) else "" }

        return items.mapIndexed { index, item ->
            val previous = items.getOrNull(index - 1)
            val next = items.getOrNull(index + 1)
            val newDay = index == 0 || days[index] != days[index - 1]

            MessageRow(
                item = item,
                joinsPrevious = previous != null && !newDay && together(previous, item),
                joinsNext = next != null && days.getOrNull(index + 1) == days[index] && together(item, next),
                day = days[index].takeIf { newDay && it.isNotEmpty() },
            )
        }
    }

    /** Одна сторона и не дальше [GROUP_GAP_MS] друг от друга. */
    private fun together(first: MessageItem, second: MessageItem): Boolean =
        first.outgoing == second.outgoing &&
            kotlin.math.abs(second.timestampMillis - first.timestampMillis) <= GROUP_GAP_MS

    /**
     * Очищает переписку.
     *
     * Вызывается при блокировке: расшифрованный текст не должен
     * оставаться в памяти после того, как пользователь заблокировал
     * приложение.
     */
    fun clear() {
        val removed = rows.size
        rows.clear()
        notifyItemRangeRemoved(0, removed)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)

        return ViewHolder(view, onAttachmentClick, onMessageLongClick)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        rows.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = rows.size

    private companion object {
        /** Сообщения ближе пяти минут — одна группа. */
        const val GROUP_GAP_MS = 5 * 60 * 1000L
    }

    /** Держатель пузыря сообщения. */
    class ViewHolder(
        view: View,
        private val onAttachmentClick: ((AttachmentPreview) -> Unit)?,
        private val onMessageLongClick: ((MessageItem) -> Unit)?,
    ) : RecyclerView.ViewHolder(view) {
        /** Показывает или прячет строку вложения. */
        private fun bindAttachment(attachment: AttachmentPreview?) {
            if (attachment == null) {
                attachmentRow.visibility = View.GONE
                attachmentRow.setOnClickListener(null)

                return
            }

            attachmentRow.visibility = View.VISIBLE

            val context = attachmentRow.context

            attachmentName.text = attachment.name ?: context.getString(
                when (attachment.kind) {
                    AttachmentKindMark.Image -> R.string.attachment_image
                    AttachmentKindMark.Video -> R.string.attachment_video
                    AttachmentKindMark.Document -> R.string.attachment_document
                },
            )

            attachmentSize.text = FileSize.format(itemView.context, attachment.size)

            attachmentIcon.setImageResource(
                when (attachment.kind) {
                    AttachmentKindMark.Image, AttachmentKindMark.Video -> R.drawable.ic_image
                    AttachmentKindMark.Document -> R.drawable.ic_file
                },
            )

            attachmentRow.setOnClickListener { onAttachmentClick?.invoke(attachment) }
        }



        private val container: LinearLayout = view.findViewById(R.id.message_container)
        private val bubble: LinearLayout = view.findViewById(R.id.message_bubble)
        private val text: TextView = view.findViewById(R.id.message_text)
        private val time: TextView = view.findViewById(R.id.message_time)
        private val status: ImageView = view.findViewById(R.id.message_status)
        private val attachmentRow: LinearLayout = view.findViewById(R.id.message_attachment)
        private val attachmentIcon: ImageView = view.findViewById(R.id.attachment_icon)
        private val attachmentName: TextView = view.findViewById(R.id.attachment_name)
        private val attachmentSize: TextView = view.findViewById(R.id.attachment_size)
        private val editedMark: TextView = view.findViewById(R.id.message_edited)
        private val day: TextView = view.findViewById(R.id.message_day)

        /** Заполняет пузырь данными сообщения. */
        fun bind(row: MessageRow) {
            val message = row.item

            text.text = withRoomForTime(message)
            time.text = message.time

            day.text = row.day
            day.visibility = if (row.day != null) View.VISIBLE else View.GONE

            // Группа: плотно внутри, воздух между группами.
            val density = itemView.resources.displayMetrics.density
            container.setPadding(
                container.paddingStart,
                ((if (row.joinsPrevious) GAP_IN_GROUP_DP else GAP_BETWEEN_GROUPS_DP) * density).toInt(),
                container.paddingEnd,
                ((if (row.joinsNext) GAP_IN_GROUP_DP else GAP_BETWEEN_GROUPS_DP) * density).toInt(),
            )

            bubble.setOnLongClickListener {
                onMessageLongClick?.invoke(message)

                // true: событие обработано, и обычное нажатие после
                // него не сработает — иначе меню открывалось бы
                // вместе с другим действием.
                onMessageLongClick != null
            }

            // Пустая подпись прячется: пузырь с вложением и без текста
            // иначе оставлял бы пустую строку над файлом.
            text.visibility = if (message.text.isEmpty()) View.GONE else View.VISIBLE

            bindAttachment(message.attachment)

            editedMark.visibility = if (message.edited) View.VISIBLE else View.GONE

            container.gravity = if (message.outgoing) Gravity.END else Gravity.START
            bubble.background = bubbleShape(message.outgoing, row.joinsPrevious, row.joinsNext)

            // Исходящее — «чернила» акцента с тёмным текстом, входящее —
            // бумага карточки со светлым: сторона читается без подписи.
            val context = itemView.context
            val ink = if (message.outgoing) R.color.bubble_outgoing_text else R.color.text_primary
            val meta = if (message.outgoing) R.color.bubble_outgoing_meta else R.color.text_tertiary
            text.setTextColor(ContextCompat.getColor(context, ink))
            time.setTextColor(ContextCompat.getColor(context, meta))
            editedMark.setTextColor(ContextCompat.getColor(context, meta))

            // Статус показывается только у исходящих: у входящих он
            // не имеет смысла и сбивал бы с толку.
            if (message.outgoing) {
                status.visibility = View.VISIBLE
                status.setImageResource(iconFor(message.status))
                status.imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(itemView.context, tintFor(message.status)),
                )
                status.contentDescription = itemView.context.getString(labelFor(message.status))
            } else {
                status.visibility = View.GONE
            }
        }

        /**
         * Фон пузыря по месту в группе.
         *
         * Большой радиус снаружи группы, малый — со стороны отправителя
         * там, где пузырь примыкает к соседу; у последнего в группе —
         * малый нижний угол со стороны отправителя («хвостик»).
         */
        private fun bubbleShape(outgoing: Boolean, joinsPrevious: Boolean, joinsNext: Boolean): GradientDrawable {
            val density = itemView.resources.displayMetrics.density
            val big = BIG_RADIUS_DP * density
            val small = SMALL_RADIUS_DP * density

            val senderTop = if (joinsPrevious) small else big
            // Нижний угол со стороны отправителя малый всегда: внутри
            // группы — стык, у последнего — хвостик.
            val senderBottom = small

            // Порядок углов: левый верхний, правый верхний, правый нижний, левый нижний.
            val corners = if (outgoing) {
                floatArrayOf(big, big, senderTop, senderTop, senderBottom, senderBottom, big, big)
            } else {
                floatArrayOf(senderTop, senderTop, big, big, big, big, senderBottom, senderBottom)
            }

            return GradientDrawable().apply {
                cornerRadii = corners
                setColor(
                    ContextCompat.getColor(
                        itemView.context,
                        if (outgoing) R.color.bubble_outgoing else R.color.bg_card,
                    ),
                )
            }
        }

        /**
         * Текст с местом под время в последней строке.
         *
         * Время лежит поверх пузыря внизу справа. Невидимый хвост той же
         * ширины в конце текста резервирует ему место: если последняя
         * строка короткая, время встаёт в неё, если длинная — хвост
         * переносится, и время оказывается строкой ниже, не наезжая
         * на текст.
         */
        private fun withRoomForTime(message: MessageItem): CharSequence {
            if (message.text.isEmpty()) return ""

            val context = itemView.context
            val placeholder = buildString {
                append("\u00A0\u00A0")
                if (message.edited) append(context.getString(R.string.message_edited)).append('\u00A0')
                append(message.time)
                // Место под значок статуса у исходящих.
                if (message.outgoing) append("\u00A0\u2003\u2003")
            }

            return SpannableStringBuilder(message.text).apply {
                val start = length
                append(placeholder)
                setSpan(ForegroundColorSpan(Color.TRANSPARENT), start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                // В sp, как и само время: в dp заполнитель не рос бы вместе
                // с системным шрифтом, и на крупном время наезжало на текст.
                val metaPx = android.util.TypedValue.applyDimension(
                    android.util.TypedValue.COMPLEX_UNIT_SP,
                    META_TEXT_SP.toFloat(),
                    context.resources.displayMetrics,
                ).toInt()
                setSpan(AbsoluteSizeSpan(metaPx), start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
        }

        /**
         * Значок статуса доставки.
         *
         * `Failed` помечается крестом, а не молчанием: сообщение,
         * которое выглядит отправленным, но не ушло, — худший исход,
         * потому что пользователь считает, что его прочитали.
         */
        private fun iconFor(status: DeliveryMark): Int = when (status) {
            DeliveryMark.Pending -> R.drawable.ic_tick_pending
            DeliveryMark.Sent -> R.drawable.ic_tick_single
            DeliveryMark.Delivered, DeliveryMark.Read -> R.drawable.ic_tick_double
            DeliveryMark.Failed -> R.drawable.ic_tick_failed
        }

        /**
         * Цвет значка.
         *
         * `Delivered` и `Read` используют одну форму и различаются
         * только цветом — так же, как в макете и в мессенджерах,
         * к которым пользователь привык.
         */
        /** Статус словами — для чтения с экрана: значок сам по себе немой. */
        private fun labelFor(status: DeliveryMark): Int = when (status) {
            DeliveryMark.Pending -> R.string.delivery_pending
            DeliveryMark.Sent -> R.string.delivery_sent
            DeliveryMark.Delivered -> R.string.delivery_delivered
            DeliveryMark.Read -> R.string.delivery_read
            DeliveryMark.Failed -> R.string.delivery_failed
        }

        private fun tintFor(status: DeliveryMark): Int = when (status) {
            // На «чернилах» исходящего пузыря: прочитанное — полной
            // краской, остальное — приглушённой; неудача видна формой.
            DeliveryMark.Read, DeliveryMark.Failed -> R.color.bubble_outgoing_text
            else -> R.color.bubble_outgoing_meta
        }

        private companion object {
            const val BIG_RADIUS_DP = 18f
            const val SMALL_RADIUS_DP = 6f
            const val GAP_IN_GROUP_DP = 1f
            const val GAP_BETWEEN_GROUPS_DP = 6f

            /** Кегль времени — для ширины заполнителя. */
            const val META_TEXT_SP = 11
        }
    }
}
