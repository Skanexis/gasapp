// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.content.res.ColorStateList
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
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
) : RecyclerView.Adapter<MessageAdapter.ViewHolder>() {

    private val messages = mutableListOf<MessageItem>()

    /** Заменяет содержимое переписки. */
    fun submit(items: List<MessageItem>) {
        messages.clear()
        messages.addAll(items)
        notifyDataSetChanged()
    }

    /** Добавляет одно сообщение в конец. */
    fun append(item: MessageItem) {
        messages.add(item)
        notifyItemInserted(messages.size - 1)
    }

    /**
     * Очищает переписку.
     *
     * Вызывается при блокировке: расшифрованный текст не должен
     * оставаться в памяти после того, как пользователь заблокировал
     * приложение.
     */
    fun clear() {
        val removed = messages.size
        messages.clear()
        notifyItemRangeRemoved(0, removed)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)

        return ViewHolder(view, onAttachmentClick, onMessageLongClick)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        messages.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = messages.size

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

        /** Заполняет пузырь данными сообщения. */
        fun bind(message: MessageItem) {
            text.text = message.text
            time.text = message.time

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
            bubble.setBackgroundResource(
                if (message.outgoing) {
                    R.drawable.bg_bubble_outgoing
                } else {
                    R.drawable.bg_bubble_incoming
                },
            )

            // Статус показывается только у исходящих: у входящих он
            // не имеет смысла и сбивал бы с толку.
            if (message.outgoing) {
                status.visibility = View.VISIBLE
                status.setImageResource(iconFor(message.status))
                status.imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(itemView.context, tintFor(message.status)),
                )
            } else {
                status.visibility = View.GONE
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
        private fun tintFor(status: DeliveryMark): Int = when (status) {
            DeliveryMark.Read -> R.color.accent_base
            DeliveryMark.Failed -> R.color.status_error
            else -> R.color.text_quaternary
        }
    }
}
