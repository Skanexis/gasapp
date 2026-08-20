// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
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
)

/**
 * Адаптер переписки.
 *
 * 🔐 Держит расшифрованный текст, поэтому очищается при блокировке —
 * см. [MessageAdapter.clear].
 */
class MessageAdapter : RecyclerView.Adapter<MessageAdapter.ViewHolder>() {

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

        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        messages.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = messages.size

    /** Держатель пузыря сообщения. */
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {

        private val container: LinearLayout = view.findViewById(R.id.message_container)
        private val bubble: LinearLayout = view.findViewById(R.id.message_bubble)
        private val text: TextView = view.findViewById(R.id.message_text)
        private val time: TextView = view.findViewById(R.id.message_time)
        private val status: TextView = view.findViewById(R.id.message_status)

        /** Заполняет пузырь данными сообщения. */
        fun bind(message: MessageItem) {
            text.text = message.text
            time.text = message.time

            // Одна раскладка на обе стороны: гравитация и фон решают,
            // где окажется пузырь. Два отдельных layout разошлись бы
            // при первой же правке.
            container.gravity = if (message.outgoing) Gravity.END else Gravity.START
            bubble.setBackgroundResource(
                if (message.outgoing) {
                    R.drawable.bg_bubble_outgoing
                } else {
                    R.drawable.bg_bubble_incoming
                },
            )

            // Статус показывается только у исходящих: у входящих
            // он не имеет смысла и сбивал бы с толку.
            if (message.outgoing) {
                status.visibility = View.VISIBLE
                status.text = markFor(message.status)
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
        private fun markFor(status: DeliveryMark): String = when (status) {
            DeliveryMark.Pending -> "🕐"
            DeliveryMark.Sent -> "✓"
            DeliveryMark.Delivered -> "✓✓"
            DeliveryMark.Read -> "✓✓"
            DeliveryMark.Failed -> "✕"
        }
    }
}
