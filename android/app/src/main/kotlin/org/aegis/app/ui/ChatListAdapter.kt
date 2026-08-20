// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.R

/**
 * Строка списка чатов в том виде, в каком её показывает UI.
 *
 * 🔐 Превью уже расшифровано, поэтому список **не переживает
 * блокировку**: [ChatListAdapter.clear] вызывается при переходе
 * в состояние Locked. Оставить расшифрованный текст в памяти адаптера
 * означало бы, что блокировка защищает только от взгляда на экран,
 * а не от дампа памяти.
 */
data class ChatSummary(
    /** Идентификатор чата. */
    val chatId: String,
    /** Отображаемое имя собеседника. */
    val name: String,
    /** Превью последнего сообщения. */
    val preview: String,
    /** Время последней активности в формате для показа. */
    val time: String,
    /** Сверил ли пользователь safety number лично. */
    val verified: Boolean,
)

/**
 * Адаптер списка чатов.
 *
 * @param onClick вызывается при выборе чата.
 */
class ChatListAdapter(
    private val onClick: (ChatSummary) -> Unit,
) : RecyclerView.Adapter<ChatListAdapter.ViewHolder>() {

    private val chats = mutableListOf<ChatSummary>()

    /** Заменяет содержимое списка. */
    fun submit(items: List<ChatSummary>) {
        chats.clear()
        chats.addAll(items)
        notifyDataSetChanged()
    }

    /**
     * Очищает список.
     *
     * Вызывается при блокировке приложения: расшифрованные превью
     * не должны оставаться в памяти.
     */
    fun clear() {
        val removed = chats.size
        chats.clear()
        notifyItemRangeRemoved(0, removed)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)

        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val chat = chats.getOrNull(position) ?: return

        holder.bind(chat)
        holder.itemView.setOnClickListener { onClick(chat) }
    }

    override fun getItemCount(): Int = chats.size

    /** Держатель строки чата. */
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {

        private val avatar: TextView = view.findViewById(R.id.chat_avatar)
        private val name: TextView = view.findViewById(R.id.chat_name)
        private val preview: TextView = view.findViewById(R.id.chat_preview)
        private val time: TextView = view.findViewById(R.id.chat_time)
        private val verified: TextView = view.findViewById(R.id.chat_verified)

        /** Заполняет строку данными чата. */
        fun bind(chat: ChatSummary) {
            // Инициал вместо загруженного аватара: запрос картинки
            // с сервера раскрывал бы, кто с кем переписывается.
            avatar.text = chat.name.take(1).uppercase()
            name.text = chat.name
            preview.text = chat.preview
            time.text = chat.time

            // Значок сверки показывается только при настоящей верификации:
            // иначе он превращается в украшение, которому перестают верить.
            verified.visibility = if (chat.verified) View.VISIBLE else View.GONE
        }
    }
}
