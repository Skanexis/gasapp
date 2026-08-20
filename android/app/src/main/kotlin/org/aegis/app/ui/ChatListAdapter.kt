// SPDX-License-Identifier: Apache-2.0

package org.aegis.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.R

/** Чат в том виде, в каком его показывает список. */
data class ChatSummary(
    /** Идентификатор чата. */
    val chatId: String,
    /** Отображаемое имя собеседника. */
    val name: String,
    /** Превью последнего сообщения. */
    val preview: String,
    /** Время последней активности. */
    val time: String,
    /** Сверен ли safety number вручную. */
    val verified: Boolean,
    /** Сколько сообщений не прочитано. */
    val unread: Int = 0,
    /** В сети ли собеседник. */
    val online: Boolean = false,
)

/**
 * Адаптер списка чатов.
 *
 * 🔐 Держит расшифрованные превью, поэтому очищается при уходе
 * с экрана — см. [ChatListAdapter.clear].
 */
class ChatListAdapter(private val onClick: (ChatSummary) -> Unit) :
    RecyclerView.Adapter<ChatListAdapter.ViewHolder>() {

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
     * 🔐 Расшифрованные превью не должны переживать сворачивание
     * приложения: снимок экрана в переключателе задач показал бы их
     * любому, кто взял разблокированное устройство.
     */
    fun clear() {
        val removed = chats.size
        chats.clear()
        notifyItemRangeRemoved(0, removed)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)

        return ViewHolder(view, onClick)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        chats.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = chats.size

    /** Держатель строки чата. */
    class ViewHolder(
        view: View,
        private val onClick: (ChatSummary) -> Unit,
    ) : RecyclerView.ViewHolder(view) {

        private val avatar: TextView = view.findViewById(R.id.chat_avatar)
        private val name: TextView = view.findViewById(R.id.chat_name)
        private val preview: TextView = view.findViewById(R.id.chat_preview)
        private val time: TextView = view.findViewById(R.id.chat_time)
        private val verified: ImageView = view.findViewById(R.id.chat_verified)
        private val presence: View = view.findViewById(R.id.chat_presence)
        private val unread: TextView = view.findViewById(R.id.chat_unread)

        /** Заполняет строку данными чата. */
        fun bind(chat: ChatSummary) {
            // Инициалы, а не фото: см. комментарий в раскладке.
            avatar.text = initials(chat.name)
            name.text = chat.name
            preview.text = chat.preview
            time.text = chat.time

            // 🔐 Значок верификации — только у сверенных контактов.
            // Галочка у несверенного означала бы, что проверка
            // произошла, хотя её не было.
            verified.visibility = if (chat.verified) View.VISIBLE else View.GONE

            // Точка присутствия прячется под галочкой, если контакт
            // верифицирован: два значка в одном углу наложились бы.
            presence.visibility = if (chat.online && !chat.verified) {
                View.VISIBLE
            } else {
                View.GONE
            }

            if (chat.unread > 0) {
                unread.visibility = View.VISIBLE
                unread.text = chat.unread.toString()
            } else {
                unread.visibility = View.GONE
            }

            itemView.setOnClickListener { onClick(chat) }
        }

        /**
         * Инициалы для аватара.
         *
         * Берутся две буквы из разных слов, как в макете («Lena Novak»
         * даёт «LN»). Одна буква хуже различает контакты в длинном
         * списке.
         */
        private fun initials(name: String): String {
            val parts = name.split(' ').filter { it.isNotEmpty() }

            return when {
                parts.size >= 2 -> "${parts[0].first()}${parts[1].first()}".uppercase()
                parts.isNotEmpty() -> parts[0].take(2).uppercase()
                else -> "?"
            }
        }
    }
}
