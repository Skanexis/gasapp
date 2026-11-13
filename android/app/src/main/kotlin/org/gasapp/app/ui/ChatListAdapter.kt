// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import org.gasapp.app.R

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
    /**
     * Имя собеседника, которым ему отвечают, — пусто, если неизвестно.
     *
     * Без него экран переписки не мог отправить ни слова: прежде
     * список его не передавал вовсе.
     */
    val peerUsername: String = "",
    /** Сколько сообщений не прочитано. */
    val unread: Int = 0,
    /** В сети ли собеседник. */
    val online: Boolean = false,
    /** 🔐 Непринятый входящий запрос на переписку. */
    val request: Boolean = false,
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
        // Разница, а не перерисовка всего списка: обновление приходит
        // на каждое событие сокета, и полная перерисовка мигала строками
        // и сбивала прокрутку.
        val old = chats.toList()

        // Первое заполнение — без разницы и без анимации: строки
        // появляются сразу, а не проявляются по одной после каждого
        // возврата на экран.
        if (old.isEmpty()) {
            chats.addAll(items)
            notifyDataSetChanged()

            return
        }

        val diff = DiffUtil.calculateDiff(
            object : DiffUtil.Callback() {
                override fun getOldListSize() = old.size

                override fun getNewListSize() = items.size

                override fun areItemsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition].chatId == items[newPosition].chatId

                override fun areContentsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition] == items[newPosition]
            },
        )

        chats.clear()
        chats.addAll(items)
        diff.dispatchUpdatesTo(this)
    }

    /**
     * Очищает список.
     *
     * 🔐 Расшифрованные превью не должны переживать сворачивание
     * приложения: снимок экрана в переключателе задач показал бы их
     * любому, кто взял разблокированное устройство.
     */
    fun clear() {
        if (chats.isEmpty()) return

        // Без анимации удаления: экран уже уходит, проигрывать её некому.
        chats.clear()
        notifyDataSetChanged()
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

        // Цвета, начертания и формат чисел — один раз на строку, а не
        // на каждую привязку: прокрутка не должна ходить в ресурсы.
        private val accentColor = androidx.core.content.ContextCompat.getColor(view.context, R.color.accent_base)
        private val quietColor = androidx.core.content.ContextCompat.getColor(view.context, R.color.text_disabled)
        private val regularFace = android.graphics.Typeface.create(time.typeface, 400, false)
        private val strongFace = android.graphics.Typeface.create(time.typeface, 600, false)
        private val pillPaddingX = (8 * view.resources.displayMetrics.density).toInt()
        private val pillPaddingY = (3 * view.resources.displayMetrics.density).toInt()
        private val countFormat = java.text.NumberFormat.getIntegerInstance()

        /** Чат этой строки — для нажатия; слушатель ставится один раз. */
        private var bound: ChatSummary? = null

        init {
            itemView.setOnClickListener { bound?.let(onClick) }
        }

        /** Заполняет строку данными чата. */
        fun bind(chat: ChatSummary) {
            bound = chat

            // Инициалы, а не фото: см. комментарий в раскладке.
            avatar.text = initialsOf(chat.name)
            paintAvatar(avatar, chat.name)
            name.text = chat.name
            preview.text = chat.preview
            // Запрос виден в списке сразу: иначе незнакомец выглядел бы
            // обычной перепиской, а согласия у него ещё нет.
            time.text = if (chat.request) itemView.context.getString(R.string.request_badge) else chat.time
            // Непрочитанное — время акцентом, как в kit (Chat list).
            time.setTextColor(if (chat.request || chat.unread > 0) accentColor else quietColor)
            // Запрос — пилюлей, как прочие состояния в kit; время — простым текстом.
            // Строки переиспользуются, поэтому фон и поля ставятся в обе стороны.
            if (chat.request) {
                time.setBackgroundResource(R.drawable.bg_pill_accent)
                time.setPadding(pillPaddingX, pillPaddingY, pillPaddingX, pillPaddingY)
                time.typeface = strongFace
            } else {
                time.background = null
                time.setPadding(0, 0, 0, 0)
                time.typeface = regularFace
            }

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

                // Через формат локали, а не `toString()`: в части локалей
                // цифры пишутся другими знаками, и счётчик оказывался бы
                // единственным местом интерфейса с латинскими.
                unread.text = countFormat.format(chat.unread.toLong())
            } else {
                unread.visibility = View.GONE
            }
        }
    }
}
