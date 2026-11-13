// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app.ui

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
import org.gasapp.app.R

/**
 * Статус доставки сообщения.
 *
 * Повторяет `DeliveryStatus` из `gasapp-core`, но живёт отдельно: ядро
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

    /** Ряды кнопок под сообщением; пусто — кнопок нет. */
    val buttons: List<List<MessageButton>> = emptyList(),
)

/**
 * Строка переписки: сообщение и его место в группе.
 *
 * Считается один раз на весь список в [MessageAdapter.submit], и разница
 * строится по строкам: новое сообщение меняет форму предыдущего пузыря
 * (он перестаёт быть последним в группе), и DiffUtil перерисует его сам.
 */
/**
 * Кнопка под сообщением собеседника.
 *
 * 🔐 Подпись написал собеседник. Что кнопка отправит и куда ведёт
 * ссылка, интерфейс до нажатия не знает: это отдаёт ядро.
 */
data class MessageButton(
    val label: String,
    /** Открывает ссылку, а не отправляет данные автору. */
    val isLink: Boolean,
)

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

    /** Нажатие кнопки под сообщением: сообщение, ряд, место в ряду. */
    private val onButtonClick: ((MessageItem, Int, Int) -> Unit)? = null,
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

        // Первое заполнение — без разницы и без анимации: переписка
        // появляется сразу, а не поднимается сообщение за сообщением
        // при каждом открытии чата.
        if (old.isEmpty()) {
            rows.addAll(new)
            notifyDataSetChanged()

            return
        }

        val settled = settledIds(old, new)
        val diff = DiffUtil.calculateDiff(
            object : DiffUtil.Callback() {
                override fun getOldListSize() = old.size

                override fun getNewListSize() = new.size

                override fun areItemsTheSame(oldPosition: Int, newPosition: Int): Boolean {
                    val before = old[oldPosition].item.messageId
                    val after = new[newPosition].item.messageId

                    return before == after || settled[before] == after
                }

                override fun areContentsTheSame(oldPosition: Int, newPosition: Int) =
                    old[oldPosition] == new[newPosition]
            },
        )

        rows.clear()
        rows.addAll(new)
        diff.dispatchUpdatesTo(this)
    }

    /**
     * Какому сохранённому сообщению соответствует каждое «местное».
     *
     * Только что отправленное показывается сразу, под временным
     * идентификатором ([LOCAL_ID_PREFIX]); после отправки ядро отдаёт
     * его же под настоящим. Без этой связи разница видела бы удаление
     * и вставку: пузырь исчезал и поднимался заново. Связь — по тексту
     * среди исходящих, которых прежде в списке не было.
     */
    private fun settledIds(old: List<MessageRow>, new: List<MessageRow>): Map<String, String> {
        val locals = old.filter { it.item.messageId.startsWith(LOCAL_ID_PREFIX) }
        if (locals.isEmpty()) return emptyMap()

        val known = old.mapTo(HashSet()) { it.item.messageId }
        val fresh = new.filterTo(ArrayList()) { it.item.outgoing && it.item.messageId !in known }
        val settled = HashMap<String, String>()

        for (local in locals) {
            val match = fresh.firstOrNull { it.item.text == local.item.text } ?: continue

            fresh.remove(match)
            settled[local.item.messageId] = match.item.messageId
        }

        return settled
    }

    /** Сколько сообщений показано. */
    val size: Int
        get() = rows.size

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
        if (rows.isEmpty()) return

        // Без анимации удаления: экран уже уходит, проигрывать её некому.
        rows.clear()
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)

        return ViewHolder(view, onAttachmentClick, onMessageLongClick, onButtonClick)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        rows.getOrNull(position)?.let(holder::bind)
    }

    override fun getItemCount(): Int = rows.size

    companion object {
        /** Начало временного идентификатора ещё не сохранённого сообщения. */
        const val LOCAL_ID_PREFIX = "local-"

        /** Сообщения ближе пяти минут — одна группа. */
        private const val GROUP_GAP_MS = 5 * 60 * 1000L

        /** Высота кнопки под сообщением — не меньше области нажатия. */
        private const val BUTTON_MIN_HEIGHT_DP = 48

        /** Промежуток между кнопками и их внутренний отступ. */
        private const val BUTTON_GAP_DP = 6

        /** Кегль подписи кнопки. */
        private const val BUTTON_TEXT_SP = 14f
    }

    /** Держатель пузыря сообщения. */
    class ViewHolder(
        view: View,
        private val onAttachmentClick: ((AttachmentPreview) -> Unit)?,
        private val onMessageLongClick: ((MessageItem) -> Unit)?,
        private val onButtonClick: ((MessageItem, Int, Int) -> Unit)?,
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

        // Всё, что не зависит от сообщения, считается один раз на
        // держатель: привязка идёт на каждую строку при прокрутке,
        // и поход в ресурсы или новый фон посреди кадра — это рывок.
        private val density = view.resources.displayMetrics.density
        private val gapInGroup = (GAP_IN_GROUP_DP * density).toInt()
        private val gapBetweenGroups = (GAP_BETWEEN_GROUPS_DP * density).toInt()
        private val outgoingInk = ContextCompat.getColor(view.context, R.color.bubble_outgoing_text)
        private val outgoingMeta = ContextCompat.getColor(view.context, R.color.bubble_outgoing_meta)
        private val incomingInk = ContextCompat.getColor(view.context, R.color.text_primary)
        private val incomingMeta = ContextCompat.getColor(view.context, R.color.text_tertiary)
        private val outgoingFill = ContextCompat.getColor(view.context, R.color.bubble_outgoing)
        private val incomingFill = ContextCompat.getColor(view.context, R.color.bg_card)
        private val readTint = ColorStateList.valueOf(outgoingInk)
        private val quietTint = ColorStateList.valueOf(outgoingMeta)
        private val editedLabel = view.context.getString(R.string.message_edited)

        // В sp, как и само время: в dp заполнитель не рос бы вместе
        // с системным шрифтом, и на крупном время наезжало на текст.
        private val metaPx = android.util.TypedValue.applyDimension(
            android.util.TypedValue.COMPLEX_UNIT_SP,
            META_TEXT_SP.toFloat(),
            view.resources.displayMetrics,
        ).toInt()

        /** Фоны пузыря: сторона × примыкание к предыдущему. Свои у каждого держателя. */
        private val shapes = arrayOfNulls<GradientDrawable>(4)

        /** Сообщение этого пузыря — для нажатий; слушатель ставится один раз. */
        private var bound: MessageItem? = null

        init {
            bubble.setOnLongClickListener {
                bound?.let { onMessageLongClick?.invoke(it) }

                // true: событие обработано, и обычное нажатие после
                // него не сработает — иначе меню открывалось бы
                // вместе с другим действием.
                onMessageLongClick != null
            }
        }

        /** Ряды кнопок — последним в пузыре, под текстом и временем. */
        private val buttons: LinearLayout = LinearLayout(view.context).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            bubble.addView(
                this,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ),
            )
        }

        /**
         * Кнопки под сообщением.
         *
         * Кнопка — строка текста на карточке высотой с палец. У кнопки
         * со ссылкой подпись заканчивается стрелкой: человек видит до
         * нажатия, что его уведут из приложения.
         */
        private fun bindButtons(message: MessageItem) {
            if (buttons.childCount > 0) buttons.removeAllViews()
            buttons.visibility = if (message.buttons.isEmpty()) View.GONE else View.VISIBLE

            // Кнопки — редкость (сообщения ботов): у обычного пузыря
            // здесь делать нечего.
            if (message.buttons.isEmpty()) return

            val context = itemView.context
            val gap = (BUTTON_GAP_DP * density).toInt()

            message.buttons.forEachIndexed { rowIndex, row ->
                val line = LinearLayout(context).apply { orientation = LinearLayout.HORIZONTAL }

                row.forEachIndexed { columnIndex, button ->
                    val view = TextView(context).apply {
                        text = if (button.isLink) "${button.label} ↗" else button.label
                        gravity = Gravity.CENTER
                        maxLines = 2
                        ellipsize = android.text.TextUtils.TruncateAt.END
                        textSize = BUTTON_TEXT_SP
                        minHeight = (BUTTON_MIN_HEIGHT_DP * density).toInt()
                        setPadding(gap * 2, gap, gap * 2, gap)
                        setBackgroundResource(R.drawable.bg_card_rounded)
                        setTextColor(ContextCompat.getColor(context, R.color.accent_base))
                        isClickable = true
                        isFocusable = true
                        setOnClickListener { onButtonClick?.invoke(message, rowIndex, columnIndex) }
                    }

                    line.addView(
                        view,
                        LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                            marginStart = if (columnIndex == 0) 0 else gap
                        },
                    )
                }

                buttons.addView(
                    line,
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = gap },
                )
            }
        }

        /** Заполняет пузырь данными сообщения. */
        fun bind(row: MessageRow) {
            val message = row.item
            bound = message

            text.text = withRoomForTime(message)
            time.text = message.time

            day.text = row.day
            day.visibility = if (row.day != null) View.VISIBLE else View.GONE

            // Группа: плотно внутри, воздух между группами.
            container.setPadding(
                container.paddingStart,
                if (row.joinsPrevious) gapInGroup else gapBetweenGroups,
                container.paddingEnd,
                if (row.joinsNext) gapInGroup else gapBetweenGroups,
            )

            // Пустая подпись прячется: пузырь с вложением и без текста
            // иначе оставлял бы пустую строку над файлом.
            text.visibility = if (message.text.isEmpty()) View.GONE else View.VISIBLE

            bindAttachment(message.attachment)
            bindButtons(message)

            editedMark.visibility = if (message.edited) View.VISIBLE else View.GONE

            container.gravity = if (message.outgoing) Gravity.END else Gravity.START
            val shape = bubbleShape(message.outgoing, row.joinsPrevious)
            if (bubble.background !== shape) bubble.background = shape

            // Исходящее — «чернила» акцента с тёмным текстом, входящее —
            // бумага карточки со светлым: сторона читается без подписи.
            val meta = if (message.outgoing) outgoingMeta else incomingMeta
            text.setTextColor(if (message.outgoing) outgoingInk else incomingInk)
            time.setTextColor(meta)
            editedMark.setTextColor(meta)

            // Статус показывается только у исходящих: у входящих он
            // не имеет смысла и сбивал бы с толку.
            if (message.outgoing) {
                status.visibility = View.VISIBLE
                status.setImageResource(iconFor(message.status))
                status.imageTintList = tintFor(message.status)
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
        private fun bubbleShape(outgoing: Boolean, joinsPrevious: Boolean): GradientDrawable {
            val slot = (if (outgoing) 2 else 0) + (if (joinsPrevious) 1 else 0)
            shapes[slot]?.let { return it }

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
                setColor(if (outgoing) outgoingFill else incomingFill)
            }.also { shapes[slot] = it }
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

            val placeholder = buildString {
                append("\u00A0\u00A0")
                if (message.edited) append(editedLabel).append('\u00A0')
                append(message.time)
                // Место под значок статуса у исходящих.
                if (message.outgoing) append("\u00A0\u2003\u2003")
            }

            return SpannableStringBuilder(message.text).apply {
                val start = length
                append(placeholder)
                setSpan(ForegroundColorSpan(Color.TRANSPARENT), start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
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

        private fun tintFor(status: DeliveryMark): ColorStateList = when (status) {
            // На «чернилах» исходящего пузыря: прочитанное — полной
            // краской, остальное — приглушённой; неудача видна формой.
            DeliveryMark.Read, DeliveryMark.Failed -> readTint
            else -> quietTint
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
