// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.ui.ChatListAdapter
import org.aegis.app.ui.ChatSummary

/**
 * Экран списка чатов — главный экран приложения.
 *
 * 🔐 Криптографии здесь нет и быть не может: activity показывает то,
 * что подготовило ядро (правило 1, `check-no-crypto-in-ui.sh`).
 *
 * # Про данные на этом экране
 *
 * Пока источник данных — заглушка: связка с `aegis-core` появится
 * вместе с оркестрацией. Экран сверстан по UI kit и проверяем
 * инструментальными тестами уже сейчас — верстать вслепую под
 * несуществующий источник значило бы закреплять догадки о его форме.
 */
class ChatListActivity : AppCompatActivity() {

    private lateinit var adapter: ChatListAdapter
    private lateinit var list: RecyclerView
    private lateinit var empty: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat_list)

        list = findViewById(R.id.chat_list)
        empty = findViewById(R.id.chat_list_empty)

        adapter = ChatListAdapter(onClick = ::openChat)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        findViewById<TextView>(R.id.security_center_badge).apply {
            text = getString(R.string.security_score, SECURITY_SCORE, SECURITY_MAX)
        }

        render(demoChats())
    }

    /**
     * Очищает список при уходе с экрана.
     *
     * 🔐 Превью уже расшифрованы, поэтому не должны переживать сворачивание
     * приложения: скриншот в списке задач покажет их кому угодно, кто
     * возьмёт разблокированное устройство.
     */
    override fun onStop() {
        super.onStop()
        adapter.clear()
    }

    override fun onStart() {
        super.onStart()
        render(demoChats())
    }

    private fun render(chats: List<ChatSummary>) {
        adapter.submit(chats)

        val hasChats = chats.isNotEmpty()
        list.visibility = if (hasChats) View.VISIBLE else View.GONE
        empty.visibility = if (hasChats) View.GONE else View.VISIBLE
    }

    private fun openChat(chat: ChatSummary) {
        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra(ChatActivity.EXTRA_CHAT_ID, chat.chatId)
                .putExtra(ChatActivity.EXTRA_CHAT_NAME, chat.name)
                .putExtra(ChatActivity.EXTRA_VERIFIED, chat.verified),
        )
    }

    /**
     * Демонстрационные чаты для проверки вёрстки.
     *
     * Заменяются данными из `aegis-core`, когда появится оркестрация.
     * Имена взяты из UI kit, чтобы экран совпадал с макетом.
     */
    private fun demoChats(): List<ChatSummary> = listOf(
        ChatSummary(
            chatId = "chat-1",
            name = "Lena Novak",
            preview = "Проверим safety number?",
            time = "14:32",
            verified = true,
        ),
        ChatSummary(
            chatId = "chat-2",
            name = "Alex Vogel",
            preview = "Отправлю файл вечером",
            time = "12:05",
            verified = false,
        ),
        ChatSummary(
            chatId = "chat-3",
            name = "Maria Keller",
            preview = "Спасибо!",
            time = "Вчера",
            verified = true,
        ),
    )

    private companion object {
        /** Текущий счёт Security Center. */
        const val SECURITY_SCORE = 9

        /** Максимальный счёт. */
        const val SECURITY_MAX = 10
    }
}
