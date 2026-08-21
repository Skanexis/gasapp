// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.Core
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.ui.BottomNav
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

        // Щит в шапке ведёт в Security Center. Счёт (9/10) живёт
        // на самом экране Security Center, а не в шапке: цифра без
        // объяснения не говорит пользователю, что именно проверено.
        findViewById<ImageView>(R.id.security_center_badge).setOnClickListener {
            startActivity(Intent(this, SecurityCenterActivity::class.java))
        }

        bindNavigation()
        BottomNav.highlight(this, BottomNav.Tab.Chats)

        findViewById<ImageView>(R.id.chat_list_search).setOnClickListener {
            startActivity(Intent(this, SearchActivity::class.java))
        }
        findViewById<ImageView>(R.id.new_chat_button).setOnClickListener { promptNewChat() }
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
        loadChats()
    }

    /**
     * Читает чаты и превью последних сообщений из ядра.
     *
     * Уходит на `Dispatchers.IO`: переход через границу FFI
     * блокирующий, а внутри — расшифровка сообщений.
     */
    private fun loadChats() {
        lifecycleScope.launch {
            val chats = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()

                    messenger.chats().map { chatId ->
                        // Одно последнее сообщение на чат: превью — это
                        // именно оно, а загружать переписку целиком ради
                        // одной строки значило бы расшифровывать всё
                        // при каждом открытии списка.
                        chatId to messenger.messages(chatId, PREVIEW_LIMIT).lastOrNull()
                    }
                }.getOrDefault(emptyList())
            }

            render(
                chats.map { (chatId, last) ->
                    ChatSummary(
                        chatId = chatId,
                        // Имя собеседника хранится с контактом, а не
                        // с чатом; пока контакт не добавлен, показывается
                        // начало идентификатора — этого хватает, чтобы
                        // отличать чаты друг от друга.
                        name = chatId.take(CHAT_LABEL_CHARS),
                        preview = last?.text.orEmpty(),
                        time = last?.let { formatTime(it.timestamp) }.orEmpty(),
                        verified = false,
                    )
                },
            )
        }
    }

    private fun formatTime(millis: Long): String =
        java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(millis))


    /**
     * Связывает вкладки нижней навигации.
     *
     * `finish()` после перехода: вкладки — это разделы одного уровня,
     * и накопление их в стеке заставляло бы жать «назад» столько раз,
     * сколько было переключений.
     */
    private fun bindNavigation() {
        findViewById<View>(R.id.nav_calls).setOnClickListener {
            startActivity(Intent(this, CallsActivity::class.java))
            finish()
        }
        findViewById<View>(R.id.nav_contacts).setOnClickListener {
            startActivity(Intent(this, ContactsActivity::class.java))
            finish()
        }
        findViewById<View>(R.id.nav_settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
            finish()
        }
    }

    /**
     * Спрашивает имя собеседника и открывает переписку.
     *
     * Поиск по имени, а не по номеру телефона: номер связывает аккаунт
     * с личностью и с записной книжкой всех, у кого он записан
     * (ADR-007). Имя пользователь выбирает сам и может сменить.
     */
    private fun promptNewChat() {
        val input = android.widget.EditText(this).apply {
            hint = getString(R.string.onboarding_username_hint)
            setSingleLine()
            setTextColor(getColor(R.color.text_primary))
            setHintTextColor(getColor(R.color.text_tertiary))
            setPadding(48, 32, 48, 32)
        }

        androidx.appcompat.app.AlertDialog.Builder(this, R.style.AegisDialog)
            .setTitle(R.string.new_chat)
            .setMessage(R.string.new_chat_hint)
            .setView(input)
            .setPositiveButton(R.string.new_chat_open) { _, _ ->
                val username = input.text?.toString()?.trim().orEmpty()
                if (username.isNotEmpty()) {
                    openChatWith(username)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun openChatWith(username: String) {
        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra(ChatActivity.EXTRA_CHAT_NAME, username)
                .putExtra(ChatActivity.EXTRA_PEER_USERNAME, username)
                .putExtra(ChatActivity.EXTRA_VERIFIED, false),
        )
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
    private companion object {
        /** Текущий счёт Security Center. */
        const val SECURITY_SCORE = 9

        /** Максимальный счёт. */
        const val SECURITY_MAX = 10

        /** Сколько сообщений читать ради превью. */
        const val PREVIEW_LIMIT = 1u

        /** Сколько символов идентификатора чата показывать вместо имени. */
        const val CHAT_LABEL_CHARS = 8
    }
}
