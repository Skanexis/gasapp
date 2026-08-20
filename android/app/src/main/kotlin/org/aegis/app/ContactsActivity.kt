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
 * Экран контактов.
 *
 * Переиспользует [ChatListAdapter]: строка контакта и строка чата
 * совпадают по составу — аватар, имя, подпись. Второй адаптер с той
 * же вёрсткой разошёлся бы с первым при первой правке.
 */
class ContactsActivity : AppCompatActivity() {

    private lateinit var adapter: ChatListAdapter
    private lateinit var list: RecyclerView
    private lateinit var empty: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contacts)

        list = findViewById(R.id.contact_list)
        empty = findViewById(R.id.contact_list_empty)

        adapter = ChatListAdapter(onClick = ::openChat)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

        bindNavigation()
        render(demoContacts())
    }

    /**
     * 🔐 Очищает список при уходе с экрана.
     *
     * Список контактов — это тоже сведения о том, с кем пользователь
     * связан, и в снимке для переключателя задач ему не место.
     */
    override fun onStop() {
        super.onStop()
        adapter.clear()
    }

    override fun onStart() {
        super.onStart()
        render(demoContacts())
    }

    private fun render(contacts: List<ChatSummary>) {
        adapter.submit(contacts)

        val hasContacts = contacts.isNotEmpty()
        list.visibility = if (hasContacts) View.VISIBLE else View.GONE
        empty.visibility = if (hasContacts) View.GONE else View.VISIBLE
    }

    private fun openChat(contact: ChatSummary) {
        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra(ChatActivity.EXTRA_CHAT_ID, contact.chatId)
                .putExtra(ChatActivity.EXTRA_CHAT_NAME, contact.name)
                .putExtra(ChatActivity.EXTRA_VERIFIED, contact.verified),
        )
    }

    private fun bindNavigation() {
        findViewById<View>(R.id.nav_chats).setOnClickListener {
            startActivity(Intent(this, ChatListActivity::class.java))
            finish()
        }
        findViewById<View>(R.id.nav_settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
            finish()
        }
    }

    /**
     * Демонстрационные контакты для проверки вёрстки.
     *
     * Имена из UI kit, чтобы экран совпадал с макетом. Заменяются
     * данными из ядра вместе с оркестрацией.
     */
    private fun demoContacts(): List<ChatSummary> = listOf(
        ChatSummary(
            chatId = "contact-1",
            name = "Alex Vogel",
            preview = getString(R.string.contact_verified, "alex.v"),
            time = "",
            verified = true,
        ),
        ChatSummary(
            chatId = "contact-2",
            name = "Daniel Rios",
            preview = getString(R.string.contact_username, "daniel.r"),
            time = "",
            verified = false,
            online = true,
        ),
        ChatSummary(
            chatId = "contact-3",
            name = "Lena Novak",
            preview = getString(R.string.contact_username, "lena.n"),
            time = "",
            verified = false,
        ),
    )
}
