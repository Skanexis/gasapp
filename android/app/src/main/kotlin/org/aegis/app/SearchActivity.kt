// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisTextField
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.ui.ChatListAdapter
import org.aegis.app.ui.ChatSummary
import uniffi.aegis.FfiSearchHit

/**
 * Поиск по переписке.
 *
 * # Где он идёт
 *
 * 🔐 Целиком на устройстве, по расшифрованной базе. Ни запрос, ни
 * результаты наружу не уходят — сервер о поиске не знает вовсе.
 * Серверный поиск потребовал бы отдать ему переписку в открытом виде,
 * то есть отменить сквозное шифрование ради удобства.
 *
 * # Почему без отдельного индекса
 *
 * Ядро ищет по самой таблице сообщений. Отдельный полнотекстовый
 * индекс был бы второй копией переписки, которую тоже пришлось бы
 * стирать при удалении сообщения и при истечении срока, — и о которой
 * при этом легко забыть.
 */
class SearchActivity : AppCompatActivity() {

    private lateinit var adapter: ChatListAdapter
    private lateinit var results: RecyclerView
    private lateinit var empty: TextView

    /** Текущий отложенный поиск; отменяется при следующем нажатии клавиши. */
    private var pending: Job? = null

    /** Чат по идентификатору найденного сообщения — для перехода. */
    private val chatOf = mutableMapOf<String, String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_search)
        findViewById<android.view.View>(R.id.search_back).setOnClickListener { finish() }


        results = findViewById(R.id.search_results)
        empty = findViewById(R.id.search_empty)

        adapter = ChatListAdapter(onClick = ::openChat)
        results.layoutManager = LinearLayoutManager(this)
        results.adapter = adapter

        findViewById<AegisTextField>(R.id.search_query)
            .addTextChangedListener(object : TextWatcher {
                override fun afterTextChanged(text: Editable?) {
                    scheduleSearch(text?.toString().orEmpty())
                }

                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit

                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            })
    }

    /**
     * 🔐 Очищает результаты при уходе с экрана.
     *
     * Найденные сообщения — это расшифрованный текст переписки.
     * В снимке для переключателя задач ему не место.
     */
    override fun onStop() {
        super.onStop()

        pending?.cancel()
        adapter.clear()
        chatOf.clear()
    }

    /**
     * Откладывает поиск на паузу в наборе.
     *
     * Без паузы каждое нажатие клавиши открывало бы базу заново:
     * на слове из пяти букв это пять полных проходов по переписке
     * вместо одного.
     */
    private fun scheduleSearch(query: String) {
        pending?.cancel()

        if (query.isBlank()) {
            render(emptyList())
            return
        }

        pending = lifecycleScope.launch {
            delay(SEARCH_DELAY_MILLIS)

            val hits = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().search(query, SEARCH_LIMIT) }
                    .getOrDefault(emptyList())
            }

            render(hits)
        }
    }

    private fun render(hits: List<FfiSearchHit>) {
        chatOf.clear()

        val items = hits.map { hit ->
            chatOf[hit.message.messageId] = hit.chatId

            ChatSummary(
                // Идентификатор сообщения, а не чата: по нажатию нужно
                // открыть переписку на найденном сообщении, а не
                // в начале.
                chatId = hit.message.messageId,
                name = shortChat(hit.chatId),
                preview = hit.message.text,
                time = formatTime(hit.message.timestamp),
                verified = false,
            )
        }

        adapter.submit(items)

        val found = items.isNotEmpty()
        results.visibility = if (found) View.VISIBLE else View.GONE
        empty.visibility = if (found) View.GONE else View.VISIBLE
    }

    private fun openChat(hit: ChatSummary) {
        val chatId = chatOf[hit.chatId] ?: return

        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra(ChatActivity.EXTRA_CHAT_ID, chatId),
        )
    }

    /**
     * Короткая подпись чата.
     *
     * Имени собеседника у результата нет: сообщение хранится с чатом,
     * а не с контактом. Показывается начало идентификатора — этого
     * хватает, чтобы отличить результаты из разных чатов друг от
     * друга, и не больше.
     */
    private fun shortChat(chatId: String): String = chatId.take(CHAT_LABEL_CHARS)

    private fun formatTime(millis: Long): String =
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(millis))

    private companion object {
        /** Пауза в наборе, после которой запускается поиск. */
        const val SEARCH_DELAY_MILLIS = 250L

        /** Сколько результатов запрашивается у ядра. */
        const val SEARCH_LIMIT = 50u

        /** Сколько символов идентификатора чата показывать. */
        const val CHAT_LABEL_CHARS = 8
    }
}
