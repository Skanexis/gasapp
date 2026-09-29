// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.Core
import org.aegis.app.core.ReadMarks
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.TouchTarget
import org.aegis.app.net.EmbeddedTor
import org.aegis.app.net.NetworkProxy
import org.aegis.app.net.NotificationSocket
import org.aegis.app.ui.BottomNav
import org.aegis.app.ui.ChatListAdapter
import org.aegis.app.ui.ChatSummary
import org.aegis.app.ui.EmptyState
import org.aegis.app.ui.RowDivider
import uniffi.aegis.FfiChatRequest

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
    private lateinit var empty: View

    /**
     * Сокет уведомлений, пока открыт список.
     *
     * Без него новый чат появлялся бы только при переоткрытии экрана.
     */
    private var notifications: NotificationSocket? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_chat_list)

        list = findViewById(R.id.chat_list)
        empty = findViewById(R.id.chat_list_empty)
        EmptyState.bind(
            empty,
            icon = R.drawable.ic_chat,
            title = R.string.chat_list_empty_title,
            body = R.string.chat_list_empty,
            action = R.string.chat_list_empty_action,
        ) { promptNewChat() }

        adapter = ChatListAdapter(onClick = ::openChat)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        list.addItemDecoration(RowDivider(this))

        // Щит в шапке ведёт в Security Center. Счёт (9/10) живёт
        // на самом экране Security Center, а не в шапке: цифра без
        // объяснения не говорит пользователю, что именно проверено.
        findViewById<ImageView>(R.id.security_center_badge).setOnClickListener {
            startActivity(Intent(this, SecurityCenterActivity::class.java))
        }

        // 🔐 Иконка 24dp, область нажатия — 48dp (WCAG 2.5.5).
        // Вид не меняется: увеличивается только то, куда можно
        // попасть. Подробности — в TouchTarget.
        TouchTarget.expand(findViewById(R.id.security_center_badge))
        BottomNav.bind(this, BottomNav.Tab.Chats)

        findViewById<ImageView>(R.id.chat_list_search).setOnClickListener {
            startActivity(Intent(this, SearchActivity::class.java))
        }

        // 🔐 Иконка 24dp, область нажатия — 48dp (WCAG 2.5.5).
        // Вид не меняется: увеличивается только то, куда можно
        // попасть. Подробности — в TouchTarget.
        TouchTarget.expand(findViewById(R.id.chat_list_search))
        findViewById<ImageView>(R.id.new_chat_button).setOnClickListener { promptNewChat() }

        watchTor()
    }

    /**
     * Плашка «Подключение к Tor… N%», пока встроенный Tor не готов.
     *
     * Без неё первые секунды после запуска выглядели бы как «нет
     * сообщений»: запросы ждут Tor. Когда он подключился, очередь
     * забирается заново — первый приём мог не дождаться.
     */
    private fun watchTor() {
        val banner = findViewById<TextView>(R.id.connection_banner)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                var waited = false

                while (true) {
                    val status = EmbeddedTor.status()
                    val connecting = NetworkProxy.viaEmbeddedTor && status.running && !status.ready

                    if (connecting) {
                        // Долго не подключается — возможно, Tor здесь
                        // заблокирован: плашка ведёт к мостам.
                        val blocked = EmbeddedTor.needsUserBridges(this@ChatListActivity)

                        banner.text = when {
                            blocked -> getString(R.string.tor_blocked_hint)
                            status.bridges -> getString(R.string.tor_status_via_bridges, status.percent.toInt())
                            else -> getString(R.string.tor_status_connecting, status.percent.toInt())
                        }
                        banner.isClickable = blocked
                        banner.setOnClickListener(
                            if (blocked) {
                                View.OnClickListener { startActivity(Intent(this@ChatListActivity, NetworkActivity::class.java)) }
                            } else {
                                null
                            },
                        )
                        banner.visibility = View.VISIBLE
                        waited = true
                    } else {
                        banner.visibility = View.GONE

                        if (waited) {
                            waited = false
                            loadChats()
                        }
                    }

                    delay(TOR_POLL_MS)
                }
            }
        }
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

        notifications?.close()
        notifications = null

        adapter.clear()
    }

    override fun onStart() {
        super.onStart()
        loadChats()

        // Новый конверт — повод забрать очередь заново: так появляется
        // чат от человека, который написал впервые.
        Core.deviceId?.let { device ->
            notifications = NotificationSocket(
                baseUrl = BuildConfig.AEGIS_SERVER_URL,
                deviceId = device,
                onEnvelope = { runOnUiThread { loadChats() } },
            ).also { it.connect() }
        }
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

                    // 🔐 Сначала — очередь на сервере.
                    //
                    // Прежде входящие забирал только экран переписки,
                    // а он существует лишь для уже известного чата.
                    // Первое сообщение от нового собеседника не
                    // забиралось никогда: открыть было нечего. Нашлось
                    // только живым обменом с эмулятором — два конверта
                    // лежали на сервере, а список показывал «нет чатов».
                    //
                    // Приём общий на весь аккаунт, а не на чат, поэтому
                    // одного вызова хватает на все переписки. Сбой сети
                    // не мешает показать то, что уже есть.
                    Core.deviceId?.let { device ->
                        runCatching { messenger.receiveMessages(device, System.currentTimeMillis()) }
                    }

                    // Собеседник каждого чата: имя, которым ему отвечают,
                    // и отметка о сверке.
                    val contacts = messenger.contacts().associateBy { it.chatId }

                    messenger.chats().map { chatId ->
                        // Не больше сотни последних сообщений на чат: превью —
                        // последнее из них, счётчик — входящие после отметки
                        // прочтения. Вся переписка ради списка не читается.
                        val recent = messenger.messages(chatId, ReadMarks.SCAN_LIMIT)
                        ChatRow(
                            chatId,
                            recent.lastOrNull(),
                            contacts[chatId],
                            runCatching { messenger.chatRequest(chatId) }.getOrNull() == FfiChatRequest.INCOMING,
                            runCatching { ReadMarks.unread(messenger, chatId, recent) }.getOrDefault(0),
                        )
                    }
                }.getOrDefault(emptyList())
            }

            render(
                chats.map { (chatId, last, contact, request, unread) ->
                    val username = contact?.username.orEmpty()

                    ChatSummary(
                        chatId = chatId,
                        // Имя собеседника хранится с контактом, а не
                        // с чатом; пока оно неизвестно, показывается
                        // начало идентификатора — этого хватает, чтобы
                        // отличать чаты друг от друга.
                        name = username.ifEmpty { chatId.take(CHAT_LABEL_CHARS) },
                        preview = last?.text.orEmpty(),
                        time = last?.let { formatTime(it.timestamp) }.orEmpty(),
                        // Прежде здесь стояло `false` для всех чатов.
                        verified = contact?.verified == true,
                        peerUsername = username,
                        request = request,
                        unread = unread,
                    )
                },
            )
        }
    }

    /** Строка списка до разметки: чат, последнее сообщение, собеседник, запрос. */
    private data class ChatRow(
        val chatId: String,
        val last: uniffi.aegis.FfiMessage?,
        val contact: uniffi.aegis.FfiContact?,
        val request: Boolean,
        val unread: Int,
    )

    private fun formatTime(millis: Long): String =
        java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(millis))



    /**
     * Новый собеседник — экран с @именем и сканером QR.
     *
     * Прежде здесь был диалог с полем имени; добавление по QR жило
     * отдельно. Один экран на оба пути — одна точка входа.
     */
    private fun promptNewChat() {
        startActivity(Intent(this, AddContactActivity::class.java))
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
                // 🔐 Без имени собеседника экран переписки не мог
                // отправить ни слова — прежде оно здесь не передавалось.
                .putExtra(ChatActivity.EXTRA_PEER_USERNAME, chat.peerUsername)
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
        /** Как часто проверять подключение Tor. */
        private const val TOR_POLL_MS = 1_000L

        /** Текущий счёт Security Center. */
        const val SECURITY_SCORE = 9

        /** Максимальный счёт. */
        const val SECURITY_MAX = 10

        /** Сколько символов идентификатора чата показывать вместо имени. */
        const val CHAT_LABEL_CHARS = 8
    }
}
