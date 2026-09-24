// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.Core
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.TouchTarget
import org.aegis.app.core.showSecure
import org.aegis.app.net.NotificationSocket
import org.aegis.app.ui.BottomNav
import org.aegis.app.ui.ChatListAdapter
import org.aegis.app.ui.ChatSummary
import uniffi.aegis.FfiException

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

        adapter = ChatListAdapter(onClick = ::openChat)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter

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

        bindNavigation()
        BottomNav.highlight(this, BottomNav.Tab.Chats)

        findViewById<ImageView>(R.id.chat_list_search).setOnClickListener {
            startActivity(Intent(this, SearchActivity::class.java))
        }

        // 🔐 Иконка 24dp, область нажатия — 48dp (WCAG 2.5.5).
        // Вид не меняется: увеличивается только то, куда можно
        // попасть. Подробности — в TouchTarget.
        TouchTarget.expand(findViewById(R.id.chat_list_search))
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
                        // Одно последнее сообщение на чат: превью — это
                        // именно оно, а загружать переписку целиком ради
                        // одной строки значило бы расшифровывать всё
                        // при каждом открытии списка.
                        Triple(chatId, messenger.messages(chatId, PREVIEW_LIMIT).lastOrNull(), contacts[chatId])
                    }
                }.getOrDefault(emptyList())
            }

            render(
                chats.map { (chatId, last, contact) ->
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

            // 🔐 Имена собеседников не попадают в словарь клавиатуры.
            imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
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
            .showSecure(this)
    }

    /**
     * Открывает переписку с собеседником, найденным по имени.
     *
     * 🔐 Сначала ядро находит собеседника и записывает контактом —
     * **неподтверждённым**: его ключ назвал сервер. Экран переписки сразу
     * показывает сверку safety number, а писать можно только после неё
     * (или по ссылке/QR самого собеседника).
     */
    private fun openChatWith(username: String) {
        lifecycleScope.launch {
            val found = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().discoverContact(username, System.currentTimeMillis()) }
            }

            val contact = found.getOrElse { failure ->
                Toast.makeText(
                    this@ChatListActivity,
                    if (failure is FfiException.IdentityChanged) R.string.key_changed_title else R.string.new_chat_not_found,
                    Toast.LENGTH_LONG,
                ).show()

                return@launch
            }

            startActivity(
                Intent(this@ChatListActivity, ChatActivity::class.java)
                    .putExtra(ChatActivity.EXTRA_CHAT_ID, contact.chatId.orEmpty())
                    .putExtra(ChatActivity.EXTRA_CHAT_NAME, username)
                    .putExtra(ChatActivity.EXTRA_PEER_USERNAME, username)
                    .putExtra(ChatActivity.EXTRA_VERIFIED, contact.verified),
            )
        }
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
