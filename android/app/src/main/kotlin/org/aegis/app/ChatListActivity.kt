// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisDialog
import org.aegis.app.components.AegisTextField
import org.aegis.app.core.Core
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
import uniffi.aegis.FfiException
import uniffi.aegis.canonicalUsername

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
                val since = System.currentTimeMillis()

                while (true) {
                    val status = EmbeddedTor.status()
                    val connecting = NetworkProxy.viaEmbeddedTor && status.running && !status.ready

                    if (connecting) {
                        // Долго не подключается — возможно, Tor здесь
                        // заблокирован: плашка ведёт к мостам.
                        val blocked = EmbeddedTor.looksBlocked(status, since)

                        banner.text = if (blocked) {
                            getString(R.string.tor_blocked_hint)
                        } else {
                            getString(R.string.tor_status_connecting, status.percent.toInt())
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
                        // Одно последнее сообщение на чат: превью — это
                        // именно оно, а загружать переписку целиком ради
                        // одной строки значило бы расшифровывать всё
                        // при каждом открытии списка.
                        ChatRow(
                            chatId,
                            messenger.messages(chatId, PREVIEW_LIMIT).lastOrNull(),
                            contacts[chatId],
                            runCatching { messenger.chatRequest(chatId) }.getOrNull() == FfiChatRequest.INCOMING,
                        )
                    }
                }.getOrDefault(emptyList())
            }

            render(
                chats.map { (chatId, last, contact, request) ->
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
    )

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
        // 🔐 Имена собеседников не попадают в словарь клавиатуры:
        // AegisTextField ставит запрет обучения сам.
        val input = AegisTextField(this).apply {
            setHint(R.string.new_chat_field_hint)
            setSingleLine()
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or
                android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            // Вариант «видимый пароль» ставит моноширинный шрифт —
            // возвращается шрифт макета.
            typeface = androidx.core.content.res.ResourcesCompat.getFont(context, R.font.inter)
        }

        val shown = AegisDialog(this)
            .title(R.string.new_chat)
            .message(R.string.new_chat_hint)
            .content(input)
            .secondary()
            .primary(R.string.new_chat_open, closeOnClick = false) { dialog ->
                // Каноничная форма: «@Bob» находит «bob», двойник
                // с кириллицей не находит никого.
                val username = runCatching { canonicalUsername(input.text?.toString().orEmpty()) }
                    .getOrNull()
                    ?.takeIf { it.isNotEmpty() }

                if (username == null) {
                    input.hasError = true
                    dialog.showError(R.string.onboarding_error_username)

                    return@primary
                }

                // Своё имя — не собеседник (ядро отвергнет его и само).
                val own = runCatching { Core.messenger().ownUsername() }.getOrNull()
                if (username == own) {
                    input.hasError = true
                    dialog.showError(R.string.new_chat_own_name)

                    return@primary
                }

                openChatWith(username, dialog)
            }
            .show()

        input.doAfterTextChanged {
            input.hasError = false
            shown.clearError()
        }
        input.requestFocus()
    }

    /**
     * Открывает переписку с собеседником, найденным по имени.
     *
     * 🔐 Сначала ядро находит собеседника и записывает контактом —
     * **неподтверждённым**, пока его ключ не подтвердит журнал ключей
     * (сутки в открытом журнале) или сверка safety number: ключ назвал
     * сервер. Писать до подтверждения нельзя (или по ссылке/QR самого
     * собеседника).
     *
     * Ошибка показывается в диалоге, а не всплывающим сообщением:
     * набранное имя остаётся на месте, и его можно поправить.
     */
    private fun openChatWith(username: String, dialog: AegisDialog.Shown) {
        dialog.setBusy(true)

        lifecycleScope.launch {
            val found = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().discoverContact(username, System.currentTimeMillis()) }
            }

            dialog.setBusy(false)

            val contact = found.getOrElse { failure ->
                dialog.showError(
                    if (failure is FfiException.IdentityChanged) R.string.key_changed_title else R.string.new_chat_not_found,
                )

                return@launch
            }

            dialog.dismiss()

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
        /** Как часто проверять подключение Tor. */
        private const val TOR_POLL_MS = 1_000L

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
