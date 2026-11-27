// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

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
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppSheet
import org.gasapp.app.core.Core
import org.gasapp.app.core.ReadMarks
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.core.TouchTarget
import org.gasapp.app.net.EmbeddedTor
import org.gasapp.app.net.ClockCheck
import org.gasapp.app.net.NetworkProxy
import org.gasapp.app.net.NotificationHub
import org.gasapp.app.notify.NotifyPrefs
import org.gasapp.app.notify.NotifySetup
import org.gasapp.app.ui.BottomNav
import org.gasapp.app.ui.ChatListAdapter
import org.gasapp.app.ui.ChatSummary
import org.gasapp.app.ui.EmptyState
import org.gasapp.app.ui.RowDivider
import uniffi.gasapp.FfiChatRequest

/**
 * Экран списка чатов — главный экран приложения.
 *
 * 🔐 Криптографии здесь нет и быть не может: activity показывает то,
 * что подготовило ядро (правило 1, `check-no-crypto-in-ui.sh`).
 *
 * # Про данные на этом экране
 *
 * Пока источник данных — заглушка: связка с `gasapp-core` появится
 * вместе с оркестрацией. Экран сверстан по UI kit и проверяем
 * инструментальными тестами уже сейчас — верстать вслепую под
 * несуществующий источник значило бы закреплять догадки о его форме.
 */
class ChatListActivity : AppCompatActivity() {

    private lateinit var adapter: ChatListAdapter
    private lateinit var list: RecyclerView
    private lateinit var empty: View

    /** «Все» или только с непрочитанным — как в Telegram. */
    private var onlyUnread = false
    private var allChats: List<ChatSummary> = emptyList()
    private lateinit var filterAll: TextView
    private lateinit var filterUnread: TextView

    /**
     * Новый конверт — повод забрать очередь: так появляется чат от
     * человека, который написал впервые. Сокет общий на все экраны
     * (см. [NotificationHub]).
     */
    private val onEnvelope: () -> Unit = { syncChats() }

    /** Идёт ли приём очереди; второй одновременно не запускается. */
    private var syncing = false

    /** Пока шёл приём, пришло ещё уведомление: забрать очередь снова. */
    private var syncAgain = false

    /** Время в строке списка. Потокобезопасен, создаётся один раз. */
    private val timeFormat by lazy {
        java.time.format.DateTimeFormatter.ofPattern("HH:mm", java.util.Locale.getDefault())
            .withZone(java.time.ZoneId.systemDefault())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_chat_list)

        list = findViewById(R.id.chat_list)
        setUpFilter()
        empty = findViewById(R.id.chat_list_empty)
        EmptyState.bind(
            empty,
            icon = R.drawable.ic_chat,
            title = R.string.chat_list_empty_title,
            body = R.string.chat_list_empty,
            action = R.string.chat_list_empty_action,
        ) { promptNewChat() }

        adapter = ChatListAdapter(onClick = ::openChat, onLongClick = ::showChatActions)
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
        offerNotifications()
    }

    /**
     * Разрешение на уведомления (Android 13+) — один раз, после входа, и
     * синхронизация токена уведомлений (ADR-040).
     */
    private val askNotifications =
        registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.RequestPermission()) {
            syncNotifications()
        }

    private fun offerNotifications() {
        val prefs = NotifyPrefs(this)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU &&
            prefs.enabled && !prefs.askedPermission &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            prefs.askedPermission = true
            askNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        } else {
            syncNotifications()
        }
    }

    private fun syncNotifications() {
        val app = applicationContext
        org.gasapp.app.core.AppScope.launch(Dispatchers.IO) {
            runCatching { NotifySetup.sync(app, Core.messenger()) }
        }
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
        val strip = findViewById<View>(R.id.connection_strip)
        val progress = findViewById<View>(R.id.connection_progress)

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
                        // Подключение — не тревога: спокойная полоса цвета
                        // акцента с линией прогресса. Жёлтая — только
                        // когда Tor здесь, похоже, заблокирован.
                        val tone = if (blocked) R.color.status_warn else R.color.accent_base
                        banner.setTextColor(getColor(tone))
                        strip.setBackgroundColor(getColor(if (blocked) R.color.bg_raised else R.color.accent_dim))
                        progress.setBackgroundColor(getColor(tone))
                        progress.pivotX = 0f
                        val fraction = if (blocked) 0f else status.percent.toInt().coerceIn(0, 100) / 100f
                        if (strip.visibility == View.VISIBLE && android.animation.ValueAnimator.areAnimatorsEnabled()) {
                            progress.animate().scaleX(fraction).setDuration(TOR_POLL_MS / 2).start()
                        } else {
                            progress.scaleX = fraction
                        }
                        strip.visibility = View.VISIBLE
                        waited = true
                    } else if (ClockCheck.off) {
                        // Часы устройства расходятся с серверными: сервер
                        // отвергает запросы, и без этой полосы всё выглядело
                        // бы как «нет связи». Ведёт в настройки даты.
                        banner.setText(R.string.clock_wrong)
                        banner.setTextColor(getColor(R.color.status_warn))
                        strip.setBackgroundColor(getColor(R.color.bg_raised))
                        progress.setBackgroundColor(getColor(R.color.status_warn))
                        progress.animate().cancel()
                        progress.scaleX = 1f
                        banner.isClickable = true
                        banner.setOnClickListener {
                            runCatching { startActivity(Intent(android.provider.Settings.ACTION_DATE_SETTINGS)) }
                        }
                        strip.visibility = View.VISIBLE
                    } else {
                        strip.visibility = View.GONE

                        if (waited) {
                            waited = false
                            syncChats()
                        }
                    }

                    // Раз в секунду — только пока полоса на экране и
                    // процент меняется. В покое опрос реже: главный
                    // поток не будится ради неизменного ответа.
                    delay(if (connecting) TOR_POLL_MS else TOR_IDLE_POLL_MS)
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

        NotificationHub.unsubscribe(onEnvelope)

        adapter.clear()
    }

    override fun onStart() {
        super.onStart()
        // Приложение открыто: уведомление «есть новое» больше не нужно.
        NotifySetup.onAppOpened(this)

        // Сначала — то, что уже лежит на устройстве: это миллисекунды.
        // Очередь с сервера забирается следом и список не задерживает.
        showLocal()
        // Сервер не спрашивается, если сокет и так слушает с последнего
        // приёма: переход между экранами — не повод для запроса.
        if (!NotificationHub.caughtUp()) syncChats()

        NotificationHub.subscribe(onEnvelope)
    }

    /**
     * Показывает чаты из базы — без сети.
     *
     * Уходит на `Dispatchers.IO`: переход через границу FFI
     * блокирующий, а внутри — расшифровка сообщений.
     */
    private fun showLocal() {
        lifecycleScope.launch {
            val chats = withContext(Dispatchers.IO) { readChats() }

            // 🔐 Экран ушёл, пока читалась база: расшифрованные превью
            // в очищенный список не возвращаются (см. onStop).
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) render(chats)
        }
    }

    /**
     * Забирает очередь с сервера и перечитывает список.
     *
     * 🔐 Приём — здесь, а не только на экране переписки: тот существует
     * лишь для уже известного чата, и первое сообщение от нового
     * собеседника иначе не забиралось бы никогда. Приём общий на весь
     * аккаунт, одного вызова хватает на все переписки.
     *
     * # Почему список не ждёт сеть
     *
     * Прежде чаты читались после приёма, одним заходом: каждый показ
     * экрана — в том числе возврат из переписки — ждал ответа сервера,
     * а через Tor это секунды пустого списка. Теперь сеть только
     * обновляет уже показанное.
     *
     * Один приём за раз: уведомления приходят пачкой, и очередь из
     * одинаковых запросов только занимала бы сеть и батарею.
     */
    private fun syncChats() {
        if (syncing) {
            syncAgain = true

            return
        }

        val device = Core.deviceId ?: return
        syncing = true

        lifecycleScope.launch {
            try {
                do {
                    syncAgain = false

                    val startedAt = android.os.SystemClock.elapsedRealtime()
                    val fetched = withContext(Dispatchers.IO) {
                        runCatching { Core.messenger().receiveMessages(device, System.currentTimeMillis()) }.isSuccess
                    }
                    if (fetched) {
                        NotificationHub.fetched(startedAt)
                        // Две галочки собеседнику — за принятое, в фоне.
                        lifecycleScope.launch(Dispatchers.IO) {
                            runCatching { Core.messenger().sendDeliveryReceipts(System.currentTimeMillis()) }
                        }
                    }

                    // Перечитывается всегда, а не только при новых
                    // сообщениях: приём меняет и статусы, и запросы.
                    // Сбой сети не мешает показать то, что уже есть.
                    showLocal()
                } while (syncAgain && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))
            } finally {
                syncing = false
            }
        }
    }

    /** Читает чаты и превью последних сообщений из ядра. Фоновый поток. */
    private fun readChats(): List<ChatSummary> =
        runCatching {
            val messenger = Core.messenger()

            // Собеседник каждого чата: имя, которым ему отвечают,
            // и отметка о сверке.
            val contacts = messenger.contacts().associateBy { it.chatId }
            val prefs = runCatching { messenger.chatPrefs() }.getOrDefault(emptyList()).associateBy { it.chatId }
            val photos = runCatching { messenger.chatPhotos() }.getOrDefault(emptyList())
                .associate { it.chatId to photoOf(it.chatId, it.image) }

            messenger.chats().map { chatId ->
                // Превью — последнее сообщение. Счётчик считает сам
                // ReadMarks и просматривает переписку, только если есть
                // что считать.
                val last = messenger.messages(chatId, 1u).lastOrNull()
                val contact = contacts[chatId]
                val username = contact?.username.orEmpty()

                ChatSummary(
                    chatId = chatId,
                    // Имя собеседника хранится с контактом, а не
                    // с чатом; пока оно неизвестно, показывается
                    // начало идентификатора — этого хватает, чтобы
                    // отличать чаты друг от друга.
                    name = username.ifEmpty { chatId.take(CHAT_LABEL_CHARS) },
                    preview = last?.let { message ->
                        message.text.ifEmpty { "📎 " + getString(R.string.attachment_document) }
                    }.orEmpty(),
                    time = last?.let { timeFormat.format(java.time.Instant.ofEpochMilli(it.timestamp)) }.orEmpty(),
                    verified = contact?.verified == true,
                    peerUsername = username,
                    request = runCatching { messenger.chatRequest(chatId) }.getOrNull() == FfiChatRequest.INCOMING,
                    unread = runCatching { ReadMarks.unread(messenger, chatId, last) }.getOrDefault(0),
                    pinned = (prefs[chatId]?.pinnedAt ?: 0L) > 0L,
                    muted = prefs[chatId]?.muted == true,
                    photo = photos[chatId],
                )
            }.let { chats ->
                // Закреплённые — наверху (позже закреплённый — выше).
                val pinnedAt = { chat: ChatSummary -> prefs[chat.chatId]?.pinnedAt ?: 0L }
                chats.filter { it.pinned }.sortedByDescending(pinnedAt) + chats.filterNot { it.pinned }
            }
        }.getOrDefault(emptyList())

    /** Уменьшенное фото — один раз на картинку (кеш по чату и содержимому). */
    private fun photoOf(chatId: String, image: ByteArray): android.graphics.Bitmap? {
        val key = chatId + ":" + image.contentHashCode()
        photoCache[key]?.let { return it }
        val options = android.graphics.BitmapFactory.Options().apply { inSampleSize = 2 }
        return android.graphics.BitmapFactory.decodeByteArray(image, 0, image.size, options)
            ?.also { photoCache[key] = it }
    }

    private val photoCache = java.util.concurrent.ConcurrentHashMap<String, android.graphics.Bitmap>()

    /** Долгое нажатие на чат: закрепить, без звука, прочитано, удалить у себя. */
    private fun showChatActions(chat: ChatSummary) {
        val sheet = GasAppSheet.on(this, chat.name)
        sheet.action(getString(if (chat.pinned) R.string.chat_unpin else R.string.chat_pin), R.drawable.ic_pin) {
            changeChat { it.setChatPinned(chat.chatId, !chat.pinned, System.currentTimeMillis()) }
        }
        sheet.action(
            getString(if (chat.muted) R.string.chat_unmute else R.string.chat_mute),
            if (chat.muted) R.drawable.ic_bell else R.drawable.ic_bell_off,
        ) {
            changeChat { it.setChatMuted(chat.chatId, !chat.muted) }
        }
        if (chat.unread > 0) {
            sheet.action(getString(R.string.chat_mark_read), R.drawable.ic_check) {
                changeChat { messenger ->
                    val now = System.currentTimeMillis()
                    messenger.markChatRead(chat.chatId, now)
                    ReadMarks.markRead(messenger, chat.chatId, now)
                }
            }
        }
        sheet.action(getString(R.string.chat_delete), R.drawable.ic_trash, destructive = true) {
            GasAppDialog(this)
                .title(R.string.chat_delete_title)
                .message(R.string.chat_delete_body)
                .secondary()
                .primary(R.string.chat_delete, GasAppDialog.Tone.Danger) {
                    changeChat { it.clearChat(chat.chatId, System.currentTimeMillis()) }
                }
                .show()
        }
        sheet.show()
    }

    private fun changeChat(action: (uniffi.gasapp.Messenger) -> Unit) {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) { runCatching { action(Core.messenger()) } }
            showLocal()
        }
    }

    /**
     * Новый собеседник — экран с @именем и сканером QR.
     *
     * Прежде здесь был диалог с полем имени; добавление по QR жило
     * отдельно. Один экран на оба пути — одна точка входа.
     */
    private fun promptNewChat() {
        startActivity(Intent(this, AddContactActivity::class.java))
    }

    /** Переключатель «Все / Непрочитанные» над списком — в коде: он один. */
    private fun setUpFilter() {
        val density = resources.displayMetrics.density
        fun chip(text: Int, unread: Boolean): TextView = TextView(this).apply {
            setText(text)
            textSize = 14f
            val padX = (14 * density).toInt()
            val padY = (6 * density).toInt()
            setPadding(padX, padY, padX, padY)
            setOnClickListener {
                onlyUnread = unread
                render(allChats)
            }
        }
        filterAll = chip(R.string.chat_filter_all, false)
        filterUnread = chip(R.string.chat_filter_unread, true)
        val row = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            val pad = (12 * density).toInt()
            setPadding(pad, pad / 2, pad, pad / 2)
            addView(filterAll)
            addView(filterUnread, android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = (8 * density).toInt() })
        }
        (list.parent as? android.view.ViewGroup)?.let { parent ->
            parent.addView(row, parent.indexOfChild(list))
        }
        paintFilter()
    }

    private fun paintFilter() {
        for ((chip, active) in listOf(filterAll to !onlyUnread, filterUnread to onlyUnread)) {
            chip.setTextColor(getColor(if (active) R.color.accent_on else R.color.text_secondary))
            chip.background = android.graphics.drawable.GradientDrawable().apply {
                cornerRadius = 100f
                setColor(getColor(if (active) R.color.accent_base else R.color.bg_card))
            }
        }
        val unreadCount = allChats.count { it.unread > 0 && !it.muted }
        filterUnread.text = if (unreadCount > 0) {
            getString(R.string.chat_filter_unread) + " · " + unreadCount
        } else {
            getString(R.string.chat_filter_unread)
        }
    }

    private fun render(chats: List<ChatSummary>) {
        allChats = chats
        paintFilter()
        val shown = if (onlyUnread) chats.filter { it.unread > 0 || it.request } else chats
        adapter.submit(shown)

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
     * Заменяются данными из `gasapp-core`, когда появится оркестрация.
     * Имена взяты из UI kit, чтобы экран совпадал с макетом.
     */
    private companion object {
        /** Как часто проверять подключение Tor, пока он подключается. */
        private const val TOR_POLL_MS = 1_000L

        /** Как часто проверять состояние сети, когда полосы нет. */
        private const val TOR_IDLE_POLL_MS = 3_000L

        /** Текущий счёт Security Center. */
        const val SECURITY_SCORE = 9

        /** Максимальный счёт. */
        const val SECURITY_MAX = 10

        /** Сколько символов идентификатора чата показывать вместо имени. */
        const val CHAT_LABEL_CHARS = 8
    }
}
