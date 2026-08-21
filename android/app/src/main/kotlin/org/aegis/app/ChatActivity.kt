// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisTextField
import org.aegis.app.ui.DeliveryMark
import org.aegis.app.ui.MessageAdapter
import org.aegis.app.ui.MessageItem
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.core.Core
import org.aegis.app.net.NotificationSocket
import uniffi.aegis.FfiDeliveryStatus
import uniffi.aegis.FfiMessage
import uniffi.aegis.canSendToContact

/**
 * Экран переписки.
 *
 * 🔐 Криптографии здесь нет: activity показывает готовые данные
 * и спрашивает у ядра, разрешена ли отправка.
 */
class ChatActivity : AppCompatActivity() {

    private lateinit var adapter: MessageAdapter
    private lateinit var input: AegisTextField
    private lateinit var sendButton: AegisButton
    private lateinit var keyChangeBanner: LinearLayout

    /** Сверял ли пользователь safety number этого контакта. */
    private var wasVerified: Boolean = false

    /** Идентификатор чата в хранилище. */
    private var chatId: String = ""

    /**
     * Имя пользователя собеседника.
     *
     * Отправка адресуется по имени: ядро само найдёт устройство через
     * discovery. Хранить device_id в UI значило бы кешировать то,
     * что меняется при переустановке приложения у собеседника.
     */
    private var peerUsername: String = ""

    /**
     * Сменился ли identity-ключ контакта.
     *
     * Пока задаётся заглушкой: настоящее значение придёт из ядра вместе
     * с оркестрацией. Логика реакции на смену уже настоящая — она и есть
     * то, что важно проверить.
     */
    private var identityChanged: Boolean = false

    /**
     * Сокет уведомлений.
     *
     * 🔐 Открывается при показе экрана и закрывается при уходе с него:
     * постоянно открытый сокет — непрерывный признак присутствия,
     * видимый наблюдателю канала.
     */
    private var notifications: NotificationSocket? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        val chatName = intent.getStringExtra(EXTRA_CHAT_NAME).orEmpty()
        chatId = intent.getStringExtra(EXTRA_CHAT_ID).orEmpty()
        peerUsername = intent.getStringExtra(EXTRA_PEER_USERNAME).orEmpty()
        wasVerified = intent.getBooleanExtra(EXTRA_VERIFIED, false)

        findViewById<TextView>(R.id.chat_title).text = chatName
        findViewById<TextView>(R.id.chat_back).setOnClickListener { finish() }

        input = findViewById(R.id.message_input)
        sendButton = findViewById(R.id.send_button)
        keyChangeBanner = findViewById(R.id.key_change_banner)

        adapter = MessageAdapter()
        findViewById<RecyclerView>(R.id.message_list).apply {
            layoutManager = LinearLayoutManager(context)
            adapter = this@ChatActivity.adapter
        }

        findViewById<TextView>(R.id.chat_verification_state).apply {
            text = getString(
                if (wasVerified) R.string.chat_verified_state else R.string.chat_unverified_state,
            )
            setOnClickListener { openSafetyNumber(chatName) }
        }

        findViewById<AegisButton>(R.id.key_change_verify).setOnClickListener {
            openSafetyNumber(chatName)
        }

        sendButton.setOnClickListener { send() }

        applySendGuard()
    }

    override fun onStart() {
        super.onStart()

        reload()
        fetchIncoming()

        // Уведомления вместо опроса: сообщение появляется, как только
        // сервер поставил конверт в очередь, а не когда пользователь
        // догадался обновить экран.
        Core.deviceId?.let { device ->
            notifications = NotificationSocket(
                baseUrl = BuildConfig.AEGIS_SERVER_URL,
                deviceId = device,
                onEnvelope = { runOnUiThread { fetchIncoming() } },
            ).also { it.connect() }
        }
    }

    /**
     * 🔐 Закрывает сокет и очищает переписку при уходе с экрана.
     *
     * Расшифрованный текст не должен переживать сворачивание
     * приложения, а открытый сокет — это непрерывный признак
     * присутствия, видимый наблюдателю канала.
     */
    override fun onStop() {
        super.onStop()

        notifications?.close()
        notifications = null

        adapter.clear()
    }
    /**
     * 🔐 Применяет запрет отправки при смене ключа.
     *
     * Решение принимает **ядро** ([canSendToContact]), а не этот экран:
     * правило «верифицированному контакту со сменившимся ключом писать
     * нельзя» относится к безопасности, и дублировать его в UI значило бы
     * завести вторую реализацию, которая разойдётся с первой.
     */
    private fun applySendGuard() {
        // 🔐 При недоступном ядре отправка запрещается, а не разрешается.
        //
        // Отказ ядра означает, что проверить смену identity-ключа
        // нечем. Разрешить отправку «на всякий случай» значило бы
        // пропустить сообщение верифицированному контакту, чей ключ
        // мог смениться — то есть, возможно, подменённому собеседнику.
        // Неотправленное сообщение исправимо, отправленное не тому —
        // нет.
        val allowed = runCatching {
            canSendToContact(
                identityChanged = identityChanged,
                wasVerified = wasVerified,
            )
        }.getOrDefault(false)

        sendButton.isEnabled = allowed
        input.isEnabled = allowed
        keyChangeBanner.visibility = if (allowed) View.GONE else View.VISIBLE
    }

    private fun send() {
        val text = input.text?.toString().orEmpty().trim()
        if (text.isEmpty()) {
            return
        }

        // Статус Pending, а не Sent: сообщение ещё не ушло на сервер.
        // Показать «отправлено» до подтверждения значило бы соврать
        // пользователю о состоянии его переписки.
        val localId = "local-${System.currentTimeMillis()}"
        adapter.append(
            MessageItem(
                messageId = localId,
                text = text,
                time = timeNow(),
                outgoing = true,
                status = DeliveryMark.Pending,
            ),
        )

        input.setText("")

        lifecycleScope.launch {
            val sent = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger(this@ChatActivity)
                        .sendMessage(peerUsername, text, System.currentTimeMillis())
                }
            }

            // Отказ показывается крестом, а не молчанием: сообщение,
            // выглядящее отправленным, но не ушедшее, — худший исход,
            // потому что пользователь считает, что его прочитали.
            reload(markFailed = sent.isFailure)
        }
    }

    /**
     * Перечитывает переписку из хранилища.
     *
     * Источник истины — ядро, а не то, что уже показано на экране:
     * иначе список расходился бы с базой после отправки, приёма или
     * возврата на экран.
     */
    private fun reload(markFailed: Boolean = false) {
        lifecycleScope.launch {
            val messages = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger(this@ChatActivity)
                        .messages(chatId, MESSAGE_LIMIT)
                        .map { it.toItem() }
                }.getOrDefault(emptyList())
            }

            if (messages.isEmpty() && markFailed) {
                return@launch
            }

            adapter.submit(messages)
        }
    }

    /** Забирает входящие сообщения с сервера. */
    private fun fetchIncoming() {
        val device = Core.deviceId ?: return

        lifecycleScope.launch {
            val received = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger(this@ChatActivity)
                        .receiveMessages(device, System.currentTimeMillis())
                }.getOrDefault(0u)
            }

            if (received > 0u) {
                reload()
            }
        }
    }

    private fun FfiMessage.toItem(): MessageItem = MessageItem(
        messageId = messageId,
        text = text,
        time = formatTime(timestamp),
        outgoing = outgoing,
        status = when (status) {
            FfiDeliveryStatus.PENDING -> DeliveryMark.Pending
            FfiDeliveryStatus.SENT -> DeliveryMark.Sent
            FfiDeliveryStatus.DELIVERED -> DeliveryMark.Delivered
            FfiDeliveryStatus.READ -> DeliveryMark.Read
            FfiDeliveryStatus.FAILED -> DeliveryMark.Failed
        },
    )

    private fun formatTime(millis: Long): String =
        java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(millis))

    private fun timeNow(): String = formatTime(System.currentTimeMillis())

    private fun openSafetyNumber(peerName: String) {
        startActivity(
            Intent(this, SafetyNumberActivity::class.java)
                .putExtra(SafetyNumberActivity.EXTRA_PEER_NAME, peerName),
        )
    }


    companion object {
        /** Идентификатор чата. */
        const val EXTRA_CHAT_ID = "chat_id"

        /** Отображаемое имя собеседника. */
        const val EXTRA_CHAT_NAME = "chat_name"

        /** Имя пользователя собеседника: по нему адресуется отправка. */
        const val EXTRA_PEER_USERNAME = "peer_username"

        /** Сколько сообщений загружается в переписку. */
        private const val MESSAGE_LIMIT = 200u

        /** Сверен ли safety number. */
        const val EXTRA_VERIFIED = "chat_verified"
    }
}
