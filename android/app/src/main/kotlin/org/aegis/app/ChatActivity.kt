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

    /**
     * Сменился ли identity-ключ контакта.
     *
     * Пока задаётся заглушкой: настоящее значение придёт из ядра вместе
     * с оркестрацией. Логика реакции на смену уже настоящая — она и есть
     * то, что важно проверить.
     */
    private var identityChanged: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        val chatName = intent.getStringExtra(EXTRA_CHAT_NAME).orEmpty()
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

        adapter.submit(demoMessages())
        applySendGuard()
    }

    /**
     * 🔐 Очищает переписку при уходе с экрана.
     *
     * Расшифрованный текст не должен переживать сворачивание приложения.
     */
    override fun onStop() {
        super.onStop()
        adapter.clear()
    }

    override fun onStart() {
        super.onStart()
        adapter.submit(demoMessages())
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
        val allowed = canSendToContact(
            identityChanged = identityChanged,
            wasVerified = wasVerified,
        )

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
        adapter.append(
            MessageItem(
                messageId = "local-${System.currentTimeMillis()}",
                text = text,
                time = "сейчас",
                outgoing = true,
                status = DeliveryMark.Pending,
            ),
        )

        input.setText("")
    }

    private fun openSafetyNumber(peerName: String) {
        startActivity(
            Intent(this, SafetyNumberActivity::class.java)
                .putExtra(SafetyNumberActivity.EXTRA_PEER_NAME, peerName),
        )
    }

    /** Демонстрационная переписка для проверки вёрстки. */
    private fun demoMessages(): List<MessageItem> = listOf(
        MessageItem("m1", "Привет! Проверим safety number?", "14:30", false, DeliveryMark.Read),
        MessageItem("m2", "Да, открываю экран сверки.", "14:31", true, DeliveryMark.Read),
        MessageItem("m3", "Совпало — всё в порядке.", "14:32", false, DeliveryMark.Read),
        MessageItem("m4", "Отлично, продолжаем.", "14:32", true, DeliveryMark.Delivered),
    )

    companion object {
        /** Идентификатор чата. */
        const val EXTRA_CHAT_ID = "chat_id"

        /** Отображаемое имя собеседника. */
        const val EXTRA_CHAT_NAME = "chat_name"

        /** Сверен ли safety number. */
        const val EXTRA_VERIFIED = "chat_verified"
    }
}
