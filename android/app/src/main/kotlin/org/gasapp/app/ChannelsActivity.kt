// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.gasapp.app.components.GasAppDialog
import org.gasapp.app.components.GasAppSheet
import org.gasapp.app.components.GasAppTextField
import org.gasapp.app.components.GasAppToast
import org.gasapp.app.core.Core
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.core.TouchTarget
import org.gasapp.app.ui.BottomNav
import org.gasapp.app.ui.ChannelForm
import org.gasapp.app.ui.ChatListAdapter
import org.gasapp.app.ui.ChatSummary
import org.gasapp.app.ui.EmptyState
import org.gasapp.app.ui.PostTime
import org.gasapp.app.ui.RowDivider
import uniffi.gasapp.FfiChannel
import uniffi.gasapp.FfiException
import uniffi.gasapp.isChannelLink

/**
 * Каналы: ленты, которые человек читает или ведёт.
 *
 * # Что такое канал здесь
 *
 * Один автор пишет, остальные читают — как канал в Telegram. Отличия
 * следуют из устройства GasApp:
 *
 * * 🔐 сервер хранит записи шифротекстом и не знает, кто их читает:
 *   список каналов живёт только на этом устройстве;
 * * канал находят по ссылке-приглашению или QR-коду — каталога и
 *   поиска каналов нет;
 * * создать канал может только аккаунт с премиумом. Премиум выдаёт
 *   оператор сервера вручную; право проверяет сервер, а не этот экран.
 *
 * Криптографии здесь нет: экран показывает то, что подготовило ядро.
 */
class ChannelsActivity : AppCompatActivity() {

    private lateinit var adapter: ChatListAdapter
    private lateinit var list: RecyclerView
    private lateinit var empty: View

    private val scan = registerForActivityResult(ScanActivity.Contract()) { payload ->
        if (payload != null) join(payload, dialog = null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя —
        // до setContentView, как на остальных экранах.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_channels)

        list = findViewById(R.id.channel_list)
        empty = findViewById(R.id.channel_list_empty)
        EmptyState.bind(
            empty,
            icon = R.drawable.ic_channel,
            title = R.string.channels_empty_title,
            body = R.string.channels_empty,
            action = R.string.channels_join,
        ) { promptJoin() }

        adapter = ChatListAdapter(onClick = ::openChannel)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        list.addItemDecoration(RowDivider(this))

        findViewById<View>(R.id.channels_join).apply {
            setOnClickListener { promptJoin() }
            TouchTarget.expand(this)
        }
        findViewById<View>(R.id.channels_create).setOnClickListener { createOrExplain() }

        BottomNav.bind(this, BottomNav.Tab.Channels)
    }

    override fun onStart() {
        super.onStart()

        // Сначала — то, что уже есть на устройстве: через Tor сеть
        // отвечает секундами, и пустой экран на это время выглядел бы
        // как «каналов нет».
        showLocal()
        syncThenShow()
    }

    /**
     * 🔐 Тексты записей расшифрованы: при уходе с экрана список
     * очищается, как и список чатов.
     */
    override fun onStop() {
        super.onStop()
        adapter.clear()
    }

    private fun showLocal() {
        lifecycleScope.launch {
            render(withContext(Dispatchers.IO) { runCatching { Core.messenger().channels() }.getOrDefault(emptyList()) })
        }
    }

    private fun syncThenShow() {
        lifecycleScope.launch {
            val channels = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()

                    // Сбой сети не мешает показать то, что уже загружено.
                    runCatching { messenger.syncChannels() }
                    // Премиум — заодно: кнопка создания узнаёт о нём до нажатия.
                    runCatching { messenger.refreshPremium(System.currentTimeMillis()) }

                    messenger.channels()
                }.getOrNull()
            }

            channels?.let(::render)
        }
    }

    private fun render(channels: List<FfiChannel>) {
        adapter.submit(
            channels.map { channel ->
                ChatSummary(
                    chatId = channel.channelId,
                    name = channel.title,
                    preview = channel.lastPost
                        ?: channel.description.ifEmpty { getString(R.string.channel_no_posts) },
                    time = channel.lastPostAtMillis?.let { PostTime.short(this, it) }.orEmpty(),
                    verified = false,
                    unread = channel.unread.coerceAtMost(MAX_BADGE).toInt(),
                )
            },
        )

        val hasChannels = channels.isNotEmpty()
        list.visibility = if (hasChannels) View.VISIBLE else View.GONE
        empty.visibility = if (hasChannels) View.GONE else View.VISIBLE
    }

    private fun openChannel(channel: ChatSummary) {
        startActivity(
            Intent(this, ChannelActivity::class.java)
                .putExtra(ChannelActivity.EXTRA_CHANNEL_ID, channel.chatId),
        )
    }

    /** Добавить канал: вставить ссылку или сканировать QR-код. */
    private fun promptJoin() {
        GasAppSheet.on(this, R.string.channels_join)
            .action(getString(R.string.channels_join_paste), R.drawable.ic_link) { promptLink() }
            .action(getString(R.string.channels_join_scan), R.drawable.ic_qr) {
                scan.launch(ScanActivity.Request(R.string.channels_join_scan, R.string.channels_scan_hint))
            }
            .show()
    }

    private fun promptLink() {
        val field = GasAppTextField(this).apply {
            hint = getString(R.string.channels_link_hint)
            maxLines = 3
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = LINK_TEXT_SP
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            // 🔐 Ссылка — это доступ к каналу: клавиатуре незачем её запоминать.
            imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }

        GasAppDialog(this)
            .title(R.string.channels_join_paste)
            .message(R.string.channels_link_help)
            .content(field)
            .secondary()
            .primary(R.string.channels_join_action, closeOnClick = false) { dialog ->
                val link = field.text?.toString().orEmpty().trim()

                if (!isChannelLink(link)) {
                    field.hasError = true
                    dialog.showError(R.string.channels_link_invalid)
                    return@primary
                }

                join(link, dialog)
            }
            .show()
    }

    /**
     * Добавляет канал по ссылке и открывает его.
     *
     * [dialog] — диалог ввода ссылки, если добавление идёт из него:
     * ошибка показывается в нём, набранное не теряется.
     */
    private fun join(link: String, dialog: GasAppDialog.Shown?) {
        if (!isChannelLink(link)) {
            GasAppToast.show(this, R.string.channels_link_invalid, GasAppToast.Tone.Error)
            return
        }

        dialog?.setBusy(true)

        lifecycleScope.launch {
            val joined = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().joinChannel(link, System.currentTimeMillis()) }
            }

            dialog?.setBusy(false)

            joined
                .onSuccess { channel ->
                    dialog?.dismiss()
                    startActivity(
                        Intent(this@ChannelsActivity, ChannelActivity::class.java)
                            .putExtra(ChannelActivity.EXTRA_CHANNEL_ID, channel.channelId),
                    )
                }
                .onFailure { failure ->
                    val message = joinError(failure)
                    dialog?.showError(message) ?: GasAppToast.show(this@ChannelsActivity, message, GasAppToast.Tone.Error)
                }
        }
    }

    /**
     * Почему канал не добавился.
     *
     * Ядро не различает наружу «нет связи», «канал удалён» и «сервер
     * отдаёт не тот канал», а текст ошибки интерфейс не разбирает —
     * поэтому сообщение одно и называет все причины.
     */
    private fun joinError(failure: Throwable): Int =
        if (failure is FfiException.InvalidArgument) R.string.channels_link_invalid else R.string.channels_error_unavailable

    /**
     * Создать канал — или объяснить, почему нельзя.
     *
     * Последний известный ответ о премиуме берётся из базы; если он
     * «нет», сервер спрашивается ещё раз: премиум могли выдать минуту
     * назад.
     */
    private fun createOrExplain() {
        lifecycleScope.launch {
            val premium = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()

                    messenger.premiumCached() ||
                        runCatching { messenger.refreshPremium(System.currentTimeMillis()) }.getOrDefault(false)
                }.getOrDefault(false)
            }

            if (premium) promptCreate() else explainPremium()
        }
    }

    private fun explainPremium() {
        val username = runCatching { Core.messenger().ownUsername() }.getOrNull().orEmpty()

        GasAppDialog(this)
            .title(R.string.premium_required_title)
            .message(getString(R.string.premium_required_body, username))
            .primary(R.string.action_ok)
            .show()
    }

    private fun promptCreate() {
        ChannelForm.show(
            activity = this,
            title = R.string.channels_create,
            action = R.string.channels_create_action,
            message = R.string.channels_create_help,
        ) { name, description, dialog ->
            dialog.setBusy(true)

            lifecycleScope.launch {
                val created = withContext(Dispatchers.IO) {
                    runCatching {
                        Core.messenger().createChannel(name, description, System.currentTimeMillis())
                    }
                }

                dialog.setBusy(false)

                created
                    .onSuccess { channel ->
                        dialog.dismiss()
                        startActivity(
                            Intent(this@ChannelsActivity, ChannelActivity::class.java)
                                .putExtra(ChannelActivity.EXTRA_CHANNEL_ID, channel.channelId),
                        )
                    }
                    .onFailure { failure ->
                        when (failure) {
                            // Премиум сняли между проверкой и созданием.
                            is FfiException.PremiumRequired -> {
                                dialog.dismiss()
                                explainPremium()
                            }
                            is FfiException.InvalidArgument -> dialog.showError(R.string.channel_form_invalid)
                            else -> dialog.showError(R.string.channels_error_network)
                        }
                    }
            }
        }
    }

    private companion object {
        /** Больше этого счётчик непрочитанного не показывает. */
        const val MAX_BADGE = 999uL

        /** Кегль ссылки в поле: длинная строка должна помещаться. */
        const val LINK_TEXT_SP = 12f
    }
}
