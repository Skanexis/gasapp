// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
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
import org.gasapp.app.core.SecureClipboard
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.core.TouchTarget
import org.gasapp.app.ui.ChannelForm
import org.gasapp.app.ui.ChannelPostAdapter
import org.gasapp.app.ui.ChannelPostRow
import org.gasapp.app.ui.EmptyState
import org.gasapp.app.ui.PostTime
import org.gasapp.app.ui.QrDrawable
import org.gasapp.app.ui.initialsOf
import org.gasapp.app.ui.paintAvatar
import uniffi.gasapp.FfiChannel
import uniffi.gasapp.FfiException
import uniffi.gasapp.channelLinkQr

/**
 * Канал: лента записей и — для автора — строка ввода.
 *
 * 🔐 Что здесь важно понимать и что экран говорит человеку прямо:
 *
 * * ссылка-приглашение — это и есть доступ: кто её получил, читает
 *   весь канал, прошлое и будущее. Отозвать её у одного читателя нельзя;
 * * записи проверены подписью автора в ядре: сервер их не подделает,
 *   но может не отдать;
 * * время под записью поставил автор — оно едет внутри шифротекста.
 *
 * Криптографии в этом файле нет: ключ канала экран не видит, только
 * готовую ссылку, которой человек делится сам.
 */
class ChannelActivity : AppCompatActivity() {

    private lateinit var channelId: String
    private lateinit var adapter: ChannelPostAdapter
    private lateinit var posts: RecyclerView
    private lateinit var empty: View
    private lateinit var input: GasAppTextField
    private lateinit var send: ImageView

    private var channel: FfiChannel? = null

    /** Идёт публикация: вторую поверх неё не запускаем. */
    private var publishing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        SecureWindow.apply(this)

        setContentView(R.layout.activity_channel)

        channelId = intent.getStringExtra(EXTRA_CHANNEL_ID).orEmpty()
        if (channelId.isEmpty()) {
            finish()
            return
        }

        posts = findViewById(R.id.channel_posts)
        empty = findViewById(R.id.channel_empty)
        input = findViewById(R.id.channel_input)
        send = findViewById(R.id.channel_send)

        adapter = ChannelPostAdapter()
        posts.layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        posts.adapter = adapter

        findViewById<View>(R.id.channel_back).setOnClickListener { finish() }
        findViewById<View>(R.id.channel_share).apply {
            setOnClickListener { shareLink() }
            TouchTarget.expand(this)
        }
        findViewById<View>(R.id.channel_more).apply {
            setOnClickListener { showActions() }
            TouchTarget.expand(this)
        }
        send.setOnClickListener { publish() }
    }

    override fun onStart() {
        super.onStart()
        if (!::adapter.isInitialized) return

        // Сначала — сохранённое на устройстве, затем — свежее с сервера.
        load(sync = false)
        load(sync = true)
    }

    /** 🔐 Расшифрованные записи и черновик не переживают ухода с экрана. */
    override fun onStop() {
        super.onStop()
        if (!::adapter.isInitialized) return

        adapter.clear()
        input.setText("")
    }

    /**
     * Читает канал и его записи из ядра; с [sync] — сначала забирает
     * новое с сервера. Сбой сети не мешает показать то, что уже есть.
     */
    private fun load(sync: Boolean) {
        lifecycleScope.launch {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()

                    if (sync) runCatching { messenger.syncChannel(channelId) }

                    val found = messenger.channels().firstOrNull { it.channelId == channelId }
                    val entries = messenger.channelPosts(channelId, POSTS_LIMIT)

                    // Открытая лента прочитана.
                    if (found != null) runCatching { messenger.markChannelRead(channelId) }

                    found to entries
                }.getOrNull()
            }

            val (found, entries) = loaded ?: return@launch

            if (found == null) {
                // Канала на устройстве нет: его удалили, пока экран был открыт.
                finish()
                return@launch
            }

            render(found)

            val atEnd = !posts.canScrollVertically(1)
            val before = adapter.lastSeq()

            adapter.submit(
                entries.map { ChannelPostRow(it.seq.toLong(), it.text, PostTime.full(this@ChannelActivity, it.createdAtMillis)) },
            )

            // К новой записи лента едет, только если человек и так был внизу.
            if (entries.isNotEmpty() && (before == null || (atEnd && adapter.lastSeq() != before))) {
                posts.scrollToPosition(entries.size - 1)
            }

            val hasPosts = entries.isNotEmpty()
            posts.isVisible = hasPosts
            empty.isVisible = !hasPosts
        }
    }

    private fun render(found: FfiChannel) {
        channel = found

        findViewById<TextView>(R.id.channel_title).text = found.title
        findViewById<TextView>(R.id.channel_subtitle).setText(
            if (found.owned) R.string.channel_subtitle_owner else R.string.channel_subtitle_reader,
        )
        findViewById<TextView>(R.id.channel_avatar).apply {
            text = initialsOf(found.title)
            paintAvatar(this, found.title)
        }

        findViewById<View>(R.id.channel_input_row).isVisible = found.owned
        findViewById<View>(R.id.channel_reader_note).isVisible = !found.owned

        EmptyState.bind(
            empty,
            icon = R.drawable.ic_channel,
            title = R.string.channel_empty_title,
            body = if (found.owned) R.string.channel_empty_owner else R.string.channel_empty_reader,
        )
    }

    /** Публикует запись из строки ввода. */
    private fun publish() {
        val text = input.text?.toString().orEmpty().trim()
        if (text.isEmpty() || publishing) return

        publishing = true
        send.isEnabled = false

        lifecycleScope.launch {
            val published = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().publishChannelPost(channelId, text, System.currentTimeMillis())
                }
            }

            publishing = false
            send.isEnabled = true

            published
                .onSuccess {
                    // Черновик стирается только после успеха: при сбое
                    // сети набранное остаётся в поле.
                    input.setText("")
                    load(sync = false)
                }
                .onFailure { failure ->
                    GasAppToast.show(
                        this@ChannelActivity,
                        when (failure) {
                            is FfiException.InvalidArgument -> R.string.channel_post_too_long
                            is FfiException.PremiumRequired -> R.string.channel_reader_note
                            else -> R.string.channel_post_failed
                        },
                        GasAppToast.Tone.Error,
                    )
                }
        }
    }

    /**
     * Ссылка-приглашение: QR-код и текст для копирования.
     *
     * 🔐 Диалог говорит, что ссылка — это доступ ко всему каналу.
     */
    private fun shareLink() {
        val link = runCatching { Core.messenger().channelLink(channelId) }.getOrNull() ?: return

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }

        val side = resources.getDimensionPixelSize(R.dimen.channel_qr)
        runCatching { channelLinkQr(link) }.getOrNull()?.let { matrix ->
            content.addView(
                ImageView(this).apply {
                    setImageBitmap(QrDrawable.render(matrix, side))
                    setBackgroundResource(R.drawable.bg_qr_card)
                    val padding = resources.getDimensionPixelSize(R.dimen.space_s)
                    setPadding(padding, padding, padding, padding)
                    contentDescription = getString(R.string.channel_share_qr)
                },
                LinearLayout.LayoutParams(side, side),
            )
        }

        content.addView(
            TextView(this, null, 0, R.style.GasAppText_Mono).apply {
                text = link
                textSize = LINK_TEXT_SP
                setTextColor(getColor(R.color.text_secondary))
                setTextIsSelectable(true)
                maxLines = LINK_MAX_LINES
                ellipsize = android.text.TextUtils.TruncateAt.END
            },
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                topMargin = resources.getDimensionPixelSize(R.dimen.space_m)
            },
        )

        GasAppDialog(this)
            .title(R.string.channel_share)
            .message(R.string.channel_share_warning)
            .content(content)
            .secondary(R.string.action_close)
            .primary(R.string.channel_share_copy) {
                // 🔐 Через защищённый буфер: ссылка — доступ к каналу,
                // и в буфере она живёт ограниченное время.
                SecureClipboard.copySensitive(this, getString(R.string.channel_share), link)
                if (!SecureClipboard.systemConfirmsCopy) {
                    GasAppToast.show(this, R.string.channel_share_copied, GasAppToast.Tone.Success)
                }
            }
            .show()
    }

    private fun showActions() {
        val current = channel ?: return
        val sheet = GasAppSheet.on(this, current.title)

        if (current.owned) {
            sheet.action(getString(R.string.channel_edit), R.drawable.ic_edit) { edit(current) }
            sheet.action(getString(R.string.channel_delete), R.drawable.ic_trash, destructive = true) {
                confirmLeave(owned = true)
            }
        } else {
            if (current.description.isNotEmpty()) {
                sheet.action(getString(R.string.channel_about), R.drawable.ic_info) { showAbout(current) }
            }
            sheet.action(getString(R.string.channel_leave), R.drawable.ic_trash, destructive = true) {
                confirmLeave(owned = false)
            }
        }

        sheet.show()
    }

    private fun showAbout(current: FfiChannel) {
        GasAppDialog(this)
            .title(current.title)
            .message(current.description)
            .primary(R.string.action_close)
            .show()
    }

    private fun edit(current: FfiChannel) {
        ChannelForm.show(
            activity = this,
            title = R.string.channel_edit,
            action = R.string.action_save,
            initialTitle = current.title,
            initialDescription = current.description,
        ) { name, description, dialog ->
            dialog.setBusy(true)

            lifecycleScope.launch {
                val updated = withContext(Dispatchers.IO) {
                    runCatching {
                        Core.messenger().updateChannel(channelId, name, description, System.currentTimeMillis())
                    }
                }

                dialog.setBusy(false)

                updated
                    .onSuccess {
                        dialog.dismiss()
                        render(it)
                    }
                    .onFailure { failure ->
                        dialog.showError(
                            if (failure is FfiException.InvalidArgument) R.string.channel_form_invalid else R.string.channels_error_network,
                        )
                    }
            }
        }
    }

    /**
     * Подтверждение: автор удаляет канал у всех, читатель — только
     * убирает его у себя.
     */
    private fun confirmLeave(owned: Boolean) {
        GasAppDialog(this)
            .title(if (owned) R.string.channel_delete_title else R.string.channel_leave_title)
            .message(if (owned) R.string.channel_delete_body else R.string.channel_leave_body)
            .secondary()
            .primary(
                if (owned) R.string.channel_delete else R.string.channel_leave,
                GasAppDialog.Tone.Danger,
                closeOnClick = false,
            ) { dialog ->
                dialog.setBusy(true)

                lifecycleScope.launch {
                    val left = withContext(Dispatchers.IO) {
                        runCatching { Core.messenger().leaveChannel(channelId, System.currentTimeMillis()) }
                    }

                    dialog.setBusy(false)

                    left
                        .onSuccess {
                            dialog.dismiss()
                            finish()
                        }
                        // Свой канал не удалился с сервера — он остаётся
                        // и на устройстве: иначе пропал бы ключ автора.
                        .onFailure { dialog.showError(R.string.channels_error_network) }
                }
            }
            .show()
    }

    companion object {
        /** Идентификатор канала. */
        const val EXTRA_CHANNEL_ID = "channel_id"

        /** Сколько последних записей показывает лента. */
        private val POSTS_LIMIT = 300u

        private const val LINK_TEXT_SP = 12f
        private const val LINK_MAX_LINES = 6
    }
}
