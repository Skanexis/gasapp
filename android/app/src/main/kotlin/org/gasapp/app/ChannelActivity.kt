// SPDX-License-Identifier: Apache-2.0

package org.gasapp.app

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
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
import org.gasapp.app.core.AttachmentPrep
import org.gasapp.app.core.Core
import org.gasapp.app.core.FileNames
import org.gasapp.app.core.PendingSave
import org.gasapp.app.core.SecureClipboard
import org.gasapp.app.core.SecureWindow
import org.gasapp.app.core.TouchTarget
import org.gasapp.app.ui.BottomNav
import org.gasapp.app.ui.ChannelAttachmentRow
import org.gasapp.app.ui.ChannelAttachmentView
import org.gasapp.app.ui.ChannelForm
import org.gasapp.app.ui.ChannelGate
import org.gasapp.app.ui.ChannelImages
import org.gasapp.app.ui.ChannelPostAdapter
import org.gasapp.app.ui.ChannelPostRow
import org.gasapp.app.ui.ChannelReactionRow
import org.gasapp.app.ui.EmptyState
import org.gasapp.app.ui.PostTime
import org.gasapp.app.ui.QrDrawable
import org.gasapp.app.ui.initialsOf
import org.gasapp.app.ui.paintAvatar
import uniffi.gasapp.FfiAttachmentFile
import uniffi.gasapp.FfiAttachmentKind
import uniffi.gasapp.FfiChannel
import uniffi.gasapp.FfiChannelAdmin
import uniffi.gasapp.FfiChannelPost
import uniffi.gasapp.FfiChannelRole
import uniffi.gasapp.FfiException
import uniffi.gasapp.canonicalChannelHandle
import uniffi.gasapp.channelAdminRequestQr
import uniffi.gasapp.channelLinkQr
import uniffi.gasapp.channelMediaLimit
import uniffi.gasapp.channelPostAttachmentLimit
import uniffi.gasapp.channelReactions
import uniffi.gasapp.isChannelAdminRequest

/**
 * Канал: лента записей и — для автора — строка ввода.
 *
 * 🔐 Что здесь важно понимать и что экран говорит человеку прямо:
 *
 * * ссылка-приглашение — это и есть доступ: кто её получил, читает
 *   весь канал, прошлое и будущее. Отозвать её у одного читателя нельзя;
 * * записи, правки и удаления проверены подписью автора в ядре: сервер
 *   их не подделает и не откатит, но может не отдать;
 * * время под записью поставил автор — оно едет внутри шифротекста;
 * * счётчики просмотров, подписчиков и реакций — слова сервера, никем
 *   не подписанные. Экран показывает их как статистику;
 * * публичный канал (с `@именем`) сервер прочитать может: автору это
 *   сказано до того, как он нажмёт «сделать публичным».
 *
 * Криптографии в этом файле нет: ключ канала экран не видит, только
 * готовую ссылку, которой человек делится сам.
 */
@Suppress("TooManyFunctions", "LargeClass")
class ChannelActivity : AppCompatActivity() {

    private lateinit var channelId: String
    private lateinit var adapter: ChannelPostAdapter
    private lateinit var images: ChannelImages
    private lateinit var posts: RecyclerView
    private lateinit var empty: View
    private lateinit var input: GasAppTextField
    private lateinit var send: ImageView
    private lateinit var pendingBox: LinearLayout

    private var channel: FfiChannel? = null

    /** Идёт публикация: вторую поверх неё не запускаем. */
    private var publishing = false

    /** Сколько последних записей показывает лента; растёт при листании вверх. */
    private var shown = PAGE

    private var loadingOlder = false

    /** Сервер сказал, что истории старше больше нет. */
    private var historyDone = false

    /**
     * Открыт системный диалог (выбор файла, место сохранения). Экран
     * при этом уходит в фон, но черновик и приложенные файлы должны
     * дождаться возвращения — иначе приложить файл было бы нельзя.
     */
    private var picking = false

    /** Файлы, приложенные к ещё не опубликованной записи. */
    private val pending = mutableListOf<FfiAttachmentFile>()

    /** Вложение, для которого выбирается место сохранения (см. [PendingSave]). */
    private val pendingSave = PendingSave<ChannelAttachmentRow>()

    /** Закрытый канал: приглашения, заявки, подписчики. */
    private val gate by lazy { ChannelGate(this, channelId) { load(sync = true) } }

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
        pendingBox = findViewById(R.id.channel_pending)

        images = ChannelImages(lifecycleScope, channelId)
        adapter = ChannelPostAdapter(
            onLongPress = ::showPostActions,
            onReaction = { post, emoji -> react(post, emoji) },
            onAttachment = ::saveAttachment,
            loadImage = { attachment, view -> images.into(attachment.descriptor, view) },
        )
        posts.layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        posts.adapter = adapter
        posts.addOnScrollListener(
            object : RecyclerView.OnScrollListener() {
                override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                    // Долистали до верха — подгружаем историю.
                    if (dy < 0 && !recyclerView.canScrollVertically(-1)) loadOlder()
                }
            },
        )

        findViewById<View>(R.id.channel_back).setOnClickListener { finish() }
        findViewById<View>(R.id.channel_share).apply {
            setOnClickListener { shareLink() }
            TouchTarget.expand(this)
        }
        findViewById<View>(R.id.channel_more).apply {
            setOnClickListener { showActions() }
            TouchTarget.expand(this)
        }
        findViewById<View>(R.id.channel_pinned).setOnClickListener {
            channel?.pinnedSeq?.toLong()?.takeIf { it > 0 }?.let(::scrollToPost)
        }
        findViewById<View>(R.id.channel_attach).setOnClickListener { chooseAttachment() }
        send.setOnClickListener { publish() }
    }

    override fun onStart() {
        super.onStart()
        if (!::adapter.isInitialized) return

        // Сначала — сохранённое на устройстве, затем — свежее с сервера.
        load(sync = false)
        load(sync = true)
    }

    /**
     * 🔐 Расшифрованные записи и картинки не переживают ухода с экрана.
     * Черновик и приложенные файлы — тоже, кроме одного случая: экран
     * ушёл в фон, потому что человек сам открыл выбор файла ([picking]).
     */
    override fun onStop() {
        super.onStop()
        if (!::adapter.isInitialized) return

        adapter.clear()
        images.clear()
        findViewById<ImageView>(R.id.channel_avatar_image).setImageDrawable(null)

        if (!picking) {
            input.setText("")
            pending.clear()
            renderPending()
        }

        // Сохранение вложения здесь не отменяется: открытый диалог
        // выбора места — это и есть этот `onStop` (см. [PendingSave]).
        pendingSave.onScreenStopped()
    }

    // --- Лента ------------------------------------------------------------

    /** То, что нужно экрану из ядра за один заход. */
    private class Loaded(val channel: FfiChannel?, val posts: List<FfiChannelPost>, val pinned: FfiChannelPost?)

    /**
     * Читает канал и его записи из ядра; с [sync] — сначала забирает
     * новое с сервера. Сбой сети не мешает показать то, что уже есть.
     */
    private fun load(sync: Boolean, then: () -> Unit = {}) {
        lifecycleScope.launch {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()

                    if (sync) runCatching { messenger.syncChannel(channelId, System.currentTimeMillis()) }

                    val found = runCatching { messenger.channel(channelId) }.getOrNull()
                    val entries = messenger.channelPosts(channelId, shown.toUInt())
                    val pinned = found?.pinnedSeq?.takeIf { it > 0uL }?.let {
                        runCatching { messenger.channelPost(channelId, it) }.getOrNull()
                    }

                    // Открытая лента прочитана. Серверу об этом сообщается
                    // от имени аккаунта (из этого складываются просмотры) —
                    // и только вместе с синхронизацией, а не при каждой
                    // перерисовке.
                    if (found != null) {
                        runCatching { messenger.markChannelRead(channelId) }
                        if (sync) runCatching { messenger.reportChannelSeen(channelId, System.currentTimeMillis()) }
                    }

                    Loaded(found, entries, pinned)
                }.getOrNull()
            } ?: return@launch

            val found = loaded.channel

            if (found == null) {
                // Канала на устройстве нет: его удалили, пока экран был открыт.
                finish()
                return@launch
            }

            render(found, loaded.pinned)

            val atEnd = !posts.canScrollVertically(1)
            val before = adapter.lastSeq()

            adapter.submit(loaded.posts.map { rowOf(it, found.pinnedSeq) })

            // К новой записи лента едет, только если человек и так был внизу.
            if (loaded.posts.isNotEmpty() && (before == null || (atEnd && adapter.lastSeq() != before))) {
                posts.scrollToPosition(loaded.posts.size - 1)
            }

            val hasPosts = loaded.posts.isNotEmpty()
            posts.isVisible = hasPosts
            empty.isVisible = !hasPosts

            then()
        }
    }

    private fun rowOf(post: FfiChannelPost, pinnedSeq: ULong): ChannelPostRow =
        ChannelPostRow(
            seq = post.seq.toLong(),
            text = post.text,
            time = PostTime.full(this, post.createdAtMillis),
            edited = post.editedAtMillis != null,
            views = post.views.toLong(),
            reactions = post.reactions.map { ChannelReactionRow(it.emoji, it.count.toLong()) },
            myReaction = post.myReaction,
            attachments = post.attachments.map {
                ChannelAttachmentRow(it.descriptor, it.kind, it.name, it.size.toLong())
            },
            pinned = post.seq == pinnedSeq,
        )

    private fun render(found: FfiChannel, pinned: FfiChannelPost?) {
        channel = found

        findViewById<TextView>(R.id.channel_title).text = found.title
        findViewById<TextView>(R.id.channel_subtitle).text = subtitleOf(found)
        findViewById<TextView>(R.id.channel_avatar).apply {
            text = initialsOf(found.title)
            paintAvatar(this, found.title)
        }
        findViewById<ImageView>(R.id.channel_avatar_image).apply {
            val avatar = found.avatar
            // Из кода, а не из разметки: атрибут разметки работает с API 31.
            clipToOutline = true
            isVisible = avatar != null
            if (avatar != null) images.into(avatar, this)
        }

        findViewById<View>(R.id.channel_pinned).isVisible = pinned != null
        if (pinned != null) {
            findViewById<TextView>(R.id.channel_pinned_text).text =
                pinned.text.ifEmpty { getString(R.string.channel_post_media_only) }
        }

        findViewById<View>(R.id.channel_input_row).isVisible = found.canPost
        findViewById<TextView>(R.id.channel_reader_note).apply {
            isVisible = !found.canPost
            // Заявка показана, но владелец её не принял либо уже снял
            // администратора: писать нельзя, и экран говорит почему.
            setText(
                if (found.role == FfiChannelRole.ADMIN_PENDING) {
                    R.string.channel_admin_pending_note
                } else {
                    R.string.channel_reader_note
                },
            )
        }

        EmptyState.bind(
            empty,
            icon = R.drawable.ic_channel,
            title = R.string.channel_empty_title,
            body = if (found.canPost) R.string.channel_empty_owner else R.string.channel_empty_reader,
        )
    }

    /** Подпись под названием: `@имя`, число подписчиков, роль. */
    private fun subtitleOf(found: FfiChannel): String {
        val parts = mutableListOf<String>()

        found.handle?.let { parts += getString(R.string.channel_handle_format, it) }

        if (found.subscribers > 0uL) {
            val count = found.subscribers.coerceAtMost(Int.MAX_VALUE.toULong()).toInt()
            parts += resources.getQuantityString(R.plurals.channel_subscribers, count, count)
        }

        when (found.role) {
            FfiChannelRole.OWNER -> parts += getString(R.string.channel_role_author)
            FfiChannelRole.ADMIN -> parts += getString(R.string.channel_role_admin)
            else -> Unit
        }
        if (parts.isEmpty()) parts += getString(R.string.channel_subtitle_reader)

        return parts.joinToString(getString(R.string.channel_subtitle_separator))
    }

    /** Листание вверх: сначала то, что есть на устройстве, затем — страница с сервера. */
    private fun loadOlder() {
        if (loadingOlder || adapter.itemCount == 0) return
        // История кончилась, и всё, что есть на устройстве, уже показано.
        if (historyDone && adapter.itemCount < shown) return

        loadingOlder = true

        lifecycleScope.launch {
            val showing = adapter.itemCount

            withContext(Dispatchers.IO) {
                runCatching {
                    val messenger = Core.messenger()
                    val local = messenger.channelPosts(channelId, (shown + PAGE).toUInt())

                    if (local.size <= showing && !historyDone) {
                        // 0 — история кончилась; сбой сети концом истории не считается.
                        val added = runCatching { messenger.loadOlderChannelPosts(channelId, System.currentTimeMillis()) }.getOrNull()
                        if (added == 0u) historyDone = true
                    }
                }
            }

            shown = (shown + PAGE).coerceAtMost(MAX_SHOWN)
            load(sync = false) { loadingOlder = false }
        }
    }

    /** Показывает запись в ленте; если она выше показанного — догружает с устройства. */
    private fun scrollToPost(seq: Long) {
        val position = adapter.positionOf(seq)

        if (position >= 0) {
            posts.scrollToPosition(position)
            return
        }

        if (shown >= MAX_SHOWN) {
            GasAppToast.show(this, R.string.channel_post_not_loaded, GasAppToast.Tone.Info)
            return
        }

        shown = MAX_SHOWN
        load(sync = false) {
            val found = adapter.positionOf(seq)

            if (found >= 0) {
                posts.scrollToPosition(found)
            } else {
                GasAppToast.show(this, R.string.channel_post_not_loaded, GasAppToast.Tone.Info)
            }
        }
    }

    // --- Действия над записью ---------------------------------------------

    private fun showPostActions(post: ChannelPostRow) {
        val current = channel ?: return
        val sheet = GasAppSheet.on(this)

        sheet.action(getString(R.string.channel_post_react), R.drawable.ic_star) { chooseReaction(post) }

        if (post.text.isNotEmpty()) {
            sheet.action(getString(R.string.channel_post_copy), R.drawable.ic_copy) {
                SecureClipboard.copySensitive(this, getString(R.string.channel_post_copy), post.text)
                if (!SecureClipboard.systemConfirmsCopy) {
                    GasAppToast.show(this, R.string.channel_post_copied, GasAppToast.Tone.Success)
                }
            }
        }

        // Править и удалять записи может и администратор; закреп лежит
        // в описании канала, а его подписывает только владелец.
        if (current.canPost) {
            sheet.action(getString(R.string.channel_post_edit), R.drawable.ic_edit) { editPost(post) }
        }
        if (current.owned) {
            sheet.action(
                getString(if (post.pinned) R.string.channel_post_unpin else R.string.channel_post_pin),
                R.drawable.ic_pin,
            ) { pinPost(if (post.pinned) 0 else post.seq) }
        }
        if (current.canPost) {
            sheet.action(getString(R.string.channel_post_delete), R.drawable.ic_trash, destructive = true) {
                confirmDeletePost(post)
            }
        }

        sheet.show()
    }

    /** Набор реакций закрыт сервером: выбирают из него, а не пишут свою. */
    private fun chooseReaction(post: ChannelPostRow) {
        val sheet = GasAppSheet.on(this, R.string.channel_post_react)

        for (emoji in channelReactions()) {
            val mine = emoji == post.myReaction

            sheet.emoji(
                emoji,
                getString(if (mine) R.string.channel_reaction_remove else R.string.channel_reaction_put, emoji),
            ) { react(post, emoji) }
        }

        sheet.show()
    }

    /** Ставит реакцию; повторное нажатие на свою — снимает. */
    private fun react(post: ChannelPostRow, emoji: String) {
        val wanted = emoji.takeIf { it != post.myReaction }

        act(R.string.channel_reaction_failed) {
            Core.messenger().reactToChannelPost(channelId, post.seq.toULong(), wanted, System.currentTimeMillis())
        }
    }

    private fun pinPost(seq: Long) {
        act(R.string.channels_error_network) {
            Core.messenger().pinChannelPost(channelId, seq.toULong(), System.currentTimeMillis())
        }
    }

    /** Выполняет сетевое действие над каналом и перечитывает ленту. */
    private fun act(failure: Int, action: () -> Unit) {
        lifecycleScope.launch {
            val done = withContext(Dispatchers.IO) { runCatching(action) }

            if (done.isSuccess) {
                load(sync = false)
            } else {
                GasAppToast.show(this@ChannelActivity, failure, GasAppToast.Tone.Error)
            }
        }
    }

    private fun editPost(post: ChannelPostRow) {
        val field = GasAppTextField(this).apply {
            setText(post.text)
            setSelection(text?.length ?: 0)
            maxLines = EDIT_MAX_LINES
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            // 🔐 Как и у строки ввода: текст не попадает в сохранённое состояние.
            isSaveEnabled = false
        }

        GasAppDialog(this)
            .title(R.string.channel_post_edit)
            .message(R.string.channel_post_edit_note)
            .content(field)
            .secondary()
            .primary(R.string.action_save, closeOnClick = false) { dialog ->
                val text = field.text?.toString().orEmpty().trim()

                dialog.setBusy(true)

                lifecycleScope.launch {
                    val edited = withContext(Dispatchers.IO) {
                        runCatching {
                            Core.messenger().editChannelPost(
                                channelId,
                                post.seq.toULong(),
                                text,
                                System.currentTimeMillis(),
                            )
                        }
                    }

                    dialog.setBusy(false)

                    edited
                        .onSuccess {
                            dialog.dismiss()
                            load(sync = false)
                        }
                        .onFailure { failure ->
                            dialog.showError(
                                if (failure is FfiException.InvalidArgument) {
                                    R.string.channel_post_invalid
                                } else {
                                    R.string.channels_error_network
                                },
                            )
                        }
                }
            }
            .show()
    }

    private fun confirmDeletePost(post: ChannelPostRow) {
        GasAppDialog(this)
            .title(R.string.channel_post_delete_title)
            .message(R.string.channel_post_delete_body)
            .secondary()
            .primary(R.string.channel_post_delete, GasAppDialog.Tone.Danger, closeOnClick = false) { dialog ->
                dialog.setBusy(true)

                lifecycleScope.launch {
                    val deleted = withContext(Dispatchers.IO) {
                        runCatching {
                            Core.messenger().deleteChannelPost(
                                channelId,
                                post.seq.toULong(),
                                System.currentTimeMillis(),
                            )
                        }
                    }

                    dialog.setBusy(false)

                    deleted
                        .onSuccess {
                            dialog.dismiss()
                            load(sync = false)
                        }
                        .onFailure { dialog.showError(R.string.channels_error_network) }
                }
            }
            .show()
    }

    // --- Сохранение вложения ----------------------------------------------

    /**
     * Сохраняет файл записи туда, куда укажет человек.
     *
     * 🔐 Сначала место, потом скачивание — как в переписке: расшифрованный
     * файл не лежит в памяти, пока открыт диалог, и не пишется во
     * временный файл вне зашифрованного хранилища.
     */
    private fun saveAttachment(attachment: ChannelAttachmentRow) {
        pendingSave.begin(attachment)
        picking = true
        // 🔐 Имя назвал автор канала — до диалога оно проходит ту же
        // очистку, что имя от чужого провайдера.
        saveFile.launch(attachment.name?.let(FileNames::safe) ?: DEFAULT_FILE_NAME)
    }

    private val saveFile = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        picking = false
        val attachment = pendingSave.take()

        if (uri == null || attachment == null) return@registerForActivityResult

        GasAppToast.show(this, R.string.attachment_downloading, GasAppToast.Tone.Info)

        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().fetchChannelMedia(channelId, attachment.descriptor, System.currentTimeMillis())
                }.getOrNull()
            }

            if (bytes == null) {
                // 🔐 Запертое хранилище не выдаётся за сбой файла: пока
                // открыт диалог, автоблокировка успевает сработать.
                if (Core.isUnlocked) {
                    GasAppToast.show(this@ChannelActivity, R.string.channel_media_failed, GasAppToast.Tone.Error)
                }

                return@launch
            }

            val saved = withContext(Dispatchers.IO) {
                runCatching { contentResolver.openOutputStream(uri)?.use { it.write(bytes) } != null }
                    .getOrDefault(false)
            }

            GasAppToast.show(
                this@ChannelActivity,
                if (saved) R.string.attachment_saved else R.string.attachment_download_failed,
                if (saved) GasAppToast.Tone.Success else GasAppToast.Tone.Error,
            )
        }
    }

    // --- Новая запись -----------------------------------------------------

    /** Фото и документы разведены: за ними разные системные диалоги. */
    private fun chooseAttachment() {
        if (pending.size >= channelPostAttachmentLimit().toInt()) {
            GasAppToast.show(this, R.string.channel_attach_limit, GasAppToast.Tone.Warning)
            return
        }

        GasAppSheet.on(this, R.string.attach)
            .action(getString(R.string.attach_photo), R.drawable.ic_image) {
                picking = true
                pickMedia.launch(arrayOf("image/*", "video/*"))
            }
            .action(getString(R.string.attach_file), R.drawable.ic_file) {
                picking = true
                pickDocument.launch(arrayOf("*/*"))
            }
            .show()
    }

    /**
     * 🔐 `OpenDocument`, а не разрешение на галерею: системный диалог
     * отдаёт приложению ровно тот файл, который человек указал.
     */
    private val pickMedia = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        picking = false
        uri?.let {
            // Тип — по MIME, который назвала система, а не по имени файла.
            val video = contentResolver.getType(it)?.startsWith("video/") == true
            attach(it, if (video) FfiAttachmentKind.VIDEO else FfiAttachmentKind.IMAGE)
        }
    }

    private val pickDocument = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        picking = false
        uri?.let { attach(it, FfiAttachmentKind.DOCUMENT) }
    }

    /**
     * Читает выбранный файл и прикладывает его к будущей записи.
     *
     * 🔐 Файл читается в память, а не во временный файл: копия на диске
     * лежала бы открытой вне зашифрованного хранилища. Метаданные фото
     * и видео ядро удалит перед шифрованием; у документов они — часть
     * формата, и человек узнаёт об этом сейчас, до публикации.
     */
    private fun attach(uri: Uri, kind: FfiAttachmentKind) {
        if (!AttachmentPrep.isMediaMime(contentResolver.getType(uri))) {
            GasAppToast.show(this, R.string.channel_attach_document_metadata, GasAppToast.Tone.Warning)
        }

        lifecycleScope.launch {
            val limit = channelMediaLimit().toLong()

            val file = withContext(Dispatchers.IO) {
                runCatching {
                    val raw = readLimited(uri, limit) ?: return@runCatching null
                    if (raw.size > limit) return@runCatching TOO_LARGE

                    // HEIC/AVIF — в JPEG: их метаданные ядро вырезать не может.
                    val bytes = AttachmentPrep.prepare(raw)
                    if (bytes.size > limit) return@runCatching TOO_LARGE

                    FfiAttachmentFile(
                        kind = kind,
                        bytes = bytes,
                        name = displayNameOf(uri),
                        description = null,
                        durationMillis = null,
                        waveform = null,
                    )
                }.getOrNull()
            }

            when {
                file == null ->
                    GasAppToast.show(this@ChannelActivity, R.string.attach_unreadable, GasAppToast.Tone.Error)

                file === TOO_LARGE ->
                    GasAppToast.show(
                        this@ChannelActivity,
                        getString(R.string.channel_attach_too_large, limit / BYTES_IN_MB),
                        GasAppToast.Tone.Error,
                    )

                else -> {
                    pending.add(file)
                    renderPending()
                }
            }
        }
    }

    /** Читает не больше предела плюс байт: гигабайтный файл не читается ради отказа. */
    private fun readLimited(uri: Uri, limit: Long): ByteArray? =
        contentResolver.openInputStream(uri)?.use { stream ->
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(READ_BUFFER)
            var total = 0L

            while (total <= limit) {
                val read = stream.read(buffer)
                if (read < 0) break
                out.write(buffer, 0, read)
                total += read
            }

            out.toByteArray()
        }

    /** 🔐 Имя — от чужого провайдера: только через [FileNames.safe]. */
    private fun displayNameOf(uri: Uri): String? =
        runCatching {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)

                if (column >= 0 && cursor.moveToFirst()) cursor.getString(column)?.let(FileNames::safe) else null
            }
        }.getOrNull()

    private fun renderPending() {
        pendingBox.removeAllViews()
        pendingBox.isVisible = pending.isNotEmpty()

        val inflater = LayoutInflater.from(this)

        for (file in pending.toList()) {
            val row = inflater.inflate(R.layout.item_channel_attachment, pendingBox, false)

            ChannelAttachmentView.bind(row, file.kind, file.name, file.bytes.size.toLong())
            row.findViewById<View>(R.id.attachment_remove).apply {
                isVisible = true
                setOnClickListener {
                    pending.remove(file)
                    renderPending()
                }
            }

            pendingBox.addView(row)
        }
    }

    /** Публикует запись: текст из строки ввода и приложенные файлы. */
    private fun publish() {
        val text = input.text?.toString().orEmpty().trim()
        val files = pending.toList()

        if ((text.isEmpty() && files.isEmpty()) || publishing) return

        publishing = true
        send.isEnabled = false

        if (files.isNotEmpty()) {
            GasAppToast.show(this, R.string.channel_publishing_files, GasAppToast.Tone.Info)
        }

        lifecycleScope.launch {
            val published = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().publishChannelPost(channelId, text, files, System.currentTimeMillis())
                }
            }

            publishing = false
            send.isEnabled = true

            published
                .onSuccess {
                    // Черновик и файлы стираются только после успеха: при
                    // сбое сети набранное и приложенное остаются.
                    input.setText("")
                    pending.clear()
                    renderPending()
                    load(sync = false)
                }
                .onFailure { failure ->
                    GasAppToast.show(
                        this@ChannelActivity,
                        when (failure) {
                            is FfiException.InvalidArgument -> R.string.channel_post_invalid
                            is FfiException.PremiumRequired -> R.string.channel_reader_note
                            else -> R.string.channel_post_failed
                        },
                        GasAppToast.Tone.Error,
                    )
                }
        }
    }

    // --- Ссылка -----------------------------------------------------------

    /**
     * Ссылка-приглашение: QR-код и текст для копирования.
     *
     * 🔐 Диалог говорит, что ссылка — это доступ ко всему каналу.
     */
    private fun shareLink() {
        // 🔐 Ссылкой закрытого канала не делятся: в ней ключ чтения, а
        // входят в такой канал по заявке — по ссылке-приглашению.
        channel?.takeIf { it.closed }?.let { current ->
            if (current.canPost) {
                gate.showInvites()
            } else {
                GasAppToast.show(this, R.string.channel_closed_share_member, GasAppToast.Tone.Info)
            }
            return
        }

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

    // --- Действия с каналом -----------------------------------------------

    private fun showActions() {
        val current = channel ?: return
        val sheet = GasAppSheet.on(this, current.title)

        sheet.action(getString(R.string.channel_about), R.drawable.ic_info) { showAbout(current) }
        sheet.action(getString(R.string.channel_search), R.drawable.ic_search) { promptSearch() }
        sheet.action(
            getString(if (current.muted) R.string.channel_unmute else R.string.channel_mute),
            if (current.muted) R.drawable.ic_bell else R.drawable.ic_bell_off,
        ) { setMuted(!current.muted) }

        // Закрытый канал ведут владелец и администраторы: приглашения,
        // заявки и подписчики — у обоих.
        if (current.closed && current.canPost) {
            sheet.action(getString(R.string.channel_requests), R.drawable.ic_shield_check) { gate.showRequests() }
            sheet.action(getString(R.string.channel_invites), R.drawable.ic_link) { gate.showInvites() }
            sheet.action(getString(R.string.channel_members), R.drawable.ic_users) { gate.showSubscribers() }
        }

        if (current.owned) {
            sheet.action(getString(R.string.channel_edit), R.drawable.ic_edit) { edit(current) }
            sheet.action(getString(R.string.channel_avatar_set), R.drawable.ic_image) {
                picking = true
                pickAvatar.launch(arrayOf("image/*"))
            }
            if (current.avatar != null) {
                sheet.action(getString(R.string.channel_avatar_remove), R.drawable.ic_close) { setAvatar(null) }
            }
            sheet.action(
                getString(if (current.handle == null) R.string.channel_public_make else R.string.channel_public_manage),
                R.drawable.ic_globe,
            ) { managePublic(current) }
            sheet.action(
                getString(if (current.closed) R.string.channel_open else R.string.channel_close),
                R.drawable.ic_lock,
            ) { gate.confirmClosed(current) }
            sheet.action(getString(R.string.channel_admins), R.drawable.ic_users) { showAdmins() }
            sheet.action(getString(R.string.channel_delete), R.drawable.ic_trash, destructive = true) {
                confirmLeave(owned = true)
            }
        } else {
            // Действующему администратору проситься незачем.
            if (current.role != FfiChannelRole.ADMIN) {
                sheet.action(getString(R.string.channel_admin_request), R.drawable.ic_key) { showAdminRequest() }
            }
            sheet.action(getString(R.string.channel_leave), R.drawable.ic_trash, destructive = true) {
                confirmLeave(owned = false)
            }
        }

        sheet.show()
    }

    /** О канале: описание, имя, подписчики — и чьи это числа. */
    private fun showAbout(current: FfiChannel) {
        val lines = mutableListOf<String>()

        if (current.description.isNotEmpty()) lines += current.description
        current.handle?.let { lines += getString(R.string.channel_about_public, it) }
        if (current.rekeyPending) lines += getString(R.string.channel_about_rekey_pending)
        if (current.closed) {
            lines += getString(R.string.channel_about_closed)
        } else if (current.handle == null) {
            lines += getString(R.string.channel_about_private)
        }
        lines += getString(R.string.channel_about_counters)

        GasAppDialog(this)
            .title(current.title)
            .message(lines.joinToString("\n\n"))
            .primary(R.string.action_close)
            .show()
    }

    private fun setMuted(muted: Boolean) {
        lifecycleScope.launch {
            val updated = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().setChannelMuted(channelId, muted) }.getOrNull()
            } ?: return@launch

            channel = updated
            BottomNav.refreshChannelBadge(this@ChannelActivity)
            GasAppToast.show(
                this@ChannelActivity,
                if (muted) R.string.channel_muted else R.string.channel_unmuted,
                GasAppToast.Tone.Success,
            )
        }
    }

    /** Поиск по записям — на устройстве: сервер текста записей не знает. */
    private fun promptSearch() {
        val field = GasAppTextField(this).apply {
            hint = getString(R.string.channel_search_hint)
            maxLines = 1
            inputType = InputType.TYPE_CLASS_TEXT
            isSaveEnabled = false
        }

        GasAppDialog(this)
            .title(R.string.channel_search)
            .message(R.string.channel_search_note)
            .content(field)
            .secondary()
            .primary(R.string.channel_search_action, closeOnClick = false) { dialog ->
                val query = field.text?.toString().orEmpty().trim()
                if (query.isEmpty()) return@primary

                dialog.setBusy(true)

                lifecycleScope.launch {
                    val found = withContext(Dispatchers.IO) {
                        runCatching { Core.messenger().searchChannelPosts(channelId, query, SEARCH_LIMIT) }
                            .getOrDefault(emptyList())
                    }

                    dialog.setBusy(false)

                    if (found.isEmpty()) {
                        dialog.showError(R.string.channel_search_empty)
                    } else {
                        dialog.dismiss()
                        showSearchResults(found)
                    }
                }
            }
            .show()
    }

    private fun showSearchResults(found: List<FfiChannelPost>) {
        val sheet = GasAppSheet.on(this, R.string.channel_search)

        for (post in found) {
            val snippet = post.text.replace('\n', ' ').take(SNIPPET_CHARS)

            sheet.action(
                getString(R.string.channel_search_result, PostTime.short(this, post.createdAtMillis), snippet),
            ) { scrollToPost(post.seq.toLong()) }
        }

        sheet.show()
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
                        load(sync = false)
                    }
                    .onFailure { failure ->
                        dialog.showError(
                            if (failure is FfiException.InvalidArgument) R.string.channel_form_invalid else R.string.channels_error_network,
                        )
                    }
            }
        }
    }

    private val pickAvatar = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        picking = false
        uri ?: return@registerForActivityResult

        lifecycleScope.launch {
            val picture = withContext(Dispatchers.IO) {
                runCatching { readLimited(uri, AVATAR_SOURCE_LIMIT)?.let(AttachmentPrep::avatar) }.getOrNull()
            }

            if (picture == null) {
                GasAppToast.show(this@ChannelActivity, R.string.channel_avatar_unreadable, GasAppToast.Tone.Error)
            } else {
                setAvatar(picture)
            }
        }
    }

    private fun setAvatar(picture: ByteArray?) {
        GasAppToast.show(this, R.string.channel_avatar_saving, GasAppToast.Tone.Info)

        act(R.string.channels_error_network) {
            Core.messenger().setChannelAvatar(channelId, picture, System.currentTimeMillis())
        }
    }

    /**
     * Публичное имя канала.
     *
     * 🔐 Предупреждение — до действия: публичному каналу сервер получает
     * ссылку, а с ней ключ чтения. Это нельзя сказать после.
     */
    private fun managePublic(current: FfiChannel) {
        if (current.handle == null) {
            promptHandle(initial = "")
            return
        }

        GasAppSheet.on(this, getString(R.string.channel_handle_format, current.handle))
            .action(getString(R.string.channel_public_rename), R.drawable.ic_edit) {
                promptHandle(initial = current.handle.orEmpty())
            }
            .action(getString(R.string.channel_public_close), R.drawable.ic_lock) { confirmMakePrivate() }
            .show()
    }

    private fun promptHandle(initial: String) {
        val field = GasAppTextField(this).apply {
            hint = getString(R.string.channel_handle_hint)
            setText(initial)
            setSelection(text?.length ?: 0)
            maxLines = 1
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }

        GasAppDialog(this)
            .title(R.string.channel_public_make)
            .message(R.string.channel_public_warning)
            .content(field)
            .secondary()
            .primary(R.string.channel_public_action, closeOnClick = false) { dialog ->
                // Имя проверяется тем же правилом, что и на сервере.
                val handle = canonicalChannelHandle(field.text?.toString().orEmpty())

                if (handle == null) {
                    field.hasError = true
                    dialog.showError(R.string.channel_handle_invalid)
                    return@primary
                }

                dialog.setBusy(true)

                lifecycleScope.launch {
                    val updated = withContext(Dispatchers.IO) {
                        runCatching {
                            Core.messenger().setChannelHandle(channelId, handle, System.currentTimeMillis())
                        }
                    }

                    dialog.setBusy(false)

                    updated
                        .onSuccess {
                            dialog.dismiss()
                            load(sync = false)
                        }
                        .onFailure { failure ->
                            dialog.showError(
                                when (failure) {
                                    is FfiException.UsernameTaken -> R.string.channel_handle_taken
                                    is FfiException.InvalidArgument -> R.string.channel_handle_invalid
                                    else -> R.string.channels_error_network
                                },
                            )
                        }
                }
            }
            .show()
    }

    private fun confirmMakePrivate() {
        GasAppDialog(this)
            .title(R.string.channel_public_close)
            .message(R.string.channel_public_close_body)
            .secondary()
            .primary(R.string.channel_public_close_action) {
                act(R.string.channels_error_network) {
                    Core.messenger().setChannelHandle(channelId, null, System.currentTimeMillis())
                }
            }
            .show()
    }

    // --- Администраторы -----------------------------------------------------

    /**
     * Заявка на администрирование: QR-код и строка, которые читатель
     * показывает владельцу канала.
     *
     * 🔐 Секретов в заявке нет, но она называет владельцу устройство,
     * а серверу — аккаунт: администратор, в отличие от читателя, серверу
     * известен. Диалог говорит это до того, как заявку покажут.
     */
    private fun showAdminRequest() {
        lifecycleScope.launch {
            val request = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().channelAdminRequest(channelId) }.getOrNull()
            } ?: return@launch

            // Ключ для заявки только что заведён: роль в канале изменилась.
            load(sync = false)

            val content = LinearLayout(this@ChannelActivity).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
            }

            val side = resources.getDimensionPixelSize(R.dimen.channel_qr)
            runCatching { channelAdminRequestQr(request) }.getOrNull()?.let { matrix ->
                content.addView(
                    ImageView(this@ChannelActivity).apply {
                        setImageBitmap(QrDrawable.render(matrix, side))
                        setBackgroundResource(R.drawable.bg_qr_card)
                        val padding = resources.getDimensionPixelSize(R.dimen.space_s)
                        setPadding(padding, padding, padding, padding)
                        contentDescription = getString(R.string.channel_admin_request_qr)
                    },
                    LinearLayout.LayoutParams(side, side),
                )
            }

            GasAppDialog(this@ChannelActivity)
                .title(R.string.channel_admin_request)
                .message(R.string.channel_admin_request_body)
                .content(content)
                .secondary(R.string.action_close)
                .primary(R.string.channel_admin_request_copy) {
                    SecureClipboard.copySensitive(
                        this@ChannelActivity,
                        getString(R.string.channel_admin_request),
                        request,
                    )
                    if (!SecureClipboard.systemConfirmsCopy) {
                        GasAppToast.show(
                            this@ChannelActivity,
                            R.string.channel_admin_request_copied,
                            GasAppToast.Tone.Success,
                        )
                    }
                }
                .show()
        }
    }

    /** Администраторы канала — для владельца: список, назначение, снятие. */
    private fun showAdmins() {
        lifecycleScope.launch {
            val admins = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().channelAdmins(channelId) }.getOrDefault(emptyList())
            }

            val sheet = GasAppSheet.on(this@ChannelActivity, R.string.channel_admins)

            sheet.action(getString(R.string.channel_admin_add), R.drawable.ic_plus) { chooseAdminSource() }

            for (admin in admins) {
                val name = admin.label.ifEmpty { getString(R.string.channel_admin_unnamed, admin.verifyKey.take(KEY_HINT_CHARS)) }

                if (admin.active) {
                    sheet.action(getString(R.string.channel_admin_active, name), R.drawable.ic_users) {
                        confirmRemoveAdmin(admin, name)
                    }
                } else {
                    // Снятый остаётся в списке: по его ключу читаются
                    // записи, которые он успел написать.
                    sheet.action(getString(R.string.channel_admin_removed, name), R.drawable.ic_block) {
                        GasAppToast.show(
                            this@ChannelActivity,
                            R.string.channel_admin_removed_note,
                            GasAppToast.Tone.Info,
                        )
                    }
                }
            }

            sheet.show()
        }
    }

    private fun chooseAdminSource() {
        GasAppSheet.on(this, R.string.channel_admin_add)
            .action(getString(R.string.channel_admin_paste), R.drawable.ic_link) { promptAdmin(request = "") }
            .action(getString(R.string.channel_admin_scan), R.drawable.ic_qr) {
                picking = true
                scanAdmin.launch(
                    ScanActivity.Request(R.string.channel_admin_scan, R.string.channel_admin_scan_hint),
                )
            }
            .show()
    }

    private val scanAdmin = registerForActivityResult(ScanActivity.Contract()) { payload ->
        picking = false

        when {
            payload == null -> Unit
            isChannelAdminRequest(payload) -> promptAdmin(request = payload)
            else -> GasAppToast.show(this, R.string.channel_admin_invalid, GasAppToast.Tone.Error)
        }
    }

    /**
     * Назначение администратора: заявка и имя для себя.
     *
     * 🔐 Что получает администратор, сказано до кнопки: писать, править
     * и удалять записи от имени канала. Имя остаётся на этом телефоне
     * и в резервной копии — читатели канала его не видят.
     */
    private fun promptAdmin(request: String) {
        val form = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val code = GasAppTextField(this).apply {
            hint = getString(R.string.channel_admin_code_hint)
            setText(request)
            maxLines = CODE_MAX_LINES
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = LINK_TEXT_SP
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val name = GasAppTextField(this).apply {
            hint = getString(R.string.channel_admin_name_hint)
            maxLines = 1
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
        }

        form.addView(code)
        form.addView(
            name,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                topMargin = resources.getDimensionPixelSize(R.dimen.space_s)
            },
        )

        GasAppDialog(this)
            .title(R.string.channel_admin_add)
            .message(R.string.channel_admin_add_body)
            .content(form)
            .secondary()
            .primary(R.string.channel_admin_add_action, closeOnClick = false) { dialog ->
                val entered = code.text?.toString().orEmpty().trim()

                if (!isChannelAdminRequest(entered)) {
                    code.hasError = true
                    dialog.showError(R.string.channel_admin_invalid)
                    return@primary
                }

                dialog.setBusy(true)

                lifecycleScope.launch {
                    val added = withContext(Dispatchers.IO) {
                        runCatching {
                            Core.messenger().addChannelAdmin(
                                channelId,
                                entered,
                                name.text?.toString().orEmpty(),
                                System.currentTimeMillis(),
                            )
                        }
                    }

                    dialog.setBusy(false)

                    added
                        .onSuccess {
                            dialog.dismiss()
                            GasAppToast.show(
                                this@ChannelActivity,
                                R.string.channel_admin_added,
                                GasAppToast.Tone.Success,
                            )
                        }
                        .onFailure { failure ->
                            dialog.showError(
                                if (failure is FfiException.InvalidArgument) {
                                    R.string.channel_admin_wrong_channel
                                } else {
                                    R.string.channels_error_network
                                },
                            )
                        }
                }
            }
            .show()
    }

    private fun confirmRemoveAdmin(admin: FfiChannelAdmin, name: String) {
        GasAppDialog(this)
            .title(getString(R.string.channel_admin_remove_title, name))
            .message(R.string.channel_admin_remove_body)
            .secondary()
            .primary(R.string.channel_admin_remove, GasAppDialog.Tone.Danger, closeOnClick = false) { dialog ->
                dialog.setBusy(true)

                lifecycleScope.launch {
                    val removed = withContext(Dispatchers.IO) {
                        runCatching {
                            Core.messenger().removeChannelAdmin(
                                channelId,
                                admin.verifyKey,
                                System.currentTimeMillis(),
                            )
                        }
                    }

                    dialog.setBusy(false)

                    removed
                        .onSuccess { dialog.dismiss() }
                        .onFailure { dialog.showError(R.string.channels_error_network) }
                }
            }
            .show()
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

    /** Владелец: описание, закреп, аватар, имя, администраторы, удаление. */
    private val FfiChannel.owned: Boolean
        get() = role == FfiChannelRole.OWNER

    /** Владелец либо действующий администратор: пишет, правит, удаляет записи. */
    private val FfiChannel.canPost: Boolean
        get() = role == FfiChannelRole.OWNER || role == FfiChannelRole.ADMIN

    companion object {
        /** Идентификатор канала. */
        const val EXTRA_CHANNEL_ID = "channel_id"

        /** Сколько записей добавляет одна страница ленты. */
        private const val PAGE = 100

        /** Больше этого лента за раз не держит. */
        private const val MAX_SHOWN = 3_000

        private val SEARCH_LIMIT = 30u
        private const val SNIPPET_CHARS = 80

        private const val LINK_TEXT_SP = 12f
        private const val LINK_MAX_LINES = 6
        private const val EDIT_MAX_LINES = 10
        private const val CODE_MAX_LINES = 4

        /** Сколько знаков ключа показать у администратора без имени. */
        private const val KEY_HINT_CHARS = 8

        private const val READ_BUFFER = 64 * 1024
        private const val BYTES_IN_MB = 1024L * 1024L

        /** Предел исходной картинки для аватара — до уменьшения. */
        private const val AVATAR_SOURCE_LIMIT = 20L * BYTES_IN_MB

        private const val DEFAULT_FILE_NAME = "gasapp-file"

        /** Метка «файл больше предела»: сравнивается по ссылке, содержимого не несёт. */
        private val TOO_LARGE = FfiAttachmentFile(FfiAttachmentKind.DOCUMENT, ByteArray(0), null, null, null, null)
    }
}
