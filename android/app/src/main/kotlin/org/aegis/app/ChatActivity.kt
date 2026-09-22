// SPDX-License-Identifier: Apache-2.0

package org.aegis.app

import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisSheet
import org.aegis.app.components.AegisTextField
import org.aegis.app.core.Core
import org.aegis.app.core.PendingSave
import org.aegis.app.core.SecureClipboard
import org.aegis.app.core.SecureWindow
import org.aegis.app.core.showSecure
import org.aegis.app.net.NotificationSocket
import org.aegis.app.ui.AttachmentKindMark
import org.aegis.app.ui.AttachmentPreview
import org.aegis.app.ui.DeliveryMark
import org.aegis.app.ui.MessageAdapter
import org.aegis.app.ui.MessageItem
import uniffi.aegis.FfiAttachmentFile
import uniffi.aegis.FfiAttachmentKind
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
     * Скачанное вложение, ожидающее выбора места сохранения.
     *
     * 🔐 Расшифрованный файл в памяти. Очищается при уходе с экрана:
     * держать его дольше, чем нужно для сохранения, незачем.
     */
    /**
     * 🔐 Вложение, для которого спрошено место сохранения.
     *
     * Описание, а не содержимое: через диалог выбора места
     * расшифрованный файл не переезжает (см. [PendingSave]).
     */
    private val pendingSave = PendingSave<AttachmentPreview>()

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

        // 🔐 Блокировка снимков экрана по настройке пользователя.
        // До setContentView: после отрисовки первый кадр уже мог
        // попасть в снимок переключателя задач.
        SecureWindow.apply(this)

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

        adapter = MessageAdapter(
            onAttachmentClick = ::openAttachment,
            onMessageLongClick = ::showMessageActions,
        )
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
        findViewById<ImageView>(R.id.attach_button).setOnClickListener { chooseAttachment() }
        findViewById<ImageView>(R.id.chat_menu).setOnClickListener { showChatMenu() }

        // 🔐 Индикатор набора не отправляется. Приложение собеседника
        // его не показывает — ядро выбрасывает его при приёме, — а
        // конверт, ушедший в момент набора, сообщал серверу, когда
        // человек печатает, и ничего не давал взамен. Прежде он уходил
        // при включённой передаче присутствия, а настройка обещала,
        // что собеседник увидит набор.
        applySendGuard()
    }

    /**
     * Спрашивает, что именно прикрепить.
     *
     * Медиа и документы разведены, потому что за ними стоят разные
     * системные диалоги: для фото и видео — Photo Picker, который
     * показывает только галерею и не даёт доступа к остальным файлам.
     */
    private fun chooseAttachment() {
        AegisSheet.on(this, R.string.attach)
            .action(getString(R.string.attach_photo), R.drawable.ic_image) {
                pickMedia.launch(arrayOf("image/*", "video/*"))
            }
            .action(getString(R.string.attach_file), R.drawable.ic_file) {
                pickDocument.launch(arrayOf("*/*"))
            }
            .show()
    }

    /**
     * Выбор фото или видео.
     *
     * 🔐 `OpenDocument`, а не разрешение READ_MEDIA_IMAGES: системный
     * диалог отдаёт приложению ровно тот файл, который человек указал.
     * Разрешение открыло бы всю галерею разом и навсегда — включая
     * снимки, которые пользователь никому показывать не собирался.
     */
    private val pickMedia = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let { sendAttachment(it, mediaKindOf(it)) } }

    /** Выбор произвольного файла. */
    private val pickDocument = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let { sendAttachment(it, FfiAttachmentKind.DOCUMENT) } }

    /**
     * Определяет тип по MIME, который сообщил поставщик содержимого.
     *
     * 🔐 Не по расширению имени: имя выбирает отправитель, и
     * «отчёт.jpg», который на деле исполняемый файл, не должен
     * поехать как картинка. MIME здесь — подсказка **нашей** системы
     * о **нашем** файле, а не то, что пришло по сети.
     */
    private fun mediaKindOf(uri: Uri): FfiAttachmentKind =
        when {
            contentResolver.getType(uri)?.startsWith("video/") == true ->
                FfiAttachmentKind.VIDEO

            else -> FfiAttachmentKind.IMAGE
        }

    /**
     * Шифрует файл и отправляет его собеседнику.
     *
     * # Про чтение целиком в память
     *
     * 🔐 Файл читается в память, а не переписывается во временный
     * файл: временная копия лежала бы на диске в открытом виде вне
     * зашифрованного хранилища, и её подхватили бы системные бэкапы.
     * Предел в 100 МБ делает это допустимым.
     */
    private fun sendAttachment(uri: Uri, kind: FfiAttachmentKind) {
        val device = Core.deviceId

        if (device == null) {
            Toast.makeText(this, R.string.attach_failed, Toast.LENGTH_SHORT).show()

            return
        }

        Toast.makeText(this, R.string.attach_sending, Toast.LENGTH_SHORT).show()

        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = readAttachment(uri)
                        ?: return@runCatching AttachOutcome.Unreadable

                    if (bytes.size > MAX_ATTACHMENT_BYTES) {
                        return@runCatching AttachOutcome.TooLarge
                    }

                    Core.messenger().sendAttachment(
                        peerUsername,
                        device,
                        FfiAttachmentFile(
                            kind = kind,
                            bytes = bytes,
                            name = displayNameOf(uri),
                            description = null,
                            durationMillis = null,
                            waveform = null,
                        ),
                        "",
                        System.currentTimeMillis(),
                    )

                    AttachOutcome.Sent
                }.getOrDefault(AttachOutcome.Failed)
            }

            when (outcome) {
                AttachOutcome.Sent -> reload()
                AttachOutcome.TooLarge ->
                    Toast.makeText(this@ChatActivity, R.string.attach_too_large, Toast.LENGTH_LONG)
                        .show()

                AttachOutcome.Unreadable ->
                    Toast.makeText(
                        this@ChatActivity,
                        R.string.attach_unreadable,
                        Toast.LENGTH_LONG,
                    ).show()

                AttachOutcome.Failed ->
                    Toast.makeText(this@ChatActivity, R.string.attach_failed, Toast.LENGTH_LONG)
                        .show()
            }
        }
    }

    /**
     * Читает выбранный файл.
     *
     * Возвращает `null`, если поставщик содержимого отказал: файл мог
     * быть удалён между выбором и чтением, а на облачных хранилищах
     * ещё и не скачаться.
     */
    private fun readAttachment(uri: Uri): ByteArray? =
        runCatching {
            contentResolver.openInputStream(uri)?.use { it.readBytes() }
        }.getOrNull()

    /**
     * Достаёт отображаемое имя файла.
     *
     * 🔐 Имя уходит зашифрованным вместе с описанием: «результаты
     * анализов.jpg» говорит о человеке больше, чем сам факт отправки.
     */
    private fun displayNameOf(uri: Uri): String? =
        runCatching {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)

                if (column >= 0 && cursor.moveToFirst()) {
                    cursor.getString(column)
                } else {
                    null
                }
            }
        }.getOrNull()

    /** Чем закончилась отправка вложения. */
    private enum class AttachOutcome {
        Sent,
        TooLarge,
        Unreadable,
        Failed,
    }

    override fun onStart() {
        super.onStart()

        resolvePeerUsername()
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

        // ⚠️ Сохранение вложения здесь не отменяется, и это
        // не упущение. Диалог выбора места — полноэкранная
        // активность, то есть этот `onStop` и есть открытый
        // диалог. Очистка отсюда означала бы, что сохранить
        // вложение нельзя никогда (см. [PendingSave]).
        pendingSave.onScreenStopped()
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
                    Core.messenger()
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
                    val messenger = Core.messenger()

                    messenger.messages(chatId, MESSAGE_LIMIT).map { message ->
                        // Описания читаются здесь же: они лежат
                        // в зашифрованной базе, и поход за ними
                        // из главного потока подвесил бы прокрутку.
                        message.toItem(
                            runCatching { messenger.attachmentsOf(message.messageId) }
                                .getOrDefault(emptyList()),
                        )
                    }
                }.getOrDefault(emptyList())
            }

            if (messages.isEmpty() && markFailed) {
                return@launch
            }

            adapter.submit(messages)

            // Квитанция после показа: сообщение прочитано тогда, когда
            // оно на экране, а не когда пришло по сети.
            messages.lastOrNull { !it.outgoing }?.let { last ->
                sendReadReceipt(last.messageId)
            }
        }
    }

    /**
     * Находит имя собеседника по чату, если его не передали.
     *
     * Собеседник, написавший первым, называет себя позже — в сообщении
     * с ключом доступа (`Content::AccessKey`), — и имя появляется
     * у контакта уже после того, как чат открыли. Без имени отправить
     * в чат нельзя: ядро ищет собеседника по нему.
     */
    private fun resolvePeerUsername() {
        if (peerUsername.isNotEmpty() || chatId.isEmpty()) {
            return
        }

        lifecycleScope.launch {
            val found = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().contacts().firstOrNull { it.chatId == chatId }?.username
                }.getOrNull()
            }

            if (!found.isNullOrEmpty()) {
                peerUsername = found
            }
        }
    }

    /** Забирает входящие сообщения с сервера. */
    private fun fetchIncoming() {
        val device = Core.deviceId ?: return

        lifecycleScope.launch {
            val received = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger()
                        .receiveMessages(device, System.currentTimeMillis())
                }.getOrDefault(0u)
            }

            if (received > 0u) {
                reload()
                resolvePeerUsername()
            }
        }
    }

    private fun FfiMessage.toItem(descriptors: List<ByteArray> = emptyList()): MessageItem =
        MessageItem(
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
            // Первое вложение: одно на сообщение — то, что сейчас
            // отправляет приложение. Формат протокола допускает
            // несколько, и когда интерфейс научится их показывать,
            // менять придётся здесь, а не в ядре.
            attachment = descriptors.firstOrNull()?.let(::previewOf),
        )

    /**
     * Разбирает описание вложения для показа.
     *
     * 🔐 Разбор идёт через ядро: оно проверяет границы каждого поля.
     * Имя, размер и тип приходят от собеседника, и доверять им
     * на слово нельзя.
     */
    private fun previewOf(descriptor: ByteArray): AttachmentPreview? =
        runCatching {
            val parsed = uniffi.aegis.parseAttachmentDescriptor(descriptor)

            AttachmentPreview(
                descriptor = descriptor,
                name = parsed.name,
                size = parsed.size.toLong(),
                kind = when (parsed.kind) {
                    FfiAttachmentKind.IMAGE -> AttachmentKindMark.Image
                    FfiAttachmentKind.VIDEO -> AttachmentKindMark.Video
                    FfiAttachmentKind.VOICE -> AttachmentKindMark.Document
                    FfiAttachmentKind.DOCUMENT -> AttachmentKindMark.Document
                },
            )
        }.getOrNull()

    /**
     * Отправляет квитанцию о прочтении последнего сообщения.
     *
     * Квитанция указывает последнее прочитанное, а не каждое:
     * открытие чата с сотней непрочитанных иначе породило бы сто
     * сообщений, и по их числу собеседник узнал бы, сколько
     * накопилось.
     *
     * 🔐 Как и индикатор набора, уходит только при включённой
     * передаче присутствия — решение принимает ядро.
     */
    private fun sendReadReceipt(lastMessageId: String) {
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().sendReadReceipt(
                        peerUsername,
                        lastMessageId,
                        System.currentTimeMillis(),
                    )
                }
            }
        }
    }

    /**
     * Меню чата: сверка, таймер исчезновения, присутствие.
     */
    private fun showChatMenu() {
        AegisSheet.on(this, chatName())
            .action(getString(R.string.chat_verify), R.drawable.ic_shield) {
                openSafetyNumber(chatName())
            }
            .action(getString(R.string.chat_disappearing), R.drawable.ic_clock) {
                showDisappearingOptions()
            }
            .action(getString(R.string.chat_presence), R.drawable.ic_alert) {
                showPresenceOptions()
            }
            .show()
    }

    /**
     * Выбор срока исчезающих сообщений.
     *
     * 🔐 Срок берётся в момент получения сообщения и больше не
     * меняется: выключение таймера не воскрешает то, что пользователь
     * уже считает обречённым на исчезновение.
     */
    private fun showDisappearingOptions() {
        val sheet = AegisSheet.on(this, R.string.chat_disappearing)

        for ((label, seconds) in DISAPPEARING_OPTIONS) {
            sheet.action(getString(label)) {
                runAction {
                    Core.messenger().setDisappearingTimer(chatId, seconds)
                }
            }
        }

        sheet.show()
    }

    /**
     * Передача присутствия: индикатор набора и квитанции прочтения.
     *
     * 🔐 Выключено по умолчанию и одной настройкой на оба признака:
     * и то и другое сообщает собеседнику, когда человек у телефона,
     * то есть выдаёт распорядок дня. Разделять их значило бы
     * предлагать выбор, в котором обе половины означают одно.
     */
    private fun showPresenceOptions() {
        lifecycleScope.launch {
            val enabled = withContext(Dispatchers.IO) {
                runCatching { Core.messenger().presenceSharingEnabled() }.getOrDefault(false)
            }

            AegisSheet.on(this@ChatActivity, R.string.chat_presence)
                .action(
                    getString(
                        if (enabled) R.string.presence_disable else R.string.presence_enable,
                    ),
                    if (enabled) R.drawable.ic_lock else R.drawable.ic_alert,
                    destructive = !enabled,
                ) {
                    runAction {
                        Core.messenger().setPresenceSharing(!enabled)
                    }
                }
                .show()
        }
    }

    /** Имя собеседника для заголовков панелей. */
    private fun chatName(): String =
        intent.getStringExtra(EXTRA_CHAT_NAME).orEmpty().ifEmpty { peerUsername }

    /**
     * Меню действий над сообщением.
     *
     * Состав зависит от того, чьё сообщение: править и удалять у всех
     * можно только своё. Показывать чужому пользователю пункт, который
     * ему откажут, значит предлагать то, чего он сделать не может.
     */
    private fun showMessageActions(message: MessageItem) {
        // ⚠️ Пункта «Реакция» нет, пока реакции не хранятся и не
        // показываются: ни у отправителя, ни у получателя ядро их
        // не сохраняет. Прежде пункт был, реакция уходила и пропадала,
        // а пользователь считал, что собеседник её видит. Прежний
        // выбор эмодзи — в истории этого файла.
        val sheet = AegisSheet.on(this, R.string.message_actions)
            .action(getString(R.string.message_copy), R.drawable.ic_copy) {
                copyMessage(message)
            }

        if (message.outgoing) {
            sheet.action(getString(R.string.message_edit), R.drawable.ic_edit) {
                promptEdit(message)
            }

            // 🔐 Удаление помечено разрушительным: своё исчезает
            // безвозвратно, а у собеседника — только по просьбе.
            sheet.action(
                getString(R.string.message_delete),
                R.drawable.ic_trash,
                destructive = true,
            ) {
                confirmDelete(message)
            }
        }

        sheet.show()
    }

    /**
     * Копирует текст сообщения.
     *
     * 🔐 Через [SecureClipboard], а не напрямую: скопированное
     * помечается чувствительным (иначе Android 13+ показывает текст
     * во всплывающем окне поверх экрана, который этот же текст прячет
     * от снимка) и стирается через минуту.
     */
    private fun copyMessage(message: MessageItem) {
        SecureClipboard.copySensitive(
            context = this,
            label = getString(R.string.message_actions),
            text = message.text,
        )

        Toast.makeText(this, R.string.message_copied, Toast.LENGTH_SHORT).show()
    }

    /**
     * Правка отправленного сообщения.
     *
     * 🔐 Правка не скрывает исходный текст: получатель уже видел его
     * и мог запомнить. Изменённое сообщение помечается в переписке —
     * иначе отправитель мог бы переписать разговор задним числом.
     */
    private fun promptEdit(message: MessageItem) {
        val field = AegisTextField(this).apply {
            setText(message.text)
            setHint(R.string.message_edit_hint)
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.message_edit_title)
            .setView(field)
            .setPositiveButton(R.string.action_save) { _, _ ->
                val text = field.text?.toString().orEmpty().trim()

                if (text.isEmpty() || text == message.text) {
                    return@setPositiveButton
                }

                runAction {
                    Core.messenger().editMessage(
                        peerUsername,
                        message.messageId,
                        text,
                        System.currentTimeMillis(),
                    )
                }
            }
            .setNegativeButton(R.string.action_cancel, null)
            .showSecure(this)
    }

    /**
     * Удаление сообщения у обеих сторон.
     *
     * Подтверждение обязательно: 🔐 своё удаляется сразу и безвозвратно,
     * а у собеседника — только просьбой. Пользователь должен понимать,
     * что гарантии нет, до нажатия, а не после.
     */
    private fun confirmDelete(message: MessageItem) {
        AlertDialog.Builder(this)
            .setTitle(R.string.message_delete_title)
            .setMessage(R.string.message_delete_body)
            .setPositiveButton(R.string.action_delete) { _, _ ->
                runAction {
                    Core.messenger().deleteForEveryone(
                        peerUsername,
                        message.messageId,
                        System.currentTimeMillis(),
                    )
                }
            }
            .setNegativeButton(R.string.action_cancel, null)
            .showSecure(this)
    }

    /**
     * Выполняет действие над сообщением в фоне и перечитывает переписку.
     *
     * Отказ показывается явно: действие, которое выглядит выполненным,
     * но не ушло, — худший исход, потому что пользователь считает
     * разговор изменённым.
     */
    private fun runAction(action: () -> Unit) {
        lifecycleScope.launch {
            val done = withContext(Dispatchers.IO) { runCatching { action() }.isSuccess }

            if (!done) {
                Toast.makeText(
                    this@ChatActivity,
                    R.string.message_action_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }

            reload()
        }
    }

    /**
     * Скачивает вложение и предлагает сохранить его.
     *
     * # 🔐 Почему файл не открывается сразу
     *
     * Расшифрованный файл существует только в памяти. Чтобы открыть
     * его чужим приложением, пришлось бы записать копию на диск —
     * вне зашифрованного хранилища, где её увидит любой, кто получит
     * устройство. Поэтому пользователь сам выбирает, куда сохранить:
     * решение осознанное, и место известно ему.
     */
    private fun openAttachment(attachment: AttachmentPreview) {
        if (Core.deviceId == null) {
            Toast.makeText(this, R.string.attachment_download_failed, Toast.LENGTH_SHORT).show()

            return
        }

        // 🔐 Сначала место, потом скачивание.
        //
        // Обратный порядок означал бы, что расшифрованный файл лежит
        // в памяти всё время, пока открыт диалог выбора, — а заодно
        // не работал бы вовсе: `onStop` стирал его до возвращения
        // из диалога (см. [PendingSave]).
        pendingSave.begin(attachment)
        saveAttachment.launch(attachment.name ?: DEFAULT_ATTACHMENT_NAME)
    }

    /**
     * Записывает скачанное туда, куда указал пользователь.
     *
     * 🔐 Байты держатся в памяти между скачиванием и выбором места:
     * временный файл на диске был бы копией вне хранилища, которую
     * подхватили бы системные бэкапы.
     */
    private val saveAttachment = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        // 🔐 Описание забирается один раз: повторный вызов вернёт
        // `null`, и ключ расшифровки в памяти не задержится.
        val attachment = pendingSave.take()
        val device = Core.deviceId

        if (uri == null || attachment == null || device == null) {
            return@registerForActivityResult
        }

        Toast.makeText(this, R.string.attachment_downloading, Toast.LENGTH_SHORT).show()

        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().fetchAttachment(
                        device,
                        attachment.descriptor,
                        System.currentTimeMillis(),
                    )
                }.getOrNull()
            }

            if (bytes == null) {
                // 🔐 Запертое хранилище не выдаётся за подмену файла.
                //
                // Пока открыт диалог выбора места, автоблокировка
                // успевает сработать — экран блокировки в этот момент
                // уже поверх всего, и объяснять что-либо поздно
                // и незачем.
                //
                // ⚠️ Разница не косметическая. «Файл подменён» —
                // сообщение о нападении. Показанное там, где никакого
                // нападения нет, оно учит не верить ему и тогда,
                // когда нападение настоящее.
                if (!Core.isUnlocked) {
                    return@launch
                }

                // Остаётся недоступная сеть либо подменённый
                // на сервере файл: тег чанка не сошёлся. Второе
                // важнее, поэтому текст говорит о файле, а не о сети.
                Toast.makeText(
                    this@ChatActivity,
                    R.string.attachment_tampered,
                    Toast.LENGTH_LONG,
                ).show()

                return@launch
            }

            val saved = withContext(Dispatchers.IO) {
                runCatching {
                    contentResolver.openOutputStream(uri)?.use { it.write(bytes) } != null
                }.getOrDefault(false)
            }

            Toast.makeText(
                this@ChatActivity,
                if (saved) R.string.attachment_saved else R.string.attachment_download_failed,
                Toast.LENGTH_SHORT,
            ).show()
        }
    }

    private fun formatTime(millis: Long): String =
        java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
            .format(java.util.Date(millis))

    private fun timeNow(): String = formatTime(System.currentTimeMillis())

    /**
     * Открывает сверку safety number с собеседником этого чата.
     *
     * 🔐 Собеседник находится по чату, а не по имени. Чат выводится
     * из обоих identity-ключей и однозначен; имя после смены ключа —
     * нет, и поиск по нему мог бы показать цифры прежнего ключа.
     */
    private fun openSafetyNumber(peerName: String) {
        lifecycleScope.launch {
            val accountId = withContext(Dispatchers.IO) {
                runCatching {
                    Core.messenger().contacts().firstOrNull { it.chatId == chatId }?.accountId
                }.getOrNull()
            }

            startActivity(
                Intent(this@ChatActivity, SafetyNumberActivity::class.java)
                    .putExtra(SafetyNumberActivity.EXTRA_ACCOUNT_ID, accountId.orEmpty())
                    .putExtra(SafetyNumberActivity.EXTRA_PEER_NAME, peerName),
            )
        }
    }


    companion object {
        /** Идентификатор чата. */
        const val EXTRA_CHAT_ID = "chat_id"

        /** Отображаемое имя собеседника. */
        const val EXTRA_CHAT_NAME = "chat_name"

        /** Имя пользователя собеседника: по нему адресуется отправка. */
        const val EXTRA_PEER_USERNAME = "peer_username"

        /**
         * Набор реакций.
         *
         * Короткий и заданный: свободный ввод превратил бы реакцию
         * во второе поле сообщения, а её смысл — в одном нажатии.
         */
        /**
         * Сроки исчезающих сообщений.
         *
         * Ноль выключает таймер. Набор короткий: длинный список
         * превращает решение о том, сколько живёт переписка,
         * в перебор вариантов.
         */
        private val DISAPPEARING_OPTIONS = listOf(
            R.string.disappearing_off to 0u,
            R.string.disappearing_hour to 3_600u,
            R.string.disappearing_day to 86_400u,
            R.string.disappearing_week to 604_800u,
        )

        /**
         * Имя по умолчанию для сохранения.
         *
         * Используется, когда отправитель имени не передал: файл
         * должен сохраняться и без него.
         */
        const val DEFAULT_ATTACHMENT_NAME = "aegis-attachment"

        /**
         * Предел размера вложения.
         *
         * Совпадает с пределом ядра и серверной схемы: проверка здесь
         * лишь избавляет от чтения стомегабайтного файла в память
         * ради заведомого отказа.
         */
        const val MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024

        /** Сколько сообщений загружается в переписку. */
        private const val MESSAGE_LIMIT = 200u

        /** Сверен ли safety number. */
        const val EXTRA_VERIFIED = "chat_verified"
    }
}
