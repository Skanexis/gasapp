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
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.aegis.app.components.AegisButton
import org.aegis.app.components.AegisTextField
import org.aegis.app.ui.AttachmentKindMark
import org.aegis.app.ui.AttachmentPreview
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
import uniffi.aegis.FfiAttachmentFile
import uniffi.aegis.FfiAttachmentKind
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
    private var pendingDownload: ByteArray? = null

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

        adapter = MessageAdapter(onAttachmentClick = ::openAttachment)
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
        AlertDialog.Builder(this)
            .setTitle(R.string.attach)
            .setItems(
                arrayOf(
                    getString(R.string.attach_photo),
                    getString(R.string.attach_file),
                ),
            ) { _, which ->
                when (which) {
                    0 -> pickMedia.launch(arrayOf("image/*", "video/*"))
                    else -> pickDocument.launch(arrayOf("*/*"))
                }
            }
            .setNegativeButton(R.string.attach_cancel, null)
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
        pendingDownload = null
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
        val device = Core.deviceId

        if (device == null) {
            Toast.makeText(this, R.string.attachment_download_failed, Toast.LENGTH_SHORT).show()

            return
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
                // Отказ здесь означает либо недоступную сеть, либо
                // подменённый на сервере файл: тег чанка не сошёлся.
                // Второе важнее, поэтому текст говорит о файле,
                // а не о сети.
                Toast.makeText(
                    this@ChatActivity,
                    R.string.attachment_tampered,
                    Toast.LENGTH_LONG,
                ).show()

                return@launch
            }

            pendingDownload = bytes
            saveAttachment.launch(attachment.name ?: DEFAULT_ATTACHMENT_NAME)
        }
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
        val bytes = pendingDownload
        pendingDownload = null

        if (uri == null || bytes == null) {
            return@registerForActivityResult
        }

        val saved = runCatching {
            contentResolver.openOutputStream(uri)?.use { it.write(bytes) } != null
        }.getOrDefault(false)

        Toast.makeText(
            this,
            if (saved) R.string.attachment_saved else R.string.attachment_download_failed,
            Toast.LENGTH_SHORT,
        ).show()
    }

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
