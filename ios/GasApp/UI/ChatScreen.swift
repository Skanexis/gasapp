// SPDX-License-Identifier: Apache-2.0

import PhotosUI
import SwiftUI

/// Сообщение на экране: из ядра или только что набранное (ещё не ушло).
struct MessageRow: Identifiable, Equatable {
    let id: String
    let text: String
    let timestamp: Int64
    let outgoing: Bool
    var status: FfiDeliveryStatus
    /// Описания вложений (адрес, ключ — под сквозным шифрованием).
    var attachments: [Data] = []
    /// Кнопки бота под сообщением: ряды подписей (`messageButtons`).
    var buttons: [[ButtonCell]] = []
}

/// Кнопка бота: подпись и признак ссылки — ссылка не открывается сама.
struct ButtonCell: Equatable, Hashable {
    let label: String
    let isLink: Bool
}

/// Переписка — аналог `ChatActivity`.
///
/// 🔐 Можно ли писать, решает ядро: отправку с неподтверждённым или
/// сменившимся ключом оно отвергает. Экран лишь заранее показывает
/// почему ([SendMode]) и ведёт к сверке кода безопасности.
struct ChatScreen: View {
    let chatId: String
    let peerUsername: String
    let title: String

    // Явный инициализатор: у синтезированного уровень доступа понизился
    // бы до private из-за приватных @State, и экран не создавался бы
    // из других файлов.
    init(chatId: String, peerUsername: String, title: String) {
        self.chatId = chatId
        self.peerUsername = peerUsername
        self.title = title
    }

    @State private var inbox = Inbox.shared
    @State private var resolvedChatId = ""
    @State private var messages: [MessageRow] = []
    @State private var draft = ""
    @State private var mode: SendMode = .open
    @State private var contact: FfiContact?
    @State private var blocked = false
    @State private var showSafety = false
    @State private var confirmReport = false
    /// Ссылка из кнопки бота — ждёт решения человека.
    @State private var pendingLink: String?
    @State private var confirmDecline = false
    @State private var toast: String?
    @State private var receiptSentFor: String?
    @State private var photo: PhotosPickerItem?
    @State private var sendingPhoto = false
    @State private var editing: MessageRow?
    @State private var editText = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(messages) { message in
                            MessageBubble(message: message)
                                .id(message.id)
                                .contextMenu { messageMenu(message) }
                            if !message.buttons.isEmpty {
                                MessageButtons(rows: message.buttons) { row, column in press(message, row: row, column: column) }
                            }
                        }
                    }
                    .padding(12)
                }
                .onChange(of: messages.count) { _, _ in
                    if let last = messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }

            if let toast {
                Text(toast).font(.system(size: 13, weight: .semibold)).foregroundStyle(GasAppColor.warn)
                    .padding(.vertical, 6)
            }

            guardPanel
            composer
        }
        .gasScreen()
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                VStack(spacing: 0) {
                    Text(title).font(.system(size: 17, weight: .bold)).foregroundStyle(GasAppColor.textPrimary)
                    Text(verificationLabel.0).font(.system(size: 11, weight: .semibold)).foregroundStyle(verificationLabel.1)
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    if contact != nil {
                        Button(L10n.t("Код безопасности", "Safety number")) { showSafety = true }
                    }
                    if !resolvedChatId.isEmpty {
                        // Исчезающие сообщения: ядро стирает их у обоих по сроку.
                        Menu(L10n.t("Исчезающие сообщения", "Disappearing messages")) {
                            Button(L10n.t("Выключить", "Off")) { setTimer(0) }
                            Button(L10n.t("Через час", "After 1 hour")) { setTimer(3600) }
                            Button(L10n.t("Через сутки", "After 1 day")) { setTimer(86_400) }
                            Button(L10n.t("Через неделю", "After 1 week")) { setTimer(604_800) }
                        }
                    }
                    if !resolvedChatId.isEmpty {
                        Button(L10n.t("Пожаловаться", "Report"), role: .destructive) { startReport() }
                        Button(blocked ? L10n.t("Разблокировать", "Unblock") : L10n.t("Заблокировать", "Block"),
                               role: blocked ? nil : .destructive) { toggleBlock() }
                    }
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
        // Жалоба — как на Android (ChatActivity): что получит оператор,
        // сказано до кнопок; «и заблокировать» — второй вариант.
        .confirmationDialog(L10n.t("Пожаловаться на \(title)?", "Report \(title)?"),
                            isPresented: $confirmReport, titleVisibility: .visible) {
            Button(L10n.t("Пожаловаться и заблокировать", "Report and block"), role: .destructive) { sendReport(alsoBlock: true) }
            Button(L10n.t("Только пожаловаться", "Report only")) { sendReport(alsoBlock: false) }
            Button(L10n.t("Отмена", "Cancel"), role: .cancel) {}
        } message: {
            Text(L10n.t("Оператор сервера получит доказательство, что этот аккаунт вам писал, — но не переписку: её у сервера нет. \(title) об этом не узнает.",
                        "The server operator gets proof that this account wrote to you — not your conversation: the server does not have it. \(title) is not told."))
        }
        // Ссылка из кнопки — только https (ядро отвергает иные схемы, данные
        // входа в адресе и подменные буквы); открыть её решает человек,
        // видя адрес целиком (как на Android).
        .confirmationDialog(L10n.t("Открыть ссылку?", "Open the link?"), isPresented: Binding(
            get: { pendingLink != nil }, set: { if !$0 { pendingLink = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Открыть", "Open")) {
                if let link = pendingLink, let url = URL(string: link), url.scheme == "https" {
                    UIApplication.shared.open(url)
                }
                pendingLink = nil
            }
        } message: {
            Text(pendingLink ?? "")
        }
        .sheet(isPresented: $showSafety, onDismiss: { Task { await refresh() } }) {
            if let contact {
                NavigationStack { SafetyNumberScreen(contact: contact) }
            }
        }
        .confirmationDialog(L10n.t("Отклонить запрос?", "Decline request?"), isPresented: $confirmDecline,
                            titleVisibility: .visible) {
            Button(L10n.t("Отклонить и удалить", "Decline and delete"), role: .destructive) { decline() }
        } message: {
            Text(L10n.t("Переписка удалится. Собеседник не узнает даже того, что вы её видели.",
                        "The chat is deleted. The sender won’t even learn you saw it."))
        }
        .alert(L10n.t("Изменить сообщение", "Edit message"), isPresented: Binding(
            get: { editing != nil }, set: { if !$0 { editing = nil } }
        )) {
            TextField(L10n.t("Текст", "Text"), text: $editText)
            Button(L10n.t("Сохранить", "Save")) { saveEdit() }
            Button(L10n.t("Отмена", "Cancel"), role: .cancel) { editing = nil }
        }
        .task {
            resolvedChatId = chatId
            await inbox.receiveOnce()
            await refresh()
        }
        .onChange(of: inbox.revision) { _, _ in Task { await refresh() } }
    }

    // MARK: - Состояние

    private var verificationLabel: (String, Color) {
        if contact?.verified == true { return (L10n.t("сверен лично", "verified in person"), GasAppColor.ok) }
        if contact?.ktConfirmed == true { return (L10n.t("ключ подтверждён журналом", "key confirmed by log"), GasAppColor.accent) }
        return (L10n.t("не сверен", "not verified"), GasAppColor.textTertiary)
    }

    @ViewBuilder
    private var guardPanel: some View {
        switch mode {
        case .open:
            EmptyView()
        case .blocked:
            panel(Banner(title: L10n.t("\(title) заблокирован", "\(title) is blocked"),
                         message: L10n.t("Вы не получаете его сообщений.", "You don’t receive their messages."), tone: .info)) {
                OutlineButton(title: L10n.t("Разблокировать", "Unblock")) { toggleBlock() }
            }
        case .chooseKey:
            panel(Banner(title: L10n.t("Ключ собеседника сменился", "Their key changed"),
                         message: L10n.t("Новый телефон — или кто-то выдаёт себя за \(title). Сверьте код безопасности.",
                                         "A new phone — or someone pretending to be \(title). Compare the safety number."),
                         tone: .error)) {
                GoldButton(title: L10n.t("Сверить код", "Compare safety number")) { showSafety = true }
            }
        case .confirmKey:
            panel(Banner(title: L10n.t("Ключ ещё не подтверждён", "Key not confirmed yet"),
                         message: L10n.t("Его назвал только сервер. Сверьте код безопасности с \(title) или добавьте по его ссылке/QR.",
                                         "Only the server named it. Compare the safety number with \(title) or add them by their link/QR."))) {
                GoldButton(title: L10n.t("Сверить код", "Compare safety number")) { showSafety = true }
            }
        case .request:
            panel(Banner(title: L10n.t("\(title) хочет написать вам", "\(title) wants to message you"),
                         message: L10n.t("Пока вы не примете запрос, собеседник не узнает, что вы прочли.",
                                         "Until you accept, they won’t know you read it."), tone: .info)) {
                HStack(spacing: 10) {
                    OutlineButton(title: L10n.t("Отклонить", "Decline"), tone: GasAppColor.error) { confirmDecline = true }
                    GoldButton(title: L10n.t("Принять", "Accept")) { accept() }
                }
            }
        case .replaced:
            panel(Banner(title: L10n.t("Аккаунт заменён", "Account replaced"),
                         message: L10n.t("Это имя теперь у другого аккаунта. Писать сюда нельзя.",
                                         "This username now belongs to another account."), tone: .error)) { EmptyView() }
        }
    }

    private func panel<Actions: View>(_ banner: Banner, @ViewBuilder actions: () -> Actions) -> some View {
        VStack(spacing: 10) {
            banner
            actions()
        }
        .padding(12)
        .background(GasAppColor.bgRaised)
    }

    private var composer: some View {
        HStack(spacing: 10) {
            PhotosPicker(selection: $photo, matching: .images) {
                if sendingPhoto {
                    ProgressView().tint(GasAppColor.accent).frame(width: 30, height: 30)
                } else {
                    Image(systemName: "photo.on.rectangle.angled").font(.system(size: 24))
                        .foregroundStyle(GasAppColor.accent)
                }
            }
            .disabled(sendingPhoto)
            .accessibilityLabel(L10n.t("Отправить фото", "Send a photo"))
            .onChange(of: photo) { _, item in
                if let item { sendPhoto(item) }
            }
            TextField(L10n.t("Сообщение", "Message"), text: $draft, axis: .vertical)
                .lineLimit(1...5)
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 18).fill(GasAppColor.bgCard))
                .foregroundStyle(GasAppColor.textPrimary)
            Button(action: send) {
                Image(systemName: "arrow.up.circle.fill").font(.system(size: 34))
                    .foregroundStyle(canSend ? GasAppColor.accent : GasAppColor.textQuaternary)
            }
            .disabled(!canSend)
            .accessibilityLabel(L10n.t("Отправить", "Send"))
        }
        .padding(10)
        .background(GasAppColor.bgRaised)
        .disabled(mode != .open)
        .opacity(mode == .open ? 1 : 0.4)
    }

    private var canSend: Bool {
        mode == .open && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    // MARK: - Действия с сообщением

    @ViewBuilder
    private func messageMenu(_ message: MessageRow) -> some View {
        if !message.text.isEmpty {
            Button {
                // 🔐 Только локально и с истечением: буфер обмена видят
                // другие приложения.
                UIPasteboard.general.setItems([["public.utf8-plain-text": message.text]],
                                              options: [.localOnly: true,
                                                        .expirationDate: Date().addingTimeInterval(60)])
            } label: { Label(L10n.t("Копировать", "Copy"), systemImage: "doc.on.doc") }
        }
        if message.outgoing && mode == .open && !message.id.hasPrefix("local-") {
            Button {
                editing = message
                editText = message.text
            } label: { Label(L10n.t("Изменить", "Edit"), systemImage: "pencil") }
            Button(role: .destructive) { deleteForEveryone(message) } label: {
                Label(L10n.t("Удалить у всех", "Delete for everyone"), systemImage: "trash")
            }
        }
    }

    private func setTimer(_ seconds: UInt32) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let peer = peerUsername
        Task {
            // Таймер общий: уходит собеседнику, и сообщения исчезают у обоих.
            let done = (try? await Background.run {
                try messenger.setDisappearingTimer(peerUsername: peer, seconds: seconds, nowMillis: CoreStore.nowMillis)
            }) != nil
            toast = done
                ? (seconds == 0 ? L10n.t("Исчезающие сообщения выключены", "Disappearing messages off")
                                : L10n.t("Новые сообщения будут исчезать у вас обоих", "New messages will disappear for both of you"))
                : L10n.t("Не удалось изменить", "Could not change it")
        }
    }

    private func saveEdit() {
        guard let target = editing, let messenger = try? CoreStore.shared.current() else { return }
        let text = editText.trimmingCharacters(in: .whitespacesAndNewlines)
        editing = nil
        guard !text.isEmpty, text != target.text else { return }
        let peer = peerUsername
        Task {
            if (try? await Background.run {
                try messenger.editMessage(peerUsername: peer, targetMessageId: target.id, text: text,
                                          nowMillis: CoreStore.nowMillis)
            }) == nil {
                toast = L10n.t("Не удалось изменить", "Could not edit")
            }
            await refresh()
        }
    }

    private func deleteForEveryone(_ message: MessageRow) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let peer = peerUsername
        Task {
            if (try? await Background.run {
                try messenger.deleteForEveryone(peerUsername: peer, targetMessageId: message.id,
                                                nowMillis: CoreStore.nowMillis)
            }) == nil {
                toast = L10n.t("Не удалось удалить", "Could not delete")
            }
            await refresh()
        }
    }

    /// Фото уходит перекодированным: 🔐 перекодирование в JPEG выбрасывает
    /// EXIF — место съёмки, модель телефона, время. Отправитель не отдаёт
    /// собеседнику (и тому, кто перехватит телефон собеседника) то, чего
    /// не видит на самом снимке.
    private func sendPhoto(_ item: PhotosPickerItem) {
        guard let messenger = try? CoreStore.shared.current(), let device = CoreStore.shared.deviceId else { return }
        let peer = peerUsername
        sendingPhoto = true
        photo = nil
        toast = nil
        Task {
            defer { sendingPhoto = false }
            guard let raw = try? await item.loadTransferable(type: Data.self),
                  let clean = Self.strippedJPEG(raw)
            else {
                toast = L10n.t("Фото не открылось", "Could not open the photo")
                return
            }
            let file = FfiAttachmentFile(kind: .image, bytes: clean, name: "photo.jpg", description: nil,
                                         durationMillis: nil, waveform: nil)
            do {
                try await Background.run {
                    try messenger.sendAttachment(peerUsername: peer, deviceId: device, file: file, body: "",
                                                 nowMillis: CoreStore.nowMillis)
                }
                inbox.touch()
                await refresh()
            } catch {
                toast = L10n.t("Фото не отправлено", "Photo not sent")
            }
        }
    }

    /// Снимок без метаданных и не больше 2560 точек по длинной стороне.
    static func strippedJPEG(_ data: Data) -> Data? {
        guard let image = UIImage(data: data) else { return nil }
        let longest = max(image.size.width, image.size.height)
        let scale = longest > 2560 ? 2560 / longest : 1
        let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let redrawn = UIGraphicsImageRenderer(size: size, format: format).image { _ in
            image.draw(in: CGRect(origin: .zero, size: size))
        }
        return redrawn.jpegData(compressionQuality: 0.85)
    }

    // MARK: - Ядро

    private func refresh() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let peer = peerUsername
        let known = resolvedChatId

        struct Snapshot: Sendable {
            var chatId: String
            var contact: FfiContact?
            var messages: [FfiMessage]
            var attachments: [String: [Data]]
            var buttons: [String: [[ButtonCell]]]
            var request: FfiChatRequest
            var blocked: Bool
        }

        guard let snap = try? await Background.run({ () -> Snapshot in
            var chat = known
            let contacts = try messenger.contacts()
            let found = contacts.first { contact in
                chat.isEmpty ? (contact.username == peer && !contact.replaced) : contact.chatId == chat
            }
            if chat.isEmpty, let id = found?.chatId { chat = id }
            let list = chat.isEmpty ? [] : try messenger.messages(chatId: chat, limit: 500)
            let request = chat.isEmpty ? FfiChatRequest.settled : (try? messenger.chatRequest(chatId: chat)) ?? .settled
            let blocked = chat.isEmpty ? false : (try? messenger.isChatBlocked(chatId: chat)) ?? false
            // Описания вложений — из локальной базы; сами файлы качаются,
            // только когда сообщение на экране (AttachmentView).
            var attachments: [String: [Data]] = [:]
            var buttons: [String: [[ButtonCell]]] = [:]
            for message in list {
                if let descriptors = try? messenger.attachmentsOf(messageId: message.messageId), !descriptors.isEmpty {
                    attachments[message.messageId] = descriptors
                }
                // Кнопки бывают только под сообщением собеседника (бота).
                if !message.outgoing, let rows = try? messenger.messageButtons(messageIdText: message.messageId), !rows.isEmpty {
                    buttons[message.messageId] = rows.map { $0.map { ButtonCell(label: $0.label, isLink: $0.isLink) } }
                }
            }
            return Snapshot(chatId: chat, contact: found, messages: list, attachments: attachments,
                            buttons: buttons, request: request, blocked: blocked)
        }) else { return }

        resolvedChatId = snap.chatId
        contact = snap.contact
        blocked = snap.blocked
        messages = snap.messages.map {
            MessageRow(id: $0.messageId, text: $0.text, timestamp: $0.timestamp, outgoing: $0.outgoing,
                       status: $0.status, attachments: snap.attachments[$0.messageId] ?? [],
                       buttons: snap.buttons[$0.messageId] ?? [])
        }
        // Контакта нет или он не прочитался — ключ не подтверждён:
        // отправку это не откроет, её всё равно решает ядро.
        mode = SendMode.decide(
            keyChanged: snap.contact?.keyChanged == true,
            replaced: snap.contact?.replaced == true,
            keyConfirmed: snap.contact?.keyConfirmed == true,
            request: snap.request == .incoming,
            blocked: snap.blocked
        )

        // Отметка «прочитано» — до последнего входящего, и только после
        // принятия запроса: незнакомец не должен узнать, что прочли.
        // Одна отметка на новое входящее, а не на каждое обновление экрана.
        if mode == .open, let lastIncoming = snap.messages.last(where: { !$0.outgoing }),
           lastIncoming.messageId != receiptSentFor {
            let id = lastIncoming.messageId
            if (try? await Background.run {
                try messenger.sendReadReceipt(peerUsername: peer, untilMessageId: id, nowMillis: CoreStore.nowMillis)
            }) != nil {
                receiptSentFor = id
            }
        }
    }

    private func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, let messenger = try? CoreStore.shared.current() else { return }
        draft = ""
        toast = nil

        // «Отправляется», а не «отправлено»: на сервер оно ещё не ушло.
        let local = MessageRow(id: "local-\(UUID().uuidString)", text: text, timestamp: CoreStore.nowMillis,
                               outgoing: true, status: .pending)
        messages.append(local)
        let peer = peerUsername

        Task {
            do {
                _ = try await Background.run {
                    try messenger.sendMessage(peerUsername: peer, text: text, nowMillis: CoreStore.nowMillis)
                }
                inbox.touch()
                await refresh()
            } catch {
                messages.removeAll { $0.id == local.id }
                switch error as? FfiError {
                case .IdentityChanged, .PeerUnconfirmed:
                    // 🔐 Ядро отвергло ключ: текст возвращается в поле —
                    // он не ушёл никуда.
                    draft = text
                    toast = L10n.t("Сначала сверьте код безопасности", "Compare the safety number first")
                    await refresh()
                default:
                    // Крест, а не молчание: «отправленное», но не ушедшее
                    // сообщение — худший исход.
                    var failed = local
                    failed.status = .failed
                    messages.append(failed)
                    toast = L10n.t("Не отправлено — нет связи", "Not sent — no connection")
                }
            }
        }
    }

    private func accept() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        Task {
            _ = try? await Background.run { try messenger.acceptChat(chatId: chat, nowMillis: CoreStore.nowMillis) }
            await refresh()
        }
    }

    private func decline() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        Task {
            _ = try? await Background.run { try messenger.declineChat(chatId: chat, nowMillis: CoreStore.nowMillis) }
            inbox.touch()
            dismiss()
        }
    }

    /// 🔐 Жалоба доказывается сертификатом отправителя с его конверта:
    /// пока собеседник ничего не прислал, доказать нечем (`canReportChat`).
    private func startReport() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        Task {
            let can = (try? await Background.run { try messenger.canReportChat(chatId: chat) }) ?? false
            if can {
                confirmReport = true
            } else {
                toast = L10n.t("Пожаловаться можно, когда собеседник вам что-нибудь напишет.",
                               "You can report once they have sent you a message.")
            }
        }
    }

    private func sendReport(alsoBlock: Bool) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        let peer = peerUsername
        Task {
            do {
                let recorded = try await Background.run { try messenger.reportChat(chatId: chat, nowMillis: CoreStore.nowMillis) }
                if alsoBlock {
                    _ = try? await Background.run {
                        try messenger.blockChat(chatId: chat, username: peer.isEmpty ? nil : peer, nowMillis: CoreStore.nowMillis)
                    }
                    await refresh()
                }
                toast = recorded
                    ? L10n.t("Жалоба отправлена. Спасибо.", "Report sent. Thank you.")
                    : L10n.t("Вы уже жаловались на этот аккаунт.", "You have already reported this account.")
            } catch {
                toast = L10n.t("Жалобу отправить не удалось. Проверьте связь и попробуйте ещё раз.",
                               "Could not send the report. Check the connection and try again.")
            }
        }
    }

    /// Кнопка со ссылкой возвращает ссылку и ничего не отправляет; кнопка
    /// с данными отправляет их автору сообщения. 🔐 Нажатие сообщает боту,
    /// что человек сейчас у телефона, — как любой ответ.
    private func press(_ message: MessageRow, row: Int, column: Int) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = message.id
        Task {
            do {
                let link = try await Background.run {
                    try messenger.pressMessageButton(messageIdText: id, row: UInt32(row), column: UInt32(column),
                                                     nowMillis: CoreStore.nowMillis)
                }
                if let link {
                    pendingLink = link
                } else {
                    toast = L10n.t("Отправлено", "Sent")
                }
            } catch {
                toast = L10n.t("Кнопка не сработала", "The button didn’t work")
            }
        }
    }

    private func toggleBlock() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        let peer = peerUsername
        let unblock = blocked
        Task {
            _ = try? await Background.run {
                if unblock {
                    try messenger.unblockChat(chatId: chat)
                } else {
                    try messenger.blockChat(chatId: chat, username: peer.isEmpty ? nil : peer, nowMillis: CoreStore.nowMillis)
                }
            }
            await refresh()
        }
    }
}

struct MessageBubble: View {
    let message: MessageRow

    var body: some View {
        HStack {
            if message.outgoing { Spacer(minLength: 50) }
            VStack(alignment: .trailing, spacing: 4) {
                ForEach(Array(message.attachments.enumerated()), id: \.offset) { _, descriptor in
                    AttachmentView(descriptor: descriptor)
                }
                if !message.text.isEmpty {
                    Text(message.text)
                        .font(.system(size: 16))
                        .foregroundStyle(message.outgoing ? GasAppColor.bubbleOutgoingText : GasAppColor.textPrimary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack(spacing: 4) {
                    Text(formatChatTime(message.timestamp))
                    if message.outgoing { statusIcon }
                }
                .font(.system(size: 11))
                .foregroundStyle(message.outgoing ? GasAppColor.bubbleOutgoingMeta : GasAppColor.textTertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(message.outgoing ? GasAppColor.bubbleOutgoing : GasAppColor.bgCard)
            )
            .fixedSize(horizontal: false, vertical: true)
            if !message.outgoing { Spacer(minLength: 50) }
        }
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch message.status {
        case .pending: Image(systemName: "clock")
        case .sent: Image(systemName: "checkmark")
        case .delivered: Image(systemName: "checkmark.circle")
        case .read: Image(systemName: "checkmark.circle.fill")
        case .failed: Image(systemName: "exclamationmark.circle.fill").foregroundStyle(GasAppColor.error)
        }
    }
}

/// Ряды кнопок бота под сообщением.
struct MessageButtons: View {
    let rows: [[ButtonCell]]
    let onPress: (Int, Int) -> Void

    var body: some View {
        VStack(spacing: 6) {
            ForEach(Array(rows.enumerated()), id: \.offset) { rowIndex, row in
                HStack(spacing: 6) {
                    ForEach(Array(row.enumerated()), id: \.offset) { columnIndex, cell in
                        Button { onPress(rowIndex, columnIndex) } label: {
                            HStack(spacing: 4) {
                                Text(cell.label).lineLimit(1)
                                if cell.isLink { Image(systemName: "arrow.up.right.square").font(.system(size: 12)) }
                            }
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(GasAppColor.accent)
                            .frame(maxWidth: .infinity, minHeight: 40)
                            .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(GasAppColor.line, lineWidth: 1))
                        }
                    }
                }
            }
        }
        .frame(maxWidth: 300, alignment: .leading)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
