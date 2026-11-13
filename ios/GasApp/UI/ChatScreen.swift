// SPDX-License-Identifier: Apache-2.0

import PhotosUI
import SwiftUI
import UIKit

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
    /// Время для показа. Считается один раз, при чтении переписки, а не
    /// при каждой отрисовке пузыря; пусто — пузырь посчитает сам.
    var time = ""
    /// С этого сообщения начинается день: над ним — плашка с датой.
    var startsDay = false
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
    @State private var showProfile = false
    @State private var showReport = false
    /// Ссылка из кнопки бота — ждёт решения человека.
    @State private var pendingLink: String?
    @State private var confirmDecline = false
    @State private var toast: String?
    @State private var receiptSentFor: String?
    /// Описания вложений уже прочитанных сообщений. За каждым — поход в
    /// базу, а переписка перечитывается на любое событие; вложения
    /// сообщения не меняются. 🔐 В описании — ключ файла: живёт, пока
    /// открыт экран, вместе с самой перепиской.
    @State private var knownAttachments: [String: [Data]] = [:]
    @State private var photo: PhotosPickerItem?
    @State private var sendingPhoto = false
    @State private var editing: MessageRow?
    @State private var editText = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(messages) { message in
                            // Начало дня посчитано при чтении переписки:
                            // календарь в отрисовке — работа на каждый кадр.
                            if message.startsDay {
                                DaySeparator(date: Self.date(of: message))
                            }
                            MessageBubble(message: message)
                                .id(message.id)
                                .contextMenu { messageMenu(message) }
                                .onTapGesture { if message.status == .failed { retry(message) } }
                                .transition(.move(edge: .bottom).combined(with: .opacity))
                            if !message.buttons.isEmpty {
                                MessageButtons(rows: message.buttons) { row, column in press(message, row: row, column: column) }
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                }
                // Переписка открывается на последнем сообщении, а не сверху.
                .defaultScrollAnchor(.bottom)
                .scrollDismissesKeyboard(.interactively)
                .onChange(of: messages.count) { before, _ in
                    guard let last = messages.last else { return }
                    // Открытие чата — сразу на месте, без проезда по всей
                    // переписке; новое сообщение — плавно.
                    if before == 0 {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    } else {
                        withAnimation(.easeOut(duration: 0.25)) { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }

            if let toast {
                Text(toast).font(GasFont.text(13, .semibold)).foregroundStyle(GasAppColor.warn)
                    .padding(.vertical, 6)
            }

            guardPanel
            // Поле ввода — отдельным видом, и текст сюда идёт привязкой:
            // этот экран набираемого не читает, поэтому нажатие клавиши
            // перерисовывает одно поле, а не всю переписку.
            ChatComposer(draft: $draft, photo: $photo, enabled: mode == .open, sendingPhoto: sendingPhoto,
                         onSend: { send() }, onPhoto: { sendPhoto($0) })
        }
        .gasScreen()
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                // Нажатие на имя — профиль собеседника, как в любом мессенджере.
                Button { showProfile = true } label: {
                    HStack(spacing: 8) {
                        Avatar(name: peerUsername.isEmpty ? title : peerUsername, size: 30)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(title).font(GasFont.text(16, .bold)).foregroundStyle(GasAppColor.textPrimary)
                            Text(verificationLabel.0).font(GasFont.text(11, .semibold)).foregroundStyle(verificationLabel.1)
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityHint(L10n.t("Открыть профиль", "Open profile", "Apri il profilo"))
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    if contact != nil {
                        Button(L10n.t("Код безопасности", "Safety number", "Numero di sicurezza")) { showSafety = true }
                    }
                    if !resolvedChatId.isEmpty {
                        // Исчезающие сообщения: ядро стирает их у обоих по сроку.
                        Menu(L10n.t("Исчезающие сообщения", "Disappearing messages", "Messaggi effimeri")) {
                            Button(L10n.t("Выключить", "Off", "Disattivati")) { setTimer(0) }
                            Button(L10n.t("Через час", "After 1 hour", "Dopo 1 ora")) { setTimer(3600) }
                            Button(L10n.t("Через сутки", "After 1 day", "Dopo 1 giorno")) { setTimer(86_400) }
                            Button(L10n.t("Через неделю", "After 1 week", "Dopo 1 settimana")) { setTimer(604_800) }
                        }
                    }
                    if !resolvedChatId.isEmpty {
                        Button(L10n.t("Пожаловаться", "Report", "Segnala"), role: .destructive) { startReport() }
                        Button(blocked ? L10n.t("Разблокировать", "Unblock", "Sblocca") : L10n.t("Заблокировать", "Block", "Blocca"),
                               role: blocked ? nil : .destructive) { toggleBlock() }
                    }
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
        // Ссылка из кнопки — только https (ядро отвергает иные схемы, данные
        // входа в адресе и подменные буквы); открыть её решает человек,
        // видя адрес целиком (как на Android).
        .confirmationDialog(L10n.t("Открыть ссылку?", "Open the link?", "Aprire il link?"), isPresented: Binding(
            get: { pendingLink != nil }, set: { if !$0 { pendingLink = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Открыть", "Open", "Apri")) {
                if let link = pendingLink, let url = URL(string: link), url.scheme == "https" {
                    UIApplication.shared.open(url)
                }
                pendingLink = nil
            }
        } message: {
            Text(pendingLink ?? "")
        }
        .sheet(isPresented: $showProfile) { profileSheet }
        .sheet(isPresented: $showReport) {
            ReportSheet(username: peerUsername.isEmpty ? title : peerUsername,
                        theirMessages: messages.filter { !$0.outgoing && !$0.text.isEmpty }.suffix(5).map { $0 }) { report in
                showReport = false
                sendReport(report)
            }
        }
        .sheet(isPresented: $showSafety, onDismiss: { Task { await refresh() } }) {
            if let contact {
                NavigationStack { SafetyNumberScreen(contact: contact) }
            }
        }
        .confirmationDialog(L10n.t("Отклонить запрос?", "Decline request?", "Rifiutare la richiesta?"), isPresented: $confirmDecline,
                            titleVisibility: .visible) {
            Button(L10n.t("Отклонить и удалить", "Decline and delete", "Rifiuta ed elimina"), role: .destructive) { decline() }
        } message: {
            Text(L10n.t("Переписка удалится. Собеседник не узнает даже того, что вы её видели.",
                        "The chat is deleted. The sender won’t even learn you saw it.", "La chat viene eliminata. Il mittente non saprà nemmeno che l’hai vista."))
        }
        .alert(L10n.t("Изменить сообщение", "Edit message", "Modifica messaggio"), isPresented: Binding(
            get: { editing != nil }, set: { if !$0 { editing = nil } }
        )) {
            TextField(L10n.t("Текст", "Text", "Testo"), text: $editText)
            Button(L10n.t("Сохранить", "Save", "Salva")) { saveEdit() }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) { editing = nil }
        }
        .task {
            resolvedChatId = chatId
            // Сначала — то, что уже лежит на телефоне: это мгновенно.
            // Прежде экран ждал ответа сервера (через Tor — секунды) и
            // всё это время был пуст.
            await refresh()
            await inbox.receiveOnce()
            await refresh()
        }
        .onChange(of: inbox.revision) { _, _ in Task { await refresh() } }
    }

    // MARK: - Состояние

    private var verificationLabel: (String, Color) {
        if contact?.verified == true { return (L10n.t("сверен лично", "verified in person", "verificato di persona"), GasAppColor.ok) }
        if contact?.ktConfirmed == true { return (L10n.t("ключ подтверждён журналом", "key confirmed by log", "chiave confermata dal registro"), GasAppColor.accent) }
        return (L10n.t("не сверен", "not verified", "non verificato"), GasAppColor.textTertiary)
    }

    @ViewBuilder
    private var guardPanel: some View {
        switch mode {
        case .open:
            EmptyView()
        case .blocked:
            panel(Banner(title: L10n.t("\(title) заблокирован", "\(title) is blocked", "\(title) è bloccato"),
                         message: L10n.t("Вы не получаете его сообщений.", "You don’t receive their messages.", "Non ricevi i suoi messaggi."), tone: .info)) {
                OutlineButton(title: L10n.t("Разблокировать", "Unblock", "Sblocca")) { toggleBlock() }
            }
        case .chooseKey:
            panel(Banner(title: L10n.t("Ключ собеседника сменился", "Their key changed", "La sua chiave è cambiata"),
                         message: L10n.t("Новый телефон — или кто-то выдаёт себя за \(title). Сверьте код безопасности.",
                                         "A new phone — or someone pretending to be \(title). Compare the safety number.", "Un nuovo telefono, oppure qualcuno che si spaccia per \(title). Confronta il numero di sicurezza."),
                         tone: .error)) {
                GoldButton(title: L10n.t("Сверить код", "Compare safety number", "Confronta il numero di sicurezza")) { showSafety = true }
            }
        case .confirmKey:
            panel(Banner(title: L10n.t("Ключ ещё не подтверждён", "Key not confirmed yet", "Chiave non ancora confermata"),
                         message: L10n.t("Его назвал только сервер. Сверьте код безопасности с \(title) или добавьте по его ссылке/QR.",
                                         "Only the server named it. Compare the safety number with \(title) or add them by their link/QR.", "L’ha indicata solo il server. Confronta il numero di sicurezza con \(title) o aggiungilo tramite il suo link/QR."))) {
                GoldButton(title: L10n.t("Сверить код", "Compare safety number", "Confronta il numero di sicurezza")) { showSafety = true }
            }
        case .request:
            panel(Banner(title: L10n.t("\(title) хочет написать вам", "\(title) wants to message you", "\(title) vuole scriverti"),
                         message: L10n.t("Пока вы не примете запрос, собеседник не узнает, что вы прочли.",
                                         "Until you accept, they won’t know you read it.", "Finché non accetti, non saprà che hai letto."), tone: .info)) {
                HStack(spacing: 10) {
                    OutlineButton(title: L10n.t("Отклонить", "Decline", "Rifiuta"), tone: GasAppColor.error) { confirmDecline = true }
                    GoldButton(title: L10n.t("Принять", "Accept", "Accetta")) { accept() }
                }
            }
        case .replaced:
            panel(Banner(title: L10n.t("Аккаунт заменён", "Account replaced", "Account sostituito"),
                         message: L10n.t("Это имя теперь у другого аккаунта. Писать сюда нельзя.",
                                         "This username now belongs to another account.", "Questo nome utente ora appartiene a un altro account."), tone: .error)) { EmptyView() }
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

    static func date(of message: MessageRow) -> Date {
        Date(timeIntervalSince1970: TimeInterval(message.timestamp) / 1000)
    }

    // MARK: - Действия с сообщением

    @ViewBuilder
    private func messageMenu(_ message: MessageRow) -> some View {
        if message.outgoing {
            // Статус словами — то, что значки говорят знаками.
            Text(MessageBubble.statusText(message.status))
        }
        if message.status == .failed {
            Button { retry(message) } label: {
                Label(L10n.t("Отправить ещё раз", "Send again", "Invia di nuovo"), systemImage: "arrow.clockwise")
            }
            Button(role: .destructive) { messages.removeAll { $0.id == message.id } } label: {
                Label(L10n.t("Убрать", "Remove", "Rimuovi"), systemImage: "trash")
            }
        }
        if !message.text.isEmpty {
            Button {
                // 🔐 Только локально и с истечением: буфер обмена видят
                // другие приложения.
                UIPasteboard.general.setItems([["public.utf8-plain-text": message.text]],
                                              options: [.localOnly: true,
                                                        .expirationDate: Date().addingTimeInterval(60)])
            } label: { Label(L10n.t("Копировать", "Copy", "Copia"), systemImage: "doc.on.doc") }
        }
        if message.outgoing && mode == .open && !message.id.hasPrefix("local-") {
            Button {
                editing = message
                editText = message.text
            } label: { Label(L10n.t("Изменить", "Edit", "Modifica"), systemImage: "pencil") }
            Button(role: .destructive) { deleteForEveryone(message) } label: {
                Label(L10n.t("Удалить у всех", "Delete for everyone", "Elimina per tutti"), systemImage: "trash")
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
                ? (seconds == 0 ? L10n.t("Исчезающие сообщения выключены", "Disappearing messages off", "Messaggi effimeri disattivati")
                                : L10n.t("Новые сообщения будут исчезать у вас обоих", "New messages will disappear for both of you", "I nuovi messaggi spariranno per entrambi"))
                : L10n.t("Не удалось изменить", "Could not change it", "Impossibile modificarlo")
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
                toast = L10n.t("Не удалось изменить", "Could not edit", "Impossibile modificare")
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
                toast = L10n.t("Не удалось удалить", "Could not delete", "Impossibile eliminare")
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
                toast = L10n.t("Фото не открылось", "Could not open the photo", "Impossibile aprire la foto")
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
                toast = L10n.t("Фото не отправлено", "Photo not sent", "Foto non inviata")
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
        let remembered = knownAttachments

        struct Snapshot: Sendable {
            var chatId: String
            var contact: FfiContact?
            var rows: [MessageRow]
            var lastIncoming: String?
            var attachments: [String: [Data]]
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
            var rows: [MessageRow] = []
            rows.reserveCapacity(list.count)
            let calendar = Calendar.current
            var previousDay: Date?
            for message in list {
                let id = message.messageId
                // Уже читали — второй раз в базу не идём (и пустой ответ
                // тоже помним: у большинства сообщений вложений нет).
                let descriptors: [Data]
                if let seen = remembered[id] {
                    descriptors = seen
                } else if let read = try? messenger.attachmentsOf(messageId: id) {
                    descriptors = read
                    attachments[id] = read
                } else {
                    descriptors = []
                }
                // Кнопки бывают только под сообщением собеседника (бота).
                // Читаются каждый раз: бот вправе их сменить.
                var buttons: [[ButtonCell]] = []
                if !message.outgoing, let found = try? messenger.messageButtons(messageIdText: id), !found.isEmpty {
                    buttons = found.map { $0.map { ButtonCell(label: $0.label, isLink: $0.isLink) } }
                }
                // Время и начало дня — здесь, в фоне, один раз на сообщение.
                let date = Date(timeIntervalSince1970: TimeInterval(message.timestamp) / 1000)
                let startsDay = previousDay.map { !calendar.isDate(date, inSameDayAs: $0) } ?? true
                previousDay = date
                rows.append(MessageRow(id: id, text: message.text, timestamp: message.timestamp,
                                       outgoing: message.outgoing, status: message.status,
                                       attachments: descriptors, buttons: buttons,
                                       time: formatChatTime(message.timestamp), startsDay: startsDay))
            }
            return Snapshot(chatId: chat, contact: found, rows: rows,
                            lastIncoming: list.last(where: { !$0.outgoing })?.messageId,
                            attachments: attachments, request: request, blocked: blocked)
        }) else { return }

        if !snap.attachments.isEmpty {
            knownAttachments.merge(snap.attachments) { _, fresh in fresh }
        }
        // Присваивается только изменившееся: каждое присваивание —
        // перерисовка экрана, а перечитывание чаще всего ничего не меняет.
        if resolvedChatId != snap.chatId { resolvedChatId = snap.chatId }
        contact = snap.contact
        if blocked != snap.blocked { blocked = snap.blocked }
        if messages != snap.rows { messages = snap.rows }
        // Контакта нет или он не прочитался — ключ не подтверждён:
        // отправку это не откроет, её всё равно решает ядро.
        let decided = SendMode.decide(
            keyChanged: snap.contact?.keyChanged == true,
            replaced: snap.contact?.replaced == true,
            keyConfirmed: snap.contact?.keyConfirmed == true,
            request: snap.request == .incoming,
            blocked: snap.blocked
        )
        if mode != decided { mode = decided }

        // Отметка «прочитано» — до последнего входящего, и только после
        // принятия запроса: незнакомец не должен узнать, что прочли.
        // Одна отметка на новое входящее, а не на каждое обновление экрана.
        if mode == .open, let id = snap.lastIncoming, id != receiptSentFor {
            if (try? await Background.run {
                try messenger.sendReadReceipt(peerUsername: peer, untilMessageId: id, nowMillis: CoreStore.nowMillis)
            }) != nil {
                receiptSentFor = id
            }
        }
    }

    /// Не ушедшее — ещё раз: ядро повтора не знает, поэтому это новая
    /// отправка того же текста, а неудачная строка убирается.
    private func retry(_ message: MessageRow) {
        guard message.status == .failed, !message.text.isEmpty else { return }
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        messages.removeAll { $0.id == message.id }
        send(text: message.text)
    }

    private func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        draft = ""
        send(text: text)
    }

    private func send(text: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        toast = nil

        // «Отправляется», а не «отправлено»: на сервер оно ещё не ушло.
        let now = CoreStore.nowMillis
        let startsDay = messages.last.map {
            !Calendar.current.isDate(Self.date(of: $0), inSameDayAs: Date(timeIntervalSince1970: TimeInterval(now) / 1000))
        } ?? true
        let local = MessageRow(id: "local-\(UUID().uuidString)", text: text, timestamp: now,
                               outgoing: true, status: .pending, time: formatChatTime(now), startsDay: startsDay)
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
                    toast = L10n.t("Сначала сверьте код безопасности", "Compare the safety number first", "Prima confronta il numero di sicurezza")
                    await refresh()
                default:
                    // Крест, а не молчание: «отправленное», но не ушедшее
                    // сообщение — худший исход.
                    var failed = local
                    failed.status = .failed
                    messages.append(failed)
                    toast = L10n.t("Не отправлено — нет связи", "Not sent — no connection", "Non inviato: nessuna connessione")
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
    /// Новое окно — после того как закроется профиль: SwiftUI не
    /// показывает второе окно, пока первое ещё уезжает.
    private func presentAfterSheet(_ show: @escaping () -> Void) async {
        if showProfile {
            showProfile = false
            try? await Task.sleep(for: .milliseconds(450))
        }
        show()
    }

    private func startReport() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        Task {
            let can = (try? await Background.run { try messenger.canReportChat(chatId: chat) }) ?? false
            if can {
                await presentAfterSheet { showReport = true }
            } else {
                toast = L10n.t("Пожаловаться можно, когда собеседник вам что-нибудь напишет.",
                               "You can report once they have sent you a message.", "Puoi segnalare dopo che ti ha inviato un messaggio.")
            }
        }
    }

    /// 🔐 Жалоба уходит с сертификатом отправителя (доказательство, что
    /// он вам писал), причиной и — если человек так решил — уликами,
    /// которые ядро шифрует здесь ключом админ-центра.
    private func sendReport(_ report: ReportDraft) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let chat = resolvedChatId
        let peer = peerUsername
        let alsoBlock = report.alsoBlock
        toast = L10n.t("Отправляем жалобу…", "Sending the report…", "Invio della segnalazione…")
        Task {
            do {
                let outcome = try await Background.run {
                    try messenger.reportChatWithEvidence(chatId: chat, reason: report.reason, quotes: report.quotes,
                                                         images: report.images, nowMillis: CoreStore.nowMillis)
                }
                let recorded = outcome.recorded
                let evidenceLost = report.hasEvidence && !outcome.evidenceStored
                if alsoBlock {
                    _ = try? await Background.run {
                        try messenger.blockChat(chatId: chat, username: peer.isEmpty ? nil : peer, nowMillis: CoreStore.nowMillis)
                    }
                    await refresh()
                }
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                if evidenceLost {
                    toast = L10n.t("Жалоба отправлена, но сервер сейчас не принимает вложения.",
                                   "Report sent, but the server is not accepting attachments right now.",
                                   "Segnalazione inviata, ma ora il server non accetta allegati.")
                } else if recorded {
                    toast = L10n.t("Жалоба отправлена. Спасибо.", "Report sent. Thank you.", "Segnalazione inviata. Grazie.")
                } else {
                    toast = report.hasEvidence
                        ? L10n.t("Вы уже жаловались — вложения добавлены к жалобе.", "You had already reported — the attachments were added.", "Avevi già segnalato: gli allegati sono stati aggiunti.")
                        : L10n.t("Вы уже жаловались на этот аккаунт.", "You have already reported this account.", "Hai già segnalato questo account.")
                }
            } catch {
                toast = L10n.t("Жалобу отправить не удалось. Проверьте связь и попробуйте ещё раз.",
                               "Could not send the report. Check the connection and try again.", "Impossibile inviare la segnalazione. Controlla la connessione e riprova.")
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
                    toast = L10n.t("Отправлено", "Sent", "Inviato")
                }
            } catch {
                toast = L10n.t("Кнопка не сработала", "The button didn’t work", "Il pulsante non ha funzionato")
            }
        }
    }

    // MARK: - Профиль собеседника

    private var profileSheet: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 10) {
                        Avatar(name: peerUsername.isEmpty ? title : peerUsername, size: 92)
                        Text(peerUsername.isEmpty ? title : "@\(peerUsername)")
                            .font(GasFont.display(24)).foregroundStyle(GasAppColor.textPrimary)
                        Label(verificationLabel.0, systemImage: contact?.verified == true ? "checkmark.seal.fill" : "key.fill")
                            .font(GasFont.text(13, .semibold)).foregroundStyle(verificationLabel.1)
                            .padding(.horizontal, 12).padding(.vertical, 5)
                            .background(Capsule().fill(verificationLabel.1.opacity(0.14)))
                        if blocked {
                            Label(L10n.t("Заблокирован", "Blocked", "Bloccato"), systemImage: "hand.raised.fill")
                                .font(GasFont.text(13, .semibold)).foregroundStyle(GasAppColor.error)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .listRowBackground(Color.clear)
                }

                Section {
                    Button { Task { await presentAfterSheet { showSafety = true } } } label: {
                        SettingRow(icon: "checkmark.shield.fill", color: .green,
                                   title: L10n.t("Код безопасности", "Safety number", "Numero di sicurezza"),
                                   detail: L10n.t("Сверьте лично — и никто не встанет между вами",
                                                  "Compare in person — then nobody can stand in between",
                                                  "Confrontalo di persona: nessuno potrà mettersi in mezzo"))
                    }
                    .disabled(contact == nil)
                    Menu {
                        Button(L10n.t("Выключить", "Off", "Disattivati")) { setTimer(0) }
                        Button(L10n.t("Через час", "After 1 hour", "Dopo 1 ora")) { setTimer(3600) }
                        Button(L10n.t("Через сутки", "After 1 day", "Dopo 1 giorno")) { setTimer(86_400) }
                        Button(L10n.t("Через неделю", "After 1 week", "Dopo 1 settimana")) { setTimer(604_800) }
                    } label: {
                        SettingRow(icon: "timer", color: .purple,
                                   title: L10n.t("Исчезающие сообщения", "Disappearing messages", "Messaggi effimeri"))
                    }
                    .disabled(resolvedChatId.isEmpty)
                }

                Section {
                    Button { toggleBlock() } label: {
                        SettingRow(icon: blocked ? "hand.raised.slash.fill" : "hand.raised.fill", color: .orange,
                                   title: blocked ? L10n.t("Разблокировать", "Unblock", "Sblocca")
                                                  : L10n.t("Заблокировать", "Block", "Blocca"))
                    }
                    Button { startReport() } label: {
                        SettingRow(icon: "flag.fill", color: .red,
                                   title: L10n.t("Пожаловаться", "Report", "Segnala"),
                                   detail: L10n.t("Можно приложить скриншоты", "You can attach screenshots", "Puoi allegare screenshot"))
                    }
                } footer: {
                    Text(L10n.t("Собеседник не узнает о блокировке и жалобе.",
                                "They are not told about a block or a report.",
                                "Non viene avvisato di blocchi o segnalazioni."))
                }
                .disabled(resolvedChatId.isEmpty)
            }
            .listRowBackground(GasAppColor.bgCard)
            .scrollContentBackground(.hidden)
            .background(GasAppColor.bgBase.ignoresSafeArea())
            .navigationTitle(L10n.t("Профиль", "Profile", "Profilo"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.t("Готово", "Done", "Fatto")) { showProfile = false }
                }
            }
        }
        .presentationDetents([.medium, .large])
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

    /// Время пузыря: посчитанное при чтении переписки, иначе — здесь.
    private var time: String {
        message.time.isEmpty ? formatChatTime(message.timestamp) : message.time
    }

    var body: some View {
        HStack {
            if message.outgoing { Spacer(minLength: 56) }
            VStack(alignment: .trailing, spacing: 3) {
                ForEach(Array(message.attachments.enumerated()), id: \.offset) { _, descriptor in
                    AttachmentView(descriptor: descriptor)
                }
                if !message.text.isEmpty {
                    // Пузырь — по тексту, а не во всю ширину: прежде
                    // .frame(maxWidth: .infinity) растягивал даже «ок».
                    Text(message.text)
                        .font(GasFont.text(16))
                        .foregroundStyle(message.outgoing ? GasAppColor.bubbleOutgoingText : GasAppColor.textPrimary)
                        .multilineTextAlignment(.leading)
                }
                HStack(spacing: 4) {
                    Text(time)
                    if message.outgoing { statusIcon }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(message.outgoing
                    ? "\(time), \(Self.statusText(message.status))"
                    : time)
                .font(GasFont.text(11))
                .foregroundStyle(message.outgoing ? GasAppColor.bubbleOutgoingMeta : GasAppColor.textTertiary)
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)
            .padding(.bottom, 6)
            .background(
                // Хвостик — угол 6 со стороны говорящего (DESIGN.md).
                UnevenRoundedRectangle(
                    topLeadingRadius: 16,
                    bottomLeadingRadius: message.outgoing ? 16 : 6,
                    bottomTrailingRadius: message.outgoing ? 6 : 16,
                    topTrailingRadius: 16,
                    style: .continuous
                )
                .fill(message.outgoing ? GasAppColor.bubbleOutgoing : GasAppColor.bgCard)
            )
            .frame(maxWidth: 320, alignment: message.outgoing ? .trailing : .leading)
            .fixedSize(horizontal: false, vertical: true)
            .overlay(alignment: .bottomTrailing) {
                if message.status == .failed {
                    Text(L10n.t("Не отправлено · нажмите, чтобы повторить", "Not sent · tap to retry", "Non inviato · tocca per riprovare"))
                        .font(GasFont.text(11, .semibold)).foregroundStyle(GasAppColor.error)
                        .fixedSize()
                        .offset(y: 18)
                }
            }
            .padding(.bottom, message.status == .failed ? 18 : 0)
            if !message.outgoing { Spacer(minLength: 56) }
        }
    }

    /// Статус значком: часы — уходит; одна галочка — на сервере; две —
    /// дошло до телефона; две золотые — прочитано; красный — не ушло.
    @ViewBuilder
    private var statusIcon: some View {
        switch message.status {
        case .pending:
            Image(systemName: "clock").symbolEffect(.pulse, options: .repeating)
        case .sent:
            Image(systemName: "checkmark")
        case .delivered:
            DoubleCheck()
        case .read:
            DoubleCheck().foregroundStyle(GasAppColor.accent)
        case .failed:
            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(GasAppColor.error)
        }
    }

    static func statusText(_ status: FfiDeliveryStatus) -> String {
        switch status {
        case .pending: L10n.t("Отправляется…", "Sending…", "Invio…")
        case .sent: L10n.t("Отправлено на сервер", "Sent to the server", "Inviato al server")
        case .delivered: L10n.t("Доставлено", "Delivered", "Consegnato")
        case .read: L10n.t("Прочитано", "Read", "Letto")
        case .failed: L10n.t("Не отправлено", "Not sent", "Non inviato")
        }
    }
}

/// Поле ввода переписки: фото, текст, кнопка отправки.
///
/// Отдельный вид ради отклика: набираемый текст читает только он.
/// Пока поле было частью экрана переписки, каждая буква перерисовывала
/// экран целиком — вместе с лентой сообщений.
struct ChatComposer: View {
    @Binding var draft: String
    @Binding var photo: PhotosPickerItem?
    /// Можно ли писать (решает ядро; экран лишь показывает).
    let enabled: Bool
    let sendingPhoto: Bool
    let onSend: () -> Void
    let onPhoto: (PhotosPickerItem) -> Void

    private var canSend: Bool {
        enabled && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
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
            .accessibilityLabel(L10n.t("Отправить фото", "Send a photo", "Invia una foto"))
            .onChange(of: photo) { _, item in
                if let item { onPhoto(item) }
            }
            TextField(L10n.t("Сообщение", "Message", "Messaggio"), text: $draft, axis: .vertical)
                .font(GasFont.text(16))
                .lineLimit(1...6)
                .padding(.horizontal, 14).padding(.vertical, 10)
                .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(GasAppColor.bgCard))
                .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .stroke(canSend ? GasAppColor.accent.opacity(0.4) : GasAppColor.line, lineWidth: 1))
                .foregroundStyle(GasAppColor.textPrimary)
            Button {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                onSend()
            } label: {
                Image(systemName: "arrow.up")
                    .font(.system(size: 17, weight: .bold))
                    .foregroundStyle(canSend ? GasAppColor.accentOn : GasAppColor.textTertiary)
                    .frame(width: 40, height: 40)
                    .background(Circle().fill(canSend ? GasAppColor.accent : GasAppColor.bgCard))
                    .scaleEffect(canSend ? 1 : 0.92)
            }
            .disabled(!canSend)
            .animation(.spring(response: 0.25, dampingFraction: 0.7), value: canSend)
            .accessibilityLabel(L10n.t("Отправить", "Send", "Invia"))
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(GasAppColor.bgRaised)
        .overlay(alignment: .top) { Rectangle().fill(GasAppColor.line).frame(height: 1) }
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.4)
    }
}

/// Разделитель дней в переписке: «Сегодня», «Вчера» или дата.
struct DaySeparator: View {
    let date: Date

    var body: some View {
        Text(label)
            .font(GasFont.text(12, .semibold))
            .foregroundStyle(GasAppColor.textSecondary)
            .padding(.horizontal, 12).padding(.vertical, 5)
            .background(Capsule().fill(GasAppColor.bgRaised))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .accessibilityAddTraits(.isHeader)
    }

    private var label: String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return L10n.t("Сегодня", "Today", "Oggi") }
        if calendar.isDateInYesterday(date) { return L10n.t("Вчера", "Yesterday", "Ieri") }
        return date.formatted(.dateTime.day().month(.wide))
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
                            .font(GasFont.text(14, .semibold))
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

/// Две галочки — «дошло до телефона».
struct DoubleCheck: View {
    var body: some View {
        ZStack(alignment: .leading) {
            Image(systemName: "checkmark")
            Image(systemName: "checkmark").offset(x: 5)
        }
        .padding(.trailing, 5)
    }
}

// MARK: - Жалоба с уликами

/// Что человек решил отправить с жалобой.
struct ReportDraft {
    let reason: UInt8
    let alsoBlock: Bool
    let quotes: [FfiReportQuote]
    let images: [Data]

    var hasEvidence: Bool { !quotes.isEmpty || !images.isEmpty }
}

/// Жалоба: причина, «заодно заблокировать», последние сообщения
/// обидчика и скриншоты.
///
/// 🔐 Сервер получает сертификат отправителя (что этот аккаунт вам
/// писал) и причину. Сообщения и скриншоты — только если человек их
/// оставил: ядро шифрует их на телефоне ключом админ-центра
/// (`report_evidence`), узлы и база видят шифр. Метаданные снимков
/// стираются (`ChatScreen.strippedJPEG`), снимки ужимаются.
struct ReportSheet: View {
    let username: String
    let theirMessages: [MessageRow]
    let onSend: (ReportDraft) -> Void

    @State private var reason: UInt8 = 1
    @State private var alsoBlock = true
    @State private var attachMessages = true
    @State private var picks: [PhotosPickerItem] = []
    @State private var images: [Data] = []
    @State private var loading = false
    @Environment(\.dismiss) private var dismiss

    struct Reason: Identifiable {
        let id: UInt8
        let icon: String
        let label: String
    }

    /// Коды — как у сервера (миграция 0030).
    private var reasons: [Reason] {
        [(1, "exclamationmark.bubble", L10n.t("Спам или мошенничество", "Spam or scam", "Spam o truffa")),
         (4, "hand.raised", L10n.t("Травля или угрозы", "Harassment or threats", "Molestie o minacce")),
         (6, "person.crop.circle.badge.questionmark", L10n.t("Выдаёт себя за другого", "Impersonation", "Furto d’identità")),
         (2, "exclamationmark.triangle", L10n.t("Незаконное содержимое", "Illegal content", "Contenuti illegali")),
         (3, "figure.and.child.holdinghands", L10n.t("Безопасность детей", "Child safety", "Sicurezza dei minori")),
         (5, "ellipsis.circle", L10n.t("Другое", "Something else", "Altro"))]
            .map { Reason(id: $0.0, icon: $0.1, label: $0.2) }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(reasons) { item in
                        let code = item.id
                        Button {
                            UISelectionFeedbackGenerator().selectionChanged()
                            reason = code
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: item.icon).frame(width: 24)
                                    .foregroundStyle(code == 3 ? GasAppColor.error : GasAppColor.accent)
                                Text(item.label).foregroundStyle(GasAppColor.textPrimary)
                                Spacer()
                                if reason == code {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(GasAppColor.accent)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                } header: {
                    Text(L10n.t("Что случилось", "What happened", "Cosa è successo"))
                }

                Section {
                    Toggle(isOn: $attachMessages) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(L10n.t("Приложить его сообщения", "Attach their messages", "Allega i suoi messaggi"))
                            Text(theirMessages.isEmpty
                                 ? L10n.t("Сообщений от него нет", "No messages from them", "Nessun messaggio da lui")
                                 : L10n.t("Последние: \(theirMessages.count)", "Latest: \(theirMessages.count)", "Ultimi: \(theirMessages.count)"))
                                .font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                        }
                    }
                    .tint(GasAppColor.accent)
                    .disabled(theirMessages.isEmpty)

                    PhotosPicker(selection: $picks, maxSelectionCount: 5, matching: .images) {
                        HStack {
                            Label(images.isEmpty ? L10n.t("Приложить скриншоты", "Attach screenshots", "Allega screenshot")
                                                 : L10n.t("Скриншотов: \(images.count)", "Screenshots: \(images.count)", "Screenshot: \(images.count)"),
                                  systemImage: "photo.on.rectangle.angled")
                            Spacer()
                            if loading { ProgressView() }
                        }
                    }
                    if !images.isEmpty {
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(images.indices, id: \.self) { index in
                                    if let image = UIImage(data: images[index]) {
                                        Image(uiImage: image).resizable().scaledToFill()
                                            .frame(width: 64, height: 110)
                                            .clipShape(RoundedRectangle(cornerRadius: 10))
                                            .overlay(alignment: .topTrailing) {
                                                Button {
                                                    images.remove(at: index)
                                                } label: {
                                                    Image(systemName: "xmark.circle.fill").symbolRenderingMode(.palette)
                                                        .foregroundStyle(.white, .black.opacity(0.6))
                                                }
                                                .padding(3)
                                                .accessibilityLabel(L10n.t("Убрать", "Remove", "Rimuovi"))
                                            }
                                    }
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                } header: {
                    Text(L10n.t("Доказательства", "Evidence", "Prove"))
                } footer: {
                    Label(L10n.t("Шифруются на этом телефоне так, что открыть их может только модератор GasApp. Сервер и его база видят лишь шифр. Удаляются после решения или через 30 дней. Место съёмки и модель телефона из снимков стираются.",
                                 "Encrypted on this phone so that only the GasApp moderator can open them. The server and its database see only ciphertext. Deleted after a decision or within 30 days. Location and device details are removed from screenshots.",
                                 "Cifrate su questo telefono: solo il moderatore di GasApp può aprirle. Il server e il suo database vedono solo dati cifrati. Eliminate dopo la decisione o entro 30 giorni. Posizione e dati del telefono vengono rimossi dagli screenshot."),
                          systemImage: "lock.fill")
                        .font(GasFont.text(12))
                }

                Section {
                    Toggle(L10n.t("Заодно заблокировать", "Also block", "Blocca anche"), isOn: $alsoBlock)
                        .tint(GasAppColor.accent)
                } footer: {
                    Text(L10n.t("Сервер получит доказательство, что @\(username) вам писал. @\(username) о жалобе не узнает.",
                                "The server gets proof that @\(username) wrote to you. @\(username) is not told about the report.",
                                "Il server riceve la prova che @\(username) ti ha scritto. @\(username) non viene avvisato."))
                }
            }
            .listRowBackground(GasAppColor.bgCard)
            .scrollContentBackground(.hidden)
            .background(GasAppColor.bgBase.ignoresSafeArea())
            .navigationTitle(L10n.t("Жалоба на @\(username)", "Report @\(username)", "Segnala @\(username)"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.t("Отмена", "Cancel", "Annulla")) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.t("Отправить", "Send", "Invia")) { send() }
                        .fontWeight(.bold)
                        .disabled(loading)
                }
            }
            .onChange(of: picks) { _, items in
                loading = true
                Task {
                    var loaded: [Data] = []
                    for item in items {
                        if let raw = try? await item.loadTransferable(type: Data.self),
                           let small = Self.evidenceJPEG(raw) {
                            loaded.append(small)
                        }
                    }
                    images = loaded
                    loading = false
                }
            }
        }
    }

    private func send() {
        let quotes = attachMessages
            ? theirMessages.map { FfiReportQuote(sentAtMillis: $0.timestamp, text: Self.clipped($0.text)) }
            : []
        onSend(ReportDraft(reason: reason, alsoBlock: alsoBlock, quotes: quotes, images: images))
    }

    /// Не длиннее 4096 байт UTF-8 — предел ядра.
    static func clipped(_ text: String) -> String {
        var out = ""
        for character in text {
            if out.utf8.count + String(character).utf8.count > 4000 { break }
            out.append(character)
        }
        return out
    }

    /// Скриншот для улик: без метаданных, до 1280 точек и до 380 КБ —
    /// пять штук помещаются в одну жалобу.
    static func evidenceJPEG(_ data: Data) -> Data? {
        guard let image = UIImage(data: data) else { return nil }
        let longest = max(image.size.width, image.size.height)
        let scale = longest > 1280 ? 1280 / longest : 1
        let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let redrawn = UIGraphicsImageRenderer(size: size, format: format).image { _ in
            image.draw(in: CGRect(origin: .zero, size: size))
        }
        for quality in [0.7, 0.55, 0.4, 0.3] {
            if let jpeg = redrawn.jpegData(compressionQuality: quality), jpeg.count <= 380 * 1024 {
                return jpeg
            }
        }
        return nil
    }
}
