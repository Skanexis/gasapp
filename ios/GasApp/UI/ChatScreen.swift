// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Сообщение на экране: из ядра или только что набранное (ещё не ушло).
struct MessageRow: Identifiable, Equatable {
    let id: String
    let text: String
    let timestamp: Int64
    let outgoing: Bool
    var status: FfiDeliveryStatus
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
    @State private var confirmDecline = false
    @State private var toast: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(messages) { message in
                            MessageBubble(message: message).id(message.id)
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
                        Button(blocked ? L10n.t("Разблокировать", "Unblock") : L10n.t("Заблокировать", "Block"),
                               role: blocked ? nil : .destructive) { toggleBlock() }
                    }
                } label: { Image(systemName: "ellipsis.circle") }
            }
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

    // MARK: - Ядро

    private func refresh() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let peer = peerUsername
        let known = resolvedChatId

        struct Snapshot: Sendable {
            var chatId: String
            var contact: FfiContact?
            var messages: [FfiMessage]
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
            return Snapshot(chatId: chat, contact: found, messages: list, request: request, blocked: blocked)
        }) else { return }

        resolvedChatId = snap.chatId
        contact = snap.contact
        blocked = snap.blocked
        messages = snap.messages.map {
            MessageRow(id: $0.messageId, text: $0.text, timestamp: $0.timestamp, outgoing: $0.outgoing, status: $0.status)
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
        if mode == .open, let lastIncoming = snap.messages.last(where: { !$0.outgoing }) {
            let id = lastIncoming.messageId
            _ = try? await Background.run {
                try messenger.sendReadReceipt(peerUsername: peer, untilMessageId: id, nowMillis: CoreStore.nowMillis)
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
                Text(message.text)
                    .font(.system(size: 16))
                    .foregroundStyle(message.outgoing ? GasAppColor.bubbleOutgoingText : GasAppColor.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
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
