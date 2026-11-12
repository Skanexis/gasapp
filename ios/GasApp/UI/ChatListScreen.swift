// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Строка списка чатов.
struct ChatRowModel: Identifiable, Hashable {
    let id: String
    let name: String
    let preview: String
    let time: String
    let verified: Bool
    let isRequest: Bool
    let peerUsername: String
}

/// Список переписок — аналог `ChatListActivity`.
struct ChatListScreen: View {
    @Environment(AppModel.self) private var model
    @State private var inbox = Inbox.shared
    @State private var rows: [ChatRowModel] = []
    @State private var loaded = false
    @State private var path: [Route] = []
    /// Ссылка на контакт, которую человек должен подтвердить.
    @State private var incomingLink: String?
    @State private var incomingName: String?
    @State private var linkError: String?

    enum Route: Hashable {
        case chat(ChatRowModel)
        case addContact
        case search
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                if let error = inbox.lastError {
                    Text(error)
                        .font(GasFont.text(13, .semibold))
                        .foregroundStyle(GasAppColor.warn)
                        .listRowBackground(GasAppColor.bgBase)
                }
                if loaded && rows.isEmpty {
                    emptyState
                        .listRowBackground(GasAppColor.bgBase)
                        .listRowSeparator(.hidden)
                }
                ForEach(rows) { row in
                    NavigationLink(value: Route.chat(row)) { ChatRowView(row: row) }
                        .listRowBackground(GasAppColor.bgBase)
                        .listRowSeparatorTint(GasAppColor.line)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .refreshable {
                await inbox.receiveOnce()
                await reload()
            }
            .navigationTitle(L10n.t("Чаты", "Chats", "Chat"))
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { path.append(.search) } label: { Image(systemName: "magnifyingglass") }
                        .accessibilityLabel(L10n.t("Поиск", "Search", "Cerca"))
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { path.append(.addContact) } label: { Image(systemName: "square.and.pencil") }
                        .accessibilityLabel(L10n.t("Новый чат", "New chat", "Nuova chat"))
                }
            }
            .navigationDestination(for: Route.self) { route in
                switch route {
                case let .chat(row): ChatScreen(chatId: row.id, peerUsername: row.peerUsername, title: row.name)
                case .addContact: AddContactScreen { username, chatId in
                    path.removeLast()
                    path.append(.chat(ChatRowModel(id: chatId ?? "", name: username, preview: "", time: "",
                                                   verified: false, isRequest: false, peerUsername: username)))
                }
                case .search: SearchScreen()
                }
            }
            .gasScreen()
        }
        .task { inbox.start(); await reload() }
        .onChange(of: model.pendingContactLink, initial: true) { _, link in
            guard let link else { return }
            model.pendingContactLink = nil
            if let parsed = try? parseContactLink(uri: link) {
                incomingName = parsed.displayName
                incomingLink = link
            } else {
                linkError = L10n.t("Ссылка повреждена или неполная.", "The link is damaged or incomplete.",
                                   "Il link è danneggiato o incompleto.")
            }
        }
        // 🔐 Ссылка ничего не добавляет сама: сначала — вопрос. Имя в
        // ссылке предложил её автор, оно ничем не подтверждено.
        .alert(L10n.t("Добавить контакт?", "Add this contact?", "Aggiungere il contatto?"),
               isPresented: Binding(get: { incomingLink != nil }, set: { if !$0 { incomingLink = nil } })) {
            Button(L10n.t("Добавить", "Add", "Aggiungi")) {
                if let link = incomingLink { addIncoming(link) }
                incomingLink = nil
            }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) { incomingLink = nil }
        } message: {
            Text(incomingMessage)
        }
        .alert(L10n.t("Не получилось", "Didn’t work", "Non ha funzionato"),
               isPresented: Binding(get: { linkError != nil }, set: { if !$0 { linkError = nil } })) {
            Button("OK", role: .cancel) { linkError = nil }
        } message: {
            Text(linkError ?? "")
        }
        .onChange(of: inbox.revision) { _, _ in Task { await reload() } }
    }

    private var incomingMessage: String {
        let named = incomingName.map { L10n.t("Ссылка называет: \($0).\n\n", "The link says: \($0).\n\n", "Il link indica: \($0).\n\n") } ?? ""
        return named + L10n.t(
            "В ссылке ключ этого человека: писать можно сразу, без доверия серверу. Добавляйте, только если ссылку прислал тот, кого вы знаете.",
            "The link carries this person’s key, so you can write right away without trusting the server. Add it only if someone you know sent it.",
            "Il link contiene la chiave di questa persona: puoi scrivere subito senza fidarti del server. Aggiungilo solo se te l’ha inviato qualcuno che conosci.")
    }

    private func addIncoming(_ uri: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            do {
                let contact = try await Background.run {
                    try messenger.addContactFromLink(uri: uri, nowMillis: CoreStore.nowMillis)
                }
                let name = contact.username ?? ""
                path = [.chat(ChatRowModel(id: contact.chatId ?? "", name: name, preview: "", time: "",
                                           verified: false, isRequest: false, peerUsername: name))]
                await reload()
            } catch {
                linkError = L10n.t("Контакт не добавлен: ссылка не подошла или нет связи с сервером.",
                                   "The contact was not added: the link didn’t work or there is no connection.",
                                   "Contatto non aggiunto: il link non ha funzionato o non c’è connessione.")
            }
        }
    }

    private var emptyState: some View {
        EmptyScene(icon: "bubble.left.and.bubble.right.fill",
                   title: L10n.t("Пока нет переписок", "No chats yet", "Ancora nessuna chat"),
                   text: L10n.t("Добавьте контакт по имени, ссылке или QR-коду.",
                                "Add a contact by username, link or QR code.", "Aggiungi un contatto tramite nome utente, link o codice QR."),
                   action: L10n.t("Новый чат", "New chat", "Nuova chat")) { path.append(.addContact) }
    }

    private func reload() async {
        // Хранилище закрыто (галерея снимков без аккаунта) — пустой список,
        // а не пустой экран без единого слова.
        guard let messenger = try? CoreStore.shared.current() else { loaded = true; return }
        let loadedRows: [ChatRowModel] = (try? await Background.run {
            // Собеседник чата — по контакту: имя и отметка сверки.
            let contacts = try messenger.contacts()
            var byChat: [String: FfiContact] = [:]
            for contact in contacts { if let chat = contact.chatId { byChat[chat] = contact } }

            return try messenger.chats().map { chatId in
                // Превью — последнее из сотни последних, не вся переписка.
                let last = try messenger.messages(chatId: chatId, limit: 100).last
                let contact = byChat[chatId]
                let username = contact?.username ?? ""
                return ChatRowModel(
                    id: chatId,
                    name: username.isEmpty ? String(chatId.prefix(8)) : username,
                    preview: last?.text ?? "",
                    time: last.map { formatChatTime($0.timestamp) } ?? "",
                    verified: contact?.verified == true,
                    isRequest: (try? messenger.chatRequest(chatId: chatId)) == .incoming,
                    peerUsername: username
                )
            }
        }) ?? rows
        rows = loadedRows
        loaded = true
    }
}

/// Время сообщения: сегодня — часы, раньше — дата. Свободная функция,
/// а не член экрана: зовётся и из фонового потока (сборка списка).
func formatChatTime(_ millis: Int64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(millis) / 1000)
    return Calendar.current.isDateInToday(date)
        ? date.formatted(date: .omitted, time: .shortened)
        : date.formatted(.dateTime.day().month(.abbreviated))
}

struct ChatRowView: View {
    let row: ChatRowModel

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: row.peerUsername.isEmpty ? row.name : row.peerUsername, size: 52)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(row.name).font(GasFont.text(17, .bold)).foregroundStyle(GasAppColor.textPrimary)
                    // 🔐 Зелёная отметка — только у лично сверенных.
                    if row.verified {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(GasAppColor.ok).font(.system(size: 13))
                            .accessibilityLabel(L10n.t("Сверен", "Verified", "Verificato"))
                    }
                    Spacer()
                    Text(row.time).font(GasFont.text(13)).foregroundStyle(GasAppColor.textTertiary)
                }
                Text(row.isRequest ? L10n.t("Запрос на переписку", "Message request", "Richiesta di messaggio") : row.preview)
                    .font(GasFont.text(15, row.isRequest ? .semibold : .regular))
                    .foregroundStyle(row.isRequest ? GasAppColor.warn : GasAppColor.textSecondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}
