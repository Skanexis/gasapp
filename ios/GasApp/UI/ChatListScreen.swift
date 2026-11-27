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
    /// Непрочитанных входящих.
    var unread: Int = 0
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
    /// «Все» или «Непрочитанные».
    @State private var onlyUnread = false

    private var shown: [ChatRowModel] { onlyUnread ? rows.filter { $0.unread > 0 || $0.isRequest } : rows }
    private var unreadChats: Int { rows.filter { $0.unread > 0 }.count }

    enum Route: Hashable {
        case chat(ChatRowModel)
        case addContact
        case search
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                if !rows.isEmpty {
                    // Все чаты или только с новым — как в Telegram.
                    Picker("", selection: $onlyUnread) {
                        Text(L10n.t("Все", "All", "Tutte")).tag(false)
                        Text(unreadChats > 0
                             ? L10n.t("Непрочитанные · \(unreadChats)", "Unread · \(unreadChats)", "Non lette · \(unreadChats)")
                             : L10n.t("Непрочитанные", "Unread", "Non lette")).tag(true)
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(GasAppColor.bgBase)
                    .listRowSeparator(.hidden)
                }
                if loaded && rows.isEmpty {
                    emptyState
                        .listRowBackground(GasAppColor.bgBase)
                        .listRowSeparator(.hidden)
                }
                if onlyUnread && shown.isEmpty && !rows.isEmpty {
                    Text(L10n.t("Всё прочитано", "All caught up", "Tutto letto"))
                        .font(GasFont.text(15)).foregroundStyle(GasAppColor.textTertiary)
                        .frame(maxWidth: .infinity).padding(.vertical, 40)
                        .listRowBackground(GasAppColor.bgBase)
                        .listRowSeparator(.hidden)
                }
                ForEach(shown) { row in
                    NavigationLink(value: Route.chat(row)) { ChatRowView(row: row) }
                        .listRowBackground(GasAppColor.bgBase)
                        .listRowSeparatorTint(GasAppColor.line)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            // Состояние подключения — полосой под заголовком (DESIGN.md).
            .safeAreaInset(edge: .top, spacing: 0) { ConnectionStrip() }
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
        // Нажали @имя в записи или сообщении — сразу чат с ним.
        .onChange(of: model.pendingMention, initial: true) { _, name in
            guard let name else { return }
            model.pendingMention = nil
            openMention(name)
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
        .onChange(of: inbox.readRevision) { _, _ in Task { await reload() } }
    }

    private var incomingMessage: String {
        let named = incomingName.map { L10n.t("Ссылка называет: \($0).\n\n", "The link says: \($0).\n\n", "Il link indica: \($0).\n\n") } ?? ""
        return named + L10n.t(
            "В ссылке ключ этого человека: писать можно сразу, без доверия серверу. Добавляйте, только если ссылку прислал тот, кого вы знаете.",
            "The link carries this person’s key, so you can write right away without trusting the server. Add it only if someone you know sent it.",
            "Il link contiene la chiave di questa persona: puoi scrivere subito senza fidarti del server. Aggiungilo solo se te l’ha inviato qualcuno che conosci.")
    }

    private func openMention(_ name: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            do {
                let contact = try await Background.run {
                    try messenger.addContactByMention(username: name, nowMillis: CoreStore.nowMillis)
                }
                let username = contact.username ?? name
                path = [.chat(ChatRowModel(id: contact.chatId ?? "", name: username, preview: "", time: "",
                                           verified: contact.verified, isRequest: false, peerUsername: username))]
                await reload()
            } catch {
                linkError = L10n.t("Не удалось открыть чат с @\(name): такого имени нет или нет связи.",
                                   "Couldn’t open a chat with @\(name): no such name, or no connection.",
                                   "Impossibile aprire una chat con @\(name): nome inesistente o nessuna connessione.")
            }
        }
    }

    private func addIncoming(_ uri: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            do {
                // Сразу, без сети — чат открывается тут же; имя сверяется
                // с сервером следом, в фоне.
                let contact = try await Background.run {
                    try messenger.addContactFromLinkLocal(uri: uri, nowMillis: CoreStore.nowMillis)
                }
                verifyLinkInBackground(uri, name: contact.username ?? "", model: model)
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
            var unread: [String: Int] = [:]
            for item in (try? messenger.chatUnreadCounts()) ?? [] { unread[item.chatId] = Int(item.count) }
            var byChat: [String: FfiContact] = [:]
            for contact in contacts { if let chat = contact.chatId { byChat[chat] = contact } }

            return try messenger.chats().map { chatId in
                // Превью — одно последнее сообщение: прежде ради него
                // расшифровывалась сотня на каждый чат при каждом обновлении.
                let last = try messenger.messages(chatId: chatId, limit: 1).last
                let contact = byChat[chatId]
                let username = contact?.username ?? ""
                return ChatRowModel(
                    id: chatId,
                    name: username.isEmpty ? String(chatId.prefix(8)) : username,
                    // Чат без сообщений (добавили по ссылке или QR) — подсказка.
                    preview: last?.text ?? L10n.t("Напишите первое сообщение", "Say hello", "Scrivi il primo messaggio"),
                    time: last.map { formatChatTime($0.timestamp) } ?? "",
                    verified: contact?.verified == true,
                    isRequest: (try? messenger.chatRequest(chatId: chatId)) == .incoming,
                    peerUsername: username,
                    unread: unread[chatId] ?? 0
                )
            }
        }) ?? rows
        // Только изменившееся: присваивание — перерисовка списка.
        if rows != loadedRows { rows = loadedRows }
        if !loaded { loaded = true }
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
                    Text(row.time).font(GasFont.text(13, row.unread > 0 ? .semibold : .regular))
                        .foregroundStyle(row.unread > 0 ? GasAppColor.accent : GasAppColor.textTertiary)
                }
                HStack(spacing: 8) {
                    Text(row.isRequest ? L10n.t("Запрос на переписку", "Message request", "Richiesta di messaggio") : row.preview)
                        .font(GasFont.text(15, row.isRequest || row.unread > 0 ? .semibold : .regular))
                        .foregroundStyle(row.isRequest ? GasAppColor.warn
                                         : row.unread > 0 ? GasAppColor.textPrimary : GasAppColor.textSecondary)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                    // Новое — значком с числом, как в Telegram.
                    if row.unread > 0 {
                        Text(row.unread > 99 ? "99+" : "\(row.unread)")
                            .font(GasFont.text(13, .bold))
                            .monospacedDigit()
                            .foregroundStyle(GasAppColor.accentOn)
                            .padding(.horizontal, 7)
                            .frame(minWidth: 22, minHeight: 22)
                            .background(Capsule().fill(GasAppColor.accent))
                            .accessibilityLabel(L10n.t("Новых: \(row.unread)", "\(row.unread) new", "\(row.unread) nuovi"))
                    }
                }
            }
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}
