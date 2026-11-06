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
                        .font(.system(size: 13, weight: .semibold))
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
            .navigationTitle(L10n.t("Чаты", "Chats"))
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { path.append(.search) } label: { Image(systemName: "magnifyingglass") }
                        .accessibilityLabel(L10n.t("Поиск", "Search"))
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { path.append(.addContact) } label: { Image(systemName: "square.and.pencil") }
                        .accessibilityLabel(L10n.t("Новый чат", "New chat"))
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
        .onChange(of: inbox.revision) { _, _ in Task { await reload() } }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "bubble.left.and.bubble.right.fill")
                .font(.system(size: 44)).foregroundStyle(GasAppColor.accent)
            Text(L10n.t("Пока нет переписок", "No chats yet"))
                .font(.system(size: 20, weight: .heavy, design: .rounded))
                .foregroundStyle(GasAppColor.textPrimary)
            Text(L10n.t("Добавьте контакт по имени, ссылке или QR-коду.",
                        "Add a contact by username, link or QR code."))
                .font(.system(size: 15)).foregroundStyle(GasAppColor.textSecondary)
                .multilineTextAlignment(.center)
            GoldButton(title: L10n.t("Новый чат", "New chat")) { path.append(.addContact) }
                .frame(maxWidth: 260)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 60)
    }

    private func reload() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
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
            Circle()
                .fill(GasAppColor.bgCard)
                .overlay(Text(String(row.name.prefix(1)).uppercased())
                    .font(.system(size: 20, weight: .heavy, design: .rounded))
                    .foregroundStyle(GasAppColor.accent))
                .overlay(Circle().stroke(GasAppColor.line, lineWidth: 1))
                .frame(width: 48, height: 48)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(row.name).font(.system(size: 17, weight: .bold)).foregroundStyle(GasAppColor.textPrimary)
                    // 🔐 Зелёная отметка — только у лично сверенных.
                    if row.verified {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(GasAppColor.ok).font(.system(size: 13))
                            .accessibilityLabel(L10n.t("Сверен", "Verified"))
                    }
                    Spacer()
                    Text(row.time).font(.system(size: 13)).foregroundStyle(GasAppColor.textTertiary)
                }
                Text(row.isRequest ? L10n.t("Запрос на переписку", "Message request") : row.preview)
                    .font(.system(size: 15))
                    .foregroundStyle(row.isRequest ? GasAppColor.warn : GasAppColor.textSecondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 6)
    }
}
