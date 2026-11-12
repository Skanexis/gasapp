// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Поиск по переписке — аналог `SearchActivity`.
///
/// 🔐 Ищет ядро в локальной зашифрованной базе: запрос не уходит
/// на сервер и не сохраняется.
struct SearchScreen: View {
    @State private var query = ""
    @State private var hits: [FfiSearchHit] = []
    @State private var names: [String: String] = [:]
    @State private var searched = false

    var body: some View {
        List {
            if searched && hits.isEmpty {
                Text(L10n.t("Ничего не найдено", "Nothing found", "Nessun risultato"))
                    .foregroundStyle(GasAppColor.textTertiary)
                    .listRowBackground(GasAppColor.bgBase)
            }
            ForEach(hits, id: \.message.messageId) { hit in
                NavigationLink {
                    let name = names[hit.chatId] ?? ""
                    ChatScreen(chatId: hit.chatId, peerUsername: name, title: name.isEmpty ? String(hit.chatId.prefix(8)) : name)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(names[hit.chatId] ?? String(hit.chatId.prefix(8)))
                                .font(GasFont.text(15, .bold)).foregroundStyle(GasAppColor.textPrimary)
                            Spacer()
                            Text(formatChatTime(hit.message.timestamp))
                                .font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                        }
                        Text(hit.message.text).font(GasFont.text(15)).foregroundStyle(GasAppColor.textSecondary)
                            .lineLimit(2)
                    }
                }
                .listRowBackground(GasAppColor.bgBase)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always),
                    prompt: L10n.t("Слово из переписки", "A word from your messages", "Una parola dai tuoi messaggi"))
        .onSubmit(of: .search) { Task { await run() } }
        .navigationTitle(L10n.t("Поиск", "Search", "Cerca"))
        .gasScreen()
    }

    private func run() async {
        let text = query.trimmingCharacters(in: .whitespaces)
        guard text.count >= 2, let messenger = try? CoreStore.shared.current() else { return }
        let result = try? await Background.run { () -> ([FfiSearchHit], [String: String]) in
            var byChat: [String: String] = [:]
            for contact in try messenger.contacts() {
                if let chat = contact.chatId, let name = contact.username { byChat[chat] = name }
            }
            return (try messenger.search(query: text, limit: 100), byChat)
        }
        hits = result?.0 ?? []
        names = result?.1 ?? [:]
        searched = true
    }
}
