// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Контакты — аналог `ContactsActivity` и `ProfileActivity`: свой
/// профиль (имя, ссылка, QR), контакты с отметкой сверки, заблокированные.
struct ContactsScreen: View {
    @State private var inbox = Inbox.shared
    @State private var username = ""
    @State private var contacts: [FfiContact] = []
    @State private var blocked: [FfiBlockedChat] = []
    @State private var showProfile = false

    var body: some View {
        List {
            Section {
                Button { showProfile = true } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "qrcode").font(.system(size: 26)).foregroundStyle(GasAppColor.accent)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(username.isEmpty ? "—" : "@\(username)")
                                .font(.system(size: 17, weight: .bold)).foregroundStyle(GasAppColor.textPrimary)
                            Text(L10n.t("Моя ссылка и QR-код", "My link and QR code"))
                                .font(.system(size: 13)).foregroundStyle(GasAppColor.textTertiary)
                        }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)

            Section(L10n.t("Контакты", "Contacts")) {
                if contacts.isEmpty {
                    Text(L10n.t("Пока никого", "No one yet")).foregroundStyle(GasAppColor.textTertiary)
                }
                ForEach(contacts, id: \.accountId) { contact in
                    let name = contact.username ?? String(contact.accountId.prefix(8))
                    NavigationLink {
                        ChatScreen(chatId: contact.chatId ?? "", peerUsername: contact.username ?? "", title: name)
                    } label: {
                        HStack {
                            Text(name).foregroundStyle(GasAppColor.textPrimary)
                            Spacer()
                            // 🔐 Зелёный — только у лично сверенных.
                            if contact.verified {
                                Image(systemName: "checkmark.seal.fill").foregroundStyle(GasAppColor.ok)
                            } else if contact.keyChanged {
                                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(GasAppColor.error)
                            }
                        }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)

            if !blocked.isEmpty {
                Section(L10n.t("Заблокированные", "Blocked")) {
                    ForEach(blocked, id: \.chatId) { chat in
                        HStack {
                            Text(chat.username ?? String(chat.chatId.prefix(8))).foregroundStyle(GasAppColor.textSecondary)
                            Spacer()
                            Button(L10n.t("Разблокировать", "Unblock")) { unblock(chat.chatId) }
                                .font(.system(size: 14, weight: .semibold))
                        }
                    }
                }
                .listRowBackground(GasAppColor.bgCard)
            }
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Контакты", "Contacts"))
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink {
                    AddContactScreen { _, _ in Task { await reload() } }
                } label: { Image(systemName: "person.badge.plus") }
                .accessibilityLabel(L10n.t("Добавить контакт", "Add contact"))
            }
        }
        .sheet(isPresented: $showProfile) { NavigationStack { ProfileSheet(username: username) } }
        .task { await reload() }
        .onChange(of: inbox.revision) { _, _ in Task { await reload() } }
    }

    private func reload() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let state = try? await Background.run { () -> (String?, [FfiContact], [FfiBlockedChat]) in
            (try messenger.ownUsername(),
             try messenger.contacts().filter { !$0.replaced },
             try messenger.blockedChats())
        }
        username = state?.0 ?? ""
        contacts = (state?.1 ?? []).sorted { ($0.username ?? "") < ($1.username ?? "") }
        blocked = state?.2 ?? []
    }

    private func unblock(_ chatId: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            _ = try? await Background.run { try messenger.unblockChat(chatId: chatId) }
            await reload()
        }
    }
}

/// Свой профиль: ссылка и QR — чтобы вас добавили надёжно (с ключом).
struct ProfileSheet: View {
    let username: String
    @State private var link: String?
    @State private var qr: FfiQrMatrix?
    @Environment(\.dismiss) private var dismiss

    init(username: String) { self.username = username }

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Text("@\(username)").font(.system(size: 26, weight: .heavy, design: .rounded))
                    .foregroundStyle(GasAppColor.textPrimary)
                if let qr { QRView(matrix: qr).frame(maxWidth: 260) }
                Text(L10n.t("Покажите этот код собеседнику: по нему он добавит вас вместе с вашим ключом — без доверия серверу.",
                            "Show this code: it adds you together with your key — without trusting the server."))
                    .font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary).multilineTextAlignment(.center)
                if let link {
                    ShareLink(item: link) {
                        Label(L10n.t("Поделиться ссылкой", "Share link"), systemImage: "square.and.arrow.up")
                            .font(.system(size: 16, weight: .bold)).foregroundStyle(GasAppColor.accent)
                    }
                }
            }
            .padding(24)
        }
        .gasScreen()
        .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done")) { dismiss() } } }
        .task {
            guard let messenger = try? CoreStore.shared.current() else { return }
            if let own = try? await Background.run({ () -> (String, FfiQrMatrix) in
                let uri = try messenger.ownContactLink()
                return (uri, try contactLinkQr(uri: uri))
            }) {
                link = own.0
                qr = own.1
            }
        }
    }
}
