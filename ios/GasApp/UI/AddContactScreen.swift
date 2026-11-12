// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Новый контакт — аналог `AddContactActivity`: по имени, по ссылке
/// или QR собеседника. Здесь же — своя ссылка и свой QR.
///
/// 🔐 Ссылка или QR несут ключ самого собеседника: контакт сразу
/// подтверждён. По имени ключ называет сервер — писать можно будет
/// после сверки кода безопасности.
struct AddContactScreen: View {
    /// Контакт добавлен: имя и чат (если уже есть).
    let onAdded: (String, String?) -> Void

    init(onAdded: @escaping (String, String?) -> Void) {
        self.onAdded = onAdded
    }

    @State private var username = ""
    @State private var link = ""
    @State private var error: String?
    @State private var working = false
    @State private var ownLink: String?
    @State private var ownQR: FfiQrMatrix?
    @State private var ownName: String?
    @State private var scanning = false

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Card {
                    Text(L10n.t("По имени", "By username", "Per nome utente")).font(GasFont.text(17, .bold))
                        .foregroundStyle(GasAppColor.textPrimary)
                    Field(title: L10n.t("Имя пользователя", "Username", "Nome utente"), text: $username, placeholder: "anna_k")
                    GoldButton(title: L10n.t("Найти", "Find", "Cerca"), isLoading: working,
                               isEnabled: !username.isEmpty) { discover() }
                }

                Card {
                    Text(L10n.t("По ссылке или QR", "By link or QR", "Tramite link o QR")).font(GasFont.text(17, .bold))
                        .foregroundStyle(GasAppColor.textPrimary)
                    Text(L10n.t("Надёжнее всего: в ссылке — ключ самого собеседника.",
                                "Most secure: the link carries the person’s own key.", "Il più sicuro: il link contiene la chiave della persona stessa."))
                        .font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
                    Field(title: L10n.t("Ссылка", "Link", "Link"), text: $link, placeholder: "gasapp://…")
                    HStack(spacing: 10) {
                        OutlineButton(title: L10n.t("Сканировать QR", "Scan QR", "Scansiona QR")) { scanning = true }
                        GoldButton(title: L10n.t("Добавить", "Add", "Aggiungi"), isLoading: working,
                                   isEnabled: !link.isEmpty) { addFromLink(link) }
                    }
                }

                if let error {
                    Banner(title: L10n.t("Не получилось", "Didn’t work", "Non ha funzionato"), message: error, tone: .error)
                }

                Card {
                    Text(L10n.t("Ваш контакт", "Your contact", "Il tuo contatto")).font(GasFont.text(17, .bold))
                        .foregroundStyle(GasAppColor.textPrimary)
                    if let ownQR {
                        QRView(matrix: ownQR)
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 22).fill(.white))
                            .frame(maxWidth: 240).frame(maxWidth: .infinity)
                    }
                    if let ownLink {
                        ShareLink(item: ProfileSheet.shareText(username: ownName, link: ownLink)) {
                            Label(L10n.t("Поделиться ссылкой", "Share link", "Condividi link"), systemImage: "square.and.arrow.up")
                                .font(GasFont.text(16, .bold))
                                .foregroundStyle(GasAppColor.accent)
                        }
                    }
                }
            }
            .padding(16)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Новый чат", "New chat", "Nuova chat"))
        .sheet(isPresented: $scanning) {
            QRScanner { code in link = code; addFromLink(code) }
        }
        .task { await loadOwn() }
    }

    private func loadOwn() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        ownName = (try? messenger.ownUsername()) ?? nil
        if let own = try? await Background.run({ () -> (String, FfiQrMatrix) in
            let uri = try messenger.ownContactLink()
            return (uri, try contactLinkQr(uri: uri))
        }) {
            ownLink = own.0
            ownQR = own.1
        }
    }

    private func discover() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let name = (try? canonicalUsername(raw: username)) ?? username
        working = true
        error = nil
        Task {
            do {
                let contact = try await Background.run {
                    try messenger.discoverContact(username: name, nowMillis: CoreStore.nowMillis)
                }
                working = false
                onAdded(contact.username ?? name, contact.chatId)
            } catch {
                working = false
                self.error = L10n.t("Такого имени нет или нет связи.", "No such username, or no connection.", "Nome utente inesistente o nessuna connessione.")
            }
        }
    }

    private func addFromLink(_ uri: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        // Вставили https://gasapp.eu/add/#… — ядру нужен вид gasapp://contact/….
        let text = ContactLinks.appLink(from: uri) ?? uri.trimmingCharacters(in: .whitespacesAndNewlines)
        working = true
        error = nil
        Task {
            do {
                let contact = try await Background.run {
                    try messenger.addContactFromLink(uri: text, nowMillis: CoreStore.nowMillis)
                }
                working = false
                onAdded(contact.username ?? "", contact.chatId)
            } catch {
                working = false
                self.error = L10n.t("Ссылка не подошла.", "The link didn’t work.", "Il link non ha funzionato.")
            }
        }
    }
}
