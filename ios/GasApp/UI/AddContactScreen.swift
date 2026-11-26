// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Новый чат — по QR или ссылке собеседника. Здесь же — свой QR и своя
/// ссылка, чтобы показать или отправить их.
///
/// Поиска по имени нет (решение владельца, 2026-11-26): ключ из QR или
/// ссылки — ключ самого собеседника, писать можно сразу; по имени ключ
/// назвал бы сервер. Нажатое в приложении `@имя` работает как ссылка
/// (`AppModel.route`).
struct AddContactScreen: View {
    @Environment(AppModel.self) private var model
    /// Контакт добавлен: имя и чат (если уже есть).
    let onAdded: (String, String?) -> Void

    init(onAdded: @escaping (String, String?) -> Void) {
        self.onAdded = onAdded
    }

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
                    Text(L10n.t("Добавить собеседника", "Add someone", "Aggiungi qualcuno"))
                        .font(GasFont.text(17, .bold))
                        .foregroundStyle(GasAppColor.textPrimary)
                    Text(L10n.t("Отсканируйте QR на его телефоне или вставьте ссылку, которую он прислал.",
                                "Scan the QR on their phone or paste the link they sent you.",
                                "Scansiona il QR sul suo telefono o incolla il link che ti ha inviato."))
                        .font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
                    GoldButton(title: L10n.t("Сканировать QR", "Scan QR", "Scansiona QR"), isLoading: working) { scanning = true }
                    HStack(spacing: 10) {
                        Field(title: L10n.t("Ссылка", "Link", "Link"), text: $link, placeholder: "https://gasapp.eu/add/#…")
                    }
                    HStack(spacing: 10) {
                        OutlineButton(title: L10n.t("Вставить", "Paste", "Incolla")) {
                            if let pasted = UIPasteboard.general.string {
                                link = pasted
                                addFromLink(pasted)
                            }
                        }
                        OutlineButton(title: L10n.t("Добавить", "Add", "Aggiungi"), isEnabled: !link.isEmpty && !working) {
                            addFromLink(link)
                        }
                    }
                }

                if let error {
                    Banner(title: L10n.t("Не получилось", "Didn’t work", "Non ha funzionato"), message: error, tone: .error)
                }

                Card {
                    Text(L10n.t("Ваш QR", "Your QR", "Il tuo QR")).font(GasFont.text(17, .bold))
                        .foregroundStyle(GasAppColor.textPrimary)
                    Text(L10n.t("Покажите его собеседнику или отправьте ссылку — и он сможет написать вам сразу.",
                                "Show it to the other person or send the link — they can message you right away.",
                                "Mostralo all’altra persona o invia il link: potrà scriverti subito."))
                        .font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
                    if let ownQR {
                        QRView(matrix: ownQR)
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 22).fill(.white))
                            .frame(maxWidth: 240).frame(maxWidth: .infinity)
                    } else {
                        ProgressView().tint(GasAppColor.accent).frame(maxWidth: .infinity).frame(height: 120)
                    }
                    if let ownLink {
                        ShareLink(item: ProfileSheet.shareText(username: ownName, link: ownLink)) {
                            Label(L10n.t("Отправить свою ссылку", "Send my link", "Invia il mio link"), systemImage: "square.and.arrow.up")
                                .font(GasFont.text(16, .bold))
                                .foregroundStyle(GasAppColor.accent)
                                .frame(maxWidth: .infinity)
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
        ownName = (try? await Background.run { try messenger.ownUsername() }) ?? nil
        if let own = try? await Background.run({ () -> (String, FfiQrMatrix) in
            let uri = try messenger.ownContactLink()
            return (uri, try contactLinkQr(uri: uri))
        }) {
            ownLink = ContactLinks.webLink(from: own.0)
            ownQR = own.1
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
                // Сразу, без сети: ключ — из QR; сверка имени с сервером —
                // следом, в фоне (через Tor она занимает секунды).
                let contact = try await Background.run {
                    try messenger.addContactFromLinkLocal(uri: text, nowMillis: CoreStore.nowMillis)
                }
                verifyLinkInBackground(text, name: contact.username ?? "", model: model)
                working = false
                onAdded(contact.username ?? "", contact.chatId)
            } catch {
                working = false
                self.error = L10n.t("Это не ссылка или QR GasApp — либо это ваш собственный.",
                                    "That isn’t a GasApp link or QR — or it’s your own.",
                                    "Non è un link o un QR di GasApp, oppure è il tuo.")
            }
        }
    }
}

/// Сверка имени из ссылки с сервером — в фоне, после быстрого добавления.
/// Не совпало (ключ другой) — предупреждение: контакт уже открыт.
@MainActor
func verifyLinkInBackground(_ uri: String, name: String, model: AppModel) {
    guard let messenger = try? CoreStore.shared.current() else { return }
    Task {
        do {
            _ = try await Background.run { try messenger.addContactFromLink(uri: uri, nowMillis: CoreStore.nowMillis) }
            Inbox.shared.hurry()
        } catch FfiError.IdentityChanged {
            model.linkWarning = name.isEmpty ? L10n.t("контакт", "contact", "contatto") : "@\(name)"
        } catch {
            // Нет связи — сверится при первой отправке (ключ из ссылки).
        }
    }
}
