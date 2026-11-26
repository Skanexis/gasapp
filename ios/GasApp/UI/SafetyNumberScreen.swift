// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Код безопасности (safety number) — аналог `SafetyNumberActivity`.
///
/// 🔐 Единственная защита от оператора сервера: если коды на двух
/// телефонах совпадают, между собеседниками никого нет. Сверка — лично
/// или сканированием QR с телефона собеседника.
struct SafetyNumberScreen: View {
    let contact: FfiContact

    init(contact: FfiContact) {
        self.contact = contact
    }

    @State private var digits = ""
    @State private var qr: FfiQrMatrix?
    @State private var verified = false
    @State private var scanning = false
    @State private var result: (String, Banner.Tone)?
    @State private var loading = true
    @State private var loadError: String?
    @Environment(\.dismiss) private var dismiss

    private var name: String { contact.username ?? L10n.t("собеседник", "contact", "contatto") }

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Text(L10n.t("Сравните этот код с кодом на телефоне \(name). Совпадает — между вами никого нет.",
                            "Compare this code with the one on \(name)’s phone. If they match, nobody is in between.", "Confronta questo codice con quello sul telefono di \(name). Se coincidono, non c’è nessuno in mezzo."))
                    .font(GasFont.text(15)).foregroundStyle(GasAppColor.textSecondary)
                    .multilineTextAlignment(.center)

                // Как сверять — по шагам: прежде было непонятно, что
                // делать второму человеку.
                VStack(alignment: .leading, spacing: 6) {
                    Label(L10n.t("Попросите \(name) открыть этот же экран: чат с вами → имя вверху → «Код безопасности».",
                                 "Ask \(name) to open this same screen: the chat with you → name at the top → “Safety number”.",
                                 "Chiedi a \(name) di aprire questa stessa schermata: chat con te → nome in alto → «Numero di sicurezza»."),
                          systemImage: "1.circle.fill")
                    Label(L10n.t("Отсканируйте QR на его телефоне — или сравните цифры вслух.",
                                 "Scan the QR on their phone — or compare the digits out loud.",
                                 "Scansiona il QR sul suo telefono, oppure confronta le cifre a voce."),
                          systemImage: "2.circle.fill")
                }
                .font(GasFont.text(14))
                .foregroundStyle(GasAppColor.textSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)

                if loading {
                    ProgressView().tint(GasAppColor.accent).frame(height: 240)
                } else if let loadError {
                    Banner(title: L10n.t("Код не получен", "No code yet", "Codice non disponibile"), message: loadError, tone: .warn)
                    OutlineButton(title: L10n.t("Повторить", "Try again", "Riprova")) { Task { await load() } }
                }
                if let qr {
                    QRView(matrix: qr)
                        .padding(8)
                        .background(RoundedRectangle(cornerRadius: 22).fill(.white))
                        .frame(maxWidth: 260)
                }

                Text(grouped)
                    .font(.system(size: 22, weight: .semibold, design: .monospaced))
                    .foregroundStyle(GasAppColor.textPrimary)
                    .multilineTextAlignment(.center)
                    .textSelection(.disabled)
                    .accessibilityLabel(digits)

                if let result {
                    Banner(title: result.1 == .ok ? L10n.t("Совпадает", "Match", "Coincide") : L10n.t("Не совпадает", "Mismatch", "Non coincide"),
                           message: result.0, tone: result.1)
                }

                OutlineButton(title: L10n.t("Сканировать код собеседника", "Scan their code", "Scansiona il suo codice")) { scanning = true }

                if verified {
                    Label(L10n.t("Сверен лично", "Verified in person", "Verificato di persona"), systemImage: "checkmark.seal.fill")
                        .foregroundStyle(GasAppColor.ok).font(GasFont.text(16, .bold))
                    OutlineButton(title: L10n.t("Снять отметку", "Clear verification", "Annulla verifica")) { setVerified(false) }
                } else {
                    GoldButton(title: L10n.t("Коды совпадают — отметить", "Codes match — mark verified", "I codici coincidono: segna come verificato")) { setVerified(true) }
                }
            }
            .padding(20)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Код безопасности", "Safety number", "Numero di sicurezza"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) { dismiss() } }
        }
        .sheet(isPresented: $scanning) { QRScanner { compare($0) } }
        .task { await load() }
    }

    /// Двенадцать групп по пять цифр, по три в строке.
    private var grouped: String {
        let clean = digits.filter(\.isNumber)
        var groups: [String] = []
        var index = clean.startIndex
        while index < clean.endIndex {
            let end = clean.index(index, offsetBy: 5, limitedBy: clean.endIndex) ?? clean.endIndex
            groups.append(String(clean[index..<end]))
            index = end
        }
        return stride(from: 0, to: groups.count, by: 3)
            .map { groups[$0..<min($0 + 3, groups.count)].joined(separator: " ") }
            .joined(separator: "\n")
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let account = contact.accountId
        verified = contact.verified
        loading = true
        loadError = nil
        do {
            let loaded = try await Background.run { () -> (String, FfiQrMatrix) in
                // Ключ собеседника ещё не весь известен — ядро спросит сервер.
                let number = try messenger.safetyNumberWith(accountId: account)
                return (number, try safetyNumberQr(digits: number))
            }
            digits = loaded.0
            qr = loaded.1
        } catch FfiError.PeerUnconfirmed {
            loadError = L10n.t("У собеседника ещё нет подтверждённого имени. Попросите его прислать свою ссылку или QR — тогда код появится.",
                               "This contact has no confirmed username yet. Ask them to send their link or QR — then the code appears.",
                               "Questo contatto non ha ancora un nome confermato. Chiedigli di inviarti il suo link o QR: poi il codice apparirà.")
        } catch FfiError.IdentityChanged {
            loadError = L10n.t("Сервер называет для \(name) другой ключ. Не пишите важного, пока не сверитесь лично.",
                               "The server names a different key for \(name). Don’t send anything important until you verify in person.",
                               "Il server indica una chiave diversa per \(name). Non inviare nulla di importante finché non verifichi di persona.")
        } catch {
            loadError = L10n.t("Нет связи с сервером. Проверьте подключение и повторите.",
                               "Can’t reach the server. Check your connection and try again.",
                               "Server non raggiungibile. Controlla la connessione e riprova.")
        }
        loading = false
    }

    private func compare(_ scanned: String) {
        // Сравниваются только цифры: QR несёт тот же код без пробелов.
        if scanned.filter(\.isNumber) == digits.filter(\.isNumber), !digits.isEmpty {
            result = (L10n.t("Коды одинаковые.", "The codes are identical.", "I codici sono identici."), .ok)
            setVerified(true)
        } else {
            // 🔐 Несовпадение — повод не писать, пока не выяснится почему.
            result = (L10n.t("Это может быть подмена. Не пишите важного, пока не выясните.",
                             "This may be an impersonation. Don’t send anything important until you know why.", "Potrebbe essere un furto d’identità. Non inviare nulla di importante finché non sai perché."), .error)
        }
    }

    private func setVerified(_ value: Bool) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let account = contact.accountId
        Task {
            if (try? await Background.run {
                try messenger.setContactVerified(accountId: account, verified: value, nowMillis: CoreStore.nowMillis)
            }) != nil {
                verified = value
                Inbox.shared.touch()
            }
        }
    }
}
