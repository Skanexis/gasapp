// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Сеть — аналог `NetworkActivity`: режим выхода (напрямую, Tor, свой
/// SOCKS5-прокси) и мосты Tor.
///
/// Там, где Tor блокируют, нужны мосты. Их можно вставить строками или
/// запросить у Tor Project (moat) — 🔐 запрос идёт через сам Tor
/// встроенным транспортом, не напрямую.
///
/// 🔐 Сеть мимо Tor — только владельцу (аудит 2026-10-02, A-3): PIN
/// спрашивается заново. Свой прокси, тихо вписанный тем, кому дали
/// подержать телефон, узнавал бы адрес и время каждого соединения.
struct NetworkScreen: View {
    @Environment(AppModel.self) private var model

    enum Mode: Hashable { case direct, tor, socks }

    @State private var mode: Mode = .tor
    @State private var saved: FfiProxy?
    @State private var host = ""
    @State private var port = ""
    @State private var bridges = ""
    @State private var status = ""
    @State private var message: String?
    @State private var working = false
    @State private var pending: FfiProxy?
    @State private var askPin = false
    @State private var confirmDirect = false
    private let ticker = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        Form {
            // Строки — цветом карточек GasApp, а не системным серым.
            Group {
                Section {
                    Picker(L10n.t("Подключение", "Connection", "Connessione"), selection: $mode) {
                        Text(L10n.t("Через Tor", "Via Tor", "Tramite Tor")).tag(Mode.tor)
                        Text(L10n.t("SOCKS5-прокси", "SOCKS5 proxy", "Proxy SOCKS5")).tag(Mode.socks)
                        Text(L10n.t("Напрямую", "Direct", "Diretta")).tag(Mode.direct)
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                    if mode == .socks {
                        TextField(L10n.t("Адрес (хост или IP)", "Address (host or IP)", "Indirizzo (host o IP)"), text: $host)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .keyboardType(.URL)
                        TextField(L10n.t("Порт", "Port", "Porta"), text: $port)
                            .keyboardType(.numberPad)
                    }
                    Button(L10n.t("Сохранить", "Save", "Salva")) { saveMode() }
                        .disabled(working)
                } header: {
                    Text(L10n.t("Подключение", "Connection", "Connessione"))
                } footer: {
                    Text(hint)
                }
                if mode == .tor {
                    Section(L10n.t("Состояние Tor", "Tor status", "Stato di Tor")) {
                        Text(status).foregroundStyle(GasAppColor.textSecondary)
                    }
                    Section {
                        TextEditor(text: $bridges)
                            .frame(minHeight: 140)
                            .font(.system(size: 12, design: .monospaced))
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        Button(L10n.t("Сохранить мосты", "Save bridges", "Salva bridge")) { save() }
                            .disabled(working)
                        Button(L10n.t("Получить мосты у Tor Project", "Get bridges from Tor Project", "Ottieni bridge da Tor Project")) { fetch() }
                            .disabled(working)
                    } header: {
                        Text(L10n.t("Мосты", "Bridges", "Bridge"))
                    } footer: {
                        Text(L10n.t("По строке на мост (obfs4, webtunnel, snowflake). Пусто — прямое подключение к сети Tor.",
                                    "One bridge per line (obfs4, webtunnel, snowflake). Empty — connect to Tor directly.", "Un bridge per riga (obfs4, webtunnel, snowflake). Vuoto: connessione diretta a Tor."))
                    }
                }
                if let message {
                    Section { Text(message).foregroundStyle(GasAppColor.warn) }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Сеть", "Network", "Rete"))
        .task { await load() }
        .onReceive(ticker) { _ in updateStatus() }
        .sheet(isPresented: $askPin, onDismiss: { if !confirmDirect && !working { pending = nil } }) {
            PinConfirmSheet(title: L10n.t("Подключение без Tor", "Connect without Tor", "Connetti senza Tor")) { pin in reauth(pin) }
        }
        // 🔐 Прямое соединение отдаёт серверу адрес — только явным
        // согласием, после которого человек знает, чем платит.
        .confirmationDialog(L10n.t("Подключаться напрямую?", "Connect directly?", "Connettersi direttamente?"), isPresented: $confirmDirect,
                            titleVisibility: .visible) {
            Button(L10n.t("Подключаться напрямую", "Connect directly", "Connetti direttamente"), role: .destructive) {
                if let pending { store(pending) }
            }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) { pending = nil }
        } message: {
            Text(L10n.t("Сервер увидит ваш IP-адрес: примерное местоположение и то, какие ваши аккаунты сидят в одной сети. Tor его скрывает.",
                        "The server will see your IP address: roughly where you are, and which of your accounts share a network. Tor hides it.", "Il server vedrà il tuo indirizzo IP: più o meno dove ti trovi e quali dei tuoi account condividono una rete. Tor lo nasconde."))
        }
    }

    private var hint: String {
        switch mode {
        case .tor:
            return L10n.t("Сервер не видит ваш IP-адрес. Медленнее, чем напрямую.",
                          "The server doesn’t see your IP address. Slower than direct.", "Il server non vede il tuo indirizzo IP. Più lento della connessione diretta.")
        case .socks:
            return L10n.t("Все запросы и уведомления идут через указанный прокси. Если он недоступен, приложение не подключится — напрямую оно не пойдёт.",
                          "All requests and notifications go through the proxy you specify. If it is unreachable, the app will not connect — it will not fall back to a direct connection.", "Tutte le richieste e le notifiche passano dal proxy indicato. Se non è raggiungibile, l’app non si connette: non ripiega su una connessione diretta.")
        case .direct:
            return L10n.t("Быстрее всего, но сервер видит ваш IP-адрес.",
                          "Fastest, but the server sees your IP address.", "La più veloce, ma il server vede il tuo indirizzo IP.")
        }
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let state = try? await Background.run { () -> (FfiProxy, [String]) in
            (try messenger.proxy(), try messenger.torBridges())
        }
        if let current = state?.0 {
            saved = current
            switch current {
            case .direct: mode = .direct
            case .tor: mode = .tor
            case let .socks5(h, p):
                mode = .socks
                host = h
                port = String(p)
            }
        }
        bridges = (state?.1 ?? []).joined(separator: "\n")
        updateStatus()
    }

    /// Режим, выбранный на экране; `nil` — порт неверен.
    private var selected: FfiProxy? {
        switch mode {
        case .direct: return .direct
        case .tor: return .tor
        case .socks:
            guard let number = Int(port.trimmingCharacters(in: .whitespaces)), (1...65_535).contains(number) else { return nil }
            return .socks5(host: host.trimmingCharacters(in: .whitespaces), port: UInt16(number))
        }
    }

    private func saveMode() {
        // Проверка та же, что в ядре: ошибка в адресе видна до сохранения,
        // а не отказом сети.
        guard let choice = selected, validateProxy(proxy: choice) else {
            message = L10n.t("Адрес или порт указаны неверно. Укажите имя хоста или IP-адрес без схемы и пути; логин и пароль не поддерживаются.",
                             "The address or port is not valid. Enter a hostname or IP address without a scheme or path; usernames and passwords are not supported.", "L’indirizzo o la porta non sono validi. Inserisci un nome host o un indirizzo IP senza schema né percorso; nome utente e password non sono supportati.")
            return
        }
        message = nil
        guard choice != saved else { return }
        if choice == .tor {
            store(choice)
            return
        }
        pending = choice
        askPin = true
    }

    private func reauth(_ pin: [UInt8]) {
        working = true
        Task {
            let verdict = await Reauth.verify(pin: pin)
            working = false
            switch verdict {
            case .ok:
                guard let choice = pending else { return }
                if choice == .direct {
                    confirmDirect = true
                } else {
                    store(choice)
                }
            case .wiped:
                model.didWipe()
            case let .refused(text):
                pending = nil
                message = text
            }
        }
    }

    /// Сеть меняется, только если выбор записан: иначе после перезапуска
    /// база вернула бы прежний режим.
    private func store(_ choice: FfiProxy) {
        pending = nil
        guard let messenger = try? CoreStore.shared.current() else { return }
        working = true
        Task {
            let ok = (try? await Background.run { try messenger.setProxy(proxy: choice) }) != nil
            working = false
            guard ok else {
                message = L10n.t("Не сохранилось", "Not saved", "Non salvato")
                return
            }
            saved = choice
            let lines = try? await Background.run { try messenger.torBridges() }
            NetworkController.shared.apply(proxy: choice, bridges: lines)
            message = L10n.t("Сохранено", "Saved", "Salvato")
            updateStatus()
        }
    }

    private func updateStatus() {
        let tor = NetworkController.shared.torStatus
        status = !tor.running ? L10n.t("Не используется (напрямую)", "Not in use (direct)", "Non in uso (diretta)")
            : tor.ready ? L10n.t("Подключён\(tor.bridges ? " через мосты" : "")", "Connected\(tor.bridges ? " via bridges" : "")", "Connesso\(tor.bridges ? " tramite bridge" : "")")
            : tor.stalled ? L10n.t("Не подключается — возможно, Tor заблокирован. Нужны мосты.", "Stuck — Tor may be blocked. Add bridges.", "Bloccato: Tor potrebbe essere bloccato. Aggiungi dei bridge.")
            : L10n.t("Подключается… \(tor.percent)%", "Connecting… \(tor.percent)%", "Connessione… \(tor.percent)%")
    }

    private func save() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let text = bridges
        guard text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || validateTorBridges(text: text) else {
            message = L10n.t("Строка моста не разбирается", "A bridge line can’t be parsed", "Una riga di bridge non è valida")
            return
        }
        working = true
        Task {
            let saved = try? await Background.run { try messenger.setTorBridges(text: text) }
            working = false
            guard let saved else {
                message = L10n.t("Не сохранилось", "Not saved", "Non salvato")
                return
            }
            message = L10n.t("Мосты сохранены", "Bridges saved", "Bridge salvati")
            // Режим — тот же; Tor перезапускается с новыми мостами.
            let mode = try? await Background.run { try messenger.proxy() }
            NetworkController.shared.apply(proxy: mode, bridges: saved)
        }
    }

    private func fetch() {
        working = true
        message = L10n.t("Запрашиваем мосты…", "Requesting bridges…", "Richiesta dei bridge…")
        Task {
            let got = try? await Background.run { try fetchTorBridges(country: nil) }
            working = false
            if let got, !got.isEmpty {
                bridges = got.joined(separator: "\n")
                message = L10n.t("Мосты получены — сохраните их.", "Bridges received — save them.", "Bridge ricevuti: salvali.")
            } else {
                message = L10n.t("Не удалось получить мосты", "Could not get bridges", "Impossibile ottenere i bridge")
            }
        }
    }
}

/// Центр безопасности — аналог `SecurityCenterActivity`: что из защиты
/// включено, и журнал событий безопасности (без содержимого переписки).
struct SecurityScreen: View {
    @State private var report: FfiSecurityReport?
    @State private var events: [FfiSecurityEvent] = []

    var body: some View {
        List {
            if let report {
                Section(L10n.t("Проверено \(report.passed) из \(report.total)", "Passed \(report.passed) of \(report.total)", "Superati \(report.passed) su \(report.total)")) {
                    row(L10n.t("Ключ восстановления создан", "Recovery key created", "Chiave di recupero creata"), report.recoveryKeyCreated)
                    row(L10n.t("Копия не старше недели", "Backup within a week", "Backup entro una settimana"), report.backupRecent)
                    row(L10n.t("Отправитель скрыт (sealed sender)", "Sender hidden (sealed sender)", "Mittente nascosto (sealed sender)"), report.sealedSenderEnabled)
                    row(L10n.t("Адрес скрыт (Tor или прокси)", "IP hidden (Tor or proxy)", "IP nascosto (Tor o proxy)"), report.addressHidden)
                    row(L10n.t("Все контакты сверены", "All contacts verified", "Tutti i contatti verificati"), report.unverifiedContacts == 0,
                        detail: report.unverifiedContacts > 0
                            ? L10n.t("не сверено: \(report.unverifiedContacts)", "unverified: \(report.unverifiedContacts)", "non verificati: \(report.unverifiedContacts)") : nil)
                }
                .listRowBackground(GasAppColor.bgCard)
            }
            Section(L10n.t("События", "Events", "Eventi")) {
                if events.isEmpty {
                    Text(L10n.t("Событий нет", "No events", "Nessun evento")).foregroundStyle(GasAppColor.textTertiary)
                }
                ForEach(Array(events.enumerated()), id: \.offset) { _, event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.eventType).font(.system(size: 15, weight: .semibold)).foregroundStyle(GasAppColor.textPrimary)
                        if !event.details.isEmpty {
                            Text(event.details).font(.system(size: 13)).foregroundStyle(GasAppColor.textSecondary)
                        }
                        Text(formatChatTime(event.timestampMillis)).font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary)
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Безопасность", "Security", "Sicurezza"))
        .task {
            guard let messenger = try? CoreStore.shared.current() else { return }
            let state = try? await Background.run { () -> (FfiSecurityReport, [FfiSecurityEvent]) in
                (try messenger.securityReport(nowMillis: CoreStore.nowMillis), try messenger.securityEvents(limit: 100))
            }
            report = state?.0
            events = state?.1 ?? []
        }
    }

    private func row(_ title: String, _ ok: Bool, detail: String? = nil) -> some View {
        HStack {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle")
                .foregroundStyle(ok ? GasAppColor.ok : GasAppColor.warn)
            VStack(alignment: .leading) {
                Text(title).foregroundStyle(GasAppColor.textPrimary)
                if let detail { Text(detail).font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary) }
            }
        }
    }
}
