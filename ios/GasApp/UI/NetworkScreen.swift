// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// Сеть — аналог `NetworkActivity`: режим выхода (напрямую, Tor, свой
/// SOCKS5-прокси) и ход подключения к Tor.
///
/// Мостов здесь нет: где Tor блокируют, приложение подбирает их само
/// (`NetworkController`, «Мосты без участия человека») — человеку не
/// нужно идти сюда при каждом входе и просить новые.
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
    @State private var message: String?
    @State private var working = false
    @State private var pending: FfiProxy?
    @State private var askPin = false
    @State private var confirmDirect = false
    @State private var tor = NetworkController.shared.torStatus
    @State private var searching = false
    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        Form {
            if saved == .tor {
                Section { torCard }
                    .listRowBackground(GasAppColor.bgCard)
            }
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
                } header: {
                    Text(L10n.t("Подключение", "Connection", "Connessione"))
                } footer: {
                    Text(hint)
                }
            }
            .listRowBackground(GasAppColor.bgCard)

            Section {
                GoldButton(title: changed ? L10n.t("Сохранить", "Save", "Salva")
                                          : L10n.t("Сохранено", "Saved", "Salvato"),
                           isLoading: working, isEnabled: changed) { saveMode() }
                if let message {
                    Text(message)
                        .font(GasFont.text(14, .semibold))
                        .foregroundStyle(message == savedText ? GasAppColor.ok : GasAppColor.warn)
                        .frame(maxWidth: .infinity)
                        .padding(.top, 6)
                }
            } footer: {
                if mode == .tor {
                    Text(L10n.t("Мосты Tor подбираются сами: если в вашей сети Tor заблокирован, приложение получит новые мосты у Tor Project и переподключится. Ничего вводить не нужно.",
                                "Tor bridges are picked automatically: if Tor is blocked on your network, the app gets fresh bridges from the Tor Project and reconnects. Nothing to enter.",
                                "I bridge di Tor si scelgono da soli: se Tor è bloccato sulla tua rete, l’app ottiene nuovi bridge dal Tor Project e si riconnette. Non devi inserire nulla."))
                        .padding(.top, 8)
                }
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets())
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Сеть", "Network", "Rete"))
        .task { await load() }
        .onReceive(ticker) { _ in updateStatus() }
        .onChange(of: mode) { _, _ in message = nil }
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

    // MARK: - Состояние Tor

    private enum TorState { case ready, connecting, searching, stuck }

    private var torState: TorState {
        if tor.ready { return .ready }
        if searching { return .searching }
        if tor.stalled { return .stuck }
        return .connecting
    }

    private var torCard: some View {
        let state = torState
        let (icon, color, title, detail): (String, Color, String, String) = {
            switch state {
            case .ready:
                return ("checkmark.shield.fill", GasAppColor.ok,
                        L10n.t("Подключено через Tor", "Connected through Tor", "Connesso tramite Tor"),
                        tor.bridges
                            ? L10n.t("Через мост: в этой сети Tor заблокирован, но мост его обходит.", "Through a bridge: Tor is blocked on this network, the bridge gets around it.", "Tramite bridge: Tor è bloccato su questa rete, il bridge lo aggira.")
                            : L10n.t("Сервер не видит ваш IP-адрес.", "The server can’t see your IP address.", "Il server non vede il tuo indirizzo IP."))
            case .connecting:
                return ("point.3.connected.trianglepath.dotted", GasAppColor.accent,
                        L10n.t("Подключаемся… \(tor.percent)%", "Connecting… \(tor.percent)%", "Connessione… \(tor.percent)%"),
                        tor.bridges
                            ? L10n.t("Через мост. Обычно это 10–30 секунд.", "Through a bridge. Usually 10–30 seconds.", "Tramite bridge. Di solito 10–30 secondi.")
                            : L10n.t("Обычно это несколько секунд.", "Usually a few seconds.", "Di solito pochi secondi."))
            case .searching:
                return ("arrow.triangle.2.circlepath", GasAppColor.accent,
                        L10n.t("Подбираем мост", "Finding a bridge", "Cerchiamo un bridge"),
                        L10n.t("Tor в этой сети заблокирован. Приложение само берёт новые мосты у Tor Project — до минуты.", "Tor is blocked on this network. The app is getting fresh bridges from the Tor Project — up to a minute.", "Tor è bloccato su questa rete. L’app prende nuovi bridge dal Tor Project: fino a un minuto."))
            case .stuck:
                return ("exclamationmark.triangle.fill", GasAppColor.warn,
                        L10n.t("Tor не отвечает", "Tor isn’t responding", "Tor non risponde"),
                        L10n.t("Пробуем мосты. Проверьте, что интернет работает.", "Trying bridges. Check that the internet works.", "Proviamo i bridge. Controlla che internet funzioni."))
            }
        }()
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: icon)
                    .font(.system(size: 22, weight: .bold))
                    .foregroundStyle(color)
                    .frame(width: 46, height: 46)
                    .background(Circle().fill(color.opacity(0.15)))
                    .symbolEffect(.pulse, isActive: state != .ready)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(GasFont.text(18, .bold))
                        .foregroundStyle(GasAppColor.textPrimary)
                        .contentTransition(.numericText())
                    Text(detail)
                        .font(GasFont.text(14))
                        .foregroundStyle(GasAppColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if state == .connecting {
                ProgressView(value: Double(tor.percent), total: 100)
                    .tint(GasAppColor.accent)
                    .animation(.easeOut(duration: 0.5), value: tor.percent)
            }
            if state != .ready {
                Button {
                    NetworkController.shared.reconnectNow()
                    updateStatus()
                } label: {
                    Label(L10n.t("Переподключить", "Reconnect", "Riconnetti"), systemImage: "arrow.clockwise")
                        .font(GasFont.text(15, .semibold))
                }
                .buttonStyle(.borderless)
                .tint(GasAppColor.accent)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
        .animation(.easeInOut(duration: 0.25), value: state)
    }

    // MARK: - Режим

    private var savedText: String { L10n.t("Сохранено", "Saved", "Salvato") }

    /// Выбор на экране отличается от сохранённого — есть что сохранять.
    private var changed: Bool {
        guard let choice = selected else { return mode == .socks }
        return choice != saved
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
        let current = try? await Background.run { try messenger.proxy() }
        if let current {
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
            // Не из главного потока: смена режима останавливает или
            // запускает Tor, а это вызовы ядра.
            _ = try? await Background.run { NetworkController.shared.apply(proxy: choice, bridges: lines) }
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            withAnimation { message = savedText }
            updateStatus()
        }
    }

    private func updateStatus() {
        let network = NetworkController.shared
        tor = network.torStatus
        searching = network.isSearchingBridges
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
                        Text(event.eventType).font(GasFont.text(15, .semibold)).foregroundStyle(GasAppColor.textPrimary)
                        if !event.details.isEmpty {
                            Text(event.details).font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary)
                        }
                        Text(formatChatTime(event.timestampMillis)).font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
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
                if let detail { Text(detail).font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary) }
            }
        }
    }
}
