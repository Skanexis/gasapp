// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Сеть: мосты Tor — аналог `NetworkActivity`.
///
/// Там, где Tor блокируют, нужны мосты. Их можно вставить строками или
/// запросить у Tor Project (moat) — 🔐 запрос идёт через сам Tor
/// встроенным транспортом, не напрямую.
struct NetworkScreen: View {
    @State private var bridges = ""
    @State private var status = ""
    @State private var message: String?
    @State private var working = false
    private let ticker = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        Form {
            Section(L10n.t("Состояние Tor", "Tor status")) {
                Text(status).foregroundStyle(GasAppColor.textSecondary)
            }
            Section {
                TextEditor(text: $bridges)
                    .frame(minHeight: 140)
                    .font(.system(size: 12, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                Button(L10n.t("Сохранить мосты", "Save bridges")) { save() }
                    .disabled(working)
                Button(L10n.t("Получить мосты у Tor Project", "Get bridges from Tor Project")) { fetch() }
                    .disabled(working)
            } header: {
                Text(L10n.t("Мосты", "Bridges"))
            } footer: {
                Text(L10n.t("По строке на мост (obfs4, webtunnel, snowflake). Пусто — прямое подключение к сети Tor.",
                            "One bridge per line (obfs4, webtunnel, snowflake). Empty — connect to Tor directly."))
            }
            if let message {
                Section { Text(message).foregroundStyle(GasAppColor.warn) }
            }
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Сеть", "Network"))
        .task { await load() }
        .onReceive(ticker) { _ in updateStatus() }
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let lines = (try? await Background.run { try messenger.torBridges() }) ?? []
        bridges = lines.joined(separator: "\n")
        updateStatus()
    }

    private func updateStatus() {
        let tor = NetworkController.shared.torStatus
        status = !tor.running ? L10n.t("Не используется (напрямую)", "Not in use (direct)")
            : tor.ready ? L10n.t("Подключён\(tor.bridges ? " через мосты" : "")", "Connected\(tor.bridges ? " via bridges" : "")")
            : tor.stalled ? L10n.t("Не подключается — возможно, Tor заблокирован. Нужны мосты.", "Stuck — Tor may be blocked. Add bridges.")
            : L10n.t("Подключается… \(tor.percent)%", "Connecting… \(tor.percent)%")
    }

    private func save() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let text = bridges
        guard text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || validateTorBridges(text: text) else {
            message = L10n.t("Строка моста не разбирается", "A bridge line can’t be parsed")
            return
        }
        working = true
        Task {
            let saved = try? await Background.run { try messenger.setTorBridges(text: text) }
            working = false
            guard let saved else {
                message = L10n.t("Не сохранилось", "Not saved")
                return
            }
            message = nil
            // Режим — тот же; Tor перезапускается с новыми мостами.
            let mode = try? await Background.run { try messenger.proxy() }
            NetworkController.shared.apply(proxy: mode, bridges: saved)
        }
    }

    private func fetch() {
        working = true
        message = L10n.t("Запрашиваем мосты…", "Requesting bridges…")
        Task {
            let got = try? await Background.run { try fetchTorBridges(country: nil) }
            working = false
            if let got, !got.isEmpty {
                bridges = got.joined(separator: "\n")
                message = L10n.t("Мосты получены — сохраните их.", "Bridges received — save them.")
            } else {
                message = L10n.t("Не удалось получить мосты", "Could not get bridges")
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
                Section(L10n.t("Проверено \(report.passed) из \(report.total)", "Passed \(report.passed) of \(report.total)")) {
                    row(L10n.t("Ключ восстановления создан", "Recovery key created"), report.recoveryKeyCreated)
                    row(L10n.t("Копия не старше недели", "Backup within a week"), report.backupRecent)
                    row(L10n.t("Отправитель скрыт (sealed sender)", "Sender hidden (sealed sender)"), report.sealedSenderEnabled)
                    row(L10n.t("Адрес скрыт (Tor или прокси)", "IP hidden (Tor or proxy)"), report.addressHidden)
                    row(L10n.t("Все контакты сверены", "All contacts verified"), report.unverifiedContacts == 0,
                        detail: report.unverifiedContacts > 0
                            ? L10n.t("не сверено: \(report.unverifiedContacts)", "unverified: \(report.unverifiedContacts)") : nil)
                }
                .listRowBackground(GasAppColor.bgCard)
            }
            Section(L10n.t("События", "Events")) {
                if events.isEmpty {
                    Text(L10n.t("Событий нет", "No events")).foregroundStyle(GasAppColor.textTertiary)
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
        .navigationTitle(L10n.t("Безопасность", "Security"))
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
