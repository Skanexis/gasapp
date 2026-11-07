// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Настройки: аккаунт, сеть, защита, документы, удаление аккаунта.
///
/// Удаление аккаунта — из самого приложения: этого требует App Store
/// (Guideline 5.1.1(v)), и того же ждёт Google Play.
struct SettingsScreen: View {
    @Environment(AppModel.self) private var model

    @State private var username = ""
    @State private var wipeAfterTen = PinAttempts.wipeEnabled
    @State private var pushEnabled = Push.shared.enabled
    @State private var currentProxy: FfiProxy?
    @State private var biometricOn = Biometric.enabled
    @State private var askPinForBiometric = false
    @State private var autoLock = AppModel.autoLockSeconds
    @State private var presence = false
    @State private var presenceLoaded = false
    @State private var exportDocument: BackupDocument?
    @State private var exporting = false
    @State private var torStatus = ""
    @State private var confirmDelete = false
    @State private var deleting = false
    @State private var deletion: FfiAccountDeletion?
    @State private var error: String?

    var body: some View {
        Form {
            // Строки — цветом карточек GasApp, а не системным серым.
            Group {
                Section(L10n.t("Аккаунт", "Account")) {
                    LabeledContent(L10n.t("Имя", "Username"), value: username.isEmpty ? "—" : "@\(username)")
                    Button(L10n.t("Заблокировать сейчас", "Lock now")) { model.lock() }
                }

                Section {
                    Toggle(L10n.t("Уведомления", "Notifications"), isOn: $pushEnabled)
                        .onChange(of: pushEnabled) { _, value in
                            Push.shared.enabled = value
                            Push.shared.sync()
                        }
                } header: {
                    Text(L10n.t("Уведомления", "Notifications"))
                } footer: {
                    Text(L10n.t("Только «Новые сообщения» — без текста и имени. Apple видит лишь, что вам что-то пришло, и когда.",
                                "Only “New messages” — no text or name. Apple only sees that something arrived, and when."))
                }

                Section {
                    NavigationLink { NetworkScreen() } label: {
                        LabeledContent(L10n.t("Подключение", "Connection"), value: proxyName)
                    }
                    if currentProxy == .tor && !torStatus.isEmpty {
                        Text(torStatus).font(.system(size: 13)).foregroundStyle(GasAppColor.textTertiary)
                    }
                } header: {
                    Text(L10n.t("Сеть", "Network"))
                } footer: {
                    Text(L10n.t("Напрямую сервер видит ваш IP-адрес. Через Tor — нет, но медленнее.",
                                "Directly, the server sees your IP address. Via Tor it doesn’t, but it’s slower."))
                }

                Section {
                    if Biometric.available {
                        Toggle(L10n.t("Вход по \(Biometric.name)", "Unlock with \(Biometric.name)"), isOn: Binding(
                            get: { biometricOn },
                            set: { value in
                                if value { askPinForBiometric = true } else { Biometric.disable(); biometricOn = false }
                            }
                        ))
                    }
                    Picker(L10n.t("Автоблокировка", "Auto-lock"), selection: $autoLock) {
                        Text(L10n.t("Сразу", "Immediately")).tag(0)
                        Text(L10n.t("Через 30 с", "After 30 s")).tag(30)
                        Text(L10n.t("Через 1 мин", "After 1 min")).tag(60)
                        Text(L10n.t("Через 5 мин", "After 5 min")).tag(300)
                    }
                    .onChange(of: autoLock) { _, value in AppModel.autoLockSeconds = value }
                    Toggle(L10n.t("Показывать, что я в сети", "Show when I’m online"), isOn: $presence)
                        .onChange(of: presence) { _, value in setPresence(value) }
                    Toggle(L10n.t("Стереть всё после 10 неверных PIN", "Erase everything after 10 wrong PINs"),
                           isOn: $wipeAfterTen)
                        .onChange(of: wipeAfterTen) { _, value in PinAttempts.wipeEnabled = value }
                    NavigationLink(L10n.t("Центр безопасности", "Security center")) { SecurityScreen() }
                    NavigationLink(L10n.t("Хранилище файлов", "File vault")) { VaultScreen() }
                    NavigationLink(L10n.t("Резервная копия", "Backup")) { BackupScreen() }
                    NavigationLink(L10n.t("Восстановить из копии", "Restore from backup")) {
                        RestoreScreen(recovering: false) { Inbox.shared.touch() }
                    }
                    Button(L10n.t("Выгрузить мои данные", "Export my data")) { exportData() }
                } header: {
                    Text(L10n.t("Защита", "Security"))
                } footer: {
                    Text(L10n.t("Защищает от перебора, но ребёнок, играющий с телефоном, может всё стереть.",
                                "Stops guessing, but a child playing with the phone could erase everything."))
                }

                Section(L10n.t("Документы", "Documents")) {
                    link(L10n.t("Политика конфиденциальности", "Privacy policy"), "privacy/")
                    link(L10n.t("Условия использования", "Terms of use"), "terms/")
                    link(L10n.t("Правила сообщества", "Community guidelines"), "community-guidelines/")
                    link(L10n.t("Поддержка", "Support"), "support/")
                }

                Section {
                    Button(role: .destructive) { confirmDelete = true } label: {
                        if deleting { ProgressView() } else { Text(L10n.t("Удалить аккаунт", "Delete account")) }
                    }
                    .disabled(deleting)
                    if let error { Text(error).foregroundStyle(GasAppColor.error) }
                } footer: {
                    Text(L10n.t("Аккаунт удаляется на сервере, переписка — с этого телефона. Вернуть нельзя.",
                                "The account is deleted on the server and messages from this phone. This can’t be undone."))
                }

                Section {
                    LabeledContent(L10n.t("Версия ядра", "Core version"), value: coreVersion())
                    LabeledContent(L10n.t("Версия протокола", "Protocol version"), value: String(protocolVersion()))
                    // Язык приложения выбирается в настройках iOS (как
                    // «Язык приложения» на Android 13+).
                    Button(L10n.t("Язык приложения", "App language")) {
                        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Настройки", "Settings"))
        .confirmationDialog(L10n.t("Удалить аккаунт навсегда?", "Delete the account forever?"),
                            isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete"), role: .destructive) { deleteAccount() }
        }
        .alert(L10n.t("Аккаунт удалён", "Account deleted"), isPresented: Binding(
            get: { deletion != nil }, set: { if !$0 { finishDeletion() } }
        )) {
            Button("OK") { finishDeletion() }
        } message: {
            // 🔐 Числа, а не просто «готово»: проверить потом уже нечем.
            if let deletion {
                Text(L10n.t("Устройств: \(deletion.devices), недоставленных сообщений: \(deletion.envelopes), вложений: \(deletion.attachments).",
                            "Devices: \(deletion.devices), undelivered messages: \(deletion.envelopes), attachments: \(deletion.attachments)."))
            }
        }
        .task { await load() }
        .onAppear { Task { await load() } }
        .sheet(isPresented: $askPinForBiometric) {
            PinConfirmSheet(title: L10n.t("PIN для \(Biometric.name)", "PIN for \(Biometric.name)")) { pin in
                enableBiometric(pin: pin)
            }
        }
        .fileExporter(isPresented: $exporting, document: exportDocument, contentType: .json,
                      defaultFilename: "gasapp-my-data.json") { _ in exportDocument = nil }
    }

    private func link(_ title: String, _ path: String) -> some View {
        Link(title, destination: AppConfig.docsURL.appendingPathComponent(path))
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let state = try? await Background.run { () -> (String?, FfiProxy) in
            (try messenger.ownUsername(), try messenger.proxy())
        }
        username = state?.0 ?? ""
        currentProxy = state?.1
        updateTorStatus()
        presence = (try? await Background.run { try messenger.presenceSharingEnabled() }) ?? false
        presenceLoaded = true
    }

    private func setPresence(_ value: Bool) {
        // Значение из базы при открытии — не действие человека.
        guard presenceLoaded, let messenger = try? CoreStore.shared.current() else { return }
        Task { _ = try? await Background.run { try messenger.setPresenceSharing(enabled: value) } }
    }

    /// 🔐 Face ID включается только ключом, который действительно открыл
    /// базу: PIN спрашивается заново и проверяется.
    ///
    /// 🔐 Эта сверка — тоже ответ на «верен ли PIN», поэтому она идёт
    /// через тот же счётчик, что и вход: задержки, запись попытки до
    /// проверки и стирание после десяти (как `Reauth` на Android). Иначе
    /// открытое приложение было бы способом перебирать PIN без задержек.
    private func enableBiometric(pin: [UInt8]) {
        let wait = PinAttempts.waitRemaining()
        guard wait <= 0 else {
            biometricOn = false
            error = L10n.t("Слишком много неверных PIN. Подождите \(Int(wait.rounded(.up))) с.",
                           "Too many wrong PINs. Wait \(Int(wait.rounded(.up))) s.")
            return
        }
        guard PinAttempts.beginAttempt() else {
            biometricOn = false
            error = L10n.t("Не удалось сохранить попытку. Попробуйте ещё раз.", "Could not save the attempt. Try again.")
            return
        }
        Task {
            // nil — PIN не сверялся (сбой ключа Enclave и т. п.).
            let verdict = try? await Background.run { () -> Bool in
                var key = try CoreStore.shared.deriveKey(pin: pin)
                defer { key.wipe() }
                guard CoreStore.shared.keyOpensStorage(key) else { return false }
                try Biometric.enable(key: key)
                return true
            }
            switch verdict {
            case true?:
                PinAttempts.reset()
                biometricOn = true
            case false?:
                biometricOn = false
                if PinAttempts.shouldWipe {
                    model.didWipe()
                    return
                }
                error = L10n.t("PIN не подошёл — Face ID не включён", "Wrong PIN — Face ID not enabled")
            case nil:
                PinAttempts.cancelAttempt()
                biometricOn = false
                error = L10n.t("Не удалось включить Face ID", "Could not enable Face ID")
            }
        }
    }

    /// Выгрузка своих данных (GDPR, ст. 20): то, что знает о вас этот
    /// телефон, — в файл, который вы сохраняете сами.
    private func exportData() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            guard let json = try? await Background.run({ try messenger.exportData(nowMillis: CoreStore.nowMillis) }) else {
                error = L10n.t("Не удалось выгрузить данные", "Could not export data")
                return
            }
            exportDocument = BackupDocument(data: Data(json.utf8), name: "gasapp-my-data.json")
            exporting = true
        }
    }

    private var proxyName: String {
        switch currentProxy {
        case .tor?: return L10n.t("Через Tor", "Via Tor")
        case .socks5?: return L10n.t("SOCKS5-прокси", "SOCKS5 proxy")
        case .direct?: return L10n.t("Напрямую", "Direct")
        case nil: return "—"
        }
    }

    private func updateTorStatus() {
        let status = NetworkController.shared.torStatus
        torStatus = status.ready
            ? L10n.t("Tor подключён", "Tor connected")
            : L10n.t("Tor подключается… \(status.percent)%", "Tor connecting… \(status.percent)%")
    }

    private func deleteAccount() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        deleting = true
        error = nil
        Task {
            do {
                deletion = try await Background.run { try messenger.deleteAccount(nowMillis: CoreStore.nowMillis) }
            } catch {
                self.error = L10n.t("Нет связи с сервером — аккаунт не удалён.", "No connection — the account was not deleted.")
            }
            deleting = false
        }
    }

    /// 🔐 После удаления на сервере — всё локальное: база, ключ Enclave.
    private func finishDeletion() {
        deletion = nil
        model.didWipe()
    }
}
