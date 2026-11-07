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
    @State private var reauth: ReauthStep?
    @State private var confirmWipe = false
    @State private var confirmExport = false

    /// 🔐 Действия только для владельца (аудит 2026-10-02, A-3; как
    /// `Reauth.require` на Android): включать защиту можно сразу,
    /// ослаблять, выгружать переписку и удалять аккаунт — после PIN.
    /// Иначе тот, кому дали подержать открытый телефон, снимал бы
    /// защиту на потом.
    enum ReauthStep: Identifiable {
        case disableWipe
        case autoLock(Int)
        case export
        case delete

        var id: String {
            switch self {
            case .disableWipe: return "wipe"
            case let .autoLock(seconds): return "lock\(seconds)"
            case .export: return "export"
            case .delete: return "delete"
            }
        }

        var title: String {
            switch self {
            case .disableWipe, .autoLock: return L10n.t("Отключение защиты", "Turn off a protection")
            case .export: return L10n.t("Выгрузка переписки", "Export your messages")
            case .delete: return L10n.t("Удаление аккаунта", "Delete account")
            }
        }
    }

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
                    // Дольше — слабее: удлинить срок можно только по PIN.
                    Picker(L10n.t("Автоблокировка", "Auto-lock"), selection: Binding(
                        get: { autoLock },
                        set: { value in
                            if value > autoLock {
                                reauth = .autoLock(value)
                            } else {
                                autoLock = value
                                AppModel.autoLockSeconds = value
                            }
                        }
                    )) {
                        Text(L10n.t("Сразу", "Immediately")).tag(0)
                        Text(L10n.t("Через 30 с", "After 30 s")).tag(30)
                        Text(L10n.t("Через 1 мин", "After 1 min")).tag(60)
                        Text(L10n.t("Через 5 мин", "After 5 min")).tag(300)
                    }
                    Toggle(L10n.t("Показывать, что я в сети", "Show when I’m online"), isOn: $presence)
                        .onChange(of: presence) { _, value in setPresence(value) }
                    // Включение — через подтверждение, выключение — по PIN:
                    // иначе стирание выключали бы перед подбором PIN.
                    Toggle(L10n.t("Стереть всё после 10 неверных PIN", "Erase everything after 10 wrong PINs"),
                           isOn: Binding(
                               get: { wipeAfterTen },
                               set: { value in if value { confirmWipe = true } else { reauth = .disableWipe } }
                           ))
                    NavigationLink(L10n.t("Центр безопасности", "Security center")) { SecurityScreen() }
                    NavigationLink(L10n.t("Хранилище файлов", "File vault")) { VaultScreen() }
                    NavigationLink(L10n.t("Место на устройстве", "Storage")) { StorageScreen() }
                    NavigationLink(L10n.t("Резервная копия", "Backup")) { BackupScreen() }
                    NavigationLink(L10n.t("Восстановить из копии", "Restore from backup")) {
                        RestoreScreen(recovering: false) { Inbox.shared.touch() }
                    }
                    Button(L10n.t("Выгрузить мои данные", "Export my data")) { reauth = .export }
                } header: {
                    Text(L10n.t("Защита", "Security"))
                } footer: {
                    Text(L10n.t("Защищает от перебора, но ребёнок, играющий с телефоном, может всё стереть.",
                                "Stops guessing, but a child playing with the phone could erase everything."))
                }

                // Как `DevicesActivity` на Android: только это устройство —
                // честное состояние, а не заглушка «скоро». Модель видна
                // только здесь и на сервер не уходит.
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: "iphone").foregroundStyle(GasAppColor.accent)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(UIDevice.current.model).foregroundStyle(GasAppColor.textPrimary)
                            Text("ID \(CoreStore.shared.deviceId.map { String($0.prefix(8)) } ?? "—")")
                                .font(.system(size: 12, design: .monospaced)).foregroundStyle(GasAppColor.textTertiary)
                        }
                        Spacer()
                        Text(L10n.t("Это устройство", "This device"))
                            .font(.system(size: 11, weight: .semibold)).foregroundStyle(GasAppColor.ok)
                            .padding(.horizontal, 10).padding(.vertical, 4)
                            .background(Capsule().fill(GasAppColor.ok.opacity(0.15)))
                    }
                } header: {
                    Text(L10n.t("Связанные устройства", "Linked devices"))
                } footer: {
                    Text(L10n.t("Каждое связанное устройство читает переписку целиком. Связывание появится вместе с синхронизацией между устройствами; пока аккаунт доступен только отсюда.",
                                "Every linked device can read all of your messages. Device linking will come with multi-device sync; for now, your account works only on this device."))
                }

                Section(L10n.t("Документы", "Documents")) {
                    link(L10n.t("Политика конфиденциальности", "Privacy policy"), "privacy/")
                    link(L10n.t("Условия использования", "Terms of use"), "terms/")
                    link(L10n.t("Правила сообщества", "Community guidelines"), "community-guidelines/")
                    link(L10n.t("Поддержка", "Support"), "support/")
                }

                Section {
                    Button(role: .destructive) { reauth = .delete } label: {
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
        } message: {
            Text(L10n.t("С сервера исчезнут имя, ключи и недоставленные сообщения, а с устройства — вся переписка, контакты и файлы.\n\nЧего это не сделает: сообщения, которые уже дошли, останутся у собеседников, а присланные вам файлы пролежат на сервере до конца своего тридцатидневного срока. Имя освободится, и его сможет занять кто угодно — выдать себя за вас он не сможет: ключ будет другим, и ваши собеседники получат предупреждение.", "Your username, keys and any undelivered messages will be removed from the server, and this device will be wiped — every conversation, contact and file.\n\nWhat this does not do: messages already delivered stay on your contacts’ devices, and files sent to you stay on the server until they expire after 30 days. Your username becomes available for anyone else to take — they cannot pose as you, because their key would be different and your contacts would be warned."))
        }
        .sheet(item: $reauth) { step in
            PinConfirmSheet(title: step.title) { pin in passReauth(step, pin: pin) }
        }
        .alert(L10n.t("Стирать данные после 10 неверных PIN?", "Erase data after 10 wrong PINs?"), isPresented: $confirmWipe) {
            Button(L10n.t("Включить", "Turn on"), role: .destructive) {
                PinAttempts.wipeEnabled = true
                wipeAfterTen = true
            }
            Button(L10n.t("Отмена", "Cancel"), role: .cancel) {}
        } message: {
            Text(L10n.t("После десяти неверных PIN подряд вся переписка, контакты и файлы хранилища на этом телефоне будут стёрты — в том числе если их наберёт ребёнок или карман. Без ключа восстановления вернуть их не сможет никто, и мы тоже.", "After ten wrong PINs in a row, all messages, contacts and vault files on this phone are erased — including when a child or a pocket types them. Without a recovery key they cannot be brought back, not even by us."))
        }
        // ⚠️ Файл не зашифрован — человек узнаёт это до выбора места.
        .alert(L10n.t("Выгрузить ваши данные?", "Export your data?"), isPresented: $confirmExport) {
            Button(L10n.t("Выбрать, куда сохранить", "Choose where to save")) { exportData() }
            Button(L10n.t("Отмена", "Cancel"), role: .cancel) {}
        } message: {
            Text(L10n.t("Вы получите файл JSON с именем пользователя, контактами, перепиской и настройками.\n\n⚠️ Файл НЕ зашифрован. Любой, кто его получит, прочтёт всю переписку. Сохраняйте туда, где распоряжаетесь вы, и удаляйте, когда он больше не нужен.\n\nКлючей в файле нет, поэтому восстановить из него аккаунт нельзя — для этого есть резервная копия.", "You will get a JSON file with your username, contacts, conversations and settings.\n\n⚠️ The file is NOT encrypted. Anyone who gets it can read every message in it. Save it somewhere you control, and delete it when you are done.\n\nKeys are never included, so this file cannot restore your account — use a backup for that."))
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

    private func passReauth(_ step: ReauthStep, pin: [UInt8]) {
        Task {
            switch await Reauth.verify(pin: pin) {
            case .ok:
                error = nil
                switch step {
                case .disableWipe:
                    PinAttempts.wipeEnabled = false
                    wipeAfterTen = false
                case let .autoLock(seconds):
                    autoLock = seconds
                    AppModel.autoLockSeconds = seconds
                case .export:
                    confirmExport = true
                case .delete:
                    confirmDelete = true
                }
            case .wiped:
                model.didWipe()
            case let .refused(text):
                error = text
            }
        }
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
