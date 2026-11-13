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
    @State private var premium = false

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
            case .disableWipe, .autoLock: return L10n.t("Отключение защиты", "Turn off a protection", "Disattivare una protezione")
            case .export: return L10n.t("Выгрузка переписки", "Export your messages", "Esporta i tuoi messaggi")
            case .delete: return L10n.t("Удаление аккаунта", "Delete account", "Elimina account")
            }
        }
    }

    var body: some View {
        Form {
            // Профиль — карточкой сверху, как в системных настройках.
            Section {
                VStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill(LinearGradient(colors: [Color(red: 1, green: 0.85, blue: 0.3), Color(red: 1, green: 0.62, blue: 0.11)],
                                                 startPoint: .topLeading, endPoint: .bottomTrailing))
                        Text(initials).font(GasFont.display(30))
                            .foregroundStyle(Color(red: 0.16, green: 0.07, blue: 0))
                    }
                    .frame(width: 84, height: 84)
                    .overlay(Circle().stroke(Color(red: 0.54, green: 0.2, blue: 0.08), lineWidth: 3))
                    .accessibilityHidden(true)
                    Text(username.isEmpty ? "—" : "@\(username)")
                        .font(GasFont.display(24))
                        .foregroundStyle(GasAppColor.textPrimary)
                    if premium {
                        Label(L10n.t("Премиум", "Premium", "Premium"), systemImage: "crown.fill")
                            .font(GasFont.text(13, .bold))
                            .foregroundStyle(GasAppColor.accent)
                            .padding(.horizontal, 12).padding(.vertical, 5)
                            .background(Capsule().fill(GasAppColor.accent.opacity(0.14)))
                    }
                    HStack(spacing: 10) {
                        NavigationLink { ProfileSheet(username: username) } label: {
                            Label(L10n.t("Моя ссылка и QR", "My link and QR", "Il mio link e QR"), systemImage: "qrcode")
                                .font(GasFont.text(15, .semibold))
                                .frame(maxWidth: .infinity).padding(.vertical, 11)
                                .background(RoundedRectangle(cornerRadius: 14).fill(GasAppColor.bgRaised))
                        }
                        Button { model.lock() } label: {
                            Label(L10n.t("Заблокировать", "Lock", "Blocca"), systemImage: "lock.fill")
                                .font(GasFont.text(15, .semibold))
                                .frame(maxWidth: .infinity).padding(.vertical, 11)
                                .background(RoundedRectangle(cornerRadius: 14).fill(GasAppColor.bgRaised))
                        }
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(GasAppColor.accent)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            .listRowBackground(GasAppColor.bgCard)

            Group {
                Section {
                    NavigationLink { NetworkScreen() } label: {
                        HStack {
                            SettingRow(icon: "network", color: .blue, title: L10n.t("Подключение", "Connection", "Connessione"),
                                       detail: proxyName)
                            ConnectionBadge()
                        }
                    }
                    Toggle(isOn: $pushEnabled) {
                        SettingRow(icon: "bell.badge.fill", color: .red, title: L10n.t("Уведомления", "Notifications", "Notifiche"))
                    }
                    .onChange(of: pushEnabled) { _, value in
                        Push.shared.enabled = value
                        Push.shared.sync()
                    }
                } header: {
                    Text(L10n.t("Связь", "Connection", "Connessione"))
                } footer: {
                    Text(L10n.t("Уведомление — только «Новые сообщения», без текста и имени. Напрямую сервер видит ваш IP-адрес, через Tor — нет.",
                                "A notification only says “New messages” — no text or name. Directly, the server sees your IP address; via Tor it doesn’t.",
                                "La notifica dice solo «Nuovi messaggi», senza testo né nome. In modalità diretta il server vede il tuo indirizzo IP, tramite Tor no."))
                }

                Section {
                    if Biometric.available {
                        Toggle(isOn: Binding(
                            get: { biometricOn },
                            set: { value in
                                if value { askPinForBiometric = true } else { Biometric.disable(); biometricOn = false }
                            }
                        )) {
                            SettingRow(icon: "faceid", color: .green, title: L10n.t("Вход по \(Biometric.name)", "Unlock with \(Biometric.name)", "Sblocca con \(Biometric.name)"))
                        }
                    }
                    // Дольше — слабее: удлинить срок можно только по PIN.
                    Picker(selection: Binding(
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
                        Text(L10n.t("Сразу", "Immediately", "Subito")).tag(0)
                        Text(L10n.t("Через 30 с", "After 30 s", "Dopo 30 s")).tag(30)
                        Text(L10n.t("Через 1 мин", "After 1 min", "Dopo 1 min")).tag(60)
                        Text(L10n.t("Через 5 мин", "After 5 min", "Dopo 5 min")).tag(300)
                    } label: {
                        SettingRow(icon: "lock.rotation", color: .indigo, title: L10n.t("Автоблокировка", "Auto-lock", "Blocco automatico"))
                    }
                    Toggle(isOn: $presence) {
                        SettingRow(icon: "eye.fill", color: .teal, title: L10n.t("Показывать, что я в сети", "Show when I’m online", "Mostra quando sono online"))
                    }
                    .onChange(of: presence) { _, value in setPresence(value) }
                    // Включение — через подтверждение, выключение — по PIN:
                    // иначе стирание выключали бы перед подбором PIN.
                    Toggle(isOn: Binding(
                        get: { wipeAfterTen },
                        set: { value in if value { confirmWipe = true } else { reauth = .disableWipe } }
                    )) {
                        SettingRow(icon: "trash.fill", color: .red, title: L10n.t("Стереть всё после 10 неверных PIN", "Erase everything after 10 wrong PINs", "Cancella tutto dopo 10 PIN errati"))
                    }
                    NavigationLink { SecurityScreen() } label: {
                        SettingRow(icon: "checkmark.shield.fill", color: .orange, title: L10n.t("Центр безопасности", "Security center", "Centro sicurezza"))
                    }
                    NavigationLink { VaultScreen() } label: {
                        SettingRow(icon: "lock.square.stack.fill", color: .purple, title: L10n.t("Хранилище файлов", "File vault", "Cassaforte file"))
                    }
                } header: {
                    Text(L10n.t("Защита", "Security", "Sicurezza"))
                } footer: {
                    Text(L10n.t("Стирание защищает от перебора, но ребёнок, играющий с телефоном, может всё стереть.",
                                "Erasing stops guessing, but a child playing with the phone could erase everything.",
                                "La cancellazione ferma i tentativi, ma un bambino che gioca con il telefono potrebbe cancellare tutto."))
                }

                // Боты — только у премиума: без него сервер их не создаст.
                if premium {
                    Section {
                        NavigationLink { BotsScreen() } label: {
                            SettingRow(icon: "cpu.fill", color: .mint, title: L10n.t("Мои боты", "My bots", "I miei bot"))
                        }
                    } header: {
                        Text(L10n.t("Боты", "Bots", "Bot"))
                    }
                }

                Section {
                    NavigationLink { BackupScreen() } label: {
                        SettingRow(icon: "externaldrive.fill", color: .blue, title: L10n.t("Резервная копия", "Backup", "Backup"))
                    }
                    NavigationLink { RestoreScreen(recovering: false) { Inbox.shared.touch() } } label: {
                        SettingRow(icon: "arrow.counterclockwise", color: .cyan, title: L10n.t("Восстановить из копии", "Restore from backup", "Ripristina da backup"))
                    }
                    NavigationLink { StorageScreen() } label: {
                        SettingRow(icon: "internaldrive.fill", color: .gray, title: L10n.t("Место на устройстве", "Storage", "Spazio"))
                    }
                    Button { reauth = .export } label: {
                        SettingRow(icon: "square.and.arrow.up.fill", color: .brown, title: L10n.t("Выгрузить мои данные", "Export my data", "Esporta i miei dati"))
                    }
                } header: {
                    Text(L10n.t("Данные", "Data", "Dati"))
                }

                // Как `DevicesActivity` на Android: только это устройство —
                // честное состояние, а не заглушка «скоро». Модель видна
                // только здесь и на сервер не уходит.
                Section {
                    HStack(spacing: 12) {
                        SettingIcon(name: "iphone", color: .gray)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(UIDevice.current.model).foregroundStyle(GasAppColor.textPrimary)
                            Text("ID \(CoreStore.shared.deviceId.map { String($0.prefix(8)) } ?? "—")")
                                .font(.system(size: 12, design: .monospaced)).foregroundStyle(GasAppColor.textTertiary)
                        }
                        Spacer()
                        Text(L10n.t("Это устройство", "This device", "Questo dispositivo"))
                            .font(GasFont.text(11, .semibold)).foregroundStyle(GasAppColor.ok)
                            .padding(.horizontal, 10).padding(.vertical, 4)
                            .background(Capsule().fill(GasAppColor.ok.opacity(0.15)))
                    }
                } header: {
                    Text(L10n.t("Связанные устройства", "Linked devices", "Dispositivi collegati"))
                } footer: {
                    Text(L10n.t("Каждое связанное устройство читает переписку целиком. Связывание появится вместе с синхронизацией между устройствами; пока аккаунт доступен только отсюда.",
                                "Every linked device can read all of your messages. Device linking will come with multi-device sync; for now, your account works only on this device.", "Ogni dispositivo collegato può leggere tutti i tuoi messaggi. Il collegamento dei dispositivi arriverà con la sincronizzazione multi-dispositivo; per ora il tuo account funziona solo su questo dispositivo."))
                }

                Section {
                    link(icon: "hand.raised.fill", color: .blue, L10n.t("Политика конфиденциальности", "Privacy policy", "Informativa sulla privacy"), "privacy/")
                    link(icon: "doc.text.fill", color: .gray, L10n.t("Условия использования", "Terms of use", "Termini d’uso"), "terms/")
                    link(icon: "person.3.fill", color: .orange, L10n.t("Правила сообщества", "Community guidelines", "Linee guida della community"), "community-guidelines/")
                    link(icon: "questionmark.bubble.fill", color: .green, L10n.t("Поддержка", "Support", "Assistenza"), "support/")
                    // Язык приложения выбирается в настройках iOS (как
                    // «Язык приложения» на Android 13+).
                    Button {
                        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                    } label: {
                        SettingRow(icon: "globe", color: .blue, title: L10n.t("Язык приложения", "App language", "Lingua dell’app"), external: true)
                    }
                } header: {
                    Text(L10n.t("О приложении", "About", "Informazioni"))
                } footer: {
                    Text("GasApp · \(L10n.t("ядро", "core", "core")) \(coreVersion()) · \(L10n.t("протокол", "protocol", "protocollo")) \(protocolVersion())")
                }

                Section {
                    Button(role: .destructive) { reauth = .delete } label: {
                        HStack {
                            Spacer()
                            if deleting { ProgressView() } else {
                                Text(L10n.t("Удалить аккаунт", "Delete account", "Elimina account")).fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(deleting)
                    if let error { Text(error).foregroundStyle(GasAppColor.error) }
                } footer: {
                    Text(L10n.t("Аккаунт удаляется на сервере, переписка — с этого телефона. Вернуть нельзя.",
                                "The account is deleted on the server and messages from this phone. This can’t be undone.", "L’account viene eliminato dal server e i messaggi da questo telefono. Non si può annullare."))
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Настройки", "Settings", "Impostazioni"))
        .confirmationDialog(L10n.t("Удалить аккаунт навсегда?", "Delete the account forever?", "Eliminare l’account per sempre?"),
                            isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete", "Elimina"), role: .destructive) { deleteAccount() }
        } message: {
            Text(L10n.t("С сервера исчезнут имя, ключи и недоставленные сообщения, а с устройства — вся переписка, контакты и файлы.\n\nЧего это не сделает: сообщения, которые уже дошли, останутся у собеседников, а присланные вам файлы пролежат на сервере до конца своего тридцатидневного срока. Имя освободится, и его сможет занять кто угодно — выдать себя за вас он не сможет: ключ будет другим, и ваши собеседники получат предупреждение.", "Your username, keys and any undelivered messages will be removed from the server, and this device will be wiped — every conversation, contact and file.\n\nWhat this does not do: messages already delivered stay on your contacts’ devices, and files sent to you stay on the server until they expire after 30 days. Your username becomes available for anyone else to take — they cannot pose as you, because their key would be different and your contacts would be warned.", "Il tuo nome utente, le chiavi e i messaggi non consegnati verranno rimossi dal server, e questo dispositivo verrà cancellato: ogni conversazione, contatto e file.\n\nCosa non fa: i messaggi già consegnati restano sui dispositivi dei tuoi contatti, e i file inviati a te restano sul server finché non scadono dopo 30 giorni. Il tuo nome utente diventa disponibile per chiunque: non potranno spacciarsi per te, perché la loro chiave sarebbe diversa e i tuoi contatti verrebbero avvisati."))
        }
        .sheet(item: $reauth) { step in
            PinConfirmSheet(title: step.title) { pin in passReauth(step, pin: pin) }
        }
        .alert(L10n.t("Стирать данные после 10 неверных PIN?", "Erase data after 10 wrong PINs?", "Cancellare i dati dopo 10 PIN errati?"), isPresented: $confirmWipe) {
            Button(L10n.t("Включить", "Turn on", "Attiva"), role: .destructive) {
                PinAttempts.wipeEnabled = true
                wipeAfterTen = true
            }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) {}
        } message: {
            Text(L10n.t("После десяти неверных PIN подряд вся переписка, контакты и файлы хранилища на этом телефоне будут стёрты — в том числе если их наберёт ребёнок или карман. Без ключа восстановления вернуть их не сможет никто, и мы тоже.", "After ten wrong PINs in a row, all messages, contacts and vault files on this phone are erased — including when a child or a pocket types them. Without a recovery key they cannot be brought back, not even by us.", "Dopo dieci PIN errati di fila, tutti i messaggi, i contatti e i file della cassaforte su questo telefono vengono cancellati, anche se a digitarli è un bambino o una tasca. Senza una chiave di recupero non si possono recuperare, nemmeno da noi."))
        }
        // ⚠️ Файл не зашифрован — человек узнаёт это до выбора места.
        .alert(L10n.t("Выгрузить ваши данные?", "Export your data?", "Esportare i tuoi dati?"), isPresented: $confirmExport) {
            Button(L10n.t("Выбрать, куда сохранить", "Choose where to save", "Scegli dove salvare")) { exportData() }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) {}
        } message: {
            Text(L10n.t("Вы получите файл JSON с именем пользователя, контактами, перепиской и настройками.\n\n⚠️ Файл НЕ зашифрован. Любой, кто его получит, прочтёт всю переписку. Сохраняйте туда, где распоряжаетесь вы, и удаляйте, когда он больше не нужен.\n\nКлючей в файле нет, поэтому восстановить из него аккаунт нельзя — для этого есть резервная копия.", "You will get a JSON file with your username, contacts, conversations and settings.\n\n⚠️ The file is NOT encrypted. Anyone who gets it can read every message in it. Save it somewhere you control, and delete it when you are done.\n\nKeys are never included, so this file cannot restore your account — use a backup for that.", "Otterrai un file JSON con nome utente, contatti, conversazioni e impostazioni.\n\n⚠️ Il file NON è cifrato. Chiunque lo ottenga può leggere ogni messaggio che contiene. Salvalo in un posto che controlli ed eliminalo quando hai finito.\n\nLe chiavi non sono mai incluse, quindi questo file non può ripristinare il tuo account: per quello usa un backup."))
        }
        .alert(L10n.t("Аккаунт удалён", "Account deleted", "Account eliminato"), isPresented: Binding(
            get: { deletion != nil }, set: { if !$0 { finishDeletion() } }
        )) {
            Button("OK") { finishDeletion() }
        } message: {
            // 🔐 Числа, а не просто «готово»: проверить потом уже нечем.
            if let deletion {
                Text(L10n.t("Устройств: \(deletion.devices), недоставленных сообщений: \(deletion.envelopes), вложений: \(deletion.attachments).",
                            "Devices: \(deletion.devices), undelivered messages: \(deletion.envelopes), attachments: \(deletion.attachments).", "Dispositivi: \(deletion.devices), messaggi non consegnati: \(deletion.envelopes), allegati: \(deletion.attachments)."))
            }
        }
        .task { await load() }
        .onAppear { Task { await load() } }
        .sheet(isPresented: $askPinForBiometric) {
            PinConfirmSheet(title: L10n.t("PIN для \(Biometric.name)", "PIN for \(Biometric.name)", "PIN per \(Biometric.name)")) { pin in
                enableBiometric(pin: pin)
            }
        }
        .fileExporter(isPresented: $exporting, document: exportDocument, contentType: .json,
                      defaultFilename: "gasapp-my-data.json") { _ in exportDocument = nil }
    }

    private func link(icon: String, color: Color, _ title: String, _ path: String) -> some View {
        Link(destination: AppConfig.docsURL.appendingPathComponent(path)) {
            SettingRow(icon: icon, color: color, title: title, external: true)
        }
    }

    private var initials: String {
        let letters = username.filter { $0.isLetter }.prefix(2)
        return letters.isEmpty ? "G" : letters.uppercased()
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
        premium = (try? await Background.run { try messenger.premiumCached() }) ?? false
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
                           "Too many wrong PINs. Wait \(Int(wait.rounded(.up))) s.", "Troppi PIN errati. Attendi \(Int(wait.rounded(.up))) s.")
            return
        }
        guard PinAttempts.beginAttempt() else {
            biometricOn = false
            error = L10n.t("Не удалось сохранить попытку. Попробуйте ещё раз.", "Could not save the attempt. Try again.", "Impossibile salvare il tentativo. Riprova.")
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
                error = L10n.t("PIN не подошёл — Face ID не включён", "Wrong PIN — Face ID not enabled", "PIN errato: Face ID non attivato")
            case nil:
                PinAttempts.cancelAttempt()
                biometricOn = false
                error = L10n.t("Не удалось включить Face ID", "Could not enable Face ID", "Impossibile attivare Face ID")
            }
        }
    }

    /// Выгрузка своих данных (GDPR, ст. 20): то, что знает о вас этот
    /// телефон, — в файл, который вы сохраняете сами.
    private func exportData() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            guard let json = try? await Background.run({ try messenger.exportData(nowMillis: CoreStore.nowMillis) }) else {
                error = L10n.t("Не удалось выгрузить данные", "Could not export data", "Impossibile esportare i dati")
                return
            }
            exportDocument = BackupDocument(data: Data(json.utf8), name: "gasapp-my-data.json")
            exporting = true
        }
    }

    private var proxyName: String {
        switch currentProxy {
        case .tor?: return L10n.t("Через Tor", "Via Tor", "Tramite Tor")
        case .socks5?: return L10n.t("SOCKS5-прокси", "SOCKS5 proxy", "Proxy SOCKS5")
        case .direct?: return L10n.t("Напрямую", "Direct", "Diretta")
        case nil: return "—"
        }
    }

    private func updateTorStatus() {
        let status = NetworkController.shared.torStatus
        torStatus = status.ready
            ? L10n.t("Tor подключён", "Tor connected", "Tor connesso")
            : L10n.t("Tor подключается… \(status.percent)%", "Tor connecting… \(status.percent)%", "Connessione a Tor… \(status.percent)%")
    }

    private func deleteAccount() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        deleting = true
        error = nil
        Task {
            do {
                deletion = try await Background.run { try messenger.deleteAccount(nowMillis: CoreStore.nowMillis) }
            } catch {
                self.error = L10n.t("Нет связи с сервером — аккаунт не удалён.", "No connection — the account was not deleted.", "Nessuna connessione: l’account non è stato eliminato.")
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

/// Строка настроек: цветной значок, название, значение справа.
struct SettingRow: View {
    let icon: String
    let color: Color
    let title: String
    var value: String?
    var detail: String?
    var external = false

    var body: some View {
        HStack(spacing: 12) {
            SettingIcon(name: icon, color: color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(GasAppColor.textPrimary)
                if let detail, !detail.isEmpty {
                    Text(detail).font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                }
            }
            Spacer(minLength: 8)
            if let value { Text(value).foregroundStyle(GasAppColor.textTertiary) }
            if external {
                Image(systemName: "arrow.up.right").font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(GasAppColor.textTertiary)
            }
        }
        .contentShape(Rectangle())
    }
}

/// Значок строки настроек — белый символ на цветной плашке.
struct SettingIcon: View {
    let name: String
    let color: Color

    var body: some View {
        Image(systemName: name)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 30, height: 30)
            .background(RoundedRectangle(cornerRadius: 8).fill(color.gradient))
            .accessibilityHidden(true)
    }
}
