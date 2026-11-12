// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UniformTypeIdentifiers

/// Резервная копия — аналог `RecoveryCenterActivity` и `RecoveryKeyActivity`.
///
/// 🔐 Копия шифруется **ключом восстановления**, который знает только
/// человек: на телефоне он не хранится (иначе укравший телефон получил бы
/// и копию), сервер его не видел. Первый раз ключ показывается и
/// проверяется по группам; дальше — вводится при каждой копии.
///
/// Копии — цепочкой: полный снимок, потом добавки. Для восстановления
/// нужны все файлы цепочки — их предлагается сохранить в «Файлы»
/// (iCloud Drive или на флешку), а не в приложение: копия на том же
/// телефоне не переживёт его потерю.
struct BackupScreen: View {
    @Environment(AppModel.self) private var model
    @State private var status: FfiBackupStatus?
    @State private var askPinForNewKey = false
    @State private var confirmNewKey = false
    @State private var newKey: FfiRecoveryKey?
    @State private var confirmIndex: UInt32 = 0
    @State private var confirmText = ""
    @State private var confirmError: String?
    @State private var keyInput = ""
    @State private var working = false
    @State private var message: String?
    @State private var exportFile: BackupDocument?
    @State private var exporting = false

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if let status {
                    Card {
                        Text(status.configured ? L10n.t("Копии включены", "Backups are on", "I backup sono attivi")
                                               : L10n.t("Копий ещё нет", "No backups yet", "Ancora nessun backup"))
                            .font(.system(size: 17, weight: .bold)).foregroundStyle(GasAppColor.textPrimary)
                        if let last = status.lastBackupAtMillis {
                            Text(L10n.t("Последняя: \(formatChatTime(last))", "Last: \(formatChatTime(last))", "Ultimo: \(formatChatTime(last))"))
                                .font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary)
                        }
                    }
                }

                if let newKey {
                    keyCard(newKey)
                } else if status?.configured == true {
                    Card {
                        Text(L10n.t("Ключ восстановления", "Recovery key", "Chiave di recupero")).font(.system(size: 17, weight: .bold))
                            .foregroundStyle(GasAppColor.textPrimary)
                        SecureField(L10n.t("Введите ключ", "Enter the key", "Inserisci la chiave"), text: $keyInput)
                            .textInputAutocapitalization(.characters).autocorrectionDisabled()
                            .padding(12).background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgRaised))
                            .foregroundStyle(GasAppColor.textPrimary)
                        GoldButton(title: L10n.t("Сделать копию", "Back up now", "Esegui backup ora"), isLoading: working,
                                   isEnabled: validateRecoveryKey(text: keyInput)) { backup(with: keyInput) }
                        // Ключ потерян или мог попасть в чужие руки — новая
                        // цепочка копий под новым ключом (только владельцу).
                        OutlineButton(title: L10n.t("Создать новый ключ", "Create a new key", "Crea una nuova chiave")) { askPinForNewKey = true }
                            .disabled(working)
                    }
                } else {
                    Card {
                        Text(L10n.t("Если телефон потеряется, переписку и аккаунт вернёт копия. Её открывает ключ восстановления — запишите его на бумагу и храните отдельно от телефона.",
                                    "If you lose your phone, a backup brings back your account and messages. It opens with a recovery key — write it on paper and keep it away from the phone.", "Se perdi il telefono, un backup ti restituisce account e messaggi. Si apre con una chiave di recupero: scrivila su carta e conservala lontano dal telefono."))
                            .font(.system(size: 15)).foregroundStyle(GasAppColor.textSecondary)
                        GoldButton(title: L10n.t("Создать ключ", "Create a key", "Crea una chiave")) { createKey() }
                    }
                }

                if let message {
                    Banner(title: L10n.t("Копия", "Backup", "Backup"), message: message, tone: .info)
                }
            }
            .padding(16)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Резервная копия", "Backup", "Backup"))
        .fileExporter(isPresented: $exporting, document: exportFile, contentType: .data,
                      defaultFilename: exportFile?.name) { result in
            if case .success = result {
                message = L10n.t("Файл сохранён. Храните все файлы копий вместе.", "Saved. Keep all backup files together.", "Salvato. Tieni tutti i file di backup insieme.")
            }
            exportFile = nil
        }
        .task { await loadStatus() }
        .sheet(isPresented: $askPinForNewKey) {
            PinConfirmSheet(title: L10n.t("Ключ восстановления", "Recovery key", "Chiave di recupero")) { pin in
                Task {
                    switch await Reauth.verify(pin: pin) {
                    case .ok: confirmNewKey = true
                    case .wiped: model.didWipe()
                    case let .refused(text): message = text
                    }
                }
            }
        }
        // ⚠️ Прежние копии остаются под старым ключом — сказать это надо
        // до, а не после (как на Android).
        .alert(L10n.t("Создать новый ключ", "Create a new key", "Crea una nuova chiave"), isPresented: $confirmNewKey) {
            Button(L10n.t("Создать новый", "Create new", "Crea nuova"), role: .destructive) { startNewKey() }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) {}
        } message: {
            Text(L10n.t("Прежние копии останутся зашифрованными старым ключом — перешифровать их приложение не может. Сохраните старый ключ, пока эти копии вам нужны.",
                        "Earlier backups stay encrypted with the old key — the app cannot re-encrypt them. Keep the old key for as long as you need those backups.", "I backup precedenti restano cifrati con la vecchia chiave: l’app non può cifrarli di nuovo. Conserva la vecchia chiave finché ti servono quei backup."))
        }
    }

    /// Забыть цепочку копий и начать новую: следующая копия — полная,
    /// под новым ключом.
    private func startNewKey() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            do {
                try await Background.run { try messenger.forgetBackupChain() }
                keyInput = ""
                createKey()
                await loadStatus()
            } catch {
                message = L10n.t("Не удалось начать новую цепочку копий", "Could not start a new backup chain", "Impossibile avviare una nuova catena di backup")
            }
        }
    }

    private func keyCard(_ key: FfiRecoveryKey) -> some View {
        Card {
            Text(L10n.t("Ваш ключ восстановления", "Your recovery key", "La tua chiave di recupero")).font(.system(size: 17, weight: .bold))
                .foregroundStyle(GasAppColor.textPrimary)
            Text(L10n.t("1. Перепишите на бумагу все группы по порядку. Не фотографируйте и не делайте снимок экрана: ключ показывается один раз.",
                        "1. Copy every group onto paper, in order. Don’t photograph it or take a screenshot: the key is shown only once.",
                        "1. Copia su carta tutti i gruppi, in ordine. Non fotografarla e non fare screenshot: la chiave viene mostrata una sola volta."))
                .font(.system(size: 14)).foregroundStyle(GasAppColor.warn)
            // Группы с номерами: «группа № 7» однозначна. Раньше ключ шёл
            // одной строкой с приставкой GASAPP, и её считали первой
            // группой (снимок с iPhone, 2026-11-12).
            let groups = Self.groups(of: key.display)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 92), spacing: 8)], spacing: 8) {
                ForEach(Array(groups.enumerated()), id: \.offset) { index, group in
                    let asked = UInt32(index) == confirmIndex
                    VStack(spacing: 2) {
                        Text("\(index + 1)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(asked ? GasAppColor.accent : GasAppColor.textTertiary)
                        Text(group)
                            .font(.system(size: 18, weight: .semibold, design: .monospaced))
                            .foregroundStyle(GasAppColor.textPrimary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(RoundedRectangle(cornerRadius: 10).fill(GasAppColor.bgBase))
                    .overlay(RoundedRectangle(cornerRadius: 10)
                        .stroke(asked ? GasAppColor.accent : GasAppColor.line, lineWidth: asked ? 2 : 1))
                }
            }
            .textSelection(.disabled)
            .accessibilityElement(children: .combine)
            Text(L10n.t("2. Проверка: по своей записи введите группу № \(confirmIndex + 1) — она обведена.",
                        "2. Check: from your paper, type group #\(confirmIndex + 1) — the one outlined.",
                        "2. Verifica: dal tuo foglio, digita il gruppo n. \(confirmIndex + 1), quello evidenziato."))
                .font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary)
            Field(title: L10n.t("Группа № \(confirmIndex + 1)", "Group #\(confirmIndex + 1)", "Gruppo n. \(confirmIndex + 1)"),
                  text: $confirmText, error: confirmError)
            GoldButton(title: L10n.t("Проверить и сделать копию", "Check and back up", "Verifica ed esegui backup"), isLoading: working) {
                confirm(key)
            }
        }
    }

    /// Группы ключа без приставки `GASAPP-` — в той нумерации, в которой
    /// их сверяет ядро (`checkRecoveryKeyGroup`).
    static func groups(of display: String) -> [String] {
        let parts = display.split(separator: "-").map(String.init)
        if let first = parts.first, first.uppercased() == "GASAPP" { return Array(parts.dropFirst()) }
        return parts
    }

    private func loadStatus() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        status = try? await Background.run { try messenger.backupStatus() }
    }

    private func createKey() {
        guard let key = try? generateRecoveryKey() else { return }
        newKey = key
        confirmIndex = key.groupCount > 0 ? UInt32.random(in: 0..<key.groupCount) : 0
    }

    /// 🔐 Ключ сверяется по случайной группе: «записал» должно значить
    /// «записал», иначе копия окажется под ключом, которого ни у кого нет.
    private func confirm(_ key: FfiRecoveryKey) {
        guard (try? checkRecoveryKeyGroup(text: key.display, index: confirmIndex, entered: confirmText)) == true else {
            confirmError = L10n.t("Не совпадает — проверьте запись", "Doesn’t match — check what you wrote", "Non corrisponde: controlla cosa hai scritto")
            return
        }
        confirmError = nil
        backup(with: key.display)
    }

    private func backup(with key: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        working = true
        message = nil
        Task {
            do {
                // Argon2id с 256 МиБ и чтение всей базы — только в фоне.
                let made = try await Background.run {
                    try messenger.createBackup(recoveryKey: key, deviceLabel: "iPhone", nowMillis: CoreStore.nowMillis)
                }
                newKey = nil
                keyInput = ""
                let stamp = Date().formatted(.iso8601.year().month().day().dateSeparator(.omitted))
                exportFile = BackupDocument(data: made.archive,
                                            name: "gasapp-backup-\(stamp)-\(String(format: "%04u", made.generation)).gasappbk")
                exporting = true
                message = made.isFull
                    ? L10n.t("Полная копия готова — сохраните файл.", "Full backup ready — save the file.", "Backup completo pronto: salva il file.")
                    : L10n.t("Добавка к копии готова — сохраните её рядом с прежними.", "Incremental backup ready — save it next to the earlier ones.", "Backup incrementale pronto: salvalo accanto ai precedenti.")
                await loadStatus()
            } catch {
                message = L10n.t("Копия не сделана: ключ не тот или не хватило места.", "Backup failed: wrong key or not enough space.", "Backup non riuscito: chiave errata o spazio insufficiente.")
            }
            working = false
        }
    }
}

/// Файл копии для «Сохранить в Файлы» — из памяти, без записи в приложение.
struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data
    let name: String

    init(data: Data, name: String) {
        self.data = data
        self.name = name
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
        name = configuration.file.filename ?? "gasapp-backup.gasappbk"
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

/// Восстановление из копии — аналог `RestoreActivity`.
///
/// `recovering` — новый телефон: аккаунт возвращается **с прежним
/// именем** на новой identity (ключ восстановления аккаунта из копии
/// подписывает перепривязку). Иначе — данные в уже открытый аккаунт.
struct RestoreScreen: View {
    let recovering: Bool
    let onDone: () -> Void

    @State private var key = ""
    @State private var files: [URL] = []
    @State private var picking = false
    @State private var working = false
    @State private var result: String?
    @State private var failed = false

    init(recovering: Bool, onDone: @escaping () -> Void) {
        self.recovering = recovering
        self.onDone = onDone
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ScreenTitle(text: recovering ? L10n.t("Вернуть аккаунт", "Restore account", "Ripristina account")
                                             : L10n.t("Восстановить из копии", "Restore from backup", "Ripristina da backup"),
                            subtitle: L10n.t("Выберите все файлы копии (полный и добавки) и введите ключ восстановления.",
                                             "Pick all backup files (full and incremental) and enter the recovery key.", "Seleziona tutti i file di backup (completo e incrementali) e inserisci la chiave di recupero."))
                OutlineButton(title: files.isEmpty ? L10n.t("Выбрать файлы", "Pick files", "Seleziona file")
                                                   : L10n.t("Файлов: \(files.count)", "Files: \(files.count)", "File: \(files.count)")) {
                    picking = true
                }
                SecureField(L10n.t("Ключ восстановления", "Recovery key", "Chiave di recupero"), text: $key)
                    .textInputAutocapitalization(.characters).autocorrectionDisabled()
                    .padding(12).background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgRaised))
                    .foregroundStyle(GasAppColor.textPrimary)
                if !key.isEmpty && !validateRecoveryKey(text: key) {
                    Text(L10n.t("В ключе опечатка", "The key has a typo", "La chiave contiene un errore")).font(.system(size: 13)).foregroundStyle(GasAppColor.error)
                }
                GoldButton(title: L10n.t("Восстановить", "Restore", "Ripristina"), isLoading: working,
                           isEnabled: !files.isEmpty && validateRecoveryKey(text: key)) { restore() }
                if let result {
                    Banner(title: failed ? L10n.t("Не получилось", "Failed", "Non riuscito") : L10n.t("Готово", "Done", "Fatto"),
                           message: result, tone: failed ? .error : .ok)
                    if !failed { GoldButton(title: L10n.t("Продолжить", "Continue", "Continua")) { onDone() } }
                }
            }
            .padding(20)
        }
        .gasScreen()
        .fileImporter(isPresented: $picking, allowedContentTypes: [.data], allowsMultipleSelection: true) { picked in
            if case let .success(urls) = picked {
                // Цепочка — по порядку создания: имя файла несёт дату и номер.
                files = urls.sorted { $0.lastPathComponent < $1.lastPathComponent }
            }
        }
    }

    private func restore() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let entered = key
        let chosen = files
        working = true
        result = nil
        Task {
            do {
                var links: [Data] = []
                for url in chosen {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    links.append(try Data(contentsOf: url))
                }
                let recover = recovering
                // Копия, а не var: замыкание уходит в другой поток.
                let blobs = links
                let restored = try await Background.run { () -> FfiRestore in
                    if recover {
                        let back = try messenger.recoverAccount(recoveryKey: entered, links: blobs,
                                                                nowMillis: CoreStore.nowMillis)
                        CoreStore.shared.rememberDevice(back.account.deviceId)
                        return back.restore
                    }
                    return try messenger.restoreBackup(recoveryKey: entered, links: blobs, nowMillis: CoreStore.nowMillis)
                }
                if recover { CoreStore.shared.maintainPrekeysNow() }
                failed = false
                // 🔐 Смена ключа безопасности — сказать прямо: собеседники
                // увидят её и должны сверить код заново.
                result = L10n.t("Восстановлено записей: \(restored.applied). Ключ безопасности сменился — попросите собеседников сверить код заново.",
                                "Restored \(restored.applied) records. Your safety number changed — ask contacts to verify again.", "Record ripristinati: \(restored.applied). Il tuo numero di sicurezza è cambiato: chiedi ai contatti di verificarlo di nuovo.")
            } catch {
                failed = true
                result = L10n.t("Ключ не тот, файлы не по порядку или цепочка неполная.",
                                "Wrong key, files out of order, or the chain is incomplete.", "Chiave errata, file in ordine sbagliato o catena incompleta.")
            }
            working = false
        }
    }
}
