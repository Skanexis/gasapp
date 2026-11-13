// SPDX-License-Identifier: Apache-2.0

import QuickLook
import SwiftUI
import UniformTypeIdentifiers

/// Хранилище файлов — то же, что `VaultActivity` на Android: файлы под
/// вторым фактором (раздел 11.4 плана).
///
/// # 🔐 Почему PIN спрашивается заново
///
/// Разблокированного приложения недостаточно: сценарий хранилища —
/// «телефон открыт и отдан в чужие руки». Переписку показать не жалко,
/// паспорт — жалко. Ключ хранилища выводит ядро из PIN и держит, пока
/// хранилище открыто: таймаут бездействия или уход в фон его обнуляют
/// (`onBackground`).
///
/// Закрытое хранилище показывает только число файлов: имена уже
/// говорят достаточно («паспорт.pdf»).
///
/// # 🔐 Расшифрованные файлы
///
/// Открытый файл пишется во временный каталог и показывается встроенным
/// просмотром (QuickLook) внутри приложения — чужим приложениям он не
/// отдаётся. Каталог стирается при уходе с экрана.
struct VaultScreen: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    @State private var open = false
    @State private var count = 0
    @State private var files: [FfiVaultFile] = []
    @State private var digits: [UInt8] = []
    @State private var working = false
    @State private var status: String?
    @State private var importing = false
    @State private var preview: URL?
    @State private var deleting: FfiVaultFile?

    var body: some View {
        Group {
            if open { openView } else { sealedView }
        }
        .gasScreen()
        .navigationTitle(L10n.t("Хранилище", "Vault", "Cassaforte"))
        // Заголовок — в строке навигации, а не огромным над экраном:
        // клавиатура PIN помещается целиком, без прокрутки.
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if open {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { importing = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel(L10n.t("Добавить файл", "Add a file", "Aggiungi un file"))
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { seal() } label: { Image(systemName: "lock.fill") }
                        .accessibilityLabel(L10n.t("Закрыть хранилище", "Close the vault", "Chiudi la cassaforte"))
                }
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            if case let .success(urls) = result, let url = urls.first { add(url) }
        }
        .quickLookPreview($preview)
        .confirmationDialog(L10n.t("Удалить файл?", "Delete the file?", "Eliminare il file?"), isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete", "Elimina"), role: .destructive) { if let deleting { delete(deleting) } }
        }
        .onChange(of: preview) { _, url in if url == nil { VaultFiles.clearOpened() } }
        .onChange(of: scenePhase) { _, phase in if phase != .active { leave() } }
        .onDisappear { leave() }
        .task { render() }
    }

    // MARK: - Закрытое

    private var sealedView: some View {
        ScrollView {
            VStack(spacing: 14) {
                Image(systemName: "lock.doc.fill")
                    .font(.system(size: 34, weight: .bold))
                    .foregroundStyle(GasAppColor.accent)
                    .padding(.top, 4)
                Text(count == 0 ? L10n.t("Хранилище пусто", "The vault is empty", "La cassaforte è vuota")
                                : L10n.t("Файлов в хранилище: \(count)", "Files in the vault: \(count)", "File nella cassaforte: \(count)"))
                    .font(GasFont.display(20))
                    .foregroundStyle(GasAppColor.textPrimary)
                Text(L10n.t("Файлы открываются PIN ещё раз — даже в открытом приложении.",
                            "Files open with your PIN again — even when the app is unlocked.", "I file si aprono di nuovo con il PIN, anche quando l’app è sbloccata."))
                    .font(GasFont.text(15)).foregroundStyle(GasAppColor.textSecondary)
                    .multilineTextAlignment(.center)
                if let status {
                    Text(status).font(GasFont.text(14)).foregroundStyle(GasAppColor.error)
                        .multilineTextAlignment(.center)
                }
                if working {
                    ProgressView().tint(GasAppColor.accent).frame(height: 40)
                }
                PinPad(digits: $digits, isEnabled: !working) { unlock() }
                    .padding(.top, 8)
            }
            .padding(.horizontal, 24).padding(.vertical, 12)
        }
    }

    // MARK: - Открытое

    private var openView: some View {
        List {
            if let status {
                Text(status).font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
                    .listRowBackground(GasAppColor.bgBase)
            }
            if files.isEmpty {
                EmptyScene(icon: "lock.doc.fill",
                           title: L10n.t("Пока пусто", "Nothing here yet", "Ancora niente qui"),
                           text: L10n.t("Добавьте файл: он ляжет сюда зашифрованным.",
                                        "Add a file: it is stored here encrypted.", "Aggiungi un file: qui viene conservato cifrato."),
                           action: L10n.t("Добавить файл", "Add a file", "Aggiungi un file")) { importing = true }
                    .listRowBackground(GasAppColor.bgBase).listRowSeparator(.hidden)
            }
            ForEach(files, id: \.fileId) { file in
                Button { openFile(file) } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "doc.fill").foregroundStyle(GasAppColor.accent)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(file.name).foregroundStyle(GasAppColor.textPrimary).lineLimit(2)
                            Text("\(formatBytes(file.size)) · \(formatChatTime(file.createdAtMillis))")
                                .font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                        }
                    }
                }
                .swipeActions {
                    Button(L10n.t("Удалить", "Delete", "Elimina"), role: .destructive) { deleting = file }
                }
                .listRowBackground(GasAppColor.bgCard)
            }
        }
        .scrollContentBackground(.hidden)
    }

    // MARK: - Ядро

    /// Перечитывает состояние хранилища — в фоне. Эти вызовы ждут замок
    /// ядра, который на время сетевого запроса занят: из главного потока
    /// экран замирал, пока запрос не закончится.
    private func render() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            let state = try? await Background.run { () -> (Bool, Int, [FfiVaultFile]) in
                let isOpen = (try? messenger.isVaultOpen(nowMillis: CoreStore.nowMillis)) ?? false
                let total = Int((try? messenger.vaultFileCount()) ?? 0)
                let list: [FfiVaultFile] = isOpen
                    ? ((try? messenger.vaultFiles(limit: 1000, nowMillis: CoreStore.nowMillis)) ?? [])
                    : []
                return (isOpen, total, list)
            }
            guard let state else { return }
            open = state.0
            count = state.1
            files = state.2
        }
    }

    /// 🔐 Тот же PIN и тот же счётчик, что у экрана входа (A-4 на Android):
    /// попытка записывается до проверки, задержки и стирание — общие.
    private func unlock() {
        var pin = digits
        digits.wipe()
        digits = []
        let wait = PinAttempts.waitRemaining()
        guard PinPolicy.isAcceptable(pin), wait <= 0 else {
            pin.wipe()
            if wait > 0 {
                status = L10n.t("Слишком много неверных PIN. Подождите \(Int(wait.rounded(.up))) с.",
                                "Too many wrong PINs. Wait \(Int(wait.rounded(.up))) s.", "Troppi PIN errati. Attendi \(Int(wait.rounded(.up))) s.")
            }
            return
        }
        guard PinAttempts.beginAttempt() else {
            pin.wipe()
            status = L10n.t("Не удалось сохранить попытку. Попробуйте ещё раз.", "Could not save the attempt. Try again.", "Impossibile salvare il tentativo. Riprova.")
            return
        }
        guard let messenger = try? CoreStore.shared.current(),
              let salt = try? CoreStore.shared.salt(create: false) else {
            pin.wipe()
            PinAttempts.cancelAttempt()
            return
        }
        working = true
        status = nil
        let copy = pin
        pin.wipe()
        Task {
            // Argon2id — около секунды: это норма. nil — PIN не сверялся.
            var outcome: Bool?
            do {
                try await Background.run { try messenger.unlockVault(pin: Data(copy), salt: salt, nowMillis: CoreStore.nowMillis) }
                outcome = true
            } catch is FfiError {
                outcome = false
            } catch {
                outcome = nil
            }
            working = false
            switch outcome {
            case true?:
                PinAttempts.reset()
            case false?:
                if PinAttempts.shouldWipe {
                    model.didWipe()
                    return
                }
                status = L10n.t("Хранилище не открылось этим PIN", "That PIN didn’t open the vault", "Questo PIN non ha aperto la cassaforte")
            case nil:
                PinAttempts.cancelAttempt()
                status = L10n.t("Не удалось открыть хранилище", "Could not open the vault", "Impossibile aprire la cassaforte")
            }
            render()
        }
    }

    private func seal() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        // Экран закрывается сразу; само закрытие в ядре — следом, в фоне.
        open = false
        files = []
        VaultFiles.clearOpened()
        status = nil
        Task {
            _ = try? await Background.run { try messenger.sealVault() }
            render()
        }
    }

    /// Уход с экрана или в фон закрывает хранилище и стирает открытые файлы.
    private func leave() {
        preview = nil
        VaultFiles.clearOpened()
        // 🔐 С экрана содержимое уходит сразу, ядро закрывает хранилище
        // следом — не из главного потока (см. `render`).
        open = false
        files = []
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            _ = try? await Background.run { try messenger.onBackground() }
            render()
        }
    }

    /// Шифрует ядро, на диск пишет приложение — как со вложениями.
    private func add(_ url: URL) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        working = true
        Task {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                guard size <= VaultFiles.maxBytes else {
                    status = L10n.t("Файл больше 200 МБ — в хранилище не поместится", "The file is over 200 MB — it won’t fit in the vault", "Il file supera i 200 MB: non entra nella cassaforte")
                    working = false
                    return
                }
                let contents = try Data(contentsOf: url)
                let name = VaultFiles.safeName(url.lastPathComponent)
                let blob = VaultFiles.newBlobName()
                let sealed = try await Background.run {
                    try messenger.addVaultFile(name: name, contents: contents, location: blob, nowMillis: CoreStore.nowMillis)
                }
                try VaultFiles.write(sealed.ciphertext, to: blob)
                status = L10n.t("Файл добавлен. Оригинал остался на месте — удалите его, если он больше не нужен.",
                                "File added. The original is still where it was — delete it if you no longer need it.", "File aggiunto. L’originale è ancora dov’era: eliminalo se non ti serve più.")
            } catch {
                status = L10n.t("Не удалось добавить файл", "Could not add the file", "Impossibile aggiungere il file")
            }
            working = false
            render()
        }
    }

    private func openFile(_ file: FfiVaultFile) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            do {
                let blob = try VaultFiles.read(file.location)
                let id = file.fileId
                let plain = try await Background.run {
                    try messenger.openVaultFile(fileId: id, ciphertext: blob, nowMillis: CoreStore.nowMillis)
                }
                preview = try VaultFiles.writeOpened(plain, name: file.name)
            } catch {
                // Хранилище закрылось по таймауту либо блоб подменён.
                status = L10n.t("Не удалось открыть файл — откройте хранилище заново", "Could not open the file — open the vault again", "Impossibile aprire il file: apri di nuovo la cassaforte")
                render()
            }
        }
    }

    /// Сначала запись в базе (ядро), потом блоб на диске: обратный порядок
    /// при сбое оставил бы запись без файла (как на Android).
    private func delete(_ file: FfiVaultFile) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        deleting = nil
        let id = file.fileId
        Task {
            do {
                let location = try await Background.run { try messenger.deleteVaultFile(fileId: id, nowMillis: CoreStore.nowMillis) }
                if let location { VaultFiles.remove(location) }
                status = L10n.t("Файл удалён", "File deleted", "File eliminato")
            } catch {
                status = L10n.t("Не удалось удалить файл", "Could not delete the file", "Impossibile eliminare il file")
            }
            render()
        }
    }
}
