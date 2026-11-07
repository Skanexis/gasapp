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
        .navigationTitle(L10n.t("Хранилище", "Vault"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if open {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { importing = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel(L10n.t("Добавить файл", "Add a file"))
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { seal() } label: { Image(systemName: "lock.fill") }
                        .accessibilityLabel(L10n.t("Закрыть хранилище", "Close the vault"))
                }
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            if case let .success(urls) = result, let url = urls.first { add(url) }
        }
        .quickLookPreview($preview)
        .confirmationDialog(L10n.t("Удалить файл?", "Delete the file?"), isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete"), role: .destructive) { if let deleting { delete(deleting) } }
        }
        .onChange(of: preview) { _, url in if url == nil { VaultFiles.clearOpened() } }
        .onChange(of: scenePhase) { _, phase in if phase != .active { leave() } }
        .onDisappear { leave() }
        .task { render() }
    }

    // MARK: - Закрытое

    private var sealedView: some View {
        ScrollView {
            VStack(spacing: 22) {
                Image(systemName: "lock.doc.fill")
                    .font(.system(size: 44, weight: .bold))
                    .foregroundStyle(GasAppColor.accent)
                    .padding(.top, 24)
                Text(count == 0 ? L10n.t("Хранилище пусто", "The vault is empty")
                                : L10n.t("Файлов в хранилище: \(count)", "Files in the vault: \(count)"))
                    .font(.system(size: 20, weight: .heavy, design: .rounded))
                    .foregroundStyle(GasAppColor.textPrimary)
                Text(L10n.t("Файлы открываются PIN ещё раз — даже в открытом приложении.",
                            "Files open with your PIN again — even when the app is unlocked."))
                    .font(.system(size: 15)).foregroundStyle(GasAppColor.textSecondary)
                    .multilineTextAlignment(.center)
                if let status {
                    Text(status).font(.system(size: 14)).foregroundStyle(GasAppColor.error)
                        .multilineTextAlignment(.center)
                }
                if working {
                    ProgressView().tint(GasAppColor.accent).frame(height: 40)
                }
                PinPad(digits: $digits, isEnabled: !working) { unlock() }
            }
            .padding(24)
        }
    }

    // MARK: - Открытое

    private var openView: some View {
        List {
            if let status {
                Text(status).font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary)
                    .listRowBackground(GasAppColor.bgBase)
            }
            if files.isEmpty {
                EmptyScene(icon: "lock.doc.fill",
                           title: L10n.t("Пока пусто", "Nothing here yet"),
                           text: L10n.t("Добавьте файл: он ляжет сюда зашифрованным.",
                                        "Add a file: it is stored here encrypted."),
                           action: L10n.t("Добавить файл", "Add a file")) { importing = true }
                    .listRowBackground(GasAppColor.bgBase).listRowSeparator(.hidden)
            }
            ForEach(files, id: \.fileId) { file in
                Button { openFile(file) } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "doc.fill").foregroundStyle(GasAppColor.accent)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(file.name).foregroundStyle(GasAppColor.textPrimary).lineLimit(2)
                            Text("\(ByteCountFormatter.string(fromByteCount: file.size, countStyle: .file)) · \(formatChatTime(file.createdAtMillis))")
                                .font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary)
                        }
                    }
                }
                .swipeActions {
                    Button(L10n.t("Удалить", "Delete"), role: .destructive) { deleting = file }
                }
                .listRowBackground(GasAppColor.bgCard)
            }
        }
        .scrollContentBackground(.hidden)
    }

    // MARK: - Ядро

    private func render() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        open = (try? messenger.isVaultOpen(nowMillis: CoreStore.nowMillis)) ?? false
        count = Int((try? messenger.vaultFileCount()) ?? 0)
        if open {
            files = (try? messenger.vaultFiles(limit: 1000, nowMillis: CoreStore.nowMillis)) ?? []
        } else {
            files = []
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
                                "Too many wrong PINs. Wait \(Int(wait.rounded(.up))) s.")
            }
            return
        }
        guard PinAttempts.beginAttempt() else {
            pin.wipe()
            status = L10n.t("Не удалось сохранить попытку. Попробуйте ещё раз.", "Could not save the attempt. Try again.")
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
                status = L10n.t("Хранилище не открылось этим PIN", "That PIN didn’t open the vault")
            case nil:
                PinAttempts.cancelAttempt()
                status = L10n.t("Не удалось открыть хранилище", "Could not open the vault")
            }
            render()
        }
    }

    private func seal() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        try? messenger.sealVault()
        VaultFiles.clearOpened()
        status = nil
        render()
    }

    /// Уход с экрана или в фон закрывает хранилище и стирает открытые файлы.
    private func leave() {
        if let messenger = try? CoreStore.shared.current() { try? messenger.onBackground() }
        preview = nil
        VaultFiles.clearOpened()
        render()
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
                    status = L10n.t("Файл больше 200 МБ — в хранилище не поместится", "The file is over 200 MB — it won’t fit in the vault")
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
                                "File added. The original is still where it was — delete it if you no longer need it.")
            } catch {
                status = L10n.t("Не удалось добавить файл", "Could not add the file")
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
                status = L10n.t("Не удалось открыть файл — откройте хранилище заново", "Could not open the file — open the vault again")
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
                status = L10n.t("Файл удалён", "File deleted")
            } catch {
                status = L10n.t("Не удалось удалить файл", "Could not delete the file")
            }
            render()
        }
    }
}
