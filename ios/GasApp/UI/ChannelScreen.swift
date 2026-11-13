// SPDX-License-Identifier: Apache-2.0

import PhotosUI
import SwiftUI

/// Канал — аналог `ChannelActivity`: лента записей, реакции, медиа;
/// владелец и админы публикуют.
struct ChannelScreen: View {
    let channelId: String
    let title: String

    @State private var channel: FfiChannel?
    @State private var posts: [FfiChannelPost] = []
    @State private var draft = ""
    @State private var sending = false
    @State private var showInfo = false
    @State private var showManage = false
    @State private var message: String?
    /// Поиск по сохранённым записям — без сети (`searchChannelPosts`).
    @State private var query = ""
    @State private var found: [FfiChannelPost]?
    @State private var loadingOlder = false
    @State private var historyEnded = false
    @State private var editing: FfiChannelPost?
    @State private var editText = ""
    @State private var deleting: FfiChannelPost?
    @State private var photos: [PhotosPickerItem] = []
    @State private var attached: [Data] = []
    @Environment(\.dismiss) private var dismiss

    init(channelId: String, title: String) {
        self.channelId = channelId
        self.title = title
    }

    private var canPost: Bool { channel?.role == .owner || channel?.role == .admin }
    /// Править, закреплять и удалять записи сервер разрешает только владельцу.
    private var isOwner: Bool { channel?.role == .owner }
    private var shown: [FfiChannelPost] { found ?? posts }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 10) {
                    if shown.isEmpty {
                        Text(found == nil ? L10n.t("Записей пока нет", "No posts yet", "Ancora nessun post") : L10n.t("Ничего не нашлось", "Nothing found", "Nessun risultato"))
                            .foregroundStyle(GasAppColor.textTertiary).padding(.top, 40)
                    }
                    ForEach(shown, id: \.seq) { post in
                        ChannelPostView(channelId: channelId, post: post, pinned: channel?.pinnedSeq == post.seq) { emoji in
                            react(post, emoji)
                        }
                        .contextMenu { if isOwner { postMenu(post) } }
                    }
                    if found == nil && !posts.isEmpty && !historyEnded {
                        Button {
                            loadOlder()
                        } label: {
                            if loadingOlder {
                                ProgressView().tint(GasAppColor.accent)
                            } else {
                                Text(L10n.t("Показать раньше", "Show earlier", "Mostra precedenti")).foregroundStyle(GasAppColor.accent)
                            }
                        }
                        .padding(.vertical, 12)
                    }
                }
                .padding(12)
            }
            .refreshable { await sync() }

            if let message {
                Text(message).font(GasFont.text(13)).foregroundStyle(GasAppColor.warn).padding(6)
            }
            if channel?.keyMissing == true {
                Banner(title: L10n.t("Нет ключа канала", "Channel key missing", "Manca la chiave del canale"),
                       message: L10n.t("Новые записи не прочитать: попросите у владельца новую ссылку.",
                                       "New posts can’t be read: ask the owner for a new link.", "I nuovi post non si possono leggere: chiedi un nuovo link al proprietario."), tone: .warn)
                    .padding(12)
            }
            if canPost { composer }
        }
        .gasScreen()
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $query, prompt: L10n.t("Поиск по каналу", "Search the channel", "Cerca nel canale"))
        .onChange(of: query) { _, text in search(text) }
        .toolbar {
            if isOwner {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showManage = true } label: { Image(systemName: "slider.horizontal.3") }
                        .accessibilityLabel(L10n.t("Управление каналом", "Manage the channel", "Gestisci il canale"))
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button { showInfo = true } label: { Image(systemName: "info.circle") }
            }
        }
        .sheet(isPresented: $showManage, onDismiss: { Task { await reload() } }) {
            NavigationStack {
                ChannelManageScreen(channelId: channelId) { Task { await reload() } }
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) { showManage = false } } }
            }
        }
        .alert(L10n.t("Править запись", "Edit post", "Modifica post"), isPresented: Binding(
            get: { editing != nil }, set: { if !$0 { editing = nil } }
        )) {
            TextField(L10n.t("Текст", "Text", "Testo"), text: $editText, axis: .vertical)
            Button(L10n.t("Сохранить", "Save", "Salva")) { saveEdit() }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) { editing = nil }
        }
        .confirmationDialog(L10n.t("Удалить запись?", "Delete the post?", "Eliminare il post?"), isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить у всех", "Delete for everyone", "Elimina per tutti"), role: .destructive) { deletePost() }
        } message: {
            Text(L10n.t("Запись и её файлы удалятся с сервера. У тех, кто уже открыл канал, копия может остаться.",
                        "The post and its files are deleted from the server. People who already opened the channel may still have a copy.", "Il post e i suoi file vengono eliminati dal server. Chi ha già aperto il canale potrebbe averne ancora una copia."))
        }
        .onChange(of: photos) { _, items in attach(items) }
        .sheet(isPresented: $showInfo) {
            NavigationStack {
                ChannelInfoSheet(channelId: channelId) { left in
                    if left { dismiss() } else { Task { await reload() } }
                }
            }
        }
        .task { await sync() }
    }

    @ViewBuilder
    private func postMenu(_ post: FfiChannelPost) -> some View {
        Button { editText = post.text; editing = post } label: { Label(L10n.t("Править", "Edit", "Modifica"), systemImage: "pencil") }
        if channel?.pinnedSeq == post.seq {
            Button { pin(0) } label: { Label(L10n.t("Открепить", "Unpin", "Sblocca"), systemImage: "pin.slash") }
        } else {
            Button { pin(post.seq) } label: { Label(L10n.t("Закрепить", "Pin", "Fissa"), systemImage: "pin") }
        }
        Button(role: .destructive) { deleting = post } label: { Label(L10n.t("Удалить", "Delete", "Elimina"), systemImage: "trash") }
    }

    private var composer: some View {
        VStack(spacing: 6) {
            if !attached.isEmpty {
                HStack {
                    Label(L10n.t("Фото: \(attached.count)", "Photos: \(attached.count)", "Foto: \(attached.count)"), systemImage: "photo.on.rectangle")
                        .font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary)
                    Spacer()
                    Button(L10n.t("Убрать", "Remove", "Rimuovi")) { attached = []; photos = [] }
                        .font(GasFont.text(13)).foregroundStyle(GasAppColor.accent)
                }
                .padding(.horizontal, 12)
            }
            HStack(spacing: 10) {
            PhotosPicker(selection: $photos, maxSelectionCount: Int(channelPostAttachmentLimit()), matching: .images) {
                Image(systemName: "photo").font(.system(size: 22)).foregroundStyle(GasAppColor.textSecondary)
            }
            .accessibilityLabel(L10n.t("Фото в запись", "Add photos", "Aggiungi foto"))
            TextField(L10n.t("Новая запись", "New post", "Nuovo post"), text: $draft, axis: .vertical)
                .lineLimit(1...6)
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 18).fill(GasAppColor.bgCard))
                .foregroundStyle(GasAppColor.textPrimary)
            Button(action: publish) {
                if sending {
                    ProgressView().tint(GasAppColor.accent)
                } else {
                    Image(systemName: "paperplane.circle.fill").font(.system(size: 34)).foregroundStyle(GasAppColor.accent)
                }
            }
            .disabled(sending || (draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && attached.isEmpty))
            }
        }
        .padding(10)
        .background(GasAppColor.bgRaised)
    }

    /// Фото — без метаданных (тот же пересжатый JPEG, что в чате) и не
    /// больше предела записи (`channelMediaLimit`).
    private func attach(_ items: [PhotosPickerItem]) {
        guard !items.isEmpty else { return }
        let limit = Int(channelMediaLimit())
        Task {
            var ready: [Data] = []
            for item in items {
                if let raw = try? await item.loadTransferable(type: Data.self), let clean = ChatScreen.strippedJPEG(raw) {
                    if clean.count <= limit {
                        ready.append(clean)
                    } else {
                        message = L10n.t("Фото больше предела записи — пропущено", "A photo is over the post limit — skipped", "Una foto supera il limite del post: saltata")
                    }
                }
            }
            attached = ready
        }
    }

    private func search(_ text: String) {
        let query = text.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty, let messenger = try? CoreStore.shared.current() else { found = nil; return }
        let id = channelId
        Task {
            found = (try? await Background.run { try messenger.searchChannelPosts(channelId: id, query: query, limit: 100) }) ?? []
        }
    }

    private func loadOlder() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        loadingOlder = true
        Task {
            let added = (try? await Background.run { try messenger.loadOlderChannelPosts(channelId: id, nowMillis: CoreStore.nowMillis) }) ?? 0
            historyEnded = added == 0
            loadingOlder = false
            await reload()
        }
    }

    private func pin(_ seq: UInt64) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        Task {
            do {
                channel = try await Background.run { try messenger.pinChannelPost(channelId: id, seq: seq, nowMillis: CoreStore.nowMillis) }
            } catch {
                message = L10n.t("Не удалось. Проверьте связь.", "That didn't work. Check the connection.", "Non ha funzionato. Controlla la connessione.")
            }
        }
    }

    private func saveEdit() {
        guard let post = editing, let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        let seq = post.seq
        let text = editText.trimmingCharacters(in: .whitespacesAndNewlines)
        editing = nil
        Task {
            do {
                _ = try await Background.run { try messenger.editChannelPost(channelId: id, seq: seq, text: text, nowMillis: CoreStore.nowMillis) }
                await reload()
            } catch let error as FfiError {
                message = ChannelManageScreen.explain(error)
            } catch {
                message = L10n.t("Не удалось. Проверьте связь.", "That didn't work. Check the connection.", "Non ha funzionato. Controlla la connessione.")
            }
        }
    }

    private func deletePost() {
        guard let post = deleting, let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        let seq = post.seq
        deleting = nil
        Task {
            do {
                try await Background.run { try messenger.deleteChannelPost(channelId: id, seq: seq, nowMillis: CoreStore.nowMillis) }
                await reload()
            } catch {
                message = L10n.t("Не удалось удалить. Проверьте связь.", "Couldn't delete. Check the connection.", "Impossibile eliminare. Controlla la connessione.")
            }
        }
    }

    private func reload() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        let state = try? await Background.run { () -> (FfiChannel, [FfiChannelPost]) in
            (try messenger.channel(channelId: id), try messenger.channelPosts(channelId: id, limit: 200))
        }
        if let state {
            channel = state.0
            posts = state.1.sorted { $0.seq > $1.seq }
        }
    }

    private func sync() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        await reload()
        _ = try? await Background.run { try messenger.syncChannel(channelId: id, nowMillis: CoreStore.nowMillis) }
        _ = try? await Background.run { try messenger.markChannelRead(channelId: id) }
        // Просмотры — общим числом, без того, кто смотрел.
        _ = try? await Background.run { try messenger.reportChannelSeen(channelId: id, nowMillis: CoreStore.nowMillis) }
        await reload()
    }

    private func publish() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        let id = channelId
        let files = attached.map {
            FfiAttachmentFile(kind: .image, bytes: $0, name: "photo.jpg", description: nil, durationMillis: nil, waveform: nil)
        }
        sending = true
        Task {
            do {
                _ = try await Background.run {
                    try messenger.publishChannelPost(channelId: id, text: text, files: files, nowMillis: CoreStore.nowMillis)
                }
                draft = ""
                attached = []
                photos = []
                message = nil
                await reload()
            } catch {
                message = L10n.t("Не опубликовано", "Not published", "Non pubblicato")
            }
            sending = false
        }
    }

    private func react(_ post: FfiChannelPost, _ emoji: String?) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        let seq = post.seq
        // Та же реакция ещё раз — снять.
        let choice = post.myReaction == emoji ? nil : emoji
        Task {
            _ = try? await Background.run {
                try messenger.reactToChannelPost(channelId: id, seq: seq, emoji: choice, nowMillis: CoreStore.nowMillis)
            }
            await reload()
        }
    }
}

struct ChannelPostView: View {
    let channelId: String
    let post: FfiChannelPost
    let pinned: Bool
    let onReact: (String?) -> Void

    init(channelId: String, post: FfiChannelPost, pinned: Bool, onReact: @escaping (String?) -> Void) {
        self.channelId = channelId
        self.post = post
        self.pinned = pinned
        self.onReact = onReact
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if pinned {
                Label(L10n.t("Закреплено", "Pinned", "Fissato"), systemImage: "pin.fill")
                    .font(GasFont.text(12, .semibold)).foregroundStyle(GasAppColor.accent)
            }
            ForEach(Array(post.attachments.enumerated()), id: \.offset) { _, attachment in
                ChannelMediaView(channelId: channelId, attachment: attachment)
            }
            if !post.text.isEmpty {
                Text(post.text).font(GasFont.text(16)).foregroundStyle(GasAppColor.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 6) {
                ForEach(post.reactions, id: \.emoji) { reaction in
                    Button { onReact(reaction.emoji) } label: {
                        Text("\(reaction.emoji) \(reaction.count)").font(GasFont.text(13))
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Capsule().fill(post.myReaction == reaction.emoji ? GasAppColor.accentDim : GasAppColor.bgHover))
                    }
                }
                Menu {
                    ForEach(channelReactions(), id: \.self) { emoji in
                        Button(emoji) { onReact(emoji) }
                    }
                } label: {
                    Image(systemName: "face.smiling").foregroundStyle(GasAppColor.textTertiary)
                }
                Spacer()
                Label("\(post.views)", systemImage: "eye").font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                Text(formatChatTime(post.createdAtMillis)).font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                if post.editedAtMillis != nil {
                    Text(L10n.t("изм.", "edited", "modificato")).font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(GasAppColor.bgCard))
    }
}

/// Медиа записи канала: качается и расшифровывается при показе, в памяти.
struct ChannelMediaView: View {
    let channelId: String
    let attachment: FfiChannelAttachment
    @State private var image: UIImage?
    @State private var failed = false

    init(channelId: String, attachment: FfiChannelAttachment) {
        self.channelId = channelId
        self.attachment = attachment
    }

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().scaledToFit().clipShape(RoundedRectangle(cornerRadius: 12))
            } else if failed || attachment.kind != .image {
                Label(attachment.name ?? L10n.t("Вложение", "Attachment", "Allegato"), systemImage: "doc.fill")
                    .foregroundStyle(GasAppColor.textSecondary)
            } else {
                ProgressView().tint(GasAppColor.accent).frame(height: 120)
            }
        }
        .task {
            guard attachment.kind == .image else { return }
            // Декодирование — в фоне и один раз: лента не дёргается на
            // картинках (см. AttachmentCache.prepared).
            if let ready = AttachmentCache.shared.image(attachment.descriptor) {
                image = ready
                return
            }
            if let cached = AttachmentCache.shared.get(attachment.descriptor) {
                image = await AttachmentCache.shared.prepared(attachment.descriptor, from: cached)
                failed = image == nil
                return
            }
            guard let messenger = try? CoreStore.shared.current() else { failed = true; return }
            let id = channelId
            let descriptor = attachment.descriptor
            if let bytes = try? await Background.run({
                try messenger.fetchChannelMedia(channelId: id, descriptor: descriptor, nowMillis: CoreStore.nowMillis)
            }) {
                AttachmentCache.shared.put(descriptor, bytes)
                image = await AttachmentCache.shared.prepared(descriptor, from: bytes)
                failed = image == nil
            } else {
                failed = true
            }
        }
    }
}

/// Сведения о канале: ссылка и QR, отключение уведомлений, выход.
struct ChannelInfoSheet: View {
    let channelId: String
    let onDone: (Bool) -> Void
    @State private var channel: FfiChannel?
    @State private var link: String?
    @State private var qr: FfiQrMatrix?
    @State private var confirmLeave = false
    @State private var showAdminRequest = false
    @State private var reportReason: UInt8?
    @State private var reportNote: String?
    @Environment(\.dismiss) private var dismiss

    init(channelId: String, onDone: @escaping (Bool) -> Void) {
        self.channelId = channelId
        self.onDone = onDone
    }

    var body: some View {
        Form {
            // Строки — цветом карточек GasApp, а не системным серым.
            Group {
                if let channel {
                    Section {
                        Text(channel.title).font(GasFont.text(20, .bold))
                        if !channel.description.isEmpty { Text(channel.description).foregroundStyle(GasAppColor.textSecondary) }
                        LabeledContent(L10n.t("Подписчиков", "Subscribers", "Iscritti"), value: "\(channel.subscribers)")
                        if let handle = channel.handle { LabeledContent(L10n.t("Имя", "Handle", "Nome"), value: "@\(handle)") }
                    }
                    Section(L10n.t("Пригласить", "Invite", "Invita")) {
                        if let qr { QRView(matrix: qr).frame(maxWidth: 220).frame(maxWidth: .infinity) }
                        if let link {
                            ShareLink(item: link) { Label(L10n.t("Поделиться ссылкой", "Share link", "Condividi link"), systemImage: "square.and.arrow.up") }
                        }
                    }
                    Section {
                        Toggle(L10n.t("Без уведомлений", "Muted", "Silenziato"), isOn: Binding(
                            get: { channel.muted }, set: { mute($0) }
                        ))
                        if channel.role == .reader {
                            Button(L10n.t("Стать администратором", "Become an admin", "Diventa admin")) { showAdminRequest = true }
                        } else if channel.role == .adminPending {
                            Text(L10n.t("Заявка у владельца: ждём, когда он назначит вас администратором.",
                                        "Request is with the owner: waiting for them to appoint you.", "La richiesta è presso il proprietario: in attesa che ti nomini."))
                                .font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary)
                        }
                        if channel.role != .owner {
                            // Причины — те же номера, что знает сервер (как на Android).
                            Menu {
                                ForEach(ChannelReport.reasons, id: \.0) { reason in
                                    Button(reason.1) { reportReason = reason.0 }
                                }
                            } label: {
                                Label(L10n.t("Пожаловаться на канал", "Report channel", "Segnala canale"), systemImage: "exclamationmark.bubble")
                            }
                            .foregroundStyle(GasAppColor.error)
                            Button(L10n.t("Покинуть канал", "Leave channel", "Lascia il canale"), role: .destructive) { confirmLeave = true }
                        }
                        if let reportNote {
                            Text(reportNote).font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary)
                        }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .navigationTitle(L10n.t("Канал", "Channel", "Canale"))
        .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) { onDone(false); dismiss() } } }
        .confirmationDialog(L10n.t("Покинуть канал?", "Leave the channel?", "Lasciare il canale?"), isPresented: $confirmLeave, titleVisibility: .visible) {
            Button(L10n.t("Покинуть", "Leave", "Lascia"), role: .destructive) { leave() }
        }
        // 🔐 Записи канала без публичного имени оператор прочитать не может:
        // дать ли ему ключ чтения, решает человек, и что получит оператор,
        // сказано до кнопок (ChannelActivity.confirmReport на Android).
        .confirmationDialog(L10n.t("Пожаловаться на канал", "Report channel", "Segnala canale"), isPresented: Binding(
            get: { reportReason != nil }, set: { if !$0 { reportReason = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Отправить с доступом", "Send with access", "Invia con accesso")) { sendReport(shareKey: true) }
            Button(L10n.t("Только жалоба", "Report only", "Solo segnalazione")) { sendReport(shareKey: false) }
            Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) { reportReason = nil }
        } message: {
            Text(L10n.t("Жалоба уйдёт оператору сервера вместе с именем вашего аккаунта. Записи этого канала оператор прочитать не может — если не дать ему доступ. «Отправить с доступом» приложит к жалобе ссылку канала: оператор сможет открыть его и увидеть, на что вы жалуетесь.",
                        "The report goes to the server operator together with your account name. The operator cannot read this channel's posts unless you give access. “Send with access” attaches the channel link to the report, so the operator can open the channel and see what you are reporting.", "La segnalazione arriva all’operatore del server insieme al nome del tuo account. L’operatore non può leggere i post di questo canale se non gli dai accesso. «Invia con accesso» allega il link del canale alla segnalazione, così l’operatore può aprire il canale e vedere cosa segnali."))
        }
        .sheet(isPresented: $showAdminRequest) {
            NavigationStack { AdminRequestSheet(channelId: channelId) }
        }
        .task { await load() }
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        channel = try? await Background.run { try messenger.channel(channelId: id) }
        if let uri = try? await Background.run({ try messenger.channelLink(channelId: id) }) {
            link = uri
            qr = try? channelLinkQr(uri: uri)
        }
    }

    private func mute(_ value: Bool) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        Task {
            channel = (try? await Background.run { try messenger.setChannelMuted(channelId: id, muted: value) }) ?? channel
        }
    }

    private func sendReport(shareKey: Bool) {
        guard let reason = reportReason, let messenger = try? CoreStore.shared.current() else { return }
        reportReason = nil
        let id = channelId
        Task {
            let sent = (try? await Background.run {
                try messenger.reportChannel(channelId: id, reason: reason, shareKey: shareKey, nowMillis: CoreStore.nowMillis)
            }) != nil
            reportNote = sent
                ? L10n.t("Жалоба отправлена", "Report sent", "Segnalazione inviata")
                : L10n.t("Нет связи с сервером. Попробуйте ещё раз.", "No connection to the server. Try again.", "Nessuna connessione al server. Riprova.")
        }
    }

    private func leave() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        Task {
            _ = try? await Background.run { try messenger.leaveChannel(channelId: id, nowMillis: CoreStore.nowMillis) }
            onDone(true)
            dismiss()
        }
    }
}

/// Причины жалобы на канал: номер, как его знает сервер, и подпись.
enum ChannelReport {
    static let reasons: [(UInt8, String)] = [
        (1, L10n.t("Спам или обман", "Spam or scam", "Spam o truffa")),
        (2, L10n.t("Незаконное содержимое", "Illegal content", "Contenuti illegali")),
        (3, L10n.t("Угроза безопасности детей", "Child safety concern", "Sicurezza dei minori")),
        (4, L10n.t("Насилие или ненависть", "Violence or hate", "Violenza o odio")),
        (5, L10n.t("Другое", "Something else", "Altro")),
    ]
}
