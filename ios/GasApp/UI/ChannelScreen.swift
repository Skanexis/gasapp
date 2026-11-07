// SPDX-License-Identifier: Apache-2.0

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
    @State private var message: String?
    @Environment(\.dismiss) private var dismiss

    init(channelId: String, title: String) {
        self.channelId = channelId
        self.title = title
    }

    private var canPost: Bool { channel?.role == .owner || channel?.role == .admin }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 10) {
                    if posts.isEmpty {
                        Text(L10n.t("Записей пока нет", "No posts yet"))
                            .foregroundStyle(GasAppColor.textTertiary).padding(.top, 40)
                    }
                    ForEach(posts, id: \.seq) { post in
                        ChannelPostView(channelId: channelId, post: post, pinned: channel?.pinnedSeq == post.seq) { emoji in
                            react(post, emoji)
                        }
                    }
                }
                .padding(12)
            }
            .refreshable { await sync() }

            if let message {
                Text(message).font(.system(size: 13)).foregroundStyle(GasAppColor.warn).padding(6)
            }
            if channel?.keyMissing == true {
                Banner(title: L10n.t("Нет ключа канала", "Channel key missing"),
                       message: L10n.t("Новые записи не прочитать: попросите у владельца новую ссылку.",
                                       "New posts can’t be read: ask the owner for a new link."), tone: .warn)
                    .padding(12)
            }
            if canPost { composer }
        }
        .gasScreen()
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showInfo = true } label: { Image(systemName: "info.circle") }
            }
        }
        .sheet(isPresented: $showInfo) {
            NavigationStack {
                ChannelInfoSheet(channelId: channelId) { left in
                    if left { dismiss() } else { Task { await reload() } }
                }
            }
        }
        .task { await sync() }
    }

    private var composer: some View {
        HStack(spacing: 10) {
            TextField(L10n.t("Новая запись", "New post"), text: $draft, axis: .vertical)
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
            .disabled(sending || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(10)
        .background(GasAppColor.bgRaised)
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
        sending = true
        Task {
            do {
                _ = try await Background.run {
                    try messenger.publishChannelPost(channelId: id, text: text, files: [], nowMillis: CoreStore.nowMillis)
                }
                draft = ""
                message = nil
                await reload()
            } catch {
                message = L10n.t("Не опубликовано", "Not published")
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
                Label(L10n.t("Закреплено", "Pinned"), systemImage: "pin.fill")
                    .font(.system(size: 12, weight: .semibold)).foregroundStyle(GasAppColor.accent)
            }
            ForEach(Array(post.attachments.enumerated()), id: \.offset) { _, attachment in
                ChannelMediaView(channelId: channelId, attachment: attachment)
            }
            if !post.text.isEmpty {
                Text(post.text).font(.system(size: 16)).foregroundStyle(GasAppColor.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 6) {
                ForEach(post.reactions, id: \.emoji) { reaction in
                    Button { onReact(reaction.emoji) } label: {
                        Text("\(reaction.emoji) \(reaction.count)").font(.system(size: 13))
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
                Label("\(post.views)", systemImage: "eye").font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary)
                Text(formatChatTime(post.createdAtMillis)).font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary)
                if post.editedAtMillis != nil {
                    Text(L10n.t("изм.", "edited")).font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary)
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
                Label(attachment.name ?? L10n.t("Вложение", "Attachment"), systemImage: "doc.fill")
                    .foregroundStyle(GasAppColor.textSecondary)
            } else {
                ProgressView().tint(GasAppColor.accent).frame(height: 120)
            }
        }
        .task {
            guard attachment.kind == .image else { return }
            if let cached = AttachmentCache.shared.get(attachment.descriptor) {
                image = UIImage(data: cached)
                return
            }
            guard let messenger = try? CoreStore.shared.current() else { failed = true; return }
            let id = channelId
            let descriptor = attachment.descriptor
            if let bytes = try? await Background.run({
                try messenger.fetchChannelMedia(channelId: id, descriptor: descriptor, nowMillis: CoreStore.nowMillis)
            }) {
                AttachmentCache.shared.put(descriptor, bytes)
                image = UIImage(data: bytes)
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
                        Text(channel.title).font(.system(size: 20, weight: .bold))
                        if !channel.description.isEmpty { Text(channel.description).foregroundStyle(GasAppColor.textSecondary) }
                        LabeledContent(L10n.t("Подписчиков", "Subscribers"), value: "\(channel.subscribers)")
                        if let handle = channel.handle { LabeledContent(L10n.t("Имя", "Handle"), value: "@\(handle)") }
                    }
                    Section(L10n.t("Пригласить", "Invite")) {
                        if let qr { QRView(matrix: qr).frame(maxWidth: 220).frame(maxWidth: .infinity) }
                        if let link {
                            ShareLink(item: link) { Label(L10n.t("Поделиться ссылкой", "Share link"), systemImage: "square.and.arrow.up") }
                        }
                    }
                    Section {
                        Toggle(L10n.t("Без уведомлений", "Muted"), isOn: Binding(
                            get: { channel.muted }, set: { mute($0) }
                        ))
                        if channel.role != .owner {
                            // Причины — те же номера, что знает сервер (как на Android).
                            Menu {
                                ForEach(ChannelReport.reasons, id: \.0) { reason in
                                    Button(reason.1) { reportReason = reason.0 }
                                }
                            } label: {
                                Label(L10n.t("Пожаловаться на канал", "Report channel"), systemImage: "exclamationmark.bubble")
                            }
                            .foregroundStyle(GasAppColor.error)
                            Button(L10n.t("Покинуть канал", "Leave channel"), role: .destructive) { confirmLeave = true }
                        }
                        if let reportNote {
                            Text(reportNote).font(.system(size: 13)).foregroundStyle(GasAppColor.textSecondary)
                        }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .navigationTitle(L10n.t("Канал", "Channel"))
        .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done")) { onDone(false); dismiss() } } }
        .confirmationDialog(L10n.t("Покинуть канал?", "Leave the channel?"), isPresented: $confirmLeave, titleVisibility: .visible) {
            Button(L10n.t("Покинуть", "Leave"), role: .destructive) { leave() }
        }
        // 🔐 Записи канала без публичного имени оператор прочитать не может:
        // дать ли ему ключ чтения, решает человек, и что получит оператор,
        // сказано до кнопок (ChannelActivity.confirmReport на Android).
        .confirmationDialog(L10n.t("Пожаловаться на канал", "Report channel"), isPresented: Binding(
            get: { reportReason != nil }, set: { if !$0 { reportReason = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Отправить с доступом", "Send with access")) { sendReport(shareKey: true) }
            Button(L10n.t("Только жалоба", "Report only")) { sendReport(shareKey: false) }
            Button(L10n.t("Отмена", "Cancel"), role: .cancel) { reportReason = nil }
        } message: {
            Text(L10n.t("Жалоба уйдёт оператору сервера вместе с именем вашего аккаунта. Записи этого канала оператор прочитать не может — если не дать ему доступ. «Отправить с доступом» приложит к жалобе ссылку канала: оператор сможет открыть его и увидеть, на что вы жалуетесь.",
                        "The report goes to the server operator together with your account name. The operator cannot read this channel's posts unless you give access. “Send with access” attaches the channel link to the report, so the operator can open the channel and see what you are reporting."))
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
                ? L10n.t("Жалоба отправлена", "Report sent")
                : L10n.t("Нет связи с сервером. Попробуйте ещё раз.", "No connection to the server. Try again.")
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
        (1, L10n.t("Спам или обман", "Spam or scam")),
        (2, L10n.t("Незаконное содержимое", "Illegal content")),
        (3, L10n.t("Угроза безопасности детей", "Child safety concern")),
        (4, L10n.t("Насилие или ненависть", "Violence or hate")),
        (5, L10n.t("Другое", "Something else")),
    ]
}
