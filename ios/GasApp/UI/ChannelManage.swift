// SPDX-License-Identifier: Apache-2.0

import PhotosUI
import SwiftUI
import UIKit

/// Управление своим каналом — то же, что у владельца на Android
/// (`ChannelActivity`, `ChannelForm`, `ChannelGate`): название и описание,
/// аватар, публичное имя, закрытый режим и заявки, приглашения,
/// администраторы, подписчики.
///
/// 🔐 Всё здесь — сетевые вызовы, которые сервер разрешает только
/// владельцу (иначе `PremiumRequired`); экран лишь не предлагает их
/// другим.
struct ChannelManageScreen: View {
    let channelId: String
    let onChanged: () -> Void

    @State private var channel: FfiChannel?
    @State private var title = ""
    @State private var about = ""
    @State private var handle = ""
    @State private var requests: [FfiChannelJoinRequest] = []
    @State private var invites: [String] = []
    @State private var admins: [FfiChannelAdmin] = []
    @State private var subscribers: [FfiChannelMember] = []
    @State private var banned: [FfiChannelMember] = []
    @State private var adminRequest = ""
    @State private var adminLabel = ""
    @State private var avatarItem: PhotosPickerItem?
    @State private var confirmPublic = false
    @State private var removing: FfiChannelMember?
    @State private var note: String?
    @State private var working = false

    init(channelId: String, onChanged: @escaping () -> Void) {
        self.channelId = channelId
        self.onChanged = onChanged
    }

    var body: some View {
        Form {
            Group {
                if let note {
                    Section { Text(note).font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary) }
                }

                Section(L10n.t("Канал", "Channel")) {
                    TextField(L10n.t("Название", "Title"), text: $title)
                    TextField(L10n.t("Описание", "Description"), text: $about, axis: .vertical).lineLimit(2...6)
                    Button(L10n.t("Сохранить", "Save")) { saveInfo() }
                        .disabled(working || title.trimmingCharacters(in: .whitespaces).isEmpty)
                }

                Section(L10n.t("Аватар", "Avatar")) {
                    if let data = channel?.avatar, let image = UIImage(data: data) {
                        Image(uiImage: image).resizable().scaledToFill()
                            .frame(width: 72, height: 72).clipShape(Circle())
                    }
                    PhotosPicker(selection: $avatarItem, matching: .images) {
                        Label(L10n.t("Выбрать фото", "Choose photo"), systemImage: "photo")
                    }
                    if channel?.avatar != nil {
                        Button(L10n.t("Убрать аватар", "Remove avatar"), role: .destructive) { setAvatar(nil) }
                    }
                }

                Section {
                    if let current = channel?.handle {
                        LabeledContent(L10n.t("Публичное имя", "Public name"), value: "@\(current)")
                        Button(L10n.t("Сделать непубличным", "Make it private")) { setHandle(nil) }
                    } else {
                        TextField(L10n.t("имя_канала", "channel_name"), text: $handle)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button(L10n.t("Сделать публичным", "Make it public")) { confirmPublic = true }
                            .disabled(handle.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } header: {
                    Text(L10n.t("Публичный канал", "Public channel"))
                } footer: {
                    Text(L10n.t("Публичный канал находят по @имени. Для этого сервер получает ссылку канала — и с ней ключ чтения: сервер сможет читать записи. Подделать ваши записи он не сможет.",
                                "A public channel can be found by its @name. For that the server receives the channel link — and with it the read key: the server will be able to read the posts. It still cannot forge your posts."))
                }

                Section {
                    Toggle(L10n.t("Вступление по заявке", "Join by request"), isOn: Binding(
                        get: { channel?.closed == true }, set: { setClosed($0) }
                    ))
                    ForEach(requests, id: \.accountId) { request in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("@\(request.username)").foregroundStyle(GasAppColor.textPrimary)
                                Text(requestHint(request)).font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary)
                            }
                            Spacer()
                            Button(L10n.t("Принять", "Approve")) { answer(request, approve: true) }
                                .buttonStyle(.borderless).foregroundStyle(GasAppColor.ok)
                            Button(L10n.t("Отклонить", "Decline")) { answer(request, approve: false) }
                                .buttonStyle(.borderless).foregroundStyle(GasAppColor.error)
                        }
                    }
                } header: {
                    Text(L10n.t("Закрытый канал", "Closed channel"))
                } footer: {
                    Text(L10n.t("По ссылке-приглашению человек присылает заявку, а вступает — когда вы её примете.",
                                "With an invite link a person sends a request and joins once you approve it."))
                }

                Section(L10n.t("Приглашения", "Invites")) {
                    ForEach(invites, id: \.self) { link in
                        HStack {
                            Text(link).font(.system(size: 13, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            ShareLink(item: link) { Image(systemName: "square.and.arrow.up") }.buttonStyle(.borderless)
                            Button { revoke(link) } label: { Image(systemName: "xmark.circle") }
                                .buttonStyle(.borderless).foregroundStyle(GasAppColor.error)
                        }
                    }
                    Button(L10n.t("Новое приглашение", "New invite")) { createInvite() }
                }

                Section {
                    ForEach(admins, id: \.verifyKey) { admin in
                        HStack {
                            Text(admin.label.isEmpty ? L10n.t("Администратор", "Admin") : admin.label)
                            if !admin.active {
                                Text(L10n.t("ждёт", "pending")).font(.system(size: 12)).foregroundStyle(GasAppColor.warn)
                            }
                            Spacer()
                            Button { removeAdmin(admin) } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless).foregroundStyle(GasAppColor.error)
                        }
                    }
                    TextField(L10n.t("Заявка администратора", "Admin request"), text: $adminRequest, axis: .vertical)
                        .font(.system(size: 13, design: .monospaced)).lineLimit(1...3)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField(L10n.t("Имя для вас", "Name for you"), text: $adminLabel)
                    Button(L10n.t("Назначить", "Appoint")) { addAdmin() }
                        .disabled(!isChannelAdminRequest(text: adminRequest))
                } header: {
                    Text(L10n.t("Администраторы", "Admins"))
                } footer: {
                    Text(L10n.t("Администратор публикует записи. Заявку он берёт в сведениях канала и присылает вам.",
                                "An admin can publish posts. They get the request in the channel info and send it to you."))
                }

                Section(L10n.t("Подписчики", "Subscribers")) {
                    if subscribers.isEmpty {
                        Text(L10n.t("Пока никого", "No one yet")).foregroundStyle(GasAppColor.textTertiary)
                    }
                    ForEach(subscribers, id: \.accountId) { member in
                        HStack {
                            Text("@\(member.username)")
                            Spacer()
                            Button(L10n.t("Удалить", "Remove"), role: .destructive) { removing = member }
                                .buttonStyle(.borderless)
                        }
                    }
                }

                if !banned.isEmpty {
                    Section(L10n.t("Удалённые", "Removed")) {
                        ForEach(banned, id: \.accountId) { member in
                            HStack {
                                Text("@\(member.username)")
                                Spacer()
                                Button(L10n.t("Разрешить заявку", "Allow requests")) { restore(member) }
                                    .buttonStyle(.borderless)
                            }
                        }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Управление", "Manage"))
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(L10n.t("Сделать канал публичным?", "Make the channel public?"),
                            isPresented: $confirmPublic, titleVisibility: .visible) {
            Button(L10n.t("Сделать публичным", "Make it public")) { setHandle(handle) }
        } message: {
            Text(L10n.t("Сервер получит ключ чтения и сможет читать этот канал, его записи и файлы. Вернуть канал в закрытые можно, но знание сервера назад не забрать.",
                        "The server receives the read key and will be able to read this channel, its posts and files. You can make it private again, but that knowledge cannot be taken back."))
        }
        .confirmationDialog(L10n.t("Удалить подписчика?", "Remove the subscriber?"), isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Remove"), role: .destructive) { if let removing { remove(removing) } }
        } message: {
            Text(L10n.t("Ключ канала сменится: новые записи удалённый не прочтёт. То, что вышло раньше, он уже читал.",
                        "The channel key changes: they will not read new posts. What was published before, they have already read."))
        }
        .onChange(of: avatarItem) { _, item in
            guard let item else { return }
            Task {
                if let raw = try? await item.loadTransferable(type: Data.self), let clean = ChatScreen.strippedJPEG(raw) {
                    setAvatar(clean)
                }
                avatarItem = nil
            }
        }
        .task { await load() }
    }

    private func requestHint(_ request: FfiChannelJoinRequest) -> String {
        if request.knownContact { return L10n.t("в ваших контактах", "in your contacts") }
        if request.inKeyLog { return L10n.t("ключ в журнале ключей", "key is in the key log") }
        return L10n.t("незнакомый аккаунт", "unknown account")
    }

    // MARK: - Ядро

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = channelId
        let now = CoreStore.nowMillis
        if let fresh = try? await Background.run({ try messenger.channel(channelId: id) }) {
            channel = fresh
            title = fresh.title
            about = fresh.description
        }
        invites = (try? await Background.run { try messenger.channelInvites(channelId: id) }) ?? []
        admins = (try? await Background.run { try messenger.channelAdmins(channelId: id) }) ?? []
        if channel?.closed == true {
            requests = (try? await Background.run { try messenger.channelJoinRequests(channelId: id, nowMillis: now) }) ?? []
        } else {
            requests = []
        }
        subscribers = (try? await Background.run { try messenger.channelSubscribers(channelId: id, after: nil, nowMillis: now) }) ?? []
        banned = (try? await Background.run { try messenger.channelBanned(channelId: id, nowMillis: now) }) ?? []
    }

    /// Общий путь: сетевой вызов, сообщение об итоге, перечитывание.
    private func run(_ done: String, _ action: @escaping @Sendable (Messenger) throws -> Void) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        working = true
        Task {
            do {
                try await Background.run { try action(messenger) }
                note = done
                onChanged()
            } catch let error as FfiError {
                note = Self.explain(error)
            } catch {
                note = L10n.t("Не получилось. Попробуйте ещё раз.", "That didn’t work. Try again.")
            }
            working = false
            await load()
        }
    }

    static func explain(_ error: FfiError) -> String {
        switch error {
        case .UsernameTaken:
            return L10n.t("Это имя уже занято.", "That name is taken.")
        case .InvalidArgument:
            return L10n.t("Проверьте введённое: так не получится.", "Check what you entered: that won’t work.")
        case .PremiumRequired:
            return L10n.t("Это может только владелец канала.", "Only the channel owner can do this.")
        default:
            return L10n.t("Нет связи с сервером. Попробуйте ещё раз.", "No connection to the server. Try again.")
        }
    }

    private func saveInfo() {
        let id = channelId
        let newTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        let newAbout = about.trimmingCharacters(in: .whitespacesAndNewlines)
        run(L10n.t("Сохранено", "Saved")) {
            _ = try $0.updateChannel(channelId: id, title: newTitle, description: newAbout, nowMillis: CoreStore.nowMillis)
        }
    }

    private func setAvatar(_ image: Data?) {
        let id = channelId
        run(image == nil ? L10n.t("Аватар убран", "Avatar removed") : L10n.t("Аватар обновлён", "Avatar updated")) {
            _ = try $0.setChannelAvatar(channelId: id, image: image, nowMillis: CoreStore.nowMillis)
        }
    }

    private func setHandle(_ value: String?) {
        let id = channelId
        let name = value?.trimmingCharacters(in: .whitespaces).lowercased()
        run(name == nil ? L10n.t("Канал больше не публичный", "The channel is no longer public")
                        : L10n.t("Канал публичный", "The channel is public")) {
            _ = try $0.setChannelHandle(channelId: id, handle: name, nowMillis: CoreStore.nowMillis)
        }
        handle = ""
    }

    private func setClosed(_ closed: Bool) {
        let id = channelId
        run(closed ? L10n.t("Вступление — по заявке", "Joining is by request")
                   : L10n.t("Вступление — по ссылке", "Joining is by link")) {
            _ = try $0.setChannelClosed(channelId: id, closed: closed, nowMillis: CoreStore.nowMillis)
        }
    }

    private func answer(_ request: FfiChannelJoinRequest, approve: Bool) {
        let id = channelId
        let account = request.accountId
        run(approve ? L10n.t("Заявка принята", "Request approved") : L10n.t("Заявка отклонена", "Request declined")) {
            try $0.answerChannelJoin(channelId: id, accountId: account, approve: approve, nowMillis: CoreStore.nowMillis)
        }
    }

    private func createInvite() {
        let id = channelId
        run(L10n.t("Приглашение создано", "Invite created")) {
            _ = try $0.createChannelInvite(channelId: id, nowMillis: CoreStore.nowMillis)
        }
    }

    private func revoke(_ link: String) {
        let id = channelId
        run(L10n.t("Приглашение отозвано", "Invite revoked")) {
            try $0.revokeChannelInvite(channelId: id, link: link, nowMillis: CoreStore.nowMillis)
        }
    }

    private func addAdmin() {
        let id = channelId
        let request = adminRequest.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = adminLabel.trimmingCharacters(in: .whitespaces)
        run(L10n.t("Администратор назначен", "Admin appointed")) {
            _ = try $0.addChannelAdmin(channelId: id, request: request, label: label, nowMillis: CoreStore.nowMillis)
        }
        adminRequest = ""
        adminLabel = ""
    }

    private func removeAdmin(_ admin: FfiChannelAdmin) {
        let id = channelId
        let key = admin.verifyKey
        run(L10n.t("Администратор снят", "Admin removed")) {
            _ = try $0.removeChannelAdmin(channelId: id, verifyKey: key, nowMillis: CoreStore.nowMillis)
        }
    }

    private func remove(_ member: FfiChannelMember) {
        let id = channelId
        let account = member.accountId
        removing = nil
        run(L10n.t("Подписчик удалён, ключ канала сменится", "Subscriber removed; the channel key will change")) {
            try $0.removeChannelSubscriber(channelId: id, accountId: account, restore: false, nowMillis: CoreStore.nowMillis)
        }
    }

    private func restore(_ member: FfiChannelMember) {
        let id = channelId
        let account = member.accountId
        run(L10n.t("Заявка снова разрешена", "Requests allowed again")) {
            try $0.removeChannelSubscriber(channelId: id, accountId: account, restore: true, nowMillis: CoreStore.nowMillis)
        }
    }
}

/// Заявка на администрирование для читателя: QR и строка, которые он
/// показывает владельцу (`channelAdminRequest`). Без сети.
struct AdminRequestSheet: View {
    let channelId: String
    @State private var request: String?
    @State private var qr: FfiQrMatrix?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Text(L10n.t("Покажите этот код владельцу канала или отправьте ему строку. Секретов в ней нет, но она называет владельцу ваше устройство.",
                            "Show this code to the channel owner or send them the text. It has no secrets, but it names your device to the owner."))
                    .font(.system(size: 15)).foregroundStyle(GasAppColor.textSecondary).multilineTextAlignment(.center)
                if let qr { QRView(matrix: qr).frame(maxWidth: 260) }
                if let request {
                    Text(request).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        .foregroundStyle(GasAppColor.textPrimary).padding(12)
                        .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                    ShareLink(item: request) { Label(L10n.t("Отправить", "Send"), systemImage: "square.and.arrow.up") }
                }
            }
            .padding(24)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Стать администратором", "Become an admin"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done")) { dismiss() } } }
        .task {
            guard let messenger = try? CoreStore.shared.current() else { return }
            let id = channelId
            request = try? await Background.run { try messenger.channelAdminRequest(channelId: id) }
            if let request {
                qr = try? channelAdminRequestQr(request: request)
            }
        }
    }
}
