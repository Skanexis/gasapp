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
    @State private var confirmClose = false
    @State private var link: String?
    /// Ошибка действия — всплывающим окном: строка вверху формы была
    /// за пределами экрана, и казалось, что кнопка не работает.
    @State private var failure: String?
    @State private var removing: FfiChannelMember?
    @State private var note: String?
    @State private var working = false

    init(channelId: String, onChanged: @escaping () -> Void) {
        self.channelId = channelId
        self.onChanged = onChanged
    }

    var body: some View {
        Form {
            // Шапка: как канал видят читатели, и главное о нём одной строкой.
            Section {
                VStack(spacing: 10) {
                    PhotosPicker(selection: $avatarItem, matching: .images) {
                        ZStack(alignment: .bottomTrailing) {
                            Avatar(name: channel?.title ?? title, size: 84,
                                   image: channel?.avatar.flatMap { UIImage(data: $0) })
                            Image(systemName: "camera.fill")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundStyle(GasAppColor.accentOn)
                                .frame(width: 28, height: 28)
                                .background(Circle().fill(GasAppColor.accent))
                                .overlay(Circle().stroke(GasAppColor.bgCard, lineWidth: 2))
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(L10n.t("Выбрать фото", "Choose photo", "Scegli foto"))
                    Text(channel?.title ?? title)
                        .font(GasFont.display(22)).foregroundStyle(GasAppColor.textPrimary)
                        .multilineTextAlignment(.center)
                    HStack(spacing: 8) {
                        modePill
                        Text(subscribersLabel).font(GasFont.text(13)).foregroundStyle(GasAppColor.textTertiary)
                    }
                    if channel?.avatar != nil {
                        Button(L10n.t("Убрать аватар", "Remove avatar", "Rimuovi avatar"), role: .destructive) { setAvatar(nil) }
                            .font(GasFont.text(14)).buttonStyle(.borderless)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
            }
            .listRowBackground(GasAppColor.bgCard)

            Group {
                // Сначала — то, что ждёт решения владельца.
                if channel?.closed == true, !requests.isEmpty {
                    Section {
                        ForEach(requests, id: \.accountId) { request in
                            HStack(spacing: 12) {
                                Avatar(name: request.username, size: 40)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("@\(request.username)").font(GasFont.text(16, .semibold)).foregroundStyle(GasAppColor.textPrimary)
                                    Text(requestHint(request)).font(GasFont.text(12))
                                        .foregroundStyle(request.knownContact ? GasAppColor.ok : GasAppColor.textTertiary)
                                }
                                Spacer()
                                Button { answer(request, approve: false) } label: {
                                    Image(systemName: "xmark").font(.system(size: 14, weight: .bold))
                                        .foregroundStyle(GasAppColor.error)
                                        .frame(width: 36, height: 36)
                                        .background(Circle().fill(GasAppColor.error.opacity(0.14)))
                                }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.t("Отклонить", "Decline", "Rifiuta"))
                                Button { answer(request, approve: true) } label: {
                                    Image(systemName: "checkmark").font(.system(size: 14, weight: .bold))
                                        .foregroundStyle(GasAppColor.accentOn)
                                        .frame(width: 36, height: 36)
                                        .background(Circle().fill(GasAppColor.ok))
                                }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.t("Принять", "Approve", "Approva"))
                            }
                        }
                    } header: {
                        Text(L10n.t("Заявки ждут: \(requests.count)", "Requests waiting: \(requests.count)", "Richieste in attesa: \(requests.count)"))
                    } footer: {
                        Text(L10n.t("Принятый получает ключ чтения канала — забрать его обратно нельзя.",
                                    "Whoever you approve gets the channel read key — it cannot be taken back.",
                                    "Chi approvi riceve la chiave di lettura del canale e non si può revocare."))
                    }
                }

                Section {
                    TextField(L10n.t("Название", "Title", "Titolo"), text: $title)
                        .font(GasFont.text(17, .semibold))
                    TextField(L10n.t("Описание", "Description", "Descrizione"), text: $about, axis: .vertical)
                        .lineLimit(2...6)
                    if infoChanged {
                        Button {
                            saveInfo()
                        } label: {
                            Label(L10n.t("Сохранить", "Save", "Salva"), systemImage: "checkmark")
                                .font(GasFont.text(16, .semibold))
                        }
                        .disabled(working || title.trimmingCharacters(in: .whitespaces).isEmpty)
                        .transition(.opacity)
                    }
                } header: {
                    Text(L10n.t("Канал", "Channel", "Canale"))
                }

                // Доступ: текущее состояние — и только подходящие к нему действия.
                Section {
                    if let current = channel?.handle {
                        LabeledContent(L10n.t("Публичное имя", "Public name", "Nome pubblico"), value: "@\(current)")
                        Button(L10n.t("Убрать публичное имя", "Remove the public name", "Rimuovi il nome pubblico")) { setHandle(nil) }
                    } else if channel?.closed == true {
                        Label(L10n.t("Вступление — по заявке", "Joining is by request", "Si entra su richiesta"), systemImage: "lock.fill")
                            .foregroundStyle(GasAppColor.ok)
                    } else {
                        if let link {
                            HStack {
                                Label(L10n.t("Ссылка канала", "Channel link", "Link del canale"), systemImage: "link")
                                Spacer()
                                ShareLink(item: link) { Image(systemName: "square.and.arrow.up") }.buttonStyle(.borderless)
                            }
                        }
                        HStack(spacing: 4) {
                            Text("@").foregroundStyle(GasAppColor.textTertiary)
                            TextField(L10n.t("имя_канала", "channel_name", "nome_canale"), text: $handle)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                            if !handle.isEmpty {
                                Button(L10n.t("Сделать публичным", "Make it public", "Rendilo pubblico")) { confirmPublic = true }
                                    .font(GasFont.text(14, .semibold))
                                    .buttonStyle(.borderless)
                                    .disabled(canonicalChannelHandle(text: handle) == nil)
                            }
                        }
                        Button {
                            confirmClose = true
                        } label: {
                            Label(L10n.t("Сделать вступление по заявке", "Make joining by request", "Rendi l’ingresso su richiesta"),
                                  systemImage: "lock")
                        }
                        .disabled(working || channel == nil)
                    }
                } header: {
                    Text(L10n.t("Доступ", "Access", "Accesso"))
                } footer: {
                    Text(accessFooter)
                }

                if channel?.closed == true {
                    Section {
                        ForEach(invites, id: \.self) { link in
                            HStack {
                                Text(link).font(.system(size: 13, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                ShareLink(item: link) { Image(systemName: "square.and.arrow.up") }.buttonStyle(.borderless)
                            }
                            .swipeActions(edge: .trailing) {
                                Button(L10n.t("Отозвать", "Revoke", "Revoca"), role: .destructive) { revoke(link) }
                            }
                        }
                        Button { createInvite() } label: {
                            Label(L10n.t("Новое приглашение", "New invite", "Nuovo invito"), systemImage: "plus")
                        }
                    } header: {
                        Text(L10n.t("Приглашения", "Invites", "Inviti"))
                    } footer: {
                        Text(L10n.t("По ссылке-приглашению человек присылает заявку, а вступает — когда вы её примете. Свайп влево — отозвать.",
                                    "With an invite link a person sends a request and joins once you approve it. Swipe left to revoke.",
                                    "Con un link di invito una persona invia una richiesta ed entra quando la approvi. Scorri a sinistra per revocare."))
                    }
                }

                Section {
                    ForEach(admins, id: \.verifyKey) { admin in
                        HStack(spacing: 12) {
                            Avatar(name: admin.label.isEmpty ? "A" : admin.label, size: 36)
                            Text(admin.label.isEmpty ? L10n.t("Администратор", "Admin", "Admin") : admin.label)
                            if !admin.active {
                                Text(L10n.t("ждёт", "pending", "in attesa")).font(GasFont.text(12)).foregroundStyle(GasAppColor.warn)
                            }
                            Spacer()
                        }
                        .swipeActions(edge: .trailing) {
                            Button(L10n.t("Снять", "Remove", "Rimuovi"), role: .destructive) { removeAdmin(admin) }
                        }
                    }
                    HStack {
                        TextField(L10n.t("Заявка администратора", "Admin request", "Richiesta di admin"), text: $adminRequest, axis: .vertical)
                            .font(.system(size: 13, design: .monospaced)).lineLimit(1...3)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button {
                            if let text = UIPasteboard.general.string { adminRequest = text }
                        } label: { Image(systemName: "doc.on.clipboard") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.t("Вставить", "Paste", "Incolla"))
                    }
                    if isChannelAdminRequest(text: adminRequest) {
                        TextField(L10n.t("Имя для вас", "Name for you", "Nome per te"), text: $adminLabel)
                        Button { addAdmin() } label: {
                            Label(L10n.t("Назначить", "Appoint", "Nomina"), systemImage: "person.badge.plus")
                                .font(GasFont.text(16, .semibold))
                        }
                    }
                } header: {
                    Text(L10n.t("Администраторы", "Admins", "Admin"))
                } footer: {
                    Text(L10n.t("Администратор публикует записи. Заявку он берёт в сведениях канала и присылает вам. Свайп влево — снять.",
                                "An admin can publish posts. They get the request in the channel info and send it to you. Swipe left to remove.",
                                "Un admin può pubblicare post. Trova la richiesta nelle informazioni del canale e te la invia. Scorri a sinistra per rimuoverlo."))
                }

                Section {
                    if subscribers.isEmpty {
                        Text(L10n.t("Пока никого", "No one yet", "Ancora nessuno")).foregroundStyle(GasAppColor.textTertiary)
                    }
                    ForEach(subscribers, id: \.accountId) { member in
                        HStack(spacing: 12) {
                            Avatar(name: member.username, size: 36)
                            Text("@\(member.username)")
                            Spacer()
                        }
                        .swipeActions(edge: .trailing) {
                            Button(L10n.t("Удалить", "Remove", "Rimuovi"), role: .destructive) { removing = member }
                        }
                    }
                } header: {
                    Text(L10n.t("Подписчики", "Subscribers", "Iscritti") + (subscribers.isEmpty ? "" : " · \(subscribers.count)"))
                } footer: {
                    if !subscribers.isEmpty {
                        Text(L10n.t("Свайп влево — удалить подписчика.", "Swipe left to remove a subscriber.", "Scorri a sinistra per rimuovere un iscritto."))
                    }
                }

                if !banned.isEmpty {
                    Section(L10n.t("Удалённые", "Removed", "Rimosso")) {
                        ForEach(banned, id: \.accountId) { member in
                            HStack {
                                Text("@\(member.username)")
                                Spacer()
                                Button(L10n.t("Разрешить заявку", "Allow requests", "Consenti richieste")) { restore(member) }
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
        // Итог действия — плашкой снизу, сама исчезает: видна, где бы ни
        // была прокрутка.
        .overlay(alignment: .bottom) {
            if let note {
                Label(note, systemImage: "checkmark.circle.fill")
                    .font(GasFont.text(15, .semibold))
                    .foregroundStyle(GasAppColor.textPrimary)
                    .padding(.horizontal, 18).padding(.vertical, 12)
                    .background(Capsule().fill(GasAppColor.bgRaised))
                    .overlay(Capsule().stroke(GasAppColor.ok.opacity(0.6), lineWidth: 1))
                    .padding(.bottom, 20)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .overlay {
            if working {
                ProgressView().tint(GasAppColor.accent)
                    .padding(18)
                    .background(RoundedRectangle(cornerRadius: 16).fill(GasAppColor.bgRaised.opacity(0.95)))
            }
        }
        .animation(.easeInOut(duration: 0.25), value: note)
        .animation(.easeInOut(duration: 0.2), value: infoChanged)
        .animation(.easeInOut(duration: 0.2), value: requests.count)
        .animation(.easeInOut(duration: 0.2), value: working)
        .navigationTitle(L10n.t("Управление", "Manage", "Gestisci"))
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(L10n.t("Сделать канал публичным?", "Make the channel public?", "Rendere pubblico il canale?"),
                            isPresented: $confirmPublic, titleVisibility: .visible) {
            Button(L10n.t("Сделать публичным", "Make it public", "Rendilo pubblico")) { setHandle(handle) }
        } message: {
            Text(L10n.t("Сервер получит ключ чтения и сможет читать этот канал, его записи и файлы. Вернуть канал в закрытые можно, но знание сервера назад не забрать.",
                        "The server receives the read key and will be able to read this channel, its posts and files. You can make it private again, but that knowledge cannot be taken back.", "Il server riceve la chiave di lettura e potrà leggere questo canale, i suoi post e i file. Puoi renderlo di nuovo privato, ma ciò che il server ha visto non si può cancellare."))
        }
        .confirmationDialog(L10n.t("Закрыть канал?", "Close the channel?", "Chiudere il canale?"),
                            isPresented: $confirmClose, titleVisibility: .visible) {
            Button(L10n.t("Закрыть", "Close", "Chiudi"), role: .destructive) { setClosed(true) }
        } message: {
            Text(L10n.t("В закрытый канал вступают по заявке: вы одобряете каждого. Ключ канала сразу сменится — по старой ссылке новые записи не откроются; нынешние подписчики остаются. Сделать канал снова открытым нельзя.",
                        "A closed channel is joined by request: you approve each person. The channel key changes at once, so the old link no longer opens new posts; current subscribers stay. A closed channel cannot be made open again.",
                        "In un canale chiuso si entra su richiesta: approvi ogni persona. La chiave del canale cambia subito, quindi il vecchio link non apre più i nuovi post; gli iscritti attuali restano. Un canale chiuso non può tornare aperto."))
        }
        .alert(L10n.t("Не получилось", "Didn’t work", "Non ha funzionato"),
               isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("OK", role: .cancel) { failure = nil }
        } message: {
            Text(failure ?? "")
        }
        .confirmationDialog(L10n.t("Удалить подписчика?", "Remove the subscriber?", "Rimuovere l’iscritto?"), isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Remove", "Rimuovi"), role: .destructive) { if let removing { remove(removing) } }
        } message: {
            Text(L10n.t("Ключ канала сменится: новые записи удалённый не прочтёт. То, что вышло раньше, он уже читал.",
                        "The channel key changes: they will not read new posts. What was published before, they have already read.", "La chiave del canale cambia: non leggerà i nuovi post. Ciò che è stato pubblicato prima l’ha già letto."))
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

    private var infoChanged: Bool {
        guard let channel else { return false }
        return title.trimmingCharacters(in: .whitespacesAndNewlines) != channel.title
            || about.trimmingCharacters(in: .whitespacesAndNewlines) != channel.description
    }

    private var subscribersLabel: String {
        let count = channel?.subscribers ?? UInt64(subscribers.count)
        return L10n.t("подписчиков: \(count)", "subscribers: \(count)", "iscritti: \(count)")
    }

    @ViewBuilder
    private var modePill: some View {
        let (text, icon, color): (String, String, Color) = {
            if channel?.handle != nil { return (L10n.t("Публичный", "Public", "Pubblico"), "at", GasAppColor.info) }
            if channel?.closed == true { return (L10n.t("По заявке", "By request", "Su richiesta"), "lock.fill", GasAppColor.ok) }
            return (L10n.t("По ссылке", "By link", "Tramite link"), "link", GasAppColor.accent)
        }()
        Label(text, systemImage: icon)
            .font(GasFont.text(12, .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 10).padding(.vertical, 4)
            .background(Capsule().fill(color.opacity(0.14)))
    }

    private var accessFooter: String {
        if channel?.handle != nil {
            return L10n.t("Публичный канал находят по @имени. Сервер получил ключ чтения и может читать записи — но не подделать их. Закрыть такой канал можно, только убрав имя.",
                          "A public channel is found by its @name. The server has the read key and can read posts — but not forge them. To close it, remove the name first.",
                          "Un canale pubblico si trova tramite il suo @nome. Il server ha la chiave di lettura e può leggere i post, ma non falsificarli. Per chiuderlo, rimuovi prima il nome.")
        }
        if channel?.closed == true {
            return L10n.t("Закрытый канал: вступают по заявке, сервер отдаёт записи только участникам. Открытым его уже не сделать.",
                          "Closed channel: people join by request, and the server gives posts only to members. It can’t be made open again.",
                          "Canale chiuso: si entra su richiesta e il server fornisce i post solo ai membri. Non può tornare aperto.")
        }
        return L10n.t("Сейчас канал читает любой, у кого есть ссылка. Можно дать ему @имя для поиска или сделать вступление по заявке — но не то и другое сразу.",
                      "Right now anyone with the link can read the channel. You can give it an @name for search or make joining by request — but not both.",
                      "Ora chiunque abbia il link può leggere il canale. Puoi dargli un @nome per la ricerca o rendere l’ingresso su richiesta, ma non entrambe le cose.")
    }

    private func requestHint(_ request: FfiChannelJoinRequest) -> String {
        if request.knownContact { return L10n.t("в ваших контактах", "in your contacts", "nei tuoi contatti") }
        if request.inKeyLog { return L10n.t("ключ в журнале ключей", "key is in the key log", "la chiave è nel registro delle chiavi") }
        return L10n.t("незнакомый аккаунт", "unknown account", "account sconosciuto")
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
        link = try? await Background.run { try messenger.channelLink(channelId: id) }
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
                Task {
                    try? await Task.sleep(nanoseconds: 2_500_000_000)
                    if note == done { note = nil }
                }
            } catch let error as FfiError {
                failure = Self.explain(error)
            } catch {
                failure = L10n.t("Не получилось. Попробуйте ещё раз.", "That didn’t work. Try again.", "Non ha funzionato. Riprova.")
            }
            working = false
            await load()
        }
    }

    static func explain(_ error: FfiError) -> String {
        switch error {
        case .UsernameTaken:
            return L10n.t("Это имя уже занято.", "That name is taken.", "Questo nome è già in uso.")
        case .InvalidArgument:
            return L10n.t("Проверьте введённое: так не получится.", "Check what you entered: that won’t work.", "Controlla cosa hai inserito: così non funziona.")
        case .PremiumRequired:
            return L10n.t("Это может только владелец канала.", "Only the channel owner can do this.", "Solo il proprietario del canale può farlo.")
        default:
            return L10n.t("Нет связи с сервером. Попробуйте ещё раз.", "No connection to the server. Try again.", "Nessuna connessione al server. Riprova.")
        }
    }

    private func saveInfo() {
        let id = channelId
        let newTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        let newAbout = about.trimmingCharacters(in: .whitespacesAndNewlines)
        run(L10n.t("Сохранено", "Saved", "Salvato")) {
            _ = try $0.updateChannel(channelId: id, title: newTitle, description: newAbout, nowMillis: CoreStore.nowMillis)
        }
    }

    private func setAvatar(_ image: Data?) {
        let id = channelId
        run(image == nil ? L10n.t("Аватар убран", "Avatar removed", "Avatar rimosso") : L10n.t("Аватар обновлён", "Avatar updated", "Avatar aggiornato")) {
            _ = try $0.setChannelAvatar(channelId: id, image: image, nowMillis: CoreStore.nowMillis)
        }
    }

    private func setHandle(_ value: String?) {
        let id = channelId
        let name = value?.trimmingCharacters(in: .whitespaces).lowercased()
        run(name == nil ? L10n.t("Канал больше не публичный", "The channel is no longer public", "Il canale non è più pubblico")
                        : L10n.t("Канал публичный", "The channel is public", "Il canale è pubblico")) {
            _ = try $0.setChannelHandle(channelId: id, handle: name, nowMillis: CoreStore.nowMillis)
        }
        handle = ""
    }

    private func setClosed(_ closed: Bool) {
        let id = channelId
        run(closed ? L10n.t("Вступление — по заявке", "Joining is by request", "Si entra su richiesta")
                   : L10n.t("Вступление — по ссылке", "Joining is by link", "Si entra tramite link")) {
            _ = try $0.setChannelClosed(channelId: id, closed: closed, nowMillis: CoreStore.nowMillis)
        }
    }

    private func answer(_ request: FfiChannelJoinRequest, approve: Bool) {
        let id = channelId
        let account = request.accountId
        run(approve ? L10n.t("Заявка принята", "Request approved", "Richiesta approvata") : L10n.t("Заявка отклонена", "Request declined", "Richiesta rifiutata")) {
            try $0.answerChannelJoin(channelId: id, accountId: account, approve: approve, nowMillis: CoreStore.nowMillis)
        }
    }

    private func createInvite() {
        let id = channelId
        run(L10n.t("Приглашение создано", "Invite created", "Invito creato")) {
            _ = try $0.createChannelInvite(channelId: id, nowMillis: CoreStore.nowMillis)
        }
    }

    private func revoke(_ link: String) {
        let id = channelId
        run(L10n.t("Приглашение отозвано", "Invite revoked", "Invito revocato")) {
            try $0.revokeChannelInvite(channelId: id, link: link, nowMillis: CoreStore.nowMillis)
        }
    }

    private func addAdmin() {
        let id = channelId
        let request = adminRequest.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = adminLabel.trimmingCharacters(in: .whitespaces)
        run(L10n.t("Администратор назначен", "Admin appointed", "Admin nominato")) {
            _ = try $0.addChannelAdmin(channelId: id, request: request, label: label, nowMillis: CoreStore.nowMillis)
        }
        adminRequest = ""
        adminLabel = ""
    }

    private func removeAdmin(_ admin: FfiChannelAdmin) {
        let id = channelId
        let key = admin.verifyKey
        run(L10n.t("Администратор снят", "Admin removed", "Admin rimosso")) {
            _ = try $0.removeChannelAdmin(channelId: id, verifyKey: key, nowMillis: CoreStore.nowMillis)
        }
    }

    private func remove(_ member: FfiChannelMember) {
        let id = channelId
        let account = member.accountId
        removing = nil
        run(L10n.t("Подписчик удалён, ключ канала сменится", "Subscriber removed; the channel key will change", "Iscritto rimosso; la chiave del canale cambierà")) {
            try $0.removeChannelSubscriber(channelId: id, accountId: account, restore: false, nowMillis: CoreStore.nowMillis)
        }
    }

    private func restore(_ member: FfiChannelMember) {
        let id = channelId
        let account = member.accountId
        run(L10n.t("Заявка снова разрешена", "Requests allowed again", "Richieste di nuovo consentite")) {
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
                            "Show this code to the channel owner or send them the text. It has no secrets, but it names your device to the owner.", "Mostra questo codice al proprietario del canale o inviagli il testo. Non contiene segreti, ma indica al proprietario il tuo dispositivo."))
                    .font(GasFont.text(15)).foregroundStyle(GasAppColor.textSecondary).multilineTextAlignment(.center)
                if let qr { QRView(matrix: qr).frame(maxWidth: 260) }
                if let request {
                    Text(request).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        .foregroundStyle(GasAppColor.textPrimary).padding(12)
                        .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                    ShareLink(item: request) { Label(L10n.t("Отправить", "Send", "Invia"), systemImage: "square.and.arrow.up") }
                }
            }
            .padding(24)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Стать администратором", "Become an admin", "Diventa admin"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) { dismiss() } } }
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
