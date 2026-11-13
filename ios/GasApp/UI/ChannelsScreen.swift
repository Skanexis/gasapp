// SPDX-License-Identifier: Apache-2.0

import PhotosUI
import SwiftUI
import UIKit

/// Каналы — аналог `ChannelsActivity`: свои и подписки, вступление по
/// ссылке, поиск открытых, создание (право на создание — премиум,
/// выдаётся оператором вручную).
///
/// 🔐 Записи каналов — шифротекст: ключ чтения приходит в ссылке и на
/// сервер не попадает.
struct ChannelsScreen: View {
    @State private var channels: [FfiChannel] = []
    @State private var loaded = false
    @State private var joinLink = ""
    @State private var showJoin = false
    @State private var showCreate = false
    @State private var showBots = false
    @State private var showPublic = false
    /// Премиум — по сохранённому ответу сервера: без него ботов не показываем.
    @State private var premium = false
    @State private var opened: OpenedChannel?

    struct OpenedChannel: Hashable { let id: String; let title: String }
    /// Объяснение «нужен премиум» — вместо формы, которую всё равно не
    /// отправить (сервер отвечает 403 без премиума).
    @State private var premiumNote: String?
    @State private var message: String?
    /// Заявки в закрытые каналы, которые ещё ждут ответа владельца.
    @State private var pending: [FfiPendingChannelJoin] = []

    var body: some View {
        NavigationStack {
            List {
                if let message {
                    Text(message).font(GasFont.text(13)).foregroundStyle(GasAppColor.warn)
                        .listRowBackground(GasAppColor.bgBase)
                }
                if loaded && channels.isEmpty {
                    EmptyScene(icon: "megaphone.fill",
                               title: L10n.t("Нет каналов", "No channels", "Nessun canale"),
                               text: L10n.t("Вступите по ссылке или найдите открытый канал.",
                                            "Join by link or find a public channel.", "Entra tramite link o trova un canale pubblico."),
                               action: L10n.t("Вступить по ссылке", "Join by link", "Entra tramite link")) { showJoin = true }
                        .listRowBackground(GasAppColor.bgBase).listRowSeparator(.hidden)
                }
                if !pending.isEmpty {
                    Section(L10n.t("Заявки ждут ответа", "Requests waiting", "Richieste in attesa")) {
                        ForEach(pending, id: \.channelId) { join in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(L10n.t("Закрытый канал", "Closed channel", "Canale chiuso")).foregroundStyle(GasAppColor.textPrimary)
                                    Text(L10n.t("отправлена \(formatChatTime(join.requestedAtMillis))",
                                                "sent \(formatChatTime(join.requestedAtMillis))", "inviata \(formatChatTime(join.requestedAtMillis))"))
                                        .font(GasFont.text(12)).foregroundStyle(GasAppColor.textTertiary)
                                }
                                Spacer()
                                Button(L10n.t("Забыть", "Forget", "Dimentica")) { forget(join) }
                                    .buttonStyle(.borderless).foregroundStyle(GasAppColor.accent)
                            }
                            .listRowBackground(GasAppColor.bgBase)
                        }
                    }
                }
                ForEach(channels, id: \.channelId) { channel in
                    NavigationLink {
                        ChannelScreen(channelId: channel.channelId, title: channel.title)
                    } label: {
                        ChannelRow(channel: channel)
                    }
                    .listRowBackground(GasAppColor.bgBase)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .safeAreaInset(edge: .top, spacing: 0) { ConnectionStrip() }
            .refreshable { await sync() }
            .navigationTitle(L10n.t("Каналы", "Channels", "Canali"))
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button(L10n.t("Вступить по ссылке", "Join by link", "Entra tramite link")) { showJoin = true }
                        // Переход — через состояние: NavigationLink внутри Menu
                        // в iOS часто не срабатывает.
                        Button(L10n.t("Найти открытый", "Find public", "Trova pubblici")) { showPublic = true }
                        Button(L10n.t("Создать канал", "Create channel", "Crea canale")) { createOrExplain { showCreate = true } }
                        if premium {
                            Button(L10n.t("Мои боты", "My bots", "I miei bot")) { showBots = true }
                        }
                    } label: { Image(systemName: "plus") }
                    .accessibilityLabel(L10n.t("Каналы: добавить", "Add a channel", "Aggiungi un canale"))
                }
            }
            .alert(L10n.t("Ссылка на канал", "Channel link", "Link del canale"), isPresented: $showJoin) {
                TextField("https://…", text: $joinLink)
                Button(L10n.t("Вступить", "Join", "Entra")) { join() }
                Button(L10n.t("Отмена", "Cancel", "Annulla"), role: .cancel) {}
            }
            .alert(L10n.t("Нужен премиум", "Premium needed", "Serve premium"), isPresented: Binding(
                get: { premiumNote != nil }, set: { if !$0 { premiumNote = nil } }
            )) {
                Button("OK") { premiumNote = nil }
            } message: {
                Text(premiumNote ?? "")
            }
            .navigationDestination(isPresented: $showPublic) { PublicChannelsScreen() }
            .navigationDestination(item: $opened) { channel in
                ChannelScreen(channelId: channel.id, title: channel.title)
            }
            .sheet(isPresented: $showBots) {
                NavigationStack {
                    BotsScreen()
                        .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) { showBots = false } } }
                }
            }
            .sheet(isPresented: $showCreate) {
                NavigationStack {
                    CreateChannelSheet { channel in
                        Task {
                            await sync()
                            // Новый канал — сразу открыть: первое, что делают
                            // с каналом, — пишут в него.
                            opened = OpenedChannel(id: channel.channelId, title: channel.title)
                        }
                    }
                }
            }
            .gasScreen()
        }
        .task { await sync() }
    }

    private func reload() async {
        guard let messenger = try? CoreStore.shared.current() else { loaded = true; return }
        premium = (try? await Background.run { try messenger.premiumCached() }) ?? false
        channels = (try? await Background.run { try messenger.channels() }) ?? channels
        pending = (try? await Background.run { try messenger.pendingChannelJoins() }) ?? []
        loaded = true
    }

    /// Как на Android (`ChannelsActivity.createOrExplain`): без премиума —
    /// объяснение, а не форма. Сначала сохранённый ответ, при «нет» —
    /// вопрос серверу: премиум могли выдать минуту назад.
    private func createOrExplain(_ then: @escaping () -> Void) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            let premium = (try? await Background.run { () -> Bool in
                if (try? messenger.premiumCached()) == true { return true }
                return (try? messenger.refreshPremium(nowMillis: CoreStore.nowMillis)) ?? false
            }) ?? false
            if premium {
                then()
            } else {
                let username = ((try? messenger.ownUsername()) ?? nil) ?? ""
                premiumNote = L10n.t(
                    "Создавать каналы и ботов могут аккаунты с премиумом; читать каналы — все. Премиум выдаёт оператор сервера вручную — пришлите ему своё имя: @\(username)",
                    "Only premium accounts can create channels and bots; reading channels is open to everyone. Premium is granted by the server operator by hand — send them your username: @\(username)", "Solo gli account premium possono creare canali e bot; leggere i canali è aperto a tutti. Il premium viene concesso a mano dall’operatore del server: inviagli il tuo nome utente: @\(username)"
                )
            }
        }
    }

    private func sync() async {
        // Хранилище закрыто (галерея снимков) — пустое состояние, а не
        // пустой экран: reload сам отметит список загруженным.
        guard let messenger = try? CoreStore.shared.current() else { await reload(); return }
        await reload()
        _ = try? await Background.run { try messenger.syncChannels(nowMillis: CoreStore.nowMillis) }
        // Ответы на заявки в закрытые каналы.
        _ = try? await Background.run { try messenger.checkChannelJoins(nowMillis: CoreStore.nowMillis) }
        await reload()
    }

    /// Забыть заявку: если владелец одобрит её позже, вступить по ней
    /// уже не выйдет — нужна новая (как на Android).
    private func forget(_ join: FfiPendingChannelJoin) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = join.channelId
        Task {
            _ = try? await Background.run { try messenger.forgetChannelJoin(channelId: id) }
            await reload()
        }
    }

    private func join() {
        let link = joinLink.trimmingCharacters(in: .whitespacesAndNewlines)
        joinLink = ""
        guard let messenger = try? CoreStore.shared.current() else { return }
        Task {
            do {
                if isChannelJoinLink(text: link) {
                    // Закрытый канал: заявка, владелец решает.
                    try await Background.run { try messenger.requestChannelJoin(link: link, nowMillis: CoreStore.nowMillis) }
                    message = L10n.t("Заявка отправлена владельцу канала", "Request sent to the channel owner", "Richiesta inviata al proprietario del canale")
                } else if isChannelLink(text: link) {
                    _ = try await Background.run { try messenger.joinChannel(link: link, nowMillis: CoreStore.nowMillis) }
                    message = nil
                } else {
                    message = L10n.t("Это не ссылка на канал", "That isn’t a channel link", "Questo non è un link di un canale")
                    return
                }
                await sync()
            } catch {
                message = L10n.t("Не удалось вступить", "Could not join", "Impossibile entrare")
            }
        }
    }
}

struct ChannelRow: View {
    let channel: FfiChannel

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: channel.title, size: 52, image: channel.avatar.flatMap { UIImage(data: $0) })
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(channel.title).font(GasFont.text(17, .bold)).foregroundStyle(GasAppColor.textPrimary)
                    if channel.closed { Image(systemName: "lock.fill").font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary) }
                    if channel.muted { Image(systemName: "bell.slash.fill").font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary) }
                    Spacer()
                    if channel.unread > 0 {
                        Text("\(channel.unread)").font(GasFont.text(12, .bold))
                            .padding(.horizontal, 7).padding(.vertical, 2)
                            .background(Capsule().fill(GasAppColor.accent)).foregroundStyle(GasAppColor.accentOn)
                    }
                }
                Text(channel.lastPost ?? channel.description).font(GasFont.text(14))
                    .foregroundStyle(GasAppColor.textSecondary).lineLimit(1)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Поиск открытых каналов по имени (`@handle`) или словам.
struct PublicChannelsScreen: View {
    @State private var query = ""
    @State private var results: [FfiChannelPreview] = []
    @State private var message: String?

    var body: some View {
        List {
            if let message { Text(message).foregroundStyle(GasAppColor.warn).listRowBackground(GasAppColor.bgBase) }
            ForEach(results, id: \.channelId) { preview in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(preview.title).font(GasFont.text(16, .bold)).foregroundStyle(GasAppColor.textPrimary)
                        Text("@\(preview.handle) · \(preview.subscribers)").font(GasFont.text(13))
                            .foregroundStyle(GasAppColor.textTertiary)
                        if !preview.description.isEmpty {
                            Text(preview.description).font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary).lineLimit(2)
                        }
                    }
                    Spacer()
                    if preview.joined {
                        Image(systemName: "checkmark").foregroundStyle(GasAppColor.ok)
                    } else {
                        Button(L10n.t("Вступить", "Join", "Entra")) { join(preview) }.buttonStyle(.borderedProminent)
                    }
                }
                .listRowBackground(GasAppColor.bgBase)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always))
        .onSubmit(of: .search) { search() }
        .navigationTitle(L10n.t("Открытые каналы", "Public channels", "Canali pubblici"))
        .gasScreen()
    }

    private func search() {
        let text = query.trimmingCharacters(in: .whitespaces)
        guard text.count >= 2, let messenger = try? CoreStore.shared.current() else { return }
        Task {
            if let handle = canonicalChannelHandle(text: text),
               let found = try? await Background.run({ try messenger.findPublicChannel(handle: handle) }) {
                results = [found]
            } else {
                results = (try? await Background.run { try messenger.searchPublicChannels(query: text) }) ?? []
            }
            message = results.isEmpty ? L10n.t("Ничего не найдено", "Nothing found", "Nessun risultato") : nil
        }
    }

    private func join(_ preview: FfiChannelPreview) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let link = preview.link
        Task {
            if (try? await Background.run { try messenger.joinChannel(link: link, nowMillis: CoreStore.nowMillis) }) != nil {
                search()
            } else {
                message = L10n.t("Не удалось вступить", "Could not join", "Impossibile entrare")
            }
        }
    }
}

/// Новый канал. Право — премиум (выдаёт оператор вручную).
struct CreateChannelSheet: View {
    /// Создан — канал, чтобы сразу его открыть.
    let onCreated: (FfiChannel) -> Void

    enum Access: CaseIterable { case link, request, publicName }

    @State private var title = ""
    @State private var about = ""
    @State private var access: Access = .link
    @State private var handle = ""
    @State private var avatar: Data?
    @State private var avatarItem: PhotosPickerItem?
    @State private var working = false
    @State private var stage = ""
    @State private var error: String?
    @FocusState private var focus: FocusField?
    @Environment(\.dismiss) private var dismiss

    enum FocusField { case title, about, handle }

    private static let titleLimit = 64
    private static let aboutLimit = 500

    init(onCreated: @escaping (FfiChannel) -> Void) { self.onCreated = onCreated }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                preview

                // Аватар и название — в одной строке, как в списке каналов.
                HStack(alignment: .center, spacing: 14) {
                    PhotosPicker(selection: $avatarItem, matching: .images) {
                        ZStack(alignment: .bottomTrailing) {
                            Avatar(name: cleanTitle.isEmpty ? "?" : cleanTitle, size: 64,
                                   image: avatar.flatMap { UIImage(data: $0) })
                            Image(systemName: "camera.fill")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundStyle(GasAppColor.accentOn)
                                .frame(width: 24, height: 24)
                                .background(Circle().fill(GasAppColor.accent))
                                .overlay(Circle().stroke(GasAppColor.bgBase, lineWidth: 2))
                        }
                    }
                    .accessibilityLabel(L10n.t("Выбрать фото", "Choose photo", "Scegli foto"))
                    VStack(alignment: .leading, spacing: 6) {
                        TextField(L10n.t("Название канала", "Channel title", "Titolo del canale"), text: $title)
                            .font(GasFont.text(18, .semibold))
                            .focused($focus, equals: .title)
                            .submitLabel(.next)
                            .onSubmit { focus = .about }
                            .padding(.horizontal, 14).padding(.vertical, 12)
                            .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                            .overlay(RoundedRectangle(cornerRadius: 12)
                                .stroke(focus == .title ? GasAppColor.accent : GasAppColor.line, lineWidth: 1))
                        counter(cleanTitle.count, Self.titleLimit)
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    TextField(L10n.t("О чём канал (необязательно)", "What the channel is about (optional)", "Di cosa parla il canale (facoltativo)"),
                              text: $about, axis: .vertical)
                        .font(GasFont.text(16))
                        .lineLimit(3...8)
                        .focused($focus, equals: .about)
                        .padding(14)
                        .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                        .overlay(RoundedRectangle(cornerRadius: 12)
                            .stroke(focus == .about ? GasAppColor.accent : GasAppColor.line, lineWidth: 1))
                    counter(about.count, Self.aboutLimit)
                }

                VStack(alignment: .leading, spacing: 10) {
                    Text(L10n.t("Кто может читать", "Who can read", "Chi può leggere"))
                        .font(GasFont.text(13, .semibold))
                        .foregroundStyle(GasAppColor.textTertiary)
                    accessCard(.link, icon: "link",
                               title: L10n.t("Все, у кого есть ссылка", "Anyone with the link", "Chiunque abbia il link"),
                               text: L10n.t("Сервер хранит записи зашифрованными и прочитать их не может.",
                                            "The server stores the posts encrypted and cannot read them.",
                                            "Il server conserva i post cifrati e non può leggerli."))
                    accessCard(.request, icon: "lock.fill",
                               title: L10n.t("Только по заявке", "By request only", "Solo su richiesta"),
                               text: L10n.t("Вы одобряете каждого. Сделать канал снова открытым будет нельзя.",
                                            "You approve each person. The channel can’t be made open again later.",
                                            "Approvi ogni persona. In seguito il canale non potrà tornare aperto."))
                    accessCard(.publicName, icon: "at",
                               title: L10n.t("Публичный, с @именем", "Public, with an @name", "Pubblico, con un @nome"),
                               text: L10n.t("Канал находят поиском. Сервер получает ключ чтения и может читать записи — но не подделать их.",
                                            "People find it by search. The server gets the read key and can read posts — but not forge them.",
                                            "Si trova con la ricerca. Il server riceve la chiave di lettura e può leggere i post, ma non falsificarli."))
                    if access == .publicName {
                        HStack(spacing: 4) {
                            Text("@").font(GasFont.text(17, .semibold)).foregroundStyle(GasAppColor.textTertiary)
                            TextField(L10n.t("имя_канала", "channel_name", "nome_canale"), text: $handle)
                                .font(GasFont.text(17))
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                                .focused($focus, equals: .handle)
                        }
                        .padding(14)
                        .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                        .overlay(RoundedRectangle(cornerRadius: 12)
                            .stroke(handleValid || handle.isEmpty ? GasAppColor.line : GasAppColor.error, lineWidth: 1))
                        Text(L10n.t("3–32 знака: латиница, цифры и _, начинается с буквы.",
                                    "3–32 characters: Latin letters, digits and _, starting with a letter.",
                                    "3–32 caratteri: lettere latine, cifre e _, iniziando con una lettera."))
                            .font(GasFont.text(12))
                            .foregroundStyle(handleValid || handle.isEmpty ? GasAppColor.textTertiary : GasAppColor.error)
                            .transition(.opacity)
                    }
                }

                if let error {
                    Banner(title: L10n.t("Не создан", "Not created", "Non creato"), message: error, tone: .warn)
                        .transition(.opacity)
                }

                GoldButton(title: working && !stage.isEmpty ? stage : L10n.t("Создать канал", "Create channel", "Crea canale"),
                           isLoading: working && stage.isEmpty, isEnabled: canCreate) { create() }
            }
            .padding(20)
            .animation(.easeInOut(duration: 0.2), value: access)
            .animation(.easeInOut(duration: 0.2), value: error)
        }
        .scrollDismissesKeyboard(.interactively)
        .gasScreen()
        .navigationTitle(L10n.t("Новый канал", "New channel", "Nuovo canale"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.t("Отмена", "Cancel", "Annulla")) { dismiss() } } }
        .interactiveDismissDisabled(working)
        .onAppear { focus = .title }
        .onChange(of: avatarItem) { _, item in
            guard let item else { return }
            Task {
                if let raw = try? await item.loadTransferable(type: Data.self), let clean = ChatScreen.strippedJPEG(raw) {
                    avatar = clean
                }
                avatarItem = nil
            }
        }
    }

    /// Как канал будет выглядеть в списке — пока человек пишет.
    private var preview: some View {
        HStack(spacing: 12) {
            Avatar(name: cleanTitle.isEmpty ? "?" : cleanTitle, size: 48, image: avatar.flatMap { UIImage(data: $0) })
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(cleanTitle.isEmpty ? L10n.t("Название канала", "Channel title", "Titolo del canale") : cleanTitle)
                        .font(GasFont.text(16, .bold))
                        .foregroundStyle(cleanTitle.isEmpty ? GasAppColor.textTertiary : GasAppColor.textPrimary)
                        .lineLimit(1)
                    if access == .request {
                        Image(systemName: "lock.fill").font(.system(size: 11)).foregroundStyle(GasAppColor.textTertiary)
                    }
                }
                Text(previewSubtitle)
                    .font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(GasAppColor.bgRaised))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(GasAppColor.line, lineWidth: 1))
        .accessibilityHidden(true)
    }

    private var previewSubtitle: String {
        if access == .publicName, !handle.isEmpty { return "@\(handle.lowercased())" }
        let text = about.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? L10n.t("Ещё нет записей", "No posts yet", "Ancora nessun post") : text
    }

    private func accessCard(_ value: Access, icon: String, title: String, text: String) -> some View {
        let selected = access == value
        return Button {
            access = value
            if value == .publicName { focus = .handle }
        } label: {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(selected ? GasAppColor.accentOn : GasAppColor.accent)
                    .frame(width: 32, height: 32)
                    .background(Circle().fill(selected ? GasAppColor.accent : GasAppColor.accent.opacity(0.14)))
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(GasFont.text(15, .semibold)).foregroundStyle(GasAppColor.textPrimary)
                    Text(text).font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 20))
                    .foregroundStyle(selected ? GasAppColor.accent : GasAppColor.line)
            }
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 14).fill(GasAppColor.bgCard))
            .overlay(RoundedRectangle(cornerRadius: 14)
                .stroke(selected ? GasAppColor.accent.opacity(0.7) : GasAppColor.line, lineWidth: selected ? 1.5 : 1))
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func counter(_ count: Int, _ limit: Int) -> some View {
        Text("\(count) / \(limit)")
            .font(GasFont.text(12))
            .monospacedDigit()
            .foregroundStyle(count > limit ? GasAppColor.error : GasAppColor.textTertiary)
            .frame(maxWidth: .infinity, alignment: .trailing)
    }

    private var cleanTitle: String { title.trimmingCharacters(in: .whitespacesAndNewlines) }

    private var handleValid: Bool { canonicalChannelHandle(text: handle) != nil }

    private var canCreate: Bool {
        !cleanTitle.isEmpty && cleanTitle.count <= Self.titleLimit && about.count <= Self.aboutLimit
            && (access != .publicName || handleValid)
    }

    private func create() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let name = cleanTitle
        let text = about.trimmingCharacters(in: .whitespacesAndNewlines)
        let picture = avatar
        let mode = access
        let publicName = mode == .publicName ? canonicalChannelHandle(text: handle) : nil
        working = true
        error = nil
        focus = nil
        Task {
            do {
                _ = try await Background.run { try messenger.refreshPremium(nowMillis: CoreStore.nowMillis) }
                stage = L10n.t("Создаю канал…", "Creating the channel…", "Creazione del canale…")
                var channel = try await Background.run {
                    try messenger.createChannel(title: name, description: text, nowMillis: CoreStore.nowMillis)
                }
                let id = channel.channelId
                // Дальше — по шагу; сбой шага не отменяет созданный канал:
                // его можно доделать в «Управлении».
                var unfinished: [String] = []
                if let picture {
                    stage = L10n.t("Ставлю аватар…", "Setting the picture…", "Imposto l’immagine…")
                    if let updated = try? await Background.run({ try messenger.setChannelAvatar(channelId: id, image: picture, nowMillis: CoreStore.nowMillis) }) {
                        channel = updated
                    } else {
                        unfinished.append(L10n.t("аватар", "picture", "immagine"))
                    }
                }
                switch mode {
                case .link:
                    break
                case .request:
                    stage = L10n.t("Закрываю канал…", "Closing the channel…", "Chiudo il canale…")
                    if let updated = try? await Background.run({ try messenger.setChannelClosed(channelId: id, closed: true, nowMillis: CoreStore.nowMillis) }) {
                        channel = updated
                    } else {
                        unfinished.append(L10n.t("вступление по заявке", "join by request", "ingresso su richiesta"))
                    }
                case .publicName:
                    stage = L10n.t("Публикую @имя…", "Publishing the @name…", "Pubblico il @nome…")
                    if let updated = try? await Background.run({ try messenger.setChannelHandle(channelId: id, handle: publicName, nowMillis: CoreStore.nowMillis) }) {
                        channel = updated
                    } else {
                        unfinished.append(L10n.t("публичное имя (занято или нет связи)", "public name (taken or no connection)", "nome pubblico (in uso o nessuna connessione)"))
                    }
                }
                working = false
                stage = ""
                UINotificationFeedbackGenerator().notificationOccurred(unfinished.isEmpty ? .success : .warning)
                onCreated(channel)
                dismiss()
            } catch {
                working = false
                stage = ""
                let username = ((try? messenger.ownUsername()) ?? nil) ?? ""
                if case .PremiumRequired = error as? FfiError {
                    self.error = L10n.t("Создавать каналы можно с премиумом. Его выдаёт оператор вручную — сообщите своё имя: @\(username).",
                                        "Creating channels needs premium. The operator grants it manually — send your username: @\(username).", "Per creare canali serve il premium. L’operatore lo concede a mano: invia il tuo nome utente: @\(username).")
                } else {
                    self.error = L10n.t("Нет связи с сервером", "No connection", "Nessuna connessione")
                }
            }
        }
    }
}
