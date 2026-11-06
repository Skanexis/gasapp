// SPDX-License-Identifier: Apache-2.0

import SwiftUI

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
    @State private var message: String?

    var body: some View {
        NavigationStack {
            List {
                if let message {
                    Text(message).font(.system(size: 13)).foregroundStyle(GasAppColor.warn)
                        .listRowBackground(GasAppColor.bgBase)
                }
                if loaded && channels.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "megaphone.fill").font(.system(size: 40)).foregroundStyle(GasAppColor.accent)
                        Text(L10n.t("Нет каналов", "No channels"))
                            .font(.system(size: 20, weight: .heavy, design: .rounded)).foregroundStyle(GasAppColor.textPrimary)
                        Text(L10n.t("Вступите по ссылке или найдите открытый канал.", "Join by link or find a public channel."))
                            .font(.system(size: 15)).foregroundStyle(GasAppColor.textSecondary)
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 40)
                    .listRowBackground(GasAppColor.bgBase).listRowSeparator(.hidden)
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
            .refreshable { await sync() }
            .navigationTitle(L10n.t("Каналы", "Channels"))
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button(L10n.t("Вступить по ссылке", "Join by link")) { showJoin = true }
                        NavigationLink(L10n.t("Найти открытый", "Find public")) { PublicChannelsScreen() }
                        Button(L10n.t("Создать канал", "Create channel")) { showCreate = true }
                    } label: { Image(systemName: "plus.circle.fill") }
                }
            }
            .alert(L10n.t("Ссылка на канал", "Channel link"), isPresented: $showJoin) {
                TextField("https://…", text: $joinLink)
                Button(L10n.t("Вступить", "Join")) { join() }
                Button(L10n.t("Отмена", "Cancel"), role: .cancel) {}
            }
            .sheet(isPresented: $showCreate) {
                NavigationStack { CreateChannelSheet { Task { await sync() } } }
            }
            .gasScreen()
        }
        .task { await sync() }
    }

    private func reload() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        channels = (try? await Background.run { try messenger.channels() }) ?? channels
        loaded = true
    }

    private func sync() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        await reload()
        _ = try? await Background.run { try messenger.syncChannels(nowMillis: CoreStore.nowMillis) }
        // Ответы на заявки в закрытые каналы.
        _ = try? await Background.run { try messenger.checkChannelJoins(nowMillis: CoreStore.nowMillis) }
        await reload()
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
                    message = L10n.t("Заявка отправлена владельцу канала", "Request sent to the channel owner")
                } else if isChannelLink(text: link) {
                    _ = try await Background.run { try messenger.joinChannel(link: link, nowMillis: CoreStore.nowMillis) }
                    message = nil
                } else {
                    message = L10n.t("Это не ссылка на канал", "That isn’t a channel link")
                    return
                }
                await sync()
            } catch {
                message = L10n.t("Не удалось вступить", "Could not join")
            }
        }
    }
}

struct ChannelRow: View {
    let channel: FfiChannel

    var body: some View {
        HStack(spacing: 12) {
            Group {
                if let data = channel.avatar, let image = UIImage(data: data) {
                    Image(uiImage: image).resizable().scaledToFill()
                } else {
                    Text(String(channel.title.prefix(1)).uppercased())
                        .font(.system(size: 20, weight: .heavy, design: .rounded))
                        .foregroundStyle(GasAppColor.accent)
                }
            }
            .frame(width: 48, height: 48)
            .background(Circle().fill(GasAppColor.bgCard))
            .clipShape(Circle())
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(channel.title).font(.system(size: 17, weight: .bold)).foregroundStyle(GasAppColor.textPrimary)
                    if channel.closed { Image(systemName: "lock.fill").font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary) }
                    if channel.muted { Image(systemName: "bell.slash.fill").font(.system(size: 12)).foregroundStyle(GasAppColor.textTertiary) }
                    Spacer()
                    if channel.unread > 0 {
                        Text("\(channel.unread)").font(.system(size: 12, weight: .bold))
                            .padding(.horizontal, 7).padding(.vertical, 2)
                            .background(Capsule().fill(GasAppColor.accent)).foregroundStyle(GasAppColor.accentOn)
                    }
                }
                Text(channel.lastPost ?? channel.description).font(.system(size: 14))
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
                        Text(preview.title).font(.system(size: 16, weight: .bold)).foregroundStyle(GasAppColor.textPrimary)
                        Text("@\(preview.handle) · \(preview.subscribers)").font(.system(size: 13))
                            .foregroundStyle(GasAppColor.textTertiary)
                        if !preview.description.isEmpty {
                            Text(preview.description).font(.system(size: 13)).foregroundStyle(GasAppColor.textSecondary).lineLimit(2)
                        }
                    }
                    Spacer()
                    if preview.joined {
                        Image(systemName: "checkmark").foregroundStyle(GasAppColor.ok)
                    } else {
                        Button(L10n.t("Вступить", "Join")) { join(preview) }.buttonStyle(.borderedProminent)
                    }
                }
                .listRowBackground(GasAppColor.bgBase)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always))
        .onSubmit(of: .search) { search() }
        .navigationTitle(L10n.t("Открытые каналы", "Public channels"))
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
            message = results.isEmpty ? L10n.t("Ничего не найдено", "Nothing found") : nil
        }
    }

    private func join(_ preview: FfiChannelPreview) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let link = preview.link
        Task {
            if (try? await Background.run { try messenger.joinChannel(link: link, nowMillis: CoreStore.nowMillis) }) != nil {
                search()
            } else {
                message = L10n.t("Не удалось вступить", "Could not join")
            }
        }
    }
}

/// Новый канал. Право — премиум (выдаёт оператор вручную).
struct CreateChannelSheet: View {
    let onCreated: () -> Void
    @State private var title = ""
    @State private var about = ""
    @State private var working = false
    @State private var error: String?
    @Environment(\.dismiss) private var dismiss

    init(onCreated: @escaping () -> Void) { self.onCreated = onCreated }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Field(title: L10n.t("Название", "Title"), text: $title)
                Field(title: L10n.t("Описание", "Description"), text: $about)
                if let error { Banner(title: L10n.t("Не создан", "Not created"), message: error, tone: .warn) }
                GoldButton(title: L10n.t("Создать", "Create"), isLoading: working,
                           isEnabled: !title.trimmingCharacters(in: .whitespaces).isEmpty) { create() }
            }
            .padding(20)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Новый канал", "New channel"))
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.t("Отмена", "Cancel")) { dismiss() } } }
    }

    private func create() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let name = title.trimmingCharacters(in: .whitespaces)
        let text = about
        working = true
        Task {
            do {
                _ = try await Background.run { try messenger.refreshPremium(nowMillis: CoreStore.nowMillis) }
                _ = try await Background.run {
                    try messenger.createChannel(title: name, description: text, nowMillis: CoreStore.nowMillis)
                }
                working = false
                onCreated()
                dismiss()
            } catch {
                working = false
                let username = ((try? messenger.ownUsername()) ?? nil) ?? ""
                if case .PremiumRequired = error as? FfiError {
                    self.error = L10n.t("Создавать каналы можно с премиумом. Его выдаёт оператор вручную — сообщите своё имя: @\(username).",
                                        "Creating channels needs premium. The operator grants it manually — send your username: @\(username).")
                } else {
                    self.error = L10n.t("Нет связи с сервером", "No connection")
                }
            }
        }
    }
}
