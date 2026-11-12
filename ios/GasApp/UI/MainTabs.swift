// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Главный экран: вкладки — как нижняя панель Android (`BottomNav`).
struct MainTabs: View {
    @Environment(AppModel.self) private var model
    @State private var tab: Tab
    /// Непрочитанные записи каналов — число на вкладке, как на Android.
    @State private var unreadPosts: Int = 0

    enum Tab: Hashable { case chats, channels, contacts, settings }

    /// Экран, уже открытый внутри стартовой вкладки (настройки или
    /// контакты); в приложении — nil.
    private let pushed: AnyView?
    @State private var pushedShown = false

    init(start: Tab = .chats, pushed: AnyView? = nil) {
        _tab = State(initialValue: start)
        self.pushed = pushed
    }

    var body: some View {
        TabView(selection: $tab) {
            ChatListScreen()
                .tabItem { Label(L10n.t("Чаты", "Chats", "Chat"), systemImage: "bubble.left.and.bubble.right.fill") }
                .tag(Tab.chats)
            ChannelsScreen()
                .tabItem { Label(L10n.t("Каналы", "Channels", "Canali"), systemImage: "megaphone.fill") }
                .badge(unreadPosts)
                .tag(Tab.channels)
            NavigationStack {
                ContactsScreen()
                    .navigationDestination(isPresented: binding(for: .contacts)) { pushed }
            }
                .tabItem { Label(L10n.t("Контакты", "Contacts", "Contatti"), systemImage: "person.2.fill") }
                .tag(Tab.contacts)
            NavigationStack {
                SettingsScreen()
                    .navigationDestination(isPresented: binding(for: .settings)) { pushed }
            }
                .tabItem { Label(L10n.t("Настройки", "Settings", "Impostazioni"), systemImage: "gearshape.fill") }
                .tag(Tab.settings)
        }
        .toolbarBackground(GasAppColor.bgRaised, for: .tabBar)
        .toolbarBackground(.visible, for: .tabBar)
        .toolbarColorScheme(.dark, for: .tabBar)
        .task(id: tab) { await countUnread() }
        // Открыли по ссылке на контакт — к чатам: там подтверждение.
        .onChange(of: model.pendingContactLink, initial: true) { _, link in
            if link != nil { tab = .chats }
        }
        .onAppear { if pushed != nil { pushedShown = true } }
    }

    private func binding(for owner: Tab) -> Binding<Bool> {
        Binding(get: { pushedShown && tab == owner && pushed != nil }, set: { pushedShown = $0 })
    }

    private func countUnread() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let count = (try? await Background.run { try messenger.unreadChannelPosts() }) ?? 0
        unreadPosts = Int(min(count, 999))
    }
}
