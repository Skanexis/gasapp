// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Главный экран: вкладки — как нижняя панель Android (`BottomNav`).
struct MainTabs: View {
    @State private var tab = Tab.chats

    enum Tab: Hashable { case chats, channels, contacts, settings }

    var body: some View {
        TabView(selection: $tab) {
            ChatListScreen()
                .tabItem { Label(L10n.t("Чаты", "Chats"), systemImage: "bubble.left.and.bubble.right.fill") }
                .tag(Tab.chats)
            ChannelsScreen()
                .tabItem { Label(L10n.t("Каналы", "Channels"), systemImage: "megaphone.fill") }
                .tag(Tab.channels)
            NavigationStack { ContactsScreen() }
                .tabItem { Label(L10n.t("Контакты", "Contacts"), systemImage: "person.2.fill") }
                .tag(Tab.contacts)
            NavigationStack { SettingsScreen() }
                .tabItem { Label(L10n.t("Настройки", "Settings"), systemImage: "gearshape.fill") }
                .tag(Tab.settings)
        }
        .toolbarBackground(GasAppColor.bgRaised, for: .tabBar)
        .toolbarBackground(.visible, for: .tabBar)
        .toolbarColorScheme(.dark, for: .tabBar)
    }
}
