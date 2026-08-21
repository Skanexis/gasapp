// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Чат в том виде, в каком его показывает список.
struct ChatSummary: Identifiable {
    let id: String
    let name: String
    let preview: String
    let time: String

    /// Сверен ли safety number вручную.
    let verified: Bool

    /// Сколько сообщений не прочитано.
    var unread: Int = 0

    /// В сети ли собеседник.
    var online: Bool = false
}

/// Список чатов — главный экран приложения.
///
/// 🔐 Криптографии здесь нет и быть не может: экран показывает то,
/// что подготовило ядро (правило 1).
struct ChatListView: View {

    // MARK: - Properties

    @State private var chats: [ChatSummary] = []
    @State private var isOffline = false

    let onOpenChat: (ChatSummary) -> Void
    let onNewChat: () -> Void
    let onSecurityCenter: () -> Void

    // MARK: - Body

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            AegisColor.bgBase.ignoresSafeArea()

            VStack(spacing: 0) {
                header

                // Баннер показывается только когда связи нет.
                // Постоянный зелёный индикатор «онлайн» приучает
                // не смотреть на него, и в нужный момент его не заметят.
                if isOffline {
                    offlineBanner
                }

                if chats.isEmpty {
                    emptyState
                } else {
                    chatList
                }
            }

            newChatButton
        }
        .onAppear { reload() }
        .onDisappear {
            // 🔐 Расшифрованные превью не должны переживать уход
            // с экрана: снимок в переключателе задач показал бы их
            // любому, кто взял разблокированное устройство.
            chats = []
        }
    }

    // MARK: - Subviews

    private var header: some View {
        HStack {
            Text("Чаты")
                .font(.system(size: 18, weight: .bold))
                .foregroundColor(AegisColor.textPrimary)

            Spacer()

            Button(action: onSecurityCenter) {
                Image(systemName: "shield")
                    .foregroundColor(AegisColor.ok)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
    }

    private var offlineBanner: some View {
        Text("Нет соединения с сервером")
            .font(.system(size: 12))
            .foregroundColor(AegisColor.warn)
            .frame(maxWidth: .infinity)
            .padding(10)
            .background(AegisColor.warnDim)
    }

    private var chatList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(chats) { chat in
                    Button {
                        onOpenChat(chat)
                    } label: {
                        ChatRow(chat: chat)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var emptyState: some View {
        VStack {
            Spacer()

            Text("Пока нет переписок. Начните с кнопки ниже.")
                .font(.system(size: 14))
                .foregroundColor(AegisColor.textTertiary)
                .multilineTextAlignment(.center)
                .padding(16)

            Spacer()
        }
    }

    private var newChatButton: some View {
        Button(action: onNewChat) {
            Image(systemName: "square.and.pencil")
                .font(.system(size: 20))
                .foregroundColor(AegisColor.accentOn)
                .frame(width: 52, height: 52)
                .background(AegisColor.accent)
                .clipShape(RoundedRectangle(cornerRadius: 16))
        }
        .padding(.trailing, 16)
        .padding(.bottom, 24)
    }

    // MARK: - Data

    private func reload() {
        // Источник данных подключается вместе с оркестрацией на iOS.
        // Имена из UI kit, чтобы экран совпадал с макетом.
        chats = [
            ChatSummary(
                id: "chat-1",
                name: "Lena Novak",
                preview: "Проверим safety number?",
                time: "14:32",
                verified: true
            ),
            ChatSummary(
                id: "chat-2",
                name: "Alex Vogel",
                preview: "Отправлю файл вечером",
                time: "12:05",
                verified: false,
                online: true
            ),
        ]
    }
}

/// Строка списка чатов.
struct ChatRow: View {

    let chat: ChatSummary

    var body: some View {
        HStack(spacing: 12) {
            avatar

            VStack(alignment: .leading, spacing: 3) {
                Text(chat.name)
                    .font(.system(size: 15, weight: .bold))
                    .foregroundColor(AegisColor.textPrimary)
                    .lineLimit(1)

                Text(chat.preview)
                    .font(.system(size: 13))
                    .foregroundColor(AegisColor.textTertiary)
                    .lineLimit(1)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 5) {
                Text(chat.time)
                    .font(.system(size: 11))
                    .foregroundColor(AegisColor.textQuaternary)

                if chat.unread > 0 {
                    Text("\(chat.unread)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(AegisColor.accentOn)
                        .padding(.horizontal, 5)
                        .frame(height: 18)
                        .background(AegisColor.accent)
                        .clipShape(Capsule())
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    /// Аватар с инициалами.
    ///
    /// 🔐 Буквы имени, а не загруженное фото: запрос картинки
    /// с сервера выдал бы оператору, кто с кем переписывается.
    private var avatar: some View {
        ZStack(alignment: .bottomTrailing) {
            Circle()
                .fill(AegisColor.bgHover)
                .frame(width: 48, height: 48)
                .overlay(
                    Text(initials)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(AegisColor.accent)
                )

            // 🔐 Значок только у контактов, чей safety number сверен
            // вручную. Автоматическая отметка обесценила бы проверку.
            if chat.verified {
                Image(systemName: "checkmark")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(AegisColor.accentOn)
                    .frame(width: 18, height: 18)
                    .background(Circle().fill(AegisColor.accent))
                    .overlay(Circle().stroke(AegisColor.bgBase, lineWidth: 2.5))
            } else if chat.online {
                Circle()
                    .fill(AegisColor.ok)
                    .frame(width: 13, height: 13)
                    .overlay(Circle().stroke(AegisColor.bgBase, lineWidth: 2.5))
            }
        }
    }

    /// Инициалы: две буквы из разных слов.
    ///
    /// Одна буква хуже различает контакты в длинном списке.
    private var initials: String {
        let parts = chat.name.split(separator: " ")

        if parts.count >= 2, let first = parts[0].first, let second = parts[1].first {
            return "\(first)\(second)".uppercased()
        }

        return String(chat.name.prefix(2)).uppercased()
    }
}
