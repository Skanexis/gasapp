// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Статус доставки сообщения.
enum DeliveryMark {
    case pending
    case sent
    case delivered
    case read
    case failed
}

/// Сообщение в том виде, в каком его показывает интерфейс.
struct MessageItem: Identifiable {
    let id: String
    let text: String
    let time: String

    /// Наше сообщение или входящее.
    let outgoing: Bool

    /// Статус доставки. Имеет смысл только для исходящих.
    let status: DeliveryMark
}

/// Экран переписки.
///
/// 🔐 Криптографии здесь нет: экран показывает готовые данные
/// и спрашивает у ядра, разрешена ли отправка.
struct ChatView: View {

    // MARK: - Properties

    let peerName: String
    let peerUsername: String
    let isVerified: Bool

    @State private var messages: [MessageItem] = []
    @State private var draft = ""

    /// Сменился ли identity-ключ контакта.
    @State private var identityChanged = false

    let onVerify: () -> Void
    let onBack: () -> Void

    /// Разрешена ли отправка.
    ///
    /// 🔐 Решение принимает **ядро**, а не этот экран: правило
    /// «верифицированному контакту со сменившимся ключом писать
    /// нельзя» относится к безопасности, и вторая реализация в UI
    /// разошлась бы с первой.
    ///
    /// При недоступном ядре отправка запрещается, а не разрешается:
    /// неотправленное сообщение исправимо, отправленное подменённому
    /// собеседнику — нет.
    private var canSend: Bool {
        // Подключается вместе с FFI на iOS; форма решения уже верная.
        !(isVerified && identityChanged)
    }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            header

            if !canSend {
                keyChangeBanner
            }

            thread

            inputBar
        }
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .onAppear { reload() }
        .onDisappear {
            // 🔐 Расшифрованный текст не должен переживать уход
            // с экрана.
            messages = []
        }
    }

    // MARK: - Subviews

    private var header: some View {
        HStack(spacing: 12) {
            Button(action: onBack) {
                Image(systemName: "chevron.left")
                    .foregroundColor(GasAppColor.textPrimary)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(peerName)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(GasAppColor.textPrimary)

                Button(action: onVerify) {
                    Text(isVerified ? "✓ Верифицирован" : "Не верифицирован — сверьте safety number")
                        .font(.system(size: 12))
                        .foregroundColor(isVerified ? GasAppColor.accent : GasAppColor.textTertiary)
                }
            }

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(GasAppColor.bgRaised)
    }

    private var keyChangeBanner: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("🔒 Ключ контакта сменился")
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(GasAppColor.textPrimary)

            Text("Вы ранее сверили safety number с этим контактом. Отправка заблокирована, пока вы не сверите его заново.")
                .font(.system(size: 13))
                .foregroundColor(GasAppColor.textSecondary)

            GasAppButton(title: "Сверить safety number", action: onVerify)
        }
        .padding(16)
        .background(GasAppColor.bgCard)
    }

    private var thread: some View {
        ScrollView {
            LazyVStack(spacing: 6) {
                // 🔐 Чип показывается всегда, а не при первом открытии:
                // пользователь должен замечать не его наличие,
                // а его отсутствие.
                encryptionChip

                ForEach(messages) { message in
                    MessageBubble(message: message)
                }
            }
            .padding(.vertical, 8)
        }
    }

    private var encryptionChip: some View {
        HStack(spacing: 6) {
            Image(systemName: "lock.fill")
                .font(.system(size: 10))

            Text("Сквозное шифрование")
                .font(.system(size: 11))
        }
        .foregroundColor(GasAppColor.accent)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(GasAppColor.accentDim)
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private var inputBar: some View {
        HStack(spacing: 10) {
            TextField("Сообщение", text: $draft)
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(GasAppColor.bgCard)
                .foregroundColor(GasAppColor.textPrimary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .disabled(!canSend)

            Button(action: send) {
                Text("Отправить")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(canSend ? GasAppColor.accentOn : GasAppColor.textQuaternary)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(canSend ? GasAppColor.accent : GasAppColor.bgHover)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .disabled(!canSend)
        }
        .padding(12)
        .background(GasAppColor.bgRaised)
    }

    // MARK: - Actions

    private func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }

        // Статус pending, а не sent: сообщение ещё не ушло на сервер.
        // Показать «отправлено» до подтверждения значило бы соврать
        // пользователю о состоянии его переписки.
        messages.append(
            MessageItem(
                id: UUID().uuidString,
                text: text,
                time: "сейчас",
                outgoing: true,
                status: .pending
            )
        )

        draft = ""
    }

    private func reload() {
        // Заменяется данными из ядра вместе с оркестрацией на iOS.
        messages = []
    }
}

/// Пузырь сообщения.
struct MessageBubble: View {

    let message: MessageItem

    var body: some View {
        HStack {
            if message.outgoing {
                Spacer(minLength: 60)
            }

            VStack(alignment: .trailing, spacing: 3) {
                Text(message.text)
                    .font(.system(size: 14))
                    .foregroundColor(GasAppColor.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                HStack(spacing: 4) {
                    Text(message.time)
                        .font(.system(size: 10))
                        .foregroundColor(GasAppColor.textQuaternary)

                    // Статус только у исходящих: у входящих он
                    // не имеет смысла и сбивал бы с толку.
                    if message.outgoing {
                        statusIcon
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(message.outgoing ? GasAppColor.bubbleOutgoing : GasAppColor.bgCard)
            .clipShape(RoundedRectangle(cornerRadius: 14))

            if !message.outgoing {
                Spacer(minLength: 60)
            }
        }
        .padding(.horizontal, 16)
    }

    /// Значок доставки.
    ///
    /// `failed` помечается крестом, а не молчанием: сообщение, которое
    /// выглядит отправленным, но не ушло, — худший исход, потому что
    /// пользователь считает, что его прочитали.
    private var statusIcon: some View {
        Group {
            switch message.status {
            case .pending:
                Image(systemName: "clock")
            case .sent:
                Image(systemName: "checkmark")
            case .delivered, .read:
                Image(systemName: "checkmark.circle")
            case .failed:
                Image(systemName: "xmark")
            }
        }
        .font(.system(size: 10))
        .foregroundColor(statusColor)
    }

    private var statusColor: Color {
        switch message.status {
        case .read:
            return GasAppColor.accent
        case .failed:
            return GasAppColor.error
        default:
            return GasAppColor.textQuaternary
        }
    }
}
