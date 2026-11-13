// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Аккаунт заморожен либо заблокирован оператором сервера.
///
/// Экран закрывает приложение целиком: сервер всё равно отвергает
/// запросы такого аккаунта (`423`), и без объяснения человек видел бы
/// только «нет связи». Переписка на телефоне цела — она хранится здесь,
/// а не у сервера.
struct RestrictedScreen: View {
    let restriction: FfiAccountRestriction
    let username: String
    let recheck: () async -> Void
    @State private var checking = false

    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                Spacer(minLength: 40)
                Image(systemName: restriction.blocked ? "nosign" : "snowflake")
                    .font(.system(size: 54, weight: .semibold))
                    .foregroundStyle(restriction.blocked ? GasAppColor.error : GasAppColor.accent)
                    .frame(width: 112, height: 112)
                    .background(Circle().fill(GasAppColor.bgCard))
                    .overlay(Circle().stroke(GasAppColor.line, lineWidth: 1))
                    .accessibilityHidden(true)

                VStack(spacing: 10) {
                    Text(title)
                        .font(GasFont.display(26))
                        .foregroundStyle(GasAppColor.textPrimary)
                        .multilineTextAlignment(.center)
                    Text(explanation)
                        .font(GasFont.text(16))
                        .foregroundStyle(GasAppColor.textSecondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }

                VStack(alignment: .leading, spacing: 12) {
                    if let reason = reasonText {
                        row("exclamationmark.bubble.fill", L10n.t("Причина", "Reason", "Motivo"), reason)
                    }
                    row("lock.fill", L10n.t("Переписка", "Your chats", "Le tue chat"),
                        L10n.t("Цела и хранится на этом телефоне.", "Safe, and stored on this phone.", "Al sicuro, salvate su questo telefono."))
                    row("envelope.fill", L10n.t("Ошибка?", "A mistake?", "Un errore?"),
                        L10n.t("Напишите на abuse@gasapp.eu и укажите своё имя: @\(username)", "Write to abuse@gasapp.eu with your username: @\(username)", "Scrivi a abuse@gasapp.eu indicando il tuo nome utente: @\(username)"))
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 16).fill(GasAppColor.bgCard))

                GoldButton(title: L10n.t("Проверить снова", "Check again", "Controlla di nuovo"), isLoading: checking) {
                    checking = true
                    Task { await recheck(); checking = false }
                }
                Spacer(minLength: 20)
            }
            .padding(.horizontal, 24)
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .gasScreen()
        .accessibilityElement(children: .contain)
    }

    private var title: String {
        restriction.blocked
            ? L10n.t("Аккаунт заблокирован", "Account blocked", "Account bloccato")
            : L10n.t("Аккаунт заморожен", "Account frozen", "Account sospeso")
    }

    private var explanation: String {
        let owner = restriction.viaOwner
        if restriction.blocked {
            return owner
                ? L10n.t("Оператор сервера заблокировал владельца этого бота. Пока блокировка действует, бот не может отправлять и получать сообщения.",
                         "The server operator blocked this bot’s owner. While the block lasts, the bot cannot send or receive messages.",
                         "L’operatore del server ha bloccato il proprietario di questo bot. Finché il blocco resta, il bot non può inviare né ricevere messaggi.")
                : L10n.t("Оператор сервера заблокировал аккаунт после жалоб. Пока блокировка действует, отправлять и получать сообщения нельзя.",
                         "The server operator blocked this account after reports. While the block lasts, you cannot send or receive messages.",
                         "L’operatore del server ha bloccato questo account dopo delle segnalazioni. Finché il blocco resta, non puoi inviare né ricevere messaggi.")
        }
        let until = untilText
        return owner
            ? L10n.t("Владелец этого бота заморожен до \(until). До этого времени бот не может отправлять и получать сообщения.",
                     "This bot’s owner is frozen until \(until). Until then the bot cannot send or receive messages.",
                     "Il proprietario di questo bot è sospeso fino al \(until). Fino ad allora il bot non può inviare né ricevere messaggi.")
            : L10n.t("Оператор сервера заморозил аккаунт после жалоб до \(until). До этого времени отправлять и получать сообщения нельзя — потом всё заработает само.",
                     "The server operator froze this account after reports until \(until). Until then you cannot send or receive messages; after that everything works again by itself.",
                     "L’operatore del server ha sospeso questo account dopo delle segnalazioni fino al \(until). Fino ad allora non puoi inviare né ricevere messaggi; poi tutto riprende da solo.")
    }

    private var untilText: String {
        guard let millis = restriction.untilMillis else { return "—" }
        let date = Date(timeIntervalSince1970: TimeInterval(millis) / 1000)
        return date.formatted(date: .long, time: .shortened)
    }

    private var reasonText: String? {
        switch restriction.reason {
        case "spam": L10n.t("Спам или мошенничество", "Spam or scam", "Spam o truffa")
        case "harassment": L10n.t("Травля или угрозы", "Harassment or threats", "Molestie o minacce")
        case "csae": L10n.t("Безопасность детей", "Child safety", "Sicurezza dei minori")
        case "impersonation": L10n.t("Выдаёт себя за другого", "Impersonation", "Furto d’identità")
        case "illegal": L10n.t("Незаконное содержимое", "Illegal content", "Contenuti illegali")
        case "other": L10n.t("Нарушение правил", "Breaking the rules", "Violazione delle regole")
        default: nil
        }
    }

    private func row(_ symbol: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(GasAppColor.accent)
                .frame(width: 22)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(GasFont.text(13, .semibold)).foregroundStyle(GasAppColor.textTertiary)
                Text(text).font(GasFont.text(15)).foregroundStyle(GasAppColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
