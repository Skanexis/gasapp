// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// Мои боты — то же, что `BotsPanel` на Android. Только для премиум-
/// аккаунта: сервер без премиума откажет (`PremiumRequired`), а экран
/// открывается из «Создать» на вкладке каналов уже после проверки.
///
/// 🔐 Токен бота показывается один раз и здесь не хранится: строка
/// действует час и годится один раз, ключи бота рождаются у его
/// программы — телефон их не видит.
struct BotsScreen: View {
    @State private var bots: [String] = []
    @State private var name = ""
    @State private var error: String?
    @State private var token: (name: String, line: String)?
    @State private var deleting: String?
    @State private var working = false

    var body: some View {
        Form {
            Group {
                Section {
                    Text(L10n.t("Бот — отдельный аккаунт, который ведёт ваша программа: отвечает на сообщения, а назначенный администратором — пишет в канал, одобряет заявки и удаляет подписчиков. Имя бота кончается на bot.",
                                "A bot is a separate account run by your program: it answers messages and, once made an administrator, posts to a channel, approves requests and removes subscribers. A bot name ends in bot."))
                        .font(.system(size: 14)).foregroundStyle(GasAppColor.textSecondary)
                }
                Section(L10n.t("Создать бота", "Create a bot")) {
                    TextField(L10n.t("имя_bot", "name_bot"), text: $name)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    if let error {
                        Text(error).font(.system(size: 13)).foregroundStyle(GasAppColor.error)
                    }
                    Button(L10n.t("Получить токен", "Get a token")) { create() }
                        .disabled(working || name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Section(L10n.t("Мои боты", "My bots")) {
                    if bots.isEmpty {
                        Text(L10n.t("Пока нет", "None yet")).foregroundStyle(GasAppColor.textTertiary)
                    }
                    ForEach(bots, id: \.self) { bot in
                        HStack {
                            Text("@\(bot)")
                            Spacer()
                            Button(L10n.t("Удалить", "Delete"), role: .destructive) { deleting = bot }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Мои боты", "My bots"))
        .navigationBarTitleDisplayMode(.inline)
        .alert(L10n.t("Токен бота @\(token?.name ?? "")", "Token for bot @\(token?.name ?? "")"), isPresented: Binding(
            get: { token != nil }, set: { if !$0 { token = nil } }
        )) {
            Button(L10n.t("Копировать токен", "Copy token")) {
                if let line = token?.line {
                    // 🔐 Только локально и с истечением — как текст сообщений.
                    UIPasteboard.general.setItems([["public.utf8-plain-text": line]],
                                                  options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
                }
                token = nil
            }
            Button("OK", role: .cancel) { token = nil }
        } message: {
            Text(L10n.t("Передайте эту строку программе бота (gasapp-bot). Она действует час и годится один раз; здесь она не сохраняется. Ключи бота появятся там, где он работает, — этот телефон их не увидит.\n\n\(token?.line ?? "")",
                        "Give this line to the bot program (gasapp-bot). It is valid for an hour and works once; it is not stored here. The bot’s keys are created where it runs — this phone never sees them.\n\n\(token?.line ?? "")"))
        }
        .confirmationDialog(L10n.t("Удалить бота @\(deleting ?? "")?", "Delete bot @\(deleting ?? "")?"), isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete"), role: .destructive) { if let deleting { delete(deleting) } }
        } message: {
            Text(L10n.t("Аккаунт бота исчезнет: он пропадёт из каналов, где был администратором, а его программа больше не сможет войти.",
                        "The bot account will disappear: it leaves the channels where it was an administrator, and its program can no longer sign in."))
        }
        .task { await load() }
    }

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        bots = (try? await Background.run { try messenger.bots(nowMillis: CoreStore.nowMillis) }) ?? []
    }

    private func create() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        // Имя — в каноническом виде ядра, как у аккаунтов.
        guard let canonical = try? canonicalUsername(raw: name), canonical.hasSuffix("bot") else {
            error = L10n.t("Имя бота: латиница, цифры и _, в конце — bot", "Bot name: Latin letters, digits and _, ending in bot")
            return
        }
        error = nil
        working = true
        Task {
            do {
                let line = try await Background.run { try messenger.createBot(username: canonical, nowMillis: CoreStore.nowMillis) }
                token = (canonical, line)
                name = ""
            } catch FfiError.UsernameTaken {
                error = L10n.t("Это имя занято", "This name is taken")
            } catch FfiError.InvalidArgument {
                error = L10n.t("Имя бота: латиница, цифры и _, в конце — bot", "Bot name: Latin letters, digits and _, ending in bot")
            } catch {
                // Внутри `catch` имя `error` — пойманная ошибка, поле — через self.
                self.error = L10n.t("Не получилось: нет связи с сервером либо ботов уже слишком много",
                               "Did not work: no connection to the server, or there are too many bots already")
            }
            working = false
            await load()
        }
    }

    private func delete(_ bot: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        deleting = nil
        Task {
            _ = try? await Background.run { try messenger.deleteBot(username: bot, nowMillis: CoreStore.nowMillis) }
            await load()
        }
    }
}
