// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// Мои боты — то же, что `BotsPanel` на Android. Только для премиум-
/// аккаунта: без премиума экран объясняет, как его получить, вместо
/// формы, которую сервер всё равно отвергнет.
///
/// 🔐 Токен бота показывается один раз и здесь не хранится: строка
/// действует час и годится один раз, ключи бота рождаются у его
/// программы — телефон их не видит.
struct BotsScreen: View {
    @State private var bots: [FfiBot] = []
    @State private var loaded = false
    @State private var premium: Bool?
    @State private var username = ""
    @State private var name = ""
    @State private var error: String?
    @State private var token: BotToken?
    @State private var deleting: String?
    @State private var working = false
    @FocusState private var nameFocused: Bool

    struct BotToken: Identifiable {
        let name: String
        let line: String
        var id: String { name }
    }

    var body: some View {
        List {
            Group {
            Section {
                HStack(alignment: .top, spacing: 14) {
                    SettingIcon(name: "cpu.fill", color: .mint)
                    Text(L10n.t("Бот — отдельный аккаунт, который ведёт ваша программа: отвечает на сообщения, а назначенный администратором — пишет в канал, одобряет заявки и удаляет подписчиков. Имя бота кончается на bot.",
                                "A bot is a separate account run by your program: it answers messages and, once made an administrator, posts to a channel, approves requests and removes subscribers. A bot name ends in bot.", "Un bot è un account separato gestito dal tuo programma: risponde ai messaggi e, se nominato amministratore, pubblica in un canale, approva le richieste e rimuove gli iscritti. Il nome di un bot termina con bot."))
                        .font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 4)
            }

            if premium == false {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(L10n.t("Нужен премиум", "Premium needed", "Serve premium"), systemImage: "crown.fill")
                            .font(GasFont.text(16, .semibold)).foregroundStyle(GasAppColor.accent)
                        Text(L10n.t("Создавать каналы и ботов могут аккаунты с премиумом. Премиум выдаёт оператор сервера вручную — пришлите ему своё имя: @\(username)",
                                    "Only premium accounts can create channels and bots. Premium is granted by the server operator by hand — send them your username: @\(username)", "Solo gli account premium possono creare canali e bot. Il premium viene concesso a mano dall’operatore del server: inviagli il tuo nome utente: @\(username)"))
                            .font(GasFont.text(14)).foregroundStyle(GasAppColor.textSecondary)
                        Button(L10n.t("Проверить ещё раз", "Check again", "Controlla di nuovo")) { Task { await load(refresh: true) } }
                            .font(GasFont.text(15, .semibold))
                    }
                    .padding(.vertical, 4)
                }
            } else {
                Section {
                    HStack(spacing: 4) {
                        Text("@").foregroundStyle(GasAppColor.textTertiary)
                        TextField(L10n.t("имя_bot", "name_bot", "nome_bot"), text: $name)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .focused($nameFocused)
                            .submitLabel(.done)
                            .onSubmit { if nameState == .ok { create() } }
                        if nameState == .ok {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(GasAppColor.ok)
                                .transition(.scale.combined(with: .opacity))
                        }
                    }
                    .font(GasFont.text(17))
                    Button {
                        create()
                    } label: {
                        HStack {
                            if working { ProgressView().tint(GasAppColor.accent) }
                            Text(L10n.t("Получить токен", "Get a token", "Ottieni un token")).font(GasFont.text(16, .semibold))
                        }
                    }
                    .disabled(working || nameState != .ok)
                } header: {
                    Text(L10n.t("Создать бота", "Create a bot", "Crea un bot"))
                } footer: {
                    Text(error ?? nameHint)
                        .foregroundStyle(error != nil || nameState == .bad ? GasAppColor.error : GasAppColor.textTertiary)
                }
                .animation(.easeInOut(duration: 0.15), value: nameState)

                Section {
                    if !loaded {
                        HStack { Spacer(); ProgressView().tint(GasAppColor.accent); Spacer() }
                    } else if bots.isEmpty {
                        Text(L10n.t("Пока нет", "None yet", "Ancora nessuno")).foregroundStyle(GasAppColor.textTertiary)
                    }
                    ForEach(bots, id: \.username) { bot in
                        botRow(bot)
                            .swipeActions(edge: .trailing) {
                                Button(L10n.t("Удалить", "Delete", "Elimina"), role: .destructive) { deleting = bot.username }
                            }
                            .contextMenu {
                                if bot.pending {
                                    Button(L10n.t("Новый токен", "New token", "Nuovo token"), systemImage: "key.fill") { create(bot.username) }
                                }
                                Button(L10n.t("Удалить", "Delete", "Elimina"), systemImage: "trash", role: .destructive) { deleting = bot.username }
                            }
                    }
                } header: {
                    Text(L10n.t("Мои боты", "My bots", "I miei bot"))
                } footer: {
                    if bots.contains(where: \.pending) {
                        Text(L10n.t("«Ждёт запуска» — имя занято за вами, но программа бота ещё не запущена с токеном. Потеряли строку — нажмите «Новый токен»: прежняя перестанет действовать.",
                                    "“Waiting to start” means the name is reserved for you, but the bot program has not been started with the token yet. Lost the line? Tap “New token” — the old one stops working.",
                                    "«In attesa di avvio»: il nome è riservato a te, ma il programma del bot non è ancora stato avviato con il token. Hai perso la riga? Tocca «Nuovo token»: quella vecchia smette di funzionare."))
                    }
                }
            }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Мои боты", "My bots", "I miei bot"))
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await load(refresh: true) }
        .sheet(item: $token) { token in BotTokenSheet(token: token) }
        .confirmationDialog(L10n.t("Удалить бота @\(deleting ?? "")?", "Delete bot @\(deleting ?? "")?", "Eliminare il bot @\(deleting ?? "")?"), isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }
        ), titleVisibility: .visible) {
            Button(L10n.t("Удалить", "Delete", "Elimina"), role: .destructive) { if let deleting { delete(deleting) } }
        } message: {
            Text(L10n.t("Аккаунт бота исчезнет: он пропадёт из каналов, где был администратором, а его программа больше не сможет войти.",
                        "The bot account will disappear: it leaves the channels where it was an administrator, and its program can no longer sign in.", "L’account del bot sparirà: lascia i canali in cui era amministratore e il suo programma non potrà più accedere."))
        }
        .task { await load(refresh: false) }
        .onChange(of: name) { _, _ in error = nil }
    }

    // MARK: - Строка бота

    private func botRow(_ bot: FfiBot) -> some View {
        HStack(spacing: 12) {
            Avatar(name: bot.username, size: 40)
                .opacity(bot.pending ? 0.55 : 1)
            VStack(alignment: .leading, spacing: 2) {
                Text("@\(bot.username)").font(GasFont.text(16, .semibold)).foregroundStyle(GasAppColor.textPrimary)
                if bot.pending {
                    Label(pendingText(bot), systemImage: "hourglass")
                        .font(GasFont.text(13)).foregroundStyle(GasAppColor.accent)
                } else {
                    Label(L10n.t("Подключён", "Connected", "Collegato"), systemImage: "checkmark.seal.fill")
                        .font(GasFont.text(13)).foregroundStyle(GasAppColor.ok)
                }
            }
            Spacer()
            if bot.pending {
                Button(L10n.t("Новый токен", "New token", "Nuovo token")) { create(bot.username) }
                    .font(GasFont.text(14, .semibold))
                    .buttonStyle(.borderless)
                    .disabled(working)
            }
        }
        .padding(.vertical, 2)
    }

    private func pendingText(_ bot: FfiBot) -> String {
        let minutes = max(1, Int(((bot.expiresInSecs ?? 0) + 59) / 60))
        return L10n.t("Ждёт запуска · токен ещё \(minutes) мин",
                      "Waiting to start · token valid \(minutes) min",
                      "In attesa di avvio · token valido \(minutes) min")
    }

    // MARK: - Имя

    enum NameState { case empty, bad, ok }

    /// Проверка на лету — тем же каноническим видом ядра, что и при отправке.
    private var nameState: NameState {
        let raw = name.trimmingCharacters(in: .whitespaces)
        if raw.isEmpty { return .empty }
        guard let canonical = try? canonicalUsername(raw: raw), canonical.hasSuffix("bot") else { return .bad }
        return .ok
    }

    private var nameHint: String {
        L10n.t("Латиница, цифры и _, в конце — bot. Например: news_bot",
               "Latin letters, digits and _, ending in bot. For example: news_bot",
               "Lettere latine, cifre e _, che termina con bot. Ad esempio: news_bot")
    }

    // MARK: - Ядро

    private func load(refresh: Bool) async {
        guard let messenger = try? CoreStore.shared.current() else { loaded = true; return }
        username = ((try? await Background.run { try messenger.ownUsername() }) ?? nil) ?? ""
        let isPremium = (try? await Background.run { () -> Bool in
            if !refresh, (try? messenger.premiumCached()) == true { return true }
            return (try? messenger.refreshPremium(nowMillis: CoreStore.nowMillis)) ?? false
        }) ?? false
        withAnimation { premium = isPremium }
        if isPremium {
            bots = (try? await Background.run { try messenger.botList(nowMillis: CoreStore.nowMillis) }) ?? bots
        }
        loaded = true
    }

    /// Токен под имя из поля — либо новый токен ждущему боту (`again`):
    /// сервер заменит прежнюю строку.
    private func create(_ again: String? = nil) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        // Имя — в каноническом виде ядра, как у аккаунтов.
        guard let canonical = try? canonicalUsername(raw: again ?? name), canonical.hasSuffix("bot") else {
            error = L10n.t("Имя бота: латиница, цифры и _, в конце — bot", "Bot name: Latin letters, digits and _, ending in bot", "Nome del bot: lettere latine, cifre e _, che termina con bot")
            return
        }
        error = nil
        working = true
        nameFocused = false
        Task {
            do {
                let line = try await Background.run { try messenger.createBot(username: canonical, nowMillis: CoreStore.nowMillis) }
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                token = BotToken(name: canonical, line: line)
                if again == nil { name = "" }
            } catch FfiError.UsernameTaken {
                error = L10n.t("Это имя занято", "This name is taken", "Questo nome è già in uso")
            } catch FfiError.InvalidArgument {
                error = L10n.t("Имя бота: латиница, цифры и _, в конце — bot", "Bot name: Latin letters, digits and _, ending in bot", "Nome del bot: lettere latine, cifre e _, che termina con bot")
            } catch {
                // Внутри `catch` имя `error` — пойманная ошибка, поле — через self.
                self.error = L10n.t("Не получилось: нет связи с сервером либо ботов уже слишком много",
                               "Did not work: no connection to the server, or there are too many bots already", "Non riuscito: nessuna connessione al server o ci sono già troppi bot")
            }
            working = false
            await load(refresh: false)
        }
    }

    private func delete(_ bot: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        deleting = nil
        Task {
            _ = try? await Background.run { try messenger.deleteBot(username: bot, nowMillis: CoreStore.nowMillis) }
            await load(refresh: false)
        }
    }
}

/// Токен нового бота: строка, кнопка «Скопировать» и что с ней делать.
/// Показывается один раз; закрыли — строки больше нигде нет.
struct BotTokenSheet: View {
    let token: BotsScreen.BotToken
    @State private var copied = false
    @State private var copiedCommand = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 12) {
                        Avatar(name: token.name, size: 52)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("@\(token.name)").font(GasFont.display(22)).foregroundStyle(GasAppColor.textPrimary)
                            Text(L10n.t("Бот создан", "Bot created", "Bot creato")).font(GasFont.text(14)).foregroundStyle(GasAppColor.ok)
                        }
                    }

                    Text(token.line)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(GasAppColor.textPrimary)
                        .textSelection(.enabled)
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(GasAppColor.line, lineWidth: 1))

                    GoldButton(title: copied ? L10n.t("Скопировано", "Copied", "Copiato") : L10n.t("Копировать токен", "Copy token", "Copia token")) {
                        // 🔐 Только локально и с истечением через минуту.
                        UIPasteboard.general.setItems([["public.utf8-plain-text": token.line]],
                                                      options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
                        UINotificationFeedbackGenerator().notificationOccurred(.success)
                        withAnimation { copied = true }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        Text(L10n.t("Или сразу команда для машины бота", "Or the whole command for the bot’s machine", "Oppure il comando completo per la macchina del bot"))
                            .font(GasFont.text(13, .semibold)).foregroundStyle(GasAppColor.textSecondary)
                        Text(command)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(GasAppColor.textSecondary)
                            .textSelection(.enabled)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(RoundedRectangle(cornerRadius: 12).fill(GasAppColor.bgCard))
                        Button {
                            UIPasteboard.general.setItems([["public.utf8-plain-text": command]],
                                                          options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
                            UINotificationFeedbackGenerator().notificationOccurred(.success)
                            withAnimation { copiedCommand = true }
                        } label: {
                            Label(copiedCommand ? L10n.t("Скопировано", "Copied", "Copiato") : L10n.t("Копировать команду", "Copy command", "Copia comando"),
                                  systemImage: copiedCommand ? "checkmark" : "terminal")
                                .font(GasFont.text(15, .semibold))
                        }
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        step(1, L10n.t("На машине, где будет работать бот, выполните эту команду: она зарегистрирует бота по токену.",
                                       "On the machine where the bot will run, execute this command: it registers the bot with the token.",
                                       "Sulla macchina dove girerà il bot, esegui questo comando: registra il bot con il token."))
                        step(2, L10n.t("Затем запускайте его: gasapp-bot run --data ./\(token.name). Пока он не зарегистрирован, в «Моих ботах» он «ждёт запуска».",
                                       "Then start it with gasapp-bot run --data ./\(token.name). Until it registers, My bots shows it as waiting to start.",
                                       "Poi avvialo con gasapp-bot run --data ./\(token.name). Finché non si registra, I miei bot lo mostra in attesa di avvio."))
                        step(3, L10n.t("Чтобы бот вёл канал — назначьте его администратором в «Управлении» канала.",
                                       "To let the bot run a channel, make it an administrator in the channel’s Manage screen.",
                                       "Perché il bot gestisca un canale, nominalo amministratore in «Gestisci» del canale."))
                    }

                    Banner(title: L10n.t("Строка показывается один раз", "Shown only once", "Mostrata una sola volta"),
                           message: L10n.t("Она действует час и годится один раз; здесь не сохраняется. Закрыли, не скопировав, — в «Моих ботах» нажмите «Новый токен». Ключи бота появятся там, где он работает, — этот телефон их не увидит.",
                                           "It is valid for an hour and works once; it is not stored here. Closed it without copying? Tap New token in My bots. The bot’s keys are created where it runs — this phone never sees them.",
                                           "Vale un’ora e funziona una sola volta; qui non viene salvata. Chiusa senza copiarla? Tocca Nuovo token in I miei bot. Le chiavi del bot vengono create dove il bot gira: questo telefono non le vede mai."),
                           tone: .info)
                }
                .padding(20)
            }
            .gasScreen()
            .navigationTitle(L10n.t("Токен бота", "Bot token", "Token del bot"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button(L10n.t("Готово", "Done", "Fatto")) { dismiss() } } }
        }
    }

    /// Команда регистрации целиком: адрес сервера — тот, с которым
    /// работает приложение.
    private var command: String {
        let server = AppConfig.serverURL?.absoluteString ?? "https://…"
        return "gasapp-bot init --server \(server) --data ./\(token.name) --token '\(token.line)'"
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(GasFont.sign(14))
                .foregroundStyle(GasAppColor.accentOn)
                .frame(width: 26, height: 26)
                .background(Circle().fill(GasAppColor.accent))
            Text(text).font(GasFont.text(15)).foregroundStyle(GasAppColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
