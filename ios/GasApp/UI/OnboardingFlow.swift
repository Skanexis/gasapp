// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// Регистрация — тот же порядок, что `OnboardingActivity`:
/// приветствие → имя и почта → PIN (дважды) и выбор сети → база
/// открывается под PIN → письмо с кодом → код → аккаунт.
///
/// 🔐 Сбой до письма стирает недорегистрированную базу: иначе повторная
/// попытка с другим PIN получила бы базу под первым PIN, а после
/// перезапуска пустая база выглядела бы аккаунтом.
struct OnboardingFlow: View {
    @Environment(AppModel.self) private var model

    enum Step { case welcome, account, pin, confirmPin, code }

    @State private var step: Step = .welcome
    @State private var username = ""
    @State private var email = ""
    @State private var usernameError: String?
    @State private var emailError: String?
    @State private var viaTor = false

    @State private var pin: [UInt8] = []
    @State private var firstPin: [UInt8] = []
    @State private var pinError: String?
    /// Ошибка шага PIN — сбой связи, а не сам PIN: другой заголовок.
    @State private var pinErrorIsNetwork = false

    @State private var code = ""
    @State private var codeError: String?
    @State private var working = false
    @State private var stage = ""
    @State private var resendAt = Date.distantPast
    /// Письмо с кодом отправляется прямо сейчас (кнопка «ещё раз»).
    @State private var resending = false
    @State private var codeNote: String?
    /// Когда начался текущий долгий запрос — для «… N с» на кнопке.
    @State private var startedAt: Date?
    @State private var now = Date()
    /// Возвращение аккаунта из копии: имя и почта не нужны — они в копии.
    @State private var recovering = false
    @State private var showRestore = false

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        GeometryReader { screen in
            ScrollView {
                VStack(spacing: 24) {
                    if canGoBack {
                        Button(action: goBack) {
                            Label(L10n.t("Назад", "Back", "Indietro"), systemImage: "chevron.left")
                                .font(GasFont.text(17, .semibold))
                                .foregroundStyle(GasAppColor.accent)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    switch step {
                    case .welcome: welcome
                    case .account: account
                    case .pin, .confirmPin: pinStep
                    case .code: codeStep
                    }
                }
                // Приветствие — во всю ширину: сцена без полей, отступы — у блоков под ней.
                .padding(step == .welcome ? 0 : 24)
                // PIN — на всю высоту экрана: клавиатура посередине, Tor
                // внизу. Раньше всё жалось к верху, а низ пустовал
                // (снимок с iPhone 15 Pro, 2026-11-12). На маленьком
                // экране высота не мешает: остаётся прокрутка.
                .frame(minHeight: isPinStep ? screen.size.height : nil, alignment: .top)
            }
        }
        .scrollDismissesKeyboard(.interactively)
        // Небо приветствия — до самого верха, под строкой состояния: иначе
        // над ним оставалась тёмная полоса (снимок на Mac).
        .ignoresSafeArea(.container, edges: step == .welcome ? .top : [])
        .gasScreen()
        .onReceive(ticker) { now = $0 }
        .fullScreenCover(isPresented: $showRestore, onDismiss: {
            // Закрыли, не вернув аккаунт, — база без аккаунта не нужна.
            if !(((try? CoreStore.shared.current().ownUsername()) ?? nil) != nil) {
                CoreStore.shared.wipe()
                recovering = false
                step = .welcome
            }
        }) {
            NavigationStack {
                RestoreScreen(recovering: true) {
                    showRestore = false
                    model.didUnlock()
                }
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(L10n.t("Отмена", "Cancel", "Annulla")) { showRestore = false }
                    }
                }
            }
        }
        .onAppear {
            // Продолжение после входа по PIN: база открыта, ждём код.
            if let pending = model.takeResume() {
                username = pending.username
                email = pending.email
                step = .code
            }
        }
    }

    // MARK: - Приветствие

    private var welcome: some View {
        VStack(spacing: 0) {
            // Сцена: ночное небо с туманностями (design/brand), на нём — логотип GAS.
            ZStack {
                // Картинка — в рамке ровно по ширине экрана: scaledToFill без
                // рамки растягивал всю страницу шире экрана, и карточка с
                // кнопками упирались в края (снимок на Mac, 2026-11-07).
                Color.clear
                    .frame(maxWidth: .infinity)
                    .frame(height: 340)
                    .overlay { Image("SceneWelcome").resizable().scaledToFill() }
                    .clipped()
                    .accessibilityHidden(true)
                VStack {
                    Spacer()
                    LinearGradient(colors: [.clear, GasAppColor.bgBase], startPoint: .top, endPoint: .bottom)
                        .frame(height: 110)
                }
                .accessibilityHidden(true)
                Image("Logo")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 260)
                    .rotationEffect(.degrees(-3))
                    .accessibilityLabel("GasApp")
                    .accessibilityAddTraits(.isHeader)
            }
            .frame(height: 340)

            VStack(spacing: 20) {
                Text(L10n.t("Мессенджер со сквозным шифрованием. Начало переписки защищено и от будущих квантовых компьютеров.",
                            "An end-to-end encrypted messenger. Starting a conversation is protected against future quantum computers too.", "Un messenger con cifratura end-to-end. L’avvio di una conversazione è protetto anche dai futuri computer quantistici."))
                    .font(GasFont.text(17, .medium))
                    .foregroundStyle(GasAppColor.textSecondary)
                    .multilineTextAlignment(.center)

                // Три обещания — коротко и без жаргона (как на Android).
                VStack(alignment: .leading, spacing: 14) {
                    WelcomePromise(icon: "lock.fill",
                                   text: L10n.t("Сообщения шифруются на телефоне. Сервер только передаёт их и прочитать не может.",
                                                "Messages are encrypted on your phone. The server only passes them on and cannot read them.", "I messaggi vengono cifrati sul tuo telefono. Il server li inoltra soltanto e non può leggerli."))
                    WelcomePromise(icon: "person.fill",
                                   text: L10n.t("Без номера телефона. Аккаунт — это имя и адрес почты; сервер хранит только хеш адреса.",
                                                "No phone number. An account is a username and an email address — the server keeps only a hash of the address.", "Nessun numero di telefono. Un account è un nome utente e un indirizzo email: il server conserva solo un hash dell’indirizzo."))
                    WelcomePromise(icon: "globe",
                                   text: L10n.t("Tor встроен: включите его — и сервер не увидит ваш IP-адрес.",
                                                "Tor is built in: turn it on and the server does not see your IP address.", "Tor è integrato: attivalo e il server non vede il tuo indirizzo IP."))
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(GasAppColor.bgCard, in: RoundedRectangle(cornerRadius: 16))
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(GasAppColor.line, lineWidth: 1))

                GoldButton(title: L10n.t("Начать", "Get started", "Inizia")) { step = .account }
                    .padding(.top, 8)
                OutlineButton(title: L10n.t("У меня есть резервная копия", "I have a backup", "Ho un backup")) {
                    recovering = true
                    step = .pin
                }
                Button(L10n.t("Политика конфиденциальности", "Privacy policy", "Informativa sulla privacy")) {
                    UIApplication.shared.open(AppConfig.docsURL.appendingPathComponent("privacy/"))
                }
                .font(GasFont.text(14))
                .foregroundStyle(GasAppColor.textTertiary)
                Text(L10n.t("Регистрация — с 16 лет.", "You must be 16 or older.", "Devi avere almeno 16 anni."))
                    .font(GasFont.text(13))
                    .foregroundStyle(GasAppColor.textQuaternary)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 24)
        }
    }

    // MARK: - Имя и почта

    private var account: some View {
        VStack(alignment: .leading, spacing: 20) {
            ScreenTitle(text: L10n.t("Аккаунт", "Account", "Account"),
                        subtitle: L10n.t("Имя увидят те, кому вы напишете. Почта нужна только для кода и не хранится на сервере.",
                                         "People you message see your name. Email is only for the code and is not stored on the server.", "Le persone a cui scrivi vedono il tuo nome. L’email serve solo per il codice e non viene salvata sul server."))
            Field(title: L10n.t("Имя пользователя", "Username", "Nome utente"), text: $username,
                  placeholder: "anna_k", error: usernameError, contentType: .username)
            Field(title: L10n.t("Почта", "Email", "Email"), text: $email,
                  placeholder: "you@example.org", error: emailError,
                  keyboard: .emailAddress, contentType: .emailAddress)
            GoldButton(title: L10n.t("Дальше", "Next", "Avanti")) { checkAccount() }
        }
    }

    private func checkAccount() {
        usernameError = nil
        emailError = nil
        // Имя — в каноническом виде ядра (регистр, пробелы): то же, что
        // увидит сервер и что найдут другие.
        guard let canonical = try? canonicalUsername(raw: username) else {
            usernameError = L10n.t("3–32 символа: латиница, цифры, «_».", "3–32 characters: letters, digits, “_”.", "3–32 caratteri: lettere, cifre, «_».")
            return
        }
        username = canonical
        let trimmed = email.trimmingCharacters(in: .whitespaces)
        guard trimmed.contains("@"), trimmed.contains(".") else {
            emailError = L10n.t("Похоже, это не адрес почты", "That doesn’t look like an email", "Non sembra un indirizzo email")
            return
        }
        step = .pin
    }

    // MARK: - Назад

    private var isPinStep: Bool { step == .pin || step == .confirmPin }

    /// Назад — до того, как открыта база: на шаге кода аккаунт уже
    /// создаётся, и возврат идёт через ошибки этого шага.
    private var canGoBack: Bool {
        !working && (step == .account || isPinStep)
    }

    private func goBack() {
        pinError = nil
        pin.wipe(); pin = []
        switch step {
        case .account:
            step = .welcome
        case .pin:
            if recovering {
                recovering = false
                step = .welcome
            } else {
                step = .account
            }
        case .confirmPin:
            firstPin.wipe(); firstPin = []
            step = .pin
        default:
            break
        }
    }

    // MARK: - PIN

    private var pinStep: some View {
        VStack(spacing: 22) {
            ScreenTitle(
                text: step == .pin ? L10n.t("Придумайте PIN", "Create a PIN", "Crea un PIN") : L10n.t("Повторите PIN", "Repeat the PIN", "Ripeti il PIN"),
                subtitle: L10n.t("Шесть цифр. Им открывается переписка на этом телефоне. Восстановить PIN нельзя.",
                                 "Six digits. It unlocks your messages on this phone. A PIN cannot be recovered.", "Sei cifre. Sblocca i tuoi messaggi su questo telefono. Il PIN non si può recuperare.")
            )
            if let pinError {
                Banner(title: pinErrorIsNetwork
                       ? L10n.t("Аккаунт не создан", "Account not created", "Account non creato")
                       : L10n.t("PIN не подходит", "PIN not accepted", "PIN non accettato"),
                       message: pinError, tone: .error)
            }
            if working {
                VStack(spacing: 10) {
                    ProgressView().tint(GasAppColor.accent)
                    Text(stage).font(GasFont.text(15)).foregroundStyle(GasAppColor.textSecondary)
                }
                .frame(height: 80)
            }
            Spacer(minLength: 8)
            PinPad(digits: $pin, isEnabled: !working) { pinEntered() }
            Spacer(minLength: 8)

            if step == .pin {
                TorChoiceCard(isOn: $viaTor)
            }
        }
    }

    private func pinEntered() {
        var entered = pin
        pin.wipe(); pin = []
        pinError = nil
        pinErrorIsNetwork = false

        if step == .pin {
            guard PinPolicy.isAcceptable(entered) else { entered.wipe(); return }
            guard !PinPolicy.isTooSimple(entered) else {
                entered.wipe()
                pinError = L10n.t("Такой PIN подбирают первым. Выберите другой.",
                                  "PINs like this are guessed first. Choose another.", "PIN come questo vengono indovinati per primi. Scegline un altro.")
                return
            }
            firstPin = entered
            step = .confirmPin
            return
        }

        // Повтор: совпал ли с первым.
        guard entered == firstPin else {
            entered.wipe(); firstPin.wipe(); firstPin = []
            pinError = L10n.t("PIN не совпали. Придумайте заново.", "PINs did not match. Try again.", "I PIN non coincidono. Riprova.")
            step = .pin
            return
        }
        firstPin.wipe(); firstPin = []
        if recovering { openForRecovery(pin: entered) } else { createAccount(pin: entered) }
    }

    private func createAccount(pin: [UInt8]) {
        working = true
        let name = username
        let address = email.trimmingCharacters(in: .whitespaces)
        let tor = viaTor

        Task {
            do {
                stage = L10n.t("Создаём ключи…", "Creating keys…", "Creazione delle chiavi…")
                // Выбор сети — до открытия базы: его применит CoreStore.open.
                CoreStore.shared.pendingProxy = tor ? .tor : .direct
                let copy = pin
                let messenger = try await Background.run { try CoreStore.shared.unlock(pin: copy) }

                if tor {
                    stage = L10n.t("Подключаемся к Tor…", "Connecting to Tor…", "Connessione a Tor…")
                    let ready = await NetworkController.shared.awaitTor(timeout: 180) { status in
                        Task { @MainActor in
                            stage = L10n.t("Подключаемся к Tor… \(status.percent)%", "Connecting to Tor… \(status.percent)%", "Connessione a Tor… \(status.percent)%")
                        }
                    }
                    guard ready else { throw OnboardingFailure.torNotReady }
                }

                stage = L10n.t("Отправляем письмо с кодом…", "Sending the code…", "Invio del codice…")
                try await Background.run {
                    try messenger.setPendingRegistration(username: name, email: address)
                    try messenger.requestEmailCode(email: address)
                }
                working = false
                resendAt = Date().addingTimeInterval(60)
                step = .code
            } catch {
                // 🔐 Незарегистрированная база стирается.
                CoreStore.shared.wipe()
                working = false
                step = .pin
                if case .InvalidEmail = error as? FfiError {
                    step = .account
                    emailError = L10n.t("Почта не принята", "Email not accepted", "Email non accettata")
                } else {
                    pinErrorIsNetwork = true
                    pinError = Self.message(for: error, viaTor: tor)
                }
            }
        }
    }

    // MARK: - Код из письма

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            ScreenTitle(text: L10n.t("Код из письма", "Code from email", "Codice dall’email"),
                        subtitle: L10n.t("Мы отправили 6 цифр на \(email). Проверьте и «Спам».",
                                         "We sent 6 digits to \(email). Check spam too.", "Abbiamo inviato 6 cifre a \(email). Controlla anche lo spam."))
            Field(title: L10n.t("Код", "Code", "Codice"), text: $code, placeholder: "123456",
                  error: codeError, keyboard: .numberPad, contentType: .oneTimeCode)
            GoldButton(title: working
                           ? L10n.t("Проверяем код… \(elapsed) с", "Checking the code… \(elapsed) s", "Verifica del codice… \(elapsed) s")
                           : L10n.t("Подтвердить", "Confirm", "Conferma"),
                       isEnabled: !working && !resending && code.filter(\.isNumber).count == 6) { confirmCode() }
            if (working || resending) && elapsed >= 15 {
                // Ожидание — штатное состояние (PRODUCT.md): говорим, что
                // происходит, а не крутим колесо молча.
                Text(L10n.t("Сервер отвечает медленно. Подождите — запрос не потерялся; если через минуту ответа не будет, появится ошибка.",
                            "The server is slow to answer. Please wait — the request is not lost; if there is no answer within a minute, you’ll see an error.",
                            "Il server risponde lentamente. Attendi: la richiesta non è persa; se entro un minuto non arriva risposta, vedrai un errore."))
                    .font(GasFont.text(13)).foregroundStyle(GasAppColor.textSecondary)
                    .transition(.opacity)
            }
            if let codeNote {
                Label(codeNote, systemImage: "checkmark.circle.fill")
                    .font(GasFont.text(14, .semibold)).foregroundStyle(GasAppColor.ok)
                    .transition(.opacity)
            }
            OutlineButton(
                title: resending
                    ? L10n.t("Отправляем письмо… \(elapsed) с", "Sending the email… \(elapsed) s", "Invio dell’email… \(elapsed) s")
                    : now < resendAt
                    ? L10n.t("Отправить ещё раз через \(Int(resendAt.timeIntervalSince(now)) + 1) с",
                             "Resend in \(Int(resendAt.timeIntervalSince(now)) + 1) s", "Nuovo invio tra \(Int(resendAt.timeIntervalSince(now)) + 1) s")
                    : L10n.t("Отправить код ещё раз", "Resend code", "Invia di nuovo il codice"),
                isEnabled: now >= resendAt && !working && !resending
            ) { resend() }
        }
    }

    /// Секунды с начала текущего долгого запроса.
    private var elapsed: Int {
        guard let startedAt else { return 0 }
        return max(0, Int(now.timeIntervalSince(startedAt)))
    }

    private func confirmCode() {
        // Повторное нажатие, пока идёт первый запрос, не шлёт второй.
        guard !working else { return }
        let digits = code.filter(\.isNumber)
        let name = username
        let address = email.trimmingCharacters(in: .whitespaces)
        working = true
        startedAt = Date()
        codeError = nil
        codeNote = nil

        Task {
            do {
                let messenger = try CoreStore.shared.current()
                let account = try await Background.run {
                    try messenger.register(username: name, email: address, emailCode: digits,
                                           nowMillis: CoreStore.nowMillis)
                }
                CoreStore.shared.rememberDevice(account.deviceId)
                CoreStore.shared.maintainPrekeysNow()
                working = false
                startedAt = nil
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                model.didUnlock()
            } catch {
                working = false
                startedAt = nil
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                switch error as? FfiError {
                case .EmailCodeRejected:
                    codeError = L10n.t("Код не подошёл или истёк", "Wrong or expired code", "Codice errato o scaduto")
                case .UsernameTaken:
                    step = .account
                    usernameError = L10n.t("Это имя занято", "That username is taken", "Questo nome utente è già in uso")
                case .EmailTaken:
                    step = .account
                    emailError = L10n.t("На эту почту уже есть аккаунт", "This email already has an account", "Questa email ha già un account")
                default:
                    codeError = Self.message(for: error, viaTor: viaTor)
                }
            }
        }
    }

    private func resend() {
        guard !resending, !working else { return }
        let address = email.trimmingCharacters(in: .whitespaces)
        resending = true
        startedAt = Date()
        codeError = nil
        codeNote = nil
        Task {
            do {
                let messenger = try CoreStore.shared.current()
                try await Background.run { try messenger.requestEmailCode(email: address) }
                resendAt = Date().addingTimeInterval(60)
                code = ""
                codeNote = L10n.t("Новый код отправлен. Прежний больше не действует.",
                                  "A new code is on its way. The previous one no longer works.",
                                  "Un nuovo codice è in arrivo. Il precedente non funziona più.")
            } catch {
                codeError = L10n.t("Письмо не ушло. Проверьте интернет; новый код можно просить раз в минуту.",
                                   "The email was not sent. Check your connection; a new code can be requested once a minute.",
                                   "L’email non è partita. Controlla la connessione; un nuovo codice si può chiedere una volta al minuto.")
                resendAt = Date().addingTimeInterval(30)
            }
            resending = false
            startedAt = nil
        }
    }

    /// База — под новым PIN, сеть — по выбору; дальше экран копии вернёт
    /// аккаунт. 🔐 Не дошло до конца — база стирается (как у регистрации).
    private func openForRecovery(pin: [UInt8]) {
        working = true
        let tor = viaTor
        Task {
            do {
                stage = L10n.t("Создаём ключи…", "Creating keys…", "Creazione delle chiavi…")
                CoreStore.shared.pendingProxy = tor ? .tor : .direct
                let copy = pin
                _ = try await Background.run { try CoreStore.shared.unlock(pin: copy) }
                if tor {
                    stage = L10n.t("Подключаемся к Tor…", "Connecting to Tor…", "Connessione a Tor…")
                    guard await NetworkController.shared.awaitTor(timeout: 180, progress: { _ in }) else {
                        throw OnboardingFailure.torNotReady
                    }
                }
                working = false
                showRestore = true
            } catch {
                CoreStore.shared.wipe()
                working = false
                step = .pin
                pinErrorIsNetwork = true
                pinError = Self.message(for: error, viaTor: tor)
            }
        }
    }

    enum OnboardingFailure: Error { case torNotReady }

    static func message(for error: Error, viaTor: Bool) -> String {
        if case .torNotReady = error as? OnboardingFailure {
            return L10n.t("Tor не подключился. Попробуйте ещё раз или без Tor.",
                          "Tor did not connect. Try again or without Tor.", "Tor non si è connesso. Riprova o continua senza Tor.")
        }
        if ClockCheck.off {
            return L10n.t("На телефоне неверное время — сервер не принимает запросы.",
                          "Your phone’s clock is wrong — the server rejects requests.", "L’orologio del telefono è sbagliato: il server rifiuta le richieste.")
        }
        if case .unavailable = error as? EnclaveKey.Failure {
            return L10n.t("Ключ устройства недоступен.", "Device key unavailable.", "Chiave del dispositivo non disponibile.")
        }
        return viaTor
            ? L10n.t("Нет связи с сервером через Tor.", "Cannot reach the server via Tor.", "Impossibile raggiungere il server tramite Tor.")
            : L10n.t("Нет связи с сервером. Проверьте интернет.", "Cannot reach the server. Check your connection.", "Impossibile raggiungere il server. Controlla la connessione.")
    }
}

/// Одно обещание на приветствии: золотой значок и короткий текст.
private struct WelcomePromise: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(GasAppColor.accent)
                .frame(width: 22)
                .accessibilityHidden(true)
            Text(text)
                .font(GasFont.text(15))
                .foregroundStyle(GasAppColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Выбор Tor на регистрации — заметной карточкой, а не строкой внизу:
/// от него зависит, увидит ли сервер адрес человека (PRODUCT.md,
/// принцип 1 — выбор осознанный).
struct TorChoiceCard: View {
    @Binding var isOn: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button {
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            withAnimation(reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.75)) { isOn.toggle() }
        } label: {
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .fill(isOn ? GasAppColor.accent : GasAppColor.bgHover)
                        .shadow(color: isOn ? GasAppColor.accent.opacity(0.55) : .clear, radius: 12, y: 2)
                    Image(systemName: isOn ? "shield.lefthalf.filled" : "shield.slash")
                        .font(.system(size: 22, weight: .bold))
                        .foregroundStyle(isOn ? GasAppColor.accentOn : GasAppColor.textTertiary)
                        .contentTransition(.symbolEffect(.replace))
                }
                .frame(width: 50, height: 50)

                VStack(alignment: .leading, spacing: 4) {
                    Text(L10n.t("Через Tor", "Use Tor", "Usa Tor"))
                        .font(GasFont.sign(17))
                        .foregroundStyle(GasAppColor.textPrimary)
                    HStack(spacing: 5) {
                        Image(systemName: isOn ? "eye.slash.fill" : "eye.fill").font(.system(size: 11, weight: .bold))
                        Text(isOn
                             ? L10n.t("IP скрыт от сервера · медленнее", "IP hidden from the server · slower", "IP nascosto al server · più lento")
                             : L10n.t("Сервер увидит ваш IP", "The server will see your IP", "Il server vedrà il tuo IP"))
                            .font(GasFont.text(13, .semibold))
                    }
                    .foregroundStyle(isOn ? GasAppColor.ok : GasAppColor.warn)
                }
                Spacer(minLength: 8)

                // Переключатель в стиле приложения: золото, а не системный зелёный.
                ZStack(alignment: isOn ? .trailing : .leading) {
                    Capsule().fill(isOn ? GasAppColor.accent : GasAppColor.bgHover)
                        .overlay(Capsule().stroke(isOn ? GasAppColor.accentEdge : GasAppColor.line, lineWidth: 1))
                    Circle().fill(isOn ? GasAppColor.accentOn : GasAppColor.textTertiary)
                        .padding(4)
                }
                .frame(width: 54, height: 32)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(isOn
                          ? AnyShapeStyle(LinearGradient(colors: [Color(hex: 0x22105C), Color(hex: 0x1B2259)],
                                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                          : AnyShapeStyle(GasAppColor.bgCard))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(isOn ? GasAppColor.accent.opacity(0.7) : GasAppColor.line, lineWidth: isOn ? 1.5 : 1)
            )
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(L10n.t("Через Tor", "Use Tor", "Usa Tor"))
        .accessibilityValue(isOn ? L10n.t("Включено", "On", "Attivo") : L10n.t("Выключено", "Off", "Disattivo"))
        .accessibilityAddTraits(.isButton)
    }
}
