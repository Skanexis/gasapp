// SPDX-License-Identifier: Apache-2.0

import SwiftUI

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

    @State private var code = ""
    @State private var codeError: String?
    @State private var working = false
    @State private var stage = ""
    @State private var resendAt = Date.distantPast
    @State private var now = Date()
    /// Возвращение аккаунта из копии: имя и почта не нужны — они в копии.
    @State private var recovering = false
    @State private var showRestore = false

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                switch step {
                case .welcome: welcome
                case .account: account
                case .pin, .confirmPin: pinStep
                case .code: codeStep
                }
            }
            .padding(24)
        }
        .scrollDismissesKeyboard(.interactively)
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
                        Button(L10n.t("Отмена", "Cancel")) { showRestore = false }
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
        VStack(spacing: 28) {
            Spacer(minLength: 40)
            Text("GasApp")
                .font(.system(size: 52, weight: .black, design: .rounded))
                .foregroundStyle(GasAppColor.accent)
                .shadow(color: GasAppColor.accentEdgeDeep, radius: 0, x: 0, y: 4)
            Text(L10n.t("Переписка, которую видите только вы и собеседник.",
                        "Messages only you and the other person can read."))
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(GasAppColor.textSecondary)
                .multilineTextAlignment(.center)
            Spacer(minLength: 60)
            GoldButton(title: L10n.t("Начать", "Get started")) { step = .account }
            OutlineButton(title: L10n.t("У меня есть резервная копия", "I have a backup")) {
                recovering = true
                step = .pin
            }
            Button(L10n.t("Политика конфиденциальности", "Privacy policy")) {
                UIApplication.shared.open(AppConfig.docsURL.appendingPathComponent("privacy/"))
            }
            .font(.system(size: 14))
            .foregroundStyle(GasAppColor.textTertiary)
            Text(L10n.t("Регистрация — с 16 лет.", "You must be 16 or older."))
                .font(.system(size: 13))
                .foregroundStyle(GasAppColor.textQuaternary)
        }
    }

    // MARK: - Имя и почта

    private var account: some View {
        VStack(alignment: .leading, spacing: 20) {
            ScreenTitle(text: L10n.t("Аккаунт", "Account"),
                        subtitle: L10n.t("Имя увидят те, кому вы напишете. Почта нужна только для кода и не хранится на сервере.",
                                         "People you message see your name. Email is only for the code and is not stored on the server."))
            Field(title: L10n.t("Имя пользователя", "Username"), text: $username,
                  placeholder: "anna_k", error: usernameError, contentType: .username)
            Field(title: L10n.t("Почта", "Email"), text: $email,
                  placeholder: "you@example.org", error: emailError,
                  keyboard: .emailAddress, contentType: .emailAddress)
            GoldButton(title: L10n.t("Дальше", "Next")) { checkAccount() }
        }
    }

    private func checkAccount() {
        usernameError = nil
        emailError = nil
        // Имя — в каноническом виде ядра (регистр, пробелы): то же, что
        // увидит сервер и что найдут другие.
        guard let canonical = try? canonicalUsername(raw: username) else {
            usernameError = L10n.t("3–32 символа: латиница, цифры, «_».", "3–32 characters: letters, digits, “_”.")
            return
        }
        username = canonical
        let trimmed = email.trimmingCharacters(in: .whitespaces)
        guard trimmed.contains("@"), trimmed.contains(".") else {
            emailError = L10n.t("Похоже, это не адрес почты", "That doesn’t look like an email")
            return
        }
        step = .pin
    }

    // MARK: - PIN

    private var pinStep: some View {
        VStack(spacing: 22) {
            ScreenTitle(
                text: step == .pin ? L10n.t("Придумайте PIN", "Create a PIN") : L10n.t("Повторите PIN", "Repeat the PIN"),
                subtitle: L10n.t("Шесть цифр. Им открывается переписка на этом телефоне. Восстановить PIN нельзя.",
                                 "Six digits. It unlocks your messages on this phone. A PIN cannot be recovered.")
            )
            if let pinError {
                Banner(title: L10n.t("PIN не подходит", "PIN not accepted"), message: pinError, tone: .error)
            }
            if working {
                VStack(spacing: 10) {
                    ProgressView().tint(GasAppColor.accent)
                    Text(stage).font(.system(size: 15)).foregroundStyle(GasAppColor.textSecondary)
                }
                .frame(height: 80)
            }
            PinPad(digits: $pin, isEnabled: !working) { pinEntered() }

            if step == .pin {
                Toggle(isOn: $viaTor) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(L10n.t("Через Tor", "Use Tor")).foregroundStyle(GasAppColor.textPrimary)
                        Text(L10n.t("Скрывает ваш адрес от сервера. Медленнее.",
                                    "Hides your address from the server. Slower."))
                            .font(.system(size: 13)).foregroundStyle(GasAppColor.textTertiary)
                    }
                }
                .tint(GasAppColor.accent)
            }
        }
    }

    private func pinEntered() {
        var entered = pin
        pin.wipe(); pin = []
        pinError = nil

        if step == .pin {
            guard PinPolicy.isAcceptable(entered) else { entered.wipe(); return }
            guard !PinPolicy.isTooSimple(entered) else {
                entered.wipe()
                pinError = L10n.t("Такой PIN подбирают первым. Выберите другой.",
                                  "PINs like this are guessed first. Choose another.")
                return
            }
            firstPin = entered
            step = .confirmPin
            return
        }

        // Повтор: совпал ли с первым.
        guard entered == firstPin else {
            entered.wipe(); firstPin.wipe(); firstPin = []
            pinError = L10n.t("PIN не совпали. Придумайте заново.", "PINs did not match. Try again.")
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
                stage = L10n.t("Создаём ключи…", "Creating keys…")
                // Выбор сети — до открытия базы: его применит CoreStore.open.
                CoreStore.shared.pendingProxy = tor ? .tor : .direct
                let copy = pin
                let messenger = try await Background.run { try CoreStore.shared.unlock(pin: copy) }

                if tor {
                    stage = L10n.t("Подключаемся к Tor…", "Connecting to Tor…")
                    let ready = await NetworkController.shared.awaitTor(timeout: 180) { status in
                        Task { @MainActor in
                            stage = L10n.t("Подключаемся к Tor… \(status.percent)%", "Connecting to Tor… \(status.percent)%")
                        }
                    }
                    guard ready else { throw OnboardingFailure.torNotReady }
                }

                stage = L10n.t("Отправляем письмо с кодом…", "Sending the code…")
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
                    emailError = L10n.t("Почта не принята", "Email not accepted")
                } else {
                    pinError = Self.message(for: error, viaTor: tor)
                }
            }
        }
    }

    // MARK: - Код из письма

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            ScreenTitle(text: L10n.t("Код из письма", "Code from email"),
                        subtitle: L10n.t("Мы отправили 6 цифр на \(email). Проверьте и «Спам».",
                                         "We sent 6 digits to \(email). Check spam too."))
            Field(title: L10n.t("Код", "Code"), text: $code, placeholder: "123456",
                  error: codeError, keyboard: .numberPad, contentType: .oneTimeCode)
            GoldButton(title: L10n.t("Подтвердить", "Confirm"), isLoading: working,
                       isEnabled: code.filter(\.isNumber).count == 6) { confirmCode() }
            OutlineButton(
                title: now < resendAt
                    ? L10n.t("Отправить ещё раз через \(Int(resendAt.timeIntervalSince(now)) + 1) с",
                             "Resend in \(Int(resendAt.timeIntervalSince(now)) + 1) s")
                    : L10n.t("Отправить код ещё раз", "Resend code"),
                isEnabled: now >= resendAt && !working
            ) { resend() }
        }
    }

    private func confirmCode() {
        let digits = code.filter(\.isNumber)
        let name = username
        let address = email.trimmingCharacters(in: .whitespaces)
        working = true
        codeError = nil

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
                model.didUnlock()
            } catch {
                working = false
                switch error as? FfiError {
                case .EmailCodeRejected:
                    codeError = L10n.t("Код не подошёл или истёк", "Wrong or expired code")
                case .UsernameTaken:
                    step = .account
                    usernameError = L10n.t("Это имя занято", "That username is taken")
                case .EmailTaken:
                    step = .account
                    emailError = L10n.t("На эту почту уже есть аккаунт", "This email already has an account")
                default:
                    codeError = Self.message(for: error, viaTor: viaTor)
                }
            }
        }
    }

    private func resend() {
        let address = email.trimmingCharacters(in: .whitespaces)
        Task {
            do {
                let messenger = try CoreStore.shared.current()
                try await Background.run { try messenger.requestEmailCode(email: address) }
                resendAt = Date().addingTimeInterval(60)
                codeError = nil
            } catch {
                codeError = L10n.t("Не удалось отправить письмо", "Could not send the email")
            }
        }
    }

    /// База — под новым PIN, сеть — по выбору; дальше экран копии вернёт
    /// аккаунт. 🔐 Не дошло до конца — база стирается (как у регистрации).
    private func openForRecovery(pin: [UInt8]) {
        working = true
        let tor = viaTor
        Task {
            do {
                stage = L10n.t("Создаём ключи…", "Creating keys…")
                CoreStore.shared.pendingProxy = tor ? .tor : .direct
                let copy = pin
                _ = try await Background.run { try CoreStore.shared.unlock(pin: copy) }
                if tor {
                    stage = L10n.t("Подключаемся к Tor…", "Connecting to Tor…")
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
                pinError = Self.message(for: error, viaTor: tor)
            }
        }
    }

    enum OnboardingFailure: Error { case torNotReady }

    static func message(for error: Error, viaTor: Bool) -> String {
        if case .torNotReady = error as? OnboardingFailure {
            return L10n.t("Tor не подключился. Попробуйте ещё раз или без Tor.",
                          "Tor did not connect. Try again or without Tor.")
        }
        if ClockCheck.off {
            return L10n.t("На телефоне неверное время — сервер не принимает запросы.",
                          "Your phone’s clock is wrong — the server rejects requests.")
        }
        if case .unavailable = error as? EnclaveKey.Failure {
            return L10n.t("Ключ устройства недоступен.", "Device key unavailable.")
        }
        return viaTor
            ? L10n.t("Нет связи с сервером через Tor.", "Cannot reach the server via Tor.")
            : L10n.t("Нет связи с сервером. Проверьте интернет.", "Cannot reach the server. Check your connection.")
    }
}
