// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// «Устройства» — до пяти телефонов на одном аккаунте
/// (`docs/protocol/MULTI-DEVICE.md`).
///
/// Основной телефон сканирует QR нового, оба показывают шесть цифр, и
/// только после «Подключить» новый получает доступ. 🔐 Цифры — защита от
/// подмены QR: не совпали — подключать нельзя.
struct DevicesScreen: View {
    @State private var devices: [FfiOwnDevice] = []
    @State private var isPrimary = false
    @State private var loading = true
    @State private var error: String?
    @State private var note: String?
    @State private var scanning = false
    @State private var preparing = false
    @State private var pendingCode: String?
    @State private var approving = false
    @State private var unlinkTarget: FfiOwnDevice?

    /// Предел сервера и протокола.
    private static let limit = 5

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text(L10n.t("Один аккаунт — до пяти телефонов. Сообщения шифруются для каждого устройства отдельно; сервер прочитать их не может.",
                            "One account — up to five phones. Messages are encrypted separately for each device; the server cannot read them.",
                            "Un account — fino a cinque telefoni. I messaggi sono cifrati separatamente per ogni dispositivo; il server non può leggerli."))
                    .font(GasFont.text(15))
                    .foregroundStyle(GasAppColor.textSecondary)

                if let error {
                    Banner(title: L10n.t("Не получилось", "Didn’t work", "Non ha funzionato"), message: error, tone: .error)
                }
                if let note {
                    Banner(title: L10n.t("Почти готово", "Almost done", "Quasi fatto"), message: note, tone: .ok)
                }

                list

                if isPrimary {
                    GoldButton(title: L10n.t("Подключить устройство", "Link a device", "Collega un dispositivo"),
                               isLoading: preparing,
                               isEnabled: !loading && devices.count < Self.limit) {
                        error = nil
                        note = nil
                        scanning = true
                    }
                    Text(devices.count >= Self.limit
                         ? L10n.t("Устройств уже пять — чтобы подключить новое, отключите одно из них.",
                                  "You already have five devices — unlink one to add another.",
                                  "Hai già cinque dispositivi: scollegane uno per aggiungerne un altro.")
                         : L10n.t("На новом телефоне установите GasApp и на первом экране выберите «Войти с другого телефона» — появится QR-код.",
                                  "On the new phone, install GasApp and choose “Sign in from another phone” on the first screen — a QR code appears.",
                                  "Sul nuovo telefono installa GasApp e scegli «Accedi da un altro telefono» nella prima schermata: apparirà un codice QR."))
                        .font(GasFont.text(13))
                        .foregroundStyle(GasAppColor.textTertiary)
                } else if !loading {
                    Banner(title: L10n.t("Это подключённый телефон", "This is a linked phone", "Questo è un telefono collegato"),
                           message: L10n.t("Подключать и отключать устройства можно только с основного телефона.",
                                           "Devices can be linked and unlinked only from the main phone.",
                                           "I dispositivi si collegano e scollegano solo dal telefono principale."),
                           tone: .info)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Label(L10n.t("История переписки на новое устройство не переносится: там будут сообщения с момента подключения.",
                                 "Message history does not move to a new device: it gets messages from the moment it is linked.",
                                 "La cronologia dei messaggi non passa al nuovo dispositivo: riceve i messaggi dal momento del collegamento."),
                          systemImage: "clock.arrow.circlepath")
                    Label(L10n.t("Сервер знает, сколько у вас устройств, но не знает, с какого из них вы пишете.",
                                 "The server knows how many devices you have, but not which one you write from.",
                                 "Il server sa quanti dispositivi hai, ma non da quale scrivi."),
                          systemImage: "eye.slash")
                }
                .font(GasFont.text(13))
                .foregroundStyle(GasAppColor.textTertiary)
                .padding(.top, 4)
            }
            .padding(16)
        }
        .gasScreen()
        .navigationTitle(L10n.t("Устройства", "Devices", "Dispositivi"))
        .refreshable { await load() }
        .task { await load() }
        .sheet(isPresented: $scanning) {
            QRScanner { code in prepare(code) }
        }
        .sheet(item: Binding(
            get: { pendingCode.map { PendingCode(code: $0) } },
            set: { if $0 == nil, !approving { pendingCode = nil } }
        )) { pending in
            LinkConfirmSheet(code: pending.code, approving: approving,
                             onApprove: approve,
                             onReject: {
                                 pendingCode = nil
                                 error = L10n.t("Цифры не совпали — устройство не подключено. Если вы не начинали подключение, ничего делать не нужно.",
                                                "The digits didn’t match — the device was not linked. If you didn’t start linking, there’s nothing to do.",
                                                "Le cifre non coincidevano: il dispositivo non è stato collegato. Se non hai avviato il collegamento, non serve fare nulla.")
                             })
                .presentationDetents([.medium, .large])
                .interactiveDismissDisabled(approving)
        }
        .confirmationDialog(L10n.t("Отключить устройство?", "Unlink this device?", "Scollegare il dispositivo?"),
                            isPresented: Binding(get: { unlinkTarget != nil }, set: { if !$0 { unlinkTarget = nil } }),
                            titleVisibility: .visible,
                            presenting: unlinkTarget) { device in
            Button(L10n.t("Отключить", "Unlink", "Scollega"), role: .destructive) { unlink(device) }
        } message: { _ in
            Text(L10n.t("Новые сообщения на него больше не придут. Переписка, которая уже есть на нём, там и останется.",
                        "New messages will no longer reach it. Messages already on it stay there.",
                        "I nuovi messaggi non lo raggiungeranno più. I messaggi già presenti restano lì."))
        }
    }

    // MARK: - Список

    @ViewBuilder
    private var list: some View {
        if loading && devices.isEmpty {
            HStack { Spacer(); ProgressView().tint(GasAppColor.accent); Spacer() }
                .padding(.vertical, 24)
        } else if !devices.isEmpty {
            VStack(spacing: 0) {
                ForEach(Array(devices.enumerated()), id: \.element.deviceId) { index, device in
                    if index > 0 {
                        Rectangle().fill(GasAppColor.line).frame(height: 1).padding(.leading, 64)
                    }
                    DeviceRow(device: device, canUnlink: isPrimary && !device.thisDevice) {
                        unlinkTarget = device
                    }
                }
            }
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(GasAppColor.bgCard))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(GasAppColor.line, lineWidth: 1))
        }
    }

    // MARK: - Действия

    private func load() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        loading = true
        isPrimary = (try? await Background.run { try messenger.isPrimaryDevice() }) ?? false
        do {
            let found = try await Background.run { try messenger.ownDevices(nowMillis: CoreStore.nowMillis) }
            // Своё — первым, основное — следом.
            devices = found.sorted { lhs, rhs in
                if lhs.thisDevice != rhs.thisDevice { return lhs.thisDevice }
                return lhs.primary && !rhs.primary
            }
        } catch {
            if devices.isEmpty {
                self.error = L10n.t("Список устройств не загрузился. Проверьте связь и потяните экран вниз.",
                                    "The device list didn’t load. Check your connection and pull down to retry.",
                                    "L’elenco dei dispositivi non si è caricato. Controlla la connessione e trascina verso il basso.")
            }
        }
        loading = false
    }

    private func prepare(_ uri: String) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let text = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        preparing = true
        error = nil
        Task {
            do {
                let code = try await Background.run {
                    try messenger.prepareDeviceLink(uri: text, nowMillis: CoreStore.nowMillis)
                }
                // Лист сканера должен успеть закрыться: второй лист поверх
                // закрывающегося SwiftUI не покажет.
                while scanning { try? await Task.sleep(nanoseconds: 100_000_000) }
                try? await Task.sleep(nanoseconds: 350_000_000)
                preparing = false
                UINotificationFeedbackGenerator().notificationOccurred(.warning)
                pendingCode = code
            } catch {
                preparing = false
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                self.error = Self.message(for: error, full: devices.count >= Self.limit)
            }
        }
    }

    private func approve() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        approving = true
        Task {
            do {
                try await Background.run { try messenger.approveDeviceLink(nowMillis: CoreStore.nowMillis) }
                approving = false
                pendingCode = nil
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                note = L10n.t("На новом телефоне нажмите «Цифры совпадают» — и он войдёт в аккаунт.",
                              "On the new phone, tap “Digits match” — and it signs in to your account.",
                              "Sul nuovo telefono tocca «Le cifre coincidono» ed entrerà nel tuo account.")
                await waitForNewDevice()
            } catch {
                approving = false
                pendingCode = nil
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                self.error = Self.message(for: error, full: devices.count >= Self.limit)
            }
        }
    }

    /// Новое устройство появляется в списке, когда само завершит вход:
    /// смотрим ещё полминуты.
    private func waitForNewDevice() async {
        let before = devices.count
        for _ in 0..<10 {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            await load()
            if devices.count > before {
                note = nil
                return
            }
        }
    }

    private func unlink(_ device: FfiOwnDevice) {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let id = device.deviceId
        error = nil
        Task {
            do {
                try await Background.run { try messenger.unlinkDevice(deviceId: id, nowMillis: CoreStore.nowMillis) }
                devices.removeAll { $0.deviceId == id }
                await load()
            } catch {
                self.error = Self.message(for: error, full: false)
            }
        }
    }

    private static func message(for error: Error, full: Bool) -> String {
        switch error as? FfiError {
        case .PremiumRequired:
            return full
                ? L10n.t("Устройств уже пять — отключите одно.", "You already have five devices — unlink one.", "Hai già cinque dispositivi: scollegane uno.")
                : L10n.t("Подключать и отключать устройства можно только с основного телефона.",
                         "Devices can be linked and unlinked only from the main phone.",
                         "I dispositivi si collegano e scollegano solo dal telefono principale.")
        case .AccountRestricted:
            return L10n.t("Аккаунт ограничен — подключение недоступно.", "Your account is restricted — linking is unavailable.", "Il tuo account è limitato: il collegamento non è disponibile.")
        case .Core:
            return L10n.t("Код не подошёл или устарел. На новом телефоне появится новый QR — отсканируйте его.",
                          "The code didn’t work or has expired. A new QR appears on the new phone — scan it.",
                          "Il codice non è valido o è scaduto. Sul nuovo telefono apparirà un nuovo QR: scansionalo.")
        default:
            return L10n.t("Проверьте связь и попробуйте ещё раз.", "Check your connection and try again.", "Controlla la connessione e riprova.")
        }
    }

    private struct PendingCode: Identifiable {
        let code: String
        var id: String { code }
    }
}

/// Строка устройства: только то, что знает протокол, — никаких названий
/// моделей и имён: их пришлось бы отдавать серверу.
private struct DeviceRow: View {
    let device: FfiOwnDevice
    let canUnlink: Bool
    let onUnlink: () -> Void

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(device.thisDevice ? GasAppColor.accentDim : GasAppColor.bgRaised)
                Image(systemName: "iphone")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(device.thisDevice ? GasAppColor.accent : GasAppColor.textSecondary)
            }
            .frame(width: 40, height: 40)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(device.thisDevice
                     ? L10n.t("Этот телефон", "This phone", "Questo telefono")
                     : L10n.t("Телефон · \(shortId)", "Phone · \(shortId)", "Telefono · \(shortId)"))
                    .font(GasFont.text(16, .semibold))
                    .foregroundStyle(GasAppColor.textPrimary)
                Text(device.primary
                     ? L10n.t("Основной", "Main", "Principale")
                     : L10n.t("Подключён", "Linked", "Collegato"))
                    .font(GasFont.text(13))
                    .foregroundStyle(device.primary ? GasAppColor.accent : GasAppColor.textTertiary)
            }
            Spacer(minLength: 8)
            if canUnlink {
                Button(action: onUnlink) {
                    Text(L10n.t("Отключить", "Unlink", "Scollega"))
                        .font(GasFont.text(14, .semibold))
                        .foregroundStyle(GasAppColor.error)
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .background(Capsule().fill(GasAppColor.errorDim))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
    }

    /// Последние четыре знака идентификатора — чтобы отличить телефоны.
    private var shortId: String {
        String(device.deviceId.replacingOccurrences(of: "-", with: "").suffix(4)).uppercased()
    }
}

/// Шесть цифр — крупно, тройками.
struct LinkDigits: View {
    let code: String

    var body: some View {
        let digits = code.filter(\.isNumber)
        let spaced = digits.count == 6 ? "\(digits.prefix(3)) \(digits.suffix(3))" : digits
        Text(spaced)
            .font(GasFont.display(46))
            .monospacedDigit()
            .tracking(4)
            .foregroundStyle(GasAppColor.accent)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 18)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(GasAppColor.bgRaised))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(GasAppColor.line, lineWidth: 1))
            .accessibilityLabel(digits.map(String.init).joined(separator: " "))
    }
}

/// Основной телефон: сверка цифр перед подключением.
private struct LinkConfirmSheet: View {
    let code: String
    let approving: Bool
    let onApprove: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            ScreenTitle(text: L10n.t("Сверьте цифры", "Compare the digits", "Confronta le cifre"),
                        subtitle: L10n.t("Такие же цифры должны быть на новом телефоне.",
                                         "The new phone must show the same digits.",
                                         "Il nuovo telefono deve mostrare le stesse cifre."))
            LinkDigits(code: code)
            Text(L10n.t("Не совпадают — не подключайте: значит, QR подменили. Новый телефон получит доступ ко всем новым сообщениям.",
                        "If they don’t match, don’t link: the QR was swapped. The new phone gets access to all new messages.",
                        "Se non coincidono, non collegare: il QR è stato sostituito. Il nuovo telefono avrà accesso a tutti i nuovi messaggi."))
                .font(GasFont.text(14))
                .foregroundStyle(GasAppColor.textSecondary)
            Spacer(minLength: 0)
            GoldButton(title: L10n.t("Совпадают — подключить", "They match — link", "Coincidono — collega"),
                       isLoading: approving, action: onApprove)
            OutlineButton(title: L10n.t("Не совпадают", "They don’t match", "Non coincidono"),
                          tone: GasAppColor.error, isEnabled: !approving, action: onReject)
        }
        .padding(24)
        .gasScreen()
    }
}

/// Новый телефон: QR для основного, затем сверка цифр и вход.
///
/// QR живёт 60 секунд и обновляется сам; ответ основного телефона
/// проверяется каждые две секунды.
struct NewDeviceLinkView: View {
    /// Идёт вход: «Назад» в это время стёр бы базу посреди записи.
    @Binding var busy: Bool
    /// Вход завершён — аккаунт на этом телефоне.
    let onDone: () -> Void

    init(busy: Binding<Bool>, onDone: @escaping () -> Void) {
        _busy = busy
        self.onDone = onDone
    }

    @State private var qr: FfiQrMatrix?
    @State private var expiresAt = Date.distantPast
    @State private var offer: FfiLinkOffer?
    @State private var finishing = false
    @State private var error: String?
    @State private var attempt = 0
    @State private var now = Date()
    /// Сейчас на экране — сообщение о сбое связи (уберётся само).
    @State private var networkTrouble = false

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if let offer {
                ScreenTitle(text: L10n.t("Сверьте цифры", "Compare the digits", "Confronta le cifre"),
                            subtitle: L10n.t("Вход в @\(offer.username). Такие же цифры — на основном телефоне.",
                                             "Signing in to @\(offer.username). The main phone shows the same digits.",
                                             "Accesso a @\(offer.username). Il telefono principale mostra le stesse cifre."))
                LinkDigits(code: offer.code)
                if let error {
                    Banner(title: L10n.t("Не получилось", "Didn’t work", "Non ha funzionato"), message: error, tone: .error)
                }
                GoldButton(title: L10n.t("Цифры совпадают", "Digits match", "Le cifre coincidono"),
                           isLoading: finishing) { finish() }
                OutlineButton(title: L10n.t("Не совпадают", "They don’t match", "Non coincidono"),
                              tone: GasAppColor.error, isEnabled: !finishing) {
                    self.offer = nil
                    error = L10n.t("Цифры не совпали — вход отменён. Попробуйте ещё раз с новым QR.",
                                   "The digits didn’t match — sign-in cancelled. Try again with a new QR.",
                                   "Le cifre non coincidevano: accesso annullato. Riprova con un nuovo QR.")
                    attempt += 1
                }
            } else {
                ScreenTitle(text: L10n.t("Вход с другого телефона", "Sign in from another phone", "Accedi da un altro telefono"),
                            subtitle: L10n.t("На основном телефоне: Настройки → Устройства → «Подключить устройство». Наведите камеру на этот код.",
                                             "On your main phone: Settings → Devices → “Link a device”. Point the camera at this code.",
                                             "Sul telefono principale: Impostazioni → Dispositivi → «Collega un dispositivo». Inquadra questo codice."))
                if let error {
                    Banner(title: L10n.t("Внимание", "Heads up", "Attenzione"), message: error, tone: .warn)
                }
                ZStack {
                    RoundedRectangle(cornerRadius: 22).fill(.white)
                    if let qr {
                        QRView(matrix: qr).padding(8)
                    } else {
                        ProgressView().tint(GasAppColor.bgBase)
                    }
                }
                .aspectRatio(1, contentMode: .fit)
                .frame(maxWidth: 260)
                .frame(maxWidth: .infinity)

                HStack(spacing: 8) {
                    ProgressView().tint(GasAppColor.textTertiary).controlSize(.small)
                    Text(qr == nil || secondsLeft == 0
                         ? L10n.t("Готовим код…", "Preparing the code…", "Preparazione del codice…")
                         : L10n.t("Ждём основной телефон · код обновится через \(secondsLeft) с",
                                  "Waiting for the main phone · code refreshes in \(secondsLeft) s",
                                  "In attesa del telefono principale · il codice si aggiorna tra \(secondsLeft) s"))
                        .font(GasFont.text(13))
                        .foregroundStyle(GasAppColor.textTertiary)
                        .monospacedDigit()
                }
                .frame(maxWidth: .infinity)

                Label(L10n.t("История переписки сюда не переносится — будут сообщения с момента входа.",
                             "Message history doesn’t move here — you get messages from the moment you sign in.",
                             "La cronologia non viene trasferita qui: riceverai i messaggi dal momento dell’accesso."),
                      systemImage: "clock.arrow.circlepath")
                    .font(GasFont.text(13))
                    .foregroundStyle(GasAppColor.textTertiary)
            }
        }
        .onReceive(ticker) { now = $0 }
        .task(id: attempt) { await run() }
    }

    private var secondsLeft: Int { max(0, Int(expiresAt.timeIntervalSince(now).rounded(.up))) }

    /// Код → ожидание гранта; срок вышел — новый код.
    private func run() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        while !Task.isCancelled && offer == nil {
            do {
                let link = try await Background.run { try messenger.startDeviceLink(nowMillis: CoreStore.nowMillis) }
                let matrix = try await Background.run { try deviceLinkQr(uri: link) }
                qr = matrix
                if networkTrouble {
                    networkTrouble = false
                    error = nil
                }
                // На экране — на пару секунд меньше срока: основному
                // телефону нужно успеть проверить код.
                expiresAt = Date().addingTimeInterval(57)
            } catch {
                qr = nil
                networkTrouble = true
                self.error = L10n.t("Нет связи с сервером. Пробуем снова…", "Can’t reach the server. Retrying…", "Server non raggiungibile. Nuovo tentativo…")
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                continue
            }
            // Прежний ящик слушаем ещё несколько секунд после срока: грант,
            // одобренный на последней секунде, иначе ушёл бы в никуда.
            // Ядро основного телефона одобряет код до срока плюс 5 секунд
            // на расхождение часов — слушаем с запасом.
            let listenUntil = expiresAt.addingTimeInterval(13)
            while !Task.isCancelled && Date() < listenUntil {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if let found = try? await Background.run({ try messenger.pollDeviceLink() }) {
                    UINotificationFeedbackGenerator().notificationOccurred(.warning)
                    error = nil
                    offer = found
                    return
                }
            }
        }
    }

    private func finish() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        finishing = true
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                let account = try await Background.run {
                    try messenger.finishDeviceLink(nowMillis: CoreStore.nowMillis)
                }
                CoreStore.shared.rememberDevice(account.deviceId)
                CoreStore.shared.maintainPrekeysNow()
                finishing = false
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                onDone()
            } catch {
                finishing = false
                UINotificationFeedbackGenerator().notificationOccurred(.error)
                // Грант одноразовый: после отказа — заново, с новым QR.
                offer = nil
                self.error = L10n.t("Вход не завершился. Проверьте связь и отсканируйте новый QR основным телефоном.",
                                    "Sign-in didn’t complete. Check your connection and scan the new QR with the main phone.",
                                    "L’accesso non è stato completato. Controlla la connessione e scansiona il nuovo QR con il telefono principale.")
                attempt += 1
            }
        }
    }
}
