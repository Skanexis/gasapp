// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Состояние подключения — одно на всё приложение (DESIGN.md, «Layout»:
/// полоса под заголовком, пока подключение не через Tor или прокси).
///
/// Ожидание через Tor — штатное состояние (PRODUCT.md, принцип 3), и
/// показывается как ход, а не как сбой: процент, линия, затем «готово».
/// Читает только сохранённое состояние Tor (`NetworkController.torStatus`)
/// — главный поток ядро не спрашивает.
@MainActor
@Observable
final class ConnectionStatus {
    static let shared = ConnectionStatus()

    enum State: Equatable {
        /// Ничего не показывать: Tor или прокси работает.
        case quiet
        /// Tor подключается: процент, через мосты ли.
        case connecting(percent: Int, bridges: Bool)
        /// Tor застрял: вероятно, заблокирован.
        case stalled(percent: Int)
        /// Только что подключились — короткое «готово».
        case justConnected(bridges: Bool)
        /// Напрямую: сервер видит адрес.
        case direct
        /// Маршрут открыт, а сервер не отвечает.
        case offline
        /// Часы телефона сбиты — сервер отвергает запросы.
        case clockWrong
    }

    private(set) var state: State = .quiet
    private var wasConnecting = false
    private var ticker: Task<Void, Never>?
    private var hideDone: Task<Void, Never>?

    /// Опрос раз в секунду, пока виден экран с полосой.
    func start() {
        guard ticker == nil else { return }
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                self?.refresh()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func stop() {
        ticker?.cancel()
        ticker = nil
    }

    func refresh() {
        let network = NetworkController.shared
        let tor = network.torStatus
        let next: State
        if ClockCheck.off {
            next = .clockWrong
        } else {
            switch network.currentMode {
            case .tor?:
                if network.isConnectingTor || !tor.ready {
                    next = tor.stalled ? .stalled(percent: Int(tor.percent)) : .connecting(percent: Int(tor.percent), bridges: tor.bridges)
                } else if Inbox.shared.lastError != nil {
                    next = .offline
                } else if wasConnecting {
                    next = .justConnected(bridges: tor.bridges)
                } else {
                    next = .quiet
                }
            case .direct?:
                next = Inbox.shared.lastError != nil ? .offline : .direct
            case .socks5?:
                next = Inbox.shared.lastError != nil ? .offline : .quiet
            case nil:
                next = .quiet
            }
        }

        switch next {
        case .connecting, .stalled: wasConnecting = true
        case .justConnected:
            wasConnecting = false
            hideDone?.cancel()
            hideDone = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 2_500_000_000)
                guard !Task.isCancelled, let self, case .justConnected = self.state else { return }
                withAnimation(.easeOut(duration: 0.3)) { self.state = .quiet }
            }
        default: break
        }
        // «Готово» не сменяется на «тишину» раньше срока.
        if case .justConnected = state, next == .quiet { return }
        if next != state { withAnimation(.easeInOut(duration: 0.25)) { state = next } }
    }
}

/// Полоса подключения под заголовком списка.
struct ConnectionStrip: View {
    @State private var status = ConnectionStatus.shared
    @State private var pulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            switch status.state {
            case .quiet:
                EmptyView()
            case let .connecting(percent, bridges):
                strip(tint: GasAppColor.accent, background: GasAppColor.accentDim, icon: "point.3.connected.trianglepath.dotted",
                      text: bridges
                        ? L10n.t("Tor через мосты… \(percent)%", "Tor via bridges… \(percent)%", "Tor tramite bridge… \(percent)%")
                        : L10n.t("Подключение к Tor… \(percent)%", "Connecting to Tor… \(percent)%", "Connessione a Tor… \(percent)%"),
                      progress: Double(percent) / 100, animated: true)
            case let .stalled(percent):
                strip(tint: GasAppColor.warn, background: GasAppColor.warnDim, icon: "exclamationmark.triangle.fill",
                      text: L10n.t("Tor не подключается (\(percent)%) — возможно, заблокирован", "Tor is stuck (\(percent)%) — it may be blocked", "Tor è bloccato (\(percent)%): potrebbe essere bloccato"),
                      progress: Double(percent) / 100) {
                    NavigationLink { NetworkScreen() } label: { action(L10n.t("Мосты", "Bridges", "Bridge"), tint: GasAppColor.warn) }
                }
            case let .justConnected(bridges):
                strip(tint: GasAppColor.ok, background: GasAppColor.okDim, icon: "checkmark.shield.fill",
                      text: bridges
                        ? L10n.t("Подключено через Tor и мосты", "Connected through Tor and bridges", "Connesso tramite Tor e bridge")
                        : L10n.t("Подключено через Tor", "Connected through Tor", "Connesso tramite Tor"))
            case .direct:
                strip(tint: GasAppColor.warn, background: GasAppColor.bgRaised, icon: "eye.fill",
                      text: L10n.t("Напрямую: сервер видит ваш IP", "Direct: the server sees your IP", "Diretta: il server vede il tuo IP")) {
                    NavigationLink { NetworkScreen() } label: { action("Tor", tint: GasAppColor.accent) }
                }
            case .offline:
                strip(tint: GasAppColor.error, background: GasAppColor.errorDim, icon: "wifi.exclamationmark",
                      text: L10n.t("Нет связи с сервером", "No connection to the server", "Nessuna connessione al server")) {
                    Button { Task { await Inbox.shared.receiveOnce(); status.refresh() } } label: {
                        action(L10n.t("Повторить", "Retry", "Riprova"), tint: GasAppColor.error)
                    }
                }
            case .clockWrong:
                strip(tint: GasAppColor.warn, background: GasAppColor.warnDim, icon: "clock.badge.exclamationmark",
                      text: L10n.t("Неверное время на телефоне — включите «Автоматически»", "Phone clock is wrong — set it to automatic", "Orologio errato: impostalo su automatico"))
            }
        }
        .onAppear { status.start(); status.refresh() }
    }

    private func strip<Trailing: View>(tint: Color, background: Color, icon: String, text: String,
                                       progress: Double? = nil, animated: Bool = false,
                                       @ViewBuilder trailing: () -> Trailing = { EmptyView() }) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(tint)
                    .scaleEffect(animated && pulse && !reduceMotion ? 1.15 : 1)
                    .opacity(animated && pulse && !reduceMotion ? 0.6 : 1)
                    .animation(animated && !reduceMotion ? .easeInOut(duration: 0.9).repeatForever(autoreverses: true) : .default, value: pulse)
                    .onAppear { pulse = true }
                Text(text)
                    .font(GasFont.text(13, .semibold))
                    .foregroundStyle(tint == GasAppColor.accent ? GasAppColor.textPrimary : tint)
                    .lineLimit(2)
                    .contentTransition(.numericText())
                Spacer(minLength: 6)
                trailing()
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
            if let progress {
                GeometryReader { geo in
                    Rectangle().fill(tint.opacity(0.25))
                        .overlay(alignment: .leading) {
                            Rectangle().fill(tint).frame(width: geo.size.width * max(0.03, min(1, progress)))
                                .animation(.easeOut(duration: 0.6), value: progress)
                        }
                }
                .frame(height: 2)
            }
        }
        .background(background)
        .transition(.move(edge: .top).combined(with: .opacity))
        .accessibilityElement(children: .combine)
    }

    private func action(_ title: String, tint: Color) -> some View {
        Text(title)
            .font(GasFont.text(12, .bold))
            .foregroundStyle(tint == GasAppColor.accent ? GasAppColor.accentOn : GasAppColor.bgBase)
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Capsule().fill(tint))
    }
}

/// Значок состояния сети для строки настроек и экрана «Подключение».
struct ConnectionBadge: View {
    @State private var status = ConnectionStatus.shared

    var body: some View {
        let (text, color): (String, Color) = {
            switch status.state {
            case .quiet, .justConnected:
                return NetworkController.shared.currentMode == .tor
                    ? (L10n.t("Tor подключён", "Tor connected", "Tor connesso"), GasAppColor.ok)
                    : (L10n.t("Подключено", "Connected", "Connesso"), GasAppColor.ok)
            case let .connecting(percent, _): return ("\(percent)%", GasAppColor.accent)
            case .stalled: return (L10n.t("Застрял", "Stuck", "Bloccato"), GasAppColor.warn)
            case .direct: return (L10n.t("Напрямую", "Direct", "Diretta"), GasAppColor.warn)
            case .offline: return (L10n.t("Нет связи", "Offline", "Offline"), GasAppColor.error)
            case .clockWrong: return (L10n.t("Часы", "Clock", "Orologio"), GasAppColor.warn)
            }
        }()
        HStack(spacing: 5) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(text).font(GasFont.text(12, .semibold)).foregroundStyle(color)
                .contentTransition(.numericText())
        }
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(Capsule().fill(color.opacity(0.14)))
        .onAppear { status.start(); status.refresh() }
    }
}
