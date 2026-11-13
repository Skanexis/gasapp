// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Приём сообщений, пока приложение открыто.
///
/// Раз в несколько секунд забирает очередь с сервера (`receiveMessages`)
/// и сообщает экранам, что данные изменились (`revision`). Приём общий
/// на весь аккаунт: одного вызова хватает на все переписки.
///
/// ⚠️ Только пока приложение на экране: iOS не даёт приложению работать
/// в фоне. Уведомления о сообщениях при закрытом приложении — через
/// пуш-уведомления Apple (APNs), это отдельное решение владельца.
@MainActor
@Observable
final class Inbox {
    static let shared = Inbox()

    /// Растёт при каждом новом приёме: экраны перечитывают данные.
    private(set) var revision = 0
    private(set) var lastError: String?

    private var loop: Task<Void, Never>?

    /// Пауза между опросами. 🔋 Растёт, пока ничего не приходит: каждые
    /// 4 секунды без конца — это радио телефона, не засыпающее ни на миг.
    /// Новое сообщение, действие человека, возврат в приложение — снова
    /// быстро.
    private var interval: Double = Inbox.fastInterval
    private static let fastInterval: Double = 4
    private static let slowInterval: Double = 20
    /// Будильник для ожидающего цикла: «опроси сейчас».
    private var wake: CheckedContinuation<Void, Never>?

    func start() {
        guard loop == nil else { return }
        loop = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.receiveOnce()
                await self.pause()
            }
        }
    }

    /// Ждать текущий интервал — или раньше, если позвали `hurry()`.
    private func pause() async {
        let seconds = interval
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            wake = continuation
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                self?.fire()
            }
        }
    }

    private func fire() {
        wake?.resume()
        wake = nil
    }

    /// Опросить сейчас и вернуться к частому опросу: человек что-то
    /// сделал или приложение снова на экране.
    func hurry() {
        interval = Self.fastInterval
        fire()
    }

    func stop() {
        loop?.cancel()
        loop = nil
        fire()
    }

    /// Идущий приём. Второй одновременно не запускается: цикл, открытый
    /// чат и «потянули вниз» просили очередь каждый сам, и одинаковые
    /// запросы вставали друг за другом — лишняя работа радио.
    @ObservationIgnored private var receiving: Task<Void, Never>?

    /// Забрать очередь сейчас (потянули список вниз, открыли чат).
    /// Приём уже идёт — дождаться его, а не начинать ещё один.
    func receiveOnce() async {
        if let receiving {
            await receiving.value
            return
        }
        let task = Task { await self.receiveNow() }
        receiving = task
        await task.value
        receiving = nil
    }

    private func receiveNow() async {
        guard let device = CoreStore.shared.deviceId,
              let messenger = try? CoreStore.shared.current() else { return }
        let network = NetworkController.shared
        // Ядро спрашивается в фоне: см. NetworkController.cached.
        _ = try? await Background.run { network.ensureRoute() }
        // Tor ещё подключается — так и сказать, а не «Нет связи»: запрос
        // всё равно не ушёл бы (маршрут закрыт).
        if network.isConnectingTor {
            let percent = network.torStatus.percent
            lastError = L10n.t("Подключение к Tor… \(percent)%", "Connecting to Tor… \(percent)%",
                               "Connessione a Tor… \(percent)%")
            return
        }
        do {
            let received = try await Background.run {
                try messenger.receiveMessages(deviceId: device, nowMillis: CoreStore.nowMillis)
            }
            network.requestSucceeded()
            lastError = nil
            if received > 0 {
                revision += 1
                interval = Self.fastInterval
            } else {
                interval = min(Self.slowInterval, interval * 1.5)
            }
        } catch {
            network.requestFailed()
            lastError = ClockCheck.off
                ? L10n.t("Неверное время на телефоне", "Phone clock is wrong", "L’orologio del telefono è sbagliato")
                : L10n.t("Нет связи с сервером", "No connection", "Nessuna connessione")
        }
    }

    /// Что-то поменялось локально (отправили, приняли запрос).
    func touch() {
        revision += 1
        hurry()
    }
}
