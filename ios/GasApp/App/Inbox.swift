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

    func start() {
        guard loop == nil else { return }
        loop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.receiveOnce()
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
        }
    }

    func stop() {
        loop?.cancel()
        loop = nil
    }

    /// Забрать очередь сейчас (потянули список вниз, открыли чат).
    func receiveOnce() async {
        guard let device = CoreStore.shared.deviceId,
              let messenger = try? CoreStore.shared.current() else { return }
        do {
            let received = try await Background.run {
                try messenger.receiveMessages(deviceId: device, nowMillis: CoreStore.nowMillis)
            }
            lastError = nil
            if received > 0 { revision += 1 }
        } catch {
            lastError = ClockCheck.off
                ? L10n.t("Неверное время на телефоне", "Phone clock is wrong", "L’orologio del telefono è sbagliato")
                : L10n.t("Нет связи с сервером", "No connection", "Nessuna connessione")
        }
    }

    /// Что-то поменялось локально (отправили, приняли запрос).
    func touch() { revision += 1 }
}
