// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Единая точка доступа к ядру — аналог `Core.kt` на Android.
///
/// # Почему один экземпляр на процесс
///
/// `Messenger` владеет открытой базой. Второй экземпляр открыл бы ту же
/// базу повторно, и состояния Double Ratchet разошлись бы: сообщение,
/// зашифрованное одним, не расшифровалось бы другим.
///
/// 🔐 Ключ базы — из PIN (Argon2id в ядре) **и** ответа Secure Enclave
/// ([EnclaveKey]). Неверный PIN даёт неверный ключ, и SQLCipher просто
/// не открывает базу: отдельного «признака верного PIN» нигде нет.
///
/// ⚠️ Все методы — долгие и сетевые: вызывать только не из главного
/// потока (`Task.detached`, см. [Background]).
final class CoreStore: @unchecked Sendable {
    static let shared = CoreStore()

    enum Failure: Error {
        /// Хранилище закрыто: сначала PIN.
        case locked
        /// Сборка без адреса сервера.
        case misconfigured
        /// База есть, а соли нет (повреждение): открыть нечем.
        case saltMissing
    }

    private let lock = NSRecursiveLock()
    private var messenger: Messenger?
    private var cachedDeviceId: String?

    /// Режим сети, выбранный до появления базы (регистрация): его
    /// применит [open] до первого запроса.
    var pendingProxy: FfiProxy?

    private init() {}

    // MARK: - Файлы

    /// Каталог данных: Application Support, вне iCloud-копий.
    var dataDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("GasApp", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            // 🔐 Не в резервную копию: база под ключом Secure Enclave
            // на другом телефоне всё равно не откроется, а копия —
            // лишнее место, где лежат зашифрованные данные.
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutable = dir
            try? mutable.setResourceValues(values)
        }
        return dir
    }

    private var databasePath: String { dataDirectory.appendingPathComponent("gasapp.db").path }
    private var saltURL: URL { dataDirectory.appendingPathComponent("gasapp.salt") }

    /// Заведён ли аккаунт (есть база) на этом устройстве.
    var hasAccount: Bool { FileManager.default.fileExists(atPath: databasePath) }

    /// Соль растягивания PIN. Лежит открыто: она защищает от заранее
    /// посчитанных таблиц, а не от того, кто получил устройство.
    func salt(create: Bool) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        if let data = try? Data(contentsOf: saltURL), !data.isEmpty {
            return data
        }
        // 🔐 Соли нет, а база есть — новую не заводим: под ней ключ базы
        // не сошёлся бы никогда, и каждая попытка шла бы в счётчик
        // неверных PIN.
        guard create else { throw Failure.saltMissing }
        let fresh = generateStorageSalt()
        try fresh.write(to: saltURL, options: [.atomic, .completeFileProtection])
        return fresh
    }

    // MARK: - Открытие и закрытие

    var isUnlocked: Bool {
        lock.lock(); defer { lock.unlock() }
        return messenger != nil
    }

    /// Открытый мессенджер. 🔐 Закрыт — ошибка, а не тихое открытие.
    func current() throws -> Messenger {
        lock.lock(); defer { lock.unlock() }
        guard let messenger else { throw Failure.locked }
        return messenger
    }

    /// 🔐 Открывает базу по PIN (байты затираются вызывающим).
    ///
    /// Открытая база не возвращается как есть: вход — это проверка PIN,
    /// и проверяет её только открытие базы этим PIN.
    func unlock(pin: [UInt8]) throws -> Messenger {
        lock.lock(); defer { lock.unlock() }
        close()

        // Новая база — только если её ещё нет: тогда и ключ Enclave
        // заводится впервые.
        let creating = !hasAccount
        let salt = try salt(create: creating)
        var stretched = try [UInt8](deriveStorageKey(pin: Data(pin), salt: salt))
        defer { stretched.wipe() }

        let probe = try enclaveProbePoint(stretched: Data(stretched), salt: salt)
        var response = try EnclaveKey.respond(to: probe, create: creating)
        defer { response.wipe() }

        var key = try [UInt8](deriveStorageKeyTee(stretched: Data(stretched), salt: salt, teeMac: Data(response)))
        defer { key.wipe() }

        let opened = try open(key: key)
        // Проверочное значение хранилища файлов — тем же PIN, что открыл
        // базу (как `Core.establishVaultVerifier` на Android): хранилище
        // сверяет с ним PIN, а не открывает файлы наугад. Сбой не мешает
        // войти.
        try? opened.establishVaultVerifier(pin: Data(pin), salt: salt)
        return opened
    }

    /// 🔐 Ключ базы из PIN — без открытия: только для включения Face ID.
    /// Других вызывающих быть не должно (см. `Core.deriveKey` на Android).
    func deriveKey(pin: [UInt8]) throws -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        let salt = try salt(create: false)
        var stretched = try [UInt8](deriveStorageKey(pin: Data(pin), salt: salt))
        defer { stretched.wipe() }
        let probe = try enclaveProbePoint(stretched: Data(stretched), salt: salt)
        var response = try EnclaveKey.respond(to: probe, create: false)
        defer { response.wipe() }
        return try [UInt8](deriveStorageKeyTee(stretched: Data(stretched), salt: salt, teeMac: Data(response)))
    }

    /// Открыта ли база именно этим ключом (для включения Face ID).
    func keyOpensStorage(_ key: [UInt8]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return messenger != nil && openedKey.matches(key)
    }

    /// Вход ключом из Face ID: PIN тут не нужен — ключ уже готов.
    func unlock(key: [UInt8]) throws -> Messenger {
        lock.lock(); defer { lock.unlock() }
        close()
        return try open(key: key)
    }

    /// Отпечаток ключа открытой базы — не сам ключ (`OpenedKey`).
    private var openedKey = OpenedKey()

    private func open(key: [UInt8]) throws -> Messenger {
        guard let server = AppConfig.serverURL else { throw Failure.misconfigured }
        try awaitRetired()

        let opened = try Messenger.open(
            databasePath: databasePath,
            databaseKey: Data(key),
            transport: PlatformTransport(baseURL: server, pins: AppConfig.pins)
        )
        messenger = opened
        openedKey.remember(key)

        // 🔐 Режим сети — сразу после открытия базы и до первого запроса:
        // настройка живёт в зашифрованной базе, раньше её не прочитать,
        // а позже — запрос мог бы уйти напрямую при выбранном Tor.
        if let mode = pendingProxy {
            pendingProxy = nil
            try? opened.setProxy(proxy: mode)
        }
        NetworkController.shared.apply(proxy: try? opened.proxy(), bridges: try? opened.torBridges())

        // 🔐 Истёкшие исчезающие сообщения — сразу: таймер работает,
        // только пока приложение запущено.
        _ = try? opened.purgeExpired(nowMillis: Self.nowMillis)

        maintainPrekeys(opened)
        return opened
    }

    /// 🔐 Пополнение одноразовых предключей — в фоне, после открытия
    /// и после регистрации. Без него пул кончается, и новые переписки
    /// заводятся без одноразового ключа.
    func maintainPrekeysNow() {
        if let messenger = try? current() { maintainPrekeys(messenger) }
    }

    private func maintainPrekeys(_ messenger: Messenger) {
        Task.detached(priority: .utility) {
            _ = try? messenger.maintainPrekeys(nowMillis: CoreStore.nowMillis)
        }
    }

    /// Идентификатор устройства (адрес приёма сообщений).
    var deviceId: String? {
        lock.lock(); defer { lock.unlock() }
        if let cachedDeviceId { return cachedDeviceId }
        var stored: String?
        if let messenger, let id = try? messenger.ownDeviceId() { stored = id }
        cachedDeviceId = stored
        return stored
    }

    func rememberDevice(_ id: String) {
        lock.lock(); cachedDeviceId = id; lock.unlock()
    }

    /// 🔐 Закрывает базу при блокировке: ключ больше не держится
    /// в памяти, следующий доступ потребует PIN.
    func close() {
        lock.lock(); defer { lock.unlock() }
        // В Swift у объекта UniFFI нет close(): база закрывается, когда
        // уходит последняя ссылка. Экраны держат мессенджер только на
        // время вызова (`current()`), поэтому ссылка здесь — последняя.
        if let messenger { retired = messenger }
        messenger = nil
        openedKey.forget()
        cachedDeviceId = nil
    }

    /// Закрытый, но ещё не освобождённый экземпляр: фоновая задача
    /// (обслуживание предключей, приём) может держать его до конца
    /// своего запроса.
    private weak var retired: Messenger?

    /// 🔐 Ждёт, пока прежний экземпляр освободится, — прежде чем открыть
    /// базу снова. Два экземпляра на одной базе — два состояния Double
    /// Ratchet, которые расходятся. Не дождались — отказ, а не второй.
    private func awaitRetired() throws {
        let deadline = Date().addingTimeInterval(30)
        while retired != nil {
            guard Date() < deadline else { throw Failure.locked }
            lock.unlock()
            Thread.sleep(forTimeInterval: 0.05)
            lock.lock()
        }
    }

    /// 🔐 Стирает всё локальное: базу, соль, ключ Enclave, Keychain.
    /// Ключ Enclave уничтожается первым — после этого база нечитаема,
    /// даже если удаление файлов не дошло до конца.
    func wipe() {
        lock.lock(); defer { lock.unlock() }
        close()
        EnclaveKey.destroy()
        Biometric.disable()
        VaultFiles.clearOpened()
        try? FileManager.default.removeItem(at: dataDirectory)
        SecureStore.removeAll()
    }

    static var nowMillis: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
}

extension Array where Element == UInt8 {
    /// 🔐 Затирает байты секрета.
    mutating func wipe() {
        for index in indices { self[index] = 0 }
    }
}
