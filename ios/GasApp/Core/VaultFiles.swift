// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Файлы хранилища на диске: шифроблобы — внутри каталога данных (их
/// стирает `CoreStore.wipe`), открытые — во временном каталоге.
///
/// 🔐 В базе записано только **имя** блоба, а не путь: путь к контейнеру
/// приложения в iOS меняется при обновлении, и запись с полным путём
/// после первого же обновления указывала бы в никуда. Имя от чужого
/// провайдера в путь не попадает — только наше случайное.
enum VaultFiles {
    static let maxBytes = 200 * 1024 * 1024

    static var directory: URL {
        let dir = CoreStore.shared.dataDirectory.appendingPathComponent("vault", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static var openedDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("vault-open", isDirectory: true)
    }

    static func newBlobName() -> String { "\(UUID().uuidString).enc" }

    /// Блоб — только внутри каталога хранилища: `../` из базы наружу не
    /// выведет.
    private static func blobURL(_ location: String) throws -> URL {
        let name = (location as NSString).lastPathComponent
        guard !name.isEmpty, name == location, !name.hasPrefix(".") else { throw CocoaError(.fileNoSuchFile) }
        return directory.appendingPathComponent(name)
    }

    static func write(_ data: Data, to location: String) throws {
        try data.write(to: try blobURL(location), options: [.atomic, .completeFileProtection])
    }

    static func read(_ location: String) throws -> Data {
        try Data(contentsOf: try blobURL(location))
    }

    static func remove(_ location: String) {
        if let url = try? blobURL(location) { try? FileManager.default.removeItem(at: url) }
    }

    /// Имя для показа и для открытого файла: без каталогов и служебных знаков.
    static func safeName(_ raw: String) -> String {
        let base = (raw as NSString).lastPathComponent
        let cleaned = base.unicodeScalars.filter { !CharacterSet(charactersIn: "/\\:\0").contains($0) && $0.value >= 0x20 }
        let name = String(String.UnicodeScalarView(cleaned)).trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? "file" : String(name.prefix(120))
    }

    static func writeOpened(_ data: Data, name: String) throws -> URL {
        clearOpened()
        let dir = openedDirectory
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent(safeName(name))
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }

    static func clearOpened() {
        try? FileManager.default.removeItem(at: openedDirectory)
    }
}
