// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Место на устройстве — то же, что `StorageActivity` на Android.
///
/// 🔐 Всё, что показано здесь, лежит в зашифрованной базе на устройстве.
/// Очистка удаляет данные безвозвратно: сервер копий не хранит, и
/// восстановить стёртое будет неоткуда.
struct StorageScreen: View {
    @State private var database: Int64 = 0
    @State private var cache: Int64 = 0
    @State private var message: String?
    @State private var working = false

    var body: some View {
        Form {
            Group {
                Section(L10n.t("Занято", "Usage")) {
                    LabeledContent(L10n.t("Сообщения", "Messages"), value: format(database))
                    LabeledContent(L10n.t("Вложения", "Attachments"), value: format(cache))
                }
                Section {
                    // Отдельным действием, хотя чистка идёт и при открытии
                    // базы: включивший исчезающие сообщения вправе
                    // убедиться, что они исчезли, не дожидаясь перезапуска.
                    Button(L10n.t("Удалить истёкшие сообщения", "Delete expired messages"), role: .destructive) { purge() }
                        .disabled(working)
                    Button(L10n.t("Очистить загруженные файлы", "Clear downloaded files"), role: .destructive) { clearCache() }
                        .disabled(working)
                    if let message {
                        Text(message).foregroundStyle(GasAppColor.ok)
                    }
                } header: {
                    Text(L10n.t("Очистка", "Cleanup"))
                } footer: {
                    Text(L10n.t("Удаление необратимо: сервер копий не хранит, и восстановить стёртое будет неоткуда.",
                                "Deletion cannot be undone: the server keeps no copies, so there is nothing to restore from."))
                }
            }
            .listRowBackground(GasAppColor.bgCard)
        }
        .scrollContentBackground(.hidden)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Место на устройстве", "Storage"))
        .navigationBarTitleDisplayMode(.inline)
        .task { await measure() }
    }

    private func format(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    /// Расшифрованные копии вложений (то, что отдавалось «Поделиться»)
    /// живут только во временном каталоге и кешах.
    nonisolated private static var cacheDirectories: [URL] {
        var list = [FileManager.default.temporaryDirectory]
        if let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first { list.append(caches) }
        return list
    }

    nonisolated private static func size(of directory: URL) -> Int64 {
        guard let files = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]) else {
            return 0
        }
        var total: Int64 = 0
        for case let url as URL in files {
            let values = try? url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
            if values?.isRegularFile == true { total += Int64(values?.fileSize ?? 0) }
        }
        return total
    }

    private func measure() async {
        let base = CoreStore.shared.dataDirectory
        let sizes = await Task.detached { () -> (Int64, Int64) in
            // База и её журнал (WAL) — переписка целиком.
            let db = ["gasapp.db", "gasapp.db-wal", "gasapp.db-shm"].reduce(Int64(0)) { sum, name in
                let attributes = try? FileManager.default.attributesOfItem(atPath: base.appendingPathComponent(name).path)
                return sum + ((attributes?[.size] as? NSNumber)?.int64Value ?? 0)
            }
            let cached = Self.cacheDirectories.reduce(Int64(0)) { $0 + Self.size(of: $1) }
            return (db, cached)
        }.value
        database = sizes.0
        cache = sizes.1
    }

    private func purge() {
        guard let messenger = try? CoreStore.shared.current() else { return }
        working = true
        Task {
            let removed = (try? await Background.run { try messenger.purgeExpired(nowMillis: CoreStore.nowMillis) }) ?? 0
            working = false
            message = L10n.t("Удалено сообщений: \(removed)", "Messages deleted: \(removed)")
            await measure()
        }
    }

    /// 🔐 Кеш — единственное место, где расшифрованный файл лежит на
    /// диске вне базы. Удаляется содержимое каталогов, не они сами.
    private func clearCache() {
        working = true
        Task {
            await Task.detached {
                for directory in Self.cacheDirectories {
                    let items = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
                    for item in items { try? FileManager.default.removeItem(at: item) }
                }
            }.value
            working = false
            message = L10n.t("Загруженные файлы удалены", "Downloaded files deleted")
            await measure()
        }
    }
}
