// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UniformTypeIdentifiers

/// Вложение сообщения: качается и расшифровывается, только когда
/// сообщение на экране.
///
/// 🔐 Расшифрованное держится **только в памяти** (кеш до блокировки):
/// на диск не пишется — файл с фото в каталоге приложения пережил бы и
/// удаление переписки, и исчезающий таймер. Ядро проверяет тег каждого
/// чанка: подменённый сервером файл — ошибка, а не картинка.
struct AttachmentView: View {
    let descriptor: Data

    @State private var image: UIImage?
    @State private var file: Data?
    @State private var failed = false
    @State private var fullScreen = false

    init(descriptor: Data) { self.descriptor = descriptor }

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 260, maxHeight: 320)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .onTapGesture { fullScreen = true }
            } else if let file {
                ShareLink(item: AttachmentFile(data: file), preview: SharePreview(L10n.t("Файл", "File"))) {
                    Label(L10n.t("Файл · \(formatBytes(Int64(file.count)))",
                                 "File · \(formatBytes(Int64(file.count)))"),
                          systemImage: "doc.fill")
                        .foregroundStyle(GasAppColor.accent)
                }
            } else if failed {
                Label(L10n.t("Вложение недоступно", "Attachment unavailable"), systemImage: "exclamationmark.triangle")
                    .font(.system(size: 13)).foregroundStyle(GasAppColor.warn)
            } else {
                ProgressView().tint(GasAppColor.accent).frame(width: 120, height: 80)
            }
        }
        .task(id: descriptor) { await load() }
        .fullScreenCover(isPresented: $fullScreen) {
            ZStack(alignment: .topTrailing) {
                Color.black.ignoresSafeArea()
                if let image {
                    Image(uiImage: image).resizable().scaledToFit()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                Button { fullScreen = false } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 17, weight: .bold))
                        .foregroundStyle(.white)
                        .frame(width: 44, height: 44)
                        .background(Circle().fill(.white.opacity(0.18)))
                }
                .padding(16)
                .accessibilityLabel(L10n.t("Закрыть", "Close"))
            }
            .onTapGesture { fullScreen = false }
        }
    }

    private func load() async {
        if let cached = AttachmentCache.shared.get(descriptor) {
            apply(cached)
            return
        }
        guard let messenger = try? CoreStore.shared.current(), let device = CoreStore.shared.deviceId else {
            failed = true
            return
        }
        let key = descriptor
        guard let bytes = try? await Background.run({
            try messenger.fetchAttachment(deviceId: device, descriptor: key, nowMillis: CoreStore.nowMillis)
        }) else {
            failed = true
            return
        }
        AttachmentCache.shared.put(descriptor, bytes)
        apply(bytes)
    }

    private func apply(_ bytes: Data) {
        if let decoded = UIImage(data: bytes) { image = decoded } else { file = bytes }
    }
}

/// Файл для «Поделиться» — из памяти, без записи на диск приложения.
struct AttachmentFile: Transferable {
    let data: Data
    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .data) { $0.data }
    }
}

/// Кеш расшифрованных вложений — только в памяти, сбрасывается при
/// блокировке (`AppModel.lock`).
final class AttachmentCache: @unchecked Sendable {
    static let shared = AttachmentCache()
    private let cache = NSCache<NSData, NSData>()
    private init() { cache.totalCostLimit = 64 * 1024 * 1024 }

    func get(_ key: Data) -> Data? { cache.object(forKey: key as NSData) as Data? }
    func put(_ key: Data, _ value: Data) { cache.setObject(value as NSData, forKey: key as NSData, cost: value.count) }
    func clear() { cache.removeAllObjects() }
}
