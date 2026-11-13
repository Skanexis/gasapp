// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit
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
                ShareLink(item: AttachmentFile(data: file), preview: SharePreview(L10n.t("Файл", "File", "File"))) {
                    Label(L10n.t("Файл · \(formatBytes(Int64(file.count)))",
                                 "File · \(formatBytes(Int64(file.count)))", "File · \(formatBytes(Int64(file.count)))"),
                          systemImage: "doc.fill")
                        .foregroundStyle(GasAppColor.accent)
                }
            } else if failed {
                Label(L10n.t("Вложение недоступно", "Attachment unavailable", "Allegato non disponibile"), systemImage: "exclamationmark.triangle")
                    .font(GasFont.text(13)).foregroundStyle(GasAppColor.warn)
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
                .accessibilityLabel(L10n.t("Закрыть", "Close", "Chiudi"))
            }
            .onTapGesture { fullScreen = false }
        }
    }

    private func load() async {
        // Готовая картинка — сразу, без повторного декодирования: при
        // прокрутке пузырь появляется на экране много раз.
        if let ready = AttachmentCache.shared.image(descriptor) {
            image = ready
            return
        }
        if let cached = AttachmentCache.shared.get(descriptor) {
            await apply(cached)
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
        await apply(bytes)
    }

    /// Декодирует в фоне. Прежде снимок (до 2560 точек) разворачивался
    /// в главном потоке, прямо во время прокрутки, — лента дёргалась на
    /// каждой фотографии.
    private func apply(_ bytes: Data) async {
        if let ready = await AttachmentCache.shared.prepared(descriptor, from: bytes) {
            image = ready
        } else {
            file = bytes
        }
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
    func clear() {
        cache.removeAllObjects()
        images.removeAllObjects()
    }

    /// Готовые к показу картинки — тоже только в памяти и до блокировки.
    private let images: NSCache<NSData, UIImage> = {
        let cache = NSCache<NSData, UIImage>()
        cache.totalCostLimit = 96 * 1024 * 1024
        return cache
    }()

    func image(_ key: Data) -> UIImage? { images.object(forKey: key as NSData) }

    /// Готовая к показу картинка из расшифрованных байтов: декодируется
    /// в фоновом потоке и запоминается. Не картинка — `nil`.
    func prepared(_ key: Data, from bytes: Data) async -> UIImage? {
        if let ready = image(key) { return ready }
        let decoded = (try? await Background.run { AttachmentCache.decode(bytes) }) ?? nil
        if let decoded { putImage(key, decoded) }
        return decoded
    }

    func putImage(_ key: Data, _ value: UIImage) {
        let pixels = Int(value.size.width * value.scale) * Int(value.size.height * value.scale)
        images.setObject(value, forKey: key as NSData, cost: pixels * 4)
    }

    /// Самая длинная сторона готовой картинки, в точках экрана: хватает
    /// и пузырю, и просмотру во весь экран.
    private static let maxSide: CGFloat = 1600

    /// Разворачивает снимок в готовый к показу вид; не картинка — `nil`.
    /// Зовётся из фонового потока.
    static func decode(_ bytes: Data) -> UIImage? {
        guard let source = UIImage(data: bytes) else { return nil }
        let longest = max(source.size.width, source.size.height)
        guard longest > 0 else { return nil }
        let scale = min(1, maxSide / longest)
        let size = CGSize(width: source.size.width * scale, height: source.size.height * scale)
        return source.preparingThumbnail(of: size) ?? source
    }
}
