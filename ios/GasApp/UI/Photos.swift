// SPDX-License-Identifier: Apache-2.0

import ImageIO
import SwiftUI
import UIKit

/// Фото профиля (своё и собеседников) и картинки аватаров каналов — одно
/// место на всё приложение: список чатов, шапка чата, каналы, настройки.
///
/// 🔐 Картинки живут в зашифрованной базе ядра; здесь — только
/// разобранные копии в памяти. Разбор — уменьшенным эскизом (ImageIO):
/// картинка от собеседника не раскрывается в полный размер.
@MainActor
@Observable
final class PhotoStore {
    static let shared = PhotoStore()

    /// Фото собеседников по чату.
    private(set) var chats: [String: UIImage] = [:]
    /// Своё фото.
    private(set) var own: UIImage?
    /// Аватары каналов по каналу.
    private(set) var channels: [String: UIImage] = [:]
    /// Для какого описания файла загружен аватар канала: сменился — заново.
    @ObservationIgnored private var channelKeys: [String: Data] = [:]
    @ObservationIgnored private var loadingChannels: Set<String> = []

    /// Перечитать фото собеседников (после приёма — могли смениться).
    func reloadChats() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let found = (try? await Background.run { () -> [String: UIImage] in
            var images: [String: UIImage] = [:]
            for photo in try messenger.chatPhotos() {
                if let image = Self.thumbnail(photo.image, side: 160) { images[photo.chatId] = image }
            }
            return images
        }) ?? [:]
        chats = found
    }

    func reloadOwn() async {
        guard let messenger = try? CoreStore.shared.current() else { return }
        let data = try? await Background.run { try messenger.ownProfilePhoto() }
        own = data.flatMap { Self.thumbnail($0, side: 400) }
    }

    /// Поставить своё фото (`nil` — снять) и разослать тем, с кем
    /// переписка, — в фоне, по одному: ядро между ними свободно.
    func setOwn(_ jpeg: Data?) async throws {
        guard let messenger = try? CoreStore.shared.current() else { return }
        try await Background.run {
            try messenger.setProfilePhoto(image: jpeg, nowMillis: CoreStore.nowMillis)
        }
        await reloadOwn()
        Task.detached(priority: .utility) {
            let targets = (try? messenger.profilePhotoTargets()) ?? []
            for name in targets {
                _ = try? messenger.shareProfilePhotoWith(peerUsername: name, nowMillis: CoreStore.nowMillis)
            }
        }
    }

    /// Аватар канала: сначала из базы, а нет — скачать (один раз).
    func loadChannel(_ channel: FfiChannel) {
        let id = channel.channelId
        guard let descriptor = channel.avatar, !descriptor.isEmpty else {
            if channels[id] != nil { channels[id] = nil }
            channelKeys[id] = nil
            return
        }
        guard channelKeys[id] != descriptor, !loadingChannels.contains(id),
              let messenger = try? CoreStore.shared.current() else { return }
        loadingChannels.insert(id)
        Task {
            defer { loadingChannels.remove(id) }
            var bytes: Data? = try? await Background.run { try messenger.cachedChannelAvatarImage(channelId: id) }
            if bytes == nil {
                bytes = try? await Background.run {
                    try messenger.channelAvatarImage(channelId: id, nowMillis: CoreStore.nowMillis)
                }
            }
            guard let bytes, let image = Self.thumbnail(bytes, side: 300) else { return }
            channels[id] = image
            channelKeys[id] = descriptor
        }
    }

    /// Свой канал получил новый аватар — показать сразу, не скачивая.
    func channelAvatarChanged(_ id: String, image: Data?) {
        channelKeys[id] = nil
        channels[id] = image.flatMap { Self.thumbnail($0, side: 300) }
    }

    /// Уменьшенный эскиз без раскрытия картинки в полный размер.
    nonisolated static func thumbnail(_ data: Data, side: CGFloat) -> UIImage? {
        guard !data.isEmpty,
              let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary)
        else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: side * 2,
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        return UIImage(cgImage: cg)
    }

    /// Квадрат по центру, `side` точек, JPEG не больше `limit` байт — для
    /// фото профиля и аватара канала. 🔐 Перерисовка выбрасывает EXIF
    /// (место съёмки, модель телефона).
    nonisolated static func squareJPEG(_ data: Data, side: CGFloat = 384, limit: Int = 90_000) -> Data? {
        guard let image = UIImage(data: data) else { return nil }
        let size = image.size
        let crop = min(size.width, size.height)
        guard crop > 0 else { return nil }
        let target = CGSize(width: side, height: side)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        let scale = side / crop
        let drawn = UIGraphicsImageRenderer(size: target, format: format).image { _ in
            image.draw(in: CGRect(x: -(size.width - crop) / 2 * scale, y: -(size.height - crop) / 2 * scale,
                                  width: size.width * scale, height: size.height * scale))
        }
        for quality in stride(from: 0.85, through: 0.35, by: -0.1) {
            if let jpeg = drawn.jpegData(compressionQuality: quality), jpeg.count <= limit { return jpeg }
        }
        return nil
    }
}

/// Аватар канала — с картинкой, когда она загружена.
struct ChannelAvatar: View {
    let channel: FfiChannel
    var size: CGFloat = 52
    @State private var photos = PhotoStore.shared

    var body: some View {
        Avatar(name: channel.title, size: size, image: photos.channels[channel.channelId])
            .onAppear { photos.loadChannel(channel) }
            .onChange(of: channel.avatar) { _, _ in photos.loadChannel(channel) }
    }
}
