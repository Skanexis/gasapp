// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UIKit

/// «Медиа и файлы» переписки: фото сеткой, файлы и голосовые списком —
/// как в профиле собеседника в Telegram.
///
/// Без сети до показа: что за вложение — из описания (`parseAttachmentDescriptor`);
/// сами файлы качаются, только когда их ячейка на экране.
struct ChatMediaScreen: View {
    let messages: [MessageRow]

    enum Tab: Hashable { case media, files, voice }

    @State private var tab: Tab = .media
    @State private var opened: Data?

    struct Item: Identifiable {
        let id: String
        let descriptor: Data
        let info: FfiAttachmentInfo
        let timestamp: Int64
    }

    /// Вложения, новые сверху.
    private var items: [Item] {
        var found: [Item] = []
        for message in messages.reversed() {
            for (index, descriptor) in message.attachments.enumerated() {
                guard let info = try? parseAttachmentDescriptor(descriptor: descriptor) else { continue }
                found.append(Item(id: "\(message.id)-\(index)", descriptor: descriptor, info: info,
                                  timestamp: message.timestamp))
            }
        }
        return found
    }

    private func shown(_ all: [Item]) -> [Item] {
        all.filter { item in
            switch tab {
            case .media: item.info.kind == .image || item.info.kind == .video
            case .files: item.info.kind == .document
            case .voice: item.info.kind == .voice
            }
        }
    }

    var body: some View {
        let all = items
        let list = shown(all)
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                Text(L10n.t("Медиа", "Media", "Media")).tag(Tab.media)
                Text(L10n.t("Файлы", "Files", "File")).tag(Tab.files)
                Text(L10n.t("Голосовые", "Voice", "Vocali")).tag(Tab.voice)
            }
            .pickerStyle(.segmented)
            .padding(12)

            if list.isEmpty {
                Spacer()
                Label(emptyText, systemImage: tab == .media ? "photo.on.rectangle" : tab == .files ? "doc" : "waveform")
                    .font(GasFont.text(15)).foregroundStyle(GasAppColor.textTertiary)
                Spacer()
            } else if tab == .media {
                ScrollView {
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 2), count: 3), spacing: 2) {
                        ForEach(list) { item in
                            MediaThumb(descriptor: item.descriptor)
                                .aspectRatio(1, contentMode: .fill)
                                .clipped()
                                .contentShape(Rectangle())
                                .onTapGesture { opened = item.descriptor }
                        }
                    }
                }
            } else {
                List(list) { item in
                    VStack(alignment: .leading, spacing: 4) {
                        AttachmentView(descriptor: item.descriptor)
                        Text(formatChatTime(item.timestamp))
                            .font(GasFont.text(11)).foregroundStyle(GasAppColor.textTertiary)
                    }
                    .listRowBackground(GasAppColor.bgCard)
                }
                .scrollContentBackground(.hidden)
            }
        }
        .animation(.snappy(duration: 0.2), value: tab)
        .background(GasAppColor.bgBase.ignoresSafeArea())
        .navigationTitle(L10n.t("Медиа и файлы", "Media and files", "Media e file"))
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: Binding(get: { opened.map { Opened(descriptor: $0) } }, set: { opened = $0?.descriptor })) { item in
            ZStack {
                Color.black.ignoresSafeArea()
                AttachmentView(descriptor: item.descriptor)
            }
            .presentationDragIndicator(.visible)
        }
    }

    private struct Opened: Identifiable {
        let descriptor: Data
        var id: Data { descriptor }
    }

    private var emptyText: String {
        switch tab {
        case .media: L10n.t("Фото пока нет", "No photos yet", "Ancora nessuna foto")
        case .files: L10n.t("Файлов пока нет", "No files yet", "Ancora nessun file")
        case .voice: L10n.t("Голосовых пока нет", "No voice messages yet", "Ancora nessun vocale")
        }
    }
}

/// Квадратная миниатюра фото — качается, только когда на экране.
struct MediaThumb: View {
    let descriptor: Data
    @State private var image: UIImage?

    var body: some View {
        GeometryReader { geometry in
            ZStack {
                GasAppColor.bgCard
                if let image {
                    Image(uiImage: image).resizable().scaledToFill()
                        .frame(width: geometry.size.width, height: geometry.size.height)
                        .clipped()
                        .transition(.opacity)
                } else {
                    ProgressView().tint(GasAppColor.accent)
                }
            }
        }
        .task(id: descriptor) { await load() }
    }

    private func load() async {
        if let ready = AttachmentCache.shared.image(descriptor) {
            image = ready
            return
        }
        var bytes = AttachmentCache.shared.get(descriptor)
        if bytes == nil, let messenger = try? CoreStore.shared.current(), let device = CoreStore.shared.deviceId {
            let key = descriptor
            bytes = try? await Background.run {
                try messenger.fetchAttachment(deviceId: device, descriptor: key, nowMillis: CoreStore.nowMillis)
            }
            if let bytes { AttachmentCache.shared.put(descriptor, bytes) }
        }
        guard let bytes else { return }
        let decoded = await AttachmentCache.shared.prepared(descriptor, from: bytes)
        withAnimation(.easeOut(duration: 0.2)) { image = decoded }
    }
}
