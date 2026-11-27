// SPDX-License-Identifier: Apache-2.0

import AVFoundation
import SwiftUI
import UIKit

/// Голосовое сообщение: запись по удержанию кнопки микрофона.
///
/// 🔐 Запись идёт во временный файл с защитой «до разблокировки» и
/// удаляется сразу после чтения: на телефоне голосового не остаётся —
/// оно уходит под сквозным шифрованием, как любое вложение.
@MainActor
@Observable
final class VoiceRecorder {
    static let shared = VoiceRecorder()

    /// Идёт ли запись.
    private(set) var recording = false
    /// Сколько записано, секунды.
    private(set) var elapsed: TimeInterval = 0
    /// Текущая громкость 0…1 — для пульсирующей точки.
    private(set) var level: CGFloat = 0

    @ObservationIgnored private var recorder: AVAudioRecorder?
    @ObservationIgnored private var meter: Timer?
    @ObservationIgnored private var samples: [Float] = []
    @ObservationIgnored private var url: URL?

    /// Предел длины — 10 минут: файл AAC ~2 МБ.
    static let maxSeconds: TimeInterval = 600

    /// Начать запись. Нет разрешения на микрофон — `false`.
    func start() async -> Bool {
        guard !recording else { return true }
        let granted = await AVAudioApplication.requestRecordPermission()
        guard granted else { return false }
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playAndRecord, mode: .spokenAudio, options: [.defaultToSpeaker, .allowBluetooth])
            try session.setActive(true)
        } catch {
            return false
        }
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("voice-\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 24_000,
            AVNumberOfChannelsKey: 1,
            AVEncoderBitRateKey: 32_000,
            AVEncoderAudioQualityKey: AVAudioQuality.medium.rawValue,
        ]
        guard let recorder = try? AVAudioRecorder(url: file, settings: settings) else { return false }
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: file.path)
        recorder.isMeteringEnabled = true
        guard recorder.record(forDuration: Self.maxSeconds) else { return false }
        self.recorder = recorder
        url = file
        samples = []
        elapsed = 0
        recording = true
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        meter = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        return true
    }

    private func tick() {
        guard let recorder else { return }
        recorder.updateMeters()
        // −50 дБ и тише — тишина, 0 дБ — максимум.
        let power = max(-50, recorder.averagePower(forChannel: 0))
        let value = (power + 50) / 50
        samples.append(value)
        level = CGFloat(value)
        elapsed = recorder.currentTime
    }

    /// Закончить: файл, длительность и огибающая громкости (до 100 точек).
    /// Короче полусекунды — не голосовое, а случайное касание: `nil`.
    func finish() -> (Data, UInt32, [UInt8])? {
        let duration = recorder?.currentTime ?? 0
        let file = url
        stopRecorder()
        defer { if let file { try? FileManager.default.removeItem(at: file) } }
        guard duration >= 0.5, let file, let data = try? Data(contentsOf: file) else { return nil }
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        return (data, UInt32(min(duration, Self.maxSeconds) * 1000), Self.waveform(samples, points: 100))
    }

    /// Передумали — запись стирается.
    func cancel() {
        let file = url
        stopRecorder()
        if let file { try? FileManager.default.removeItem(at: file) }
        UINotificationFeedbackGenerator().notificationOccurred(.warning)
    }

    private func stopRecorder() {
        meter?.invalidate()
        meter = nil
        recorder?.stop()
        recorder = nil
        url = nil
        recording = false
        level = 0
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    /// Сжать замеры до `points` значений 0…255.
    nonisolated static func waveform(_ samples: [Float], points: Int) -> [UInt8] {
        guard !samples.isEmpty else { return [] }
        let count = min(points, samples.count)
        let step = Double(samples.count) / Double(count)
        return (0..<count).map { index in
            let from = Int(Double(index) * step)
            let to = max(from + 1, Int(Double(index + 1) * step))
            let slice = samples[from..<min(to, samples.count)]
            let peak = slice.max() ?? 0
            return UInt8(max(0, min(255, peak * 255)))
        }
    }
}

/// Проигрыватель голосовых — один на всё приложение: новое голосовое
/// останавливает прежнее.
@MainActor
@Observable
final class VoicePlayer: NSObject, AVAudioPlayerDelegate {
    static let shared = VoicePlayer()

    /// Что играет (описание вложения).
    private(set) var playing: Data?
    /// Доля проигранного 0…1.
    private(set) var progress: Double = 0

    @ObservationIgnored private var player: AVAudioPlayer?
    @ObservationIgnored private var timer: Timer?

    func toggle(_ key: Data, audio: Data) {
        if playing == key {
            stop()
            return
        }
        stop()
        try? AVAudioSession.sharedInstance().setCategory(.playback, mode: .spokenAudio)
        try? AVAudioSession.sharedInstance().setActive(true)
        guard let player = try? AVAudioPlayer(data: audio) else { return }
        player.delegate = self
        guard player.play() else { return }
        self.player = player
        playing = key
        progress = 0
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let player = self.player, player.duration > 0 else { return }
                self.progress = player.currentTime / player.duration
            }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        player?.stop()
        player = nil
        playing = nil
        progress = 0
    }

    nonisolated func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        Task { @MainActor in self.stop() }
    }
}

/// Голосовое в пузыре: кнопка, огибающая (проигранное — золотом), время.
struct VoiceBubble: View {
    let descriptor: Data
    let info: FfiAttachmentInfo
    /// Расшифрованный звук; `nil` — ещё качается.
    let audio: Data?
    let failed: Bool

    @State private var player = VoicePlayer.shared

    private var isPlaying: Bool { player.playing == descriptor }

    private var bars: [CGFloat] {
        let points = Array(info.waveform ?? Data())
        guard !points.isEmpty else { return Array(repeating: 0.3, count: 40) }
        return points.map { max(0.12, CGFloat($0) / 255) }
    }

    private var duration: String {
        let seconds = Int((info.durationMillis ?? 0) / 1000)
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    var body: some View {
        HStack(spacing: 10) {
            Button {
                guard let audio else { return }
                player.toggle(descriptor, audio: audio)
            } label: {
                ZStack {
                    Circle().fill(GasAppColor.accent)
                    if audio == nil && !failed {
                        ProgressView().tint(GasAppColor.accentOn)
                    } else {
                        Image(systemName: failed ? "exclamationmark" : isPlaying ? "pause.fill" : "play.fill")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(GasAppColor.accentOn)
                            .contentTransition(.symbolEffect(.replace))
                    }
                }
                .frame(width: 40, height: 40)
            }
            .buttonStyle(.plain)
            .disabled(audio == nil)
            .accessibilityLabel(isPlaying ? L10n.t("Пауза", "Pause", "Pausa") : L10n.t("Слушать голосовое", "Play voice message", "Ascolta il vocale"))

            VStack(alignment: .leading, spacing: 4) {
                GeometryReader { geometry in
                    let count = bars.count
                    let width = geometry.size.width / CGFloat(max(count, 1))
                    HStack(alignment: .center, spacing: 0) {
                        ForEach(0..<count, id: \.self) { index in
                            let played = isPlaying && Double(index) / Double(count) <= player.progress
                            Capsule()
                                .fill(played ? GasAppColor.accent : GasAppColor.textTertiary.opacity(0.6))
                                .frame(width: max(1.5, width * 0.6), height: max(3, bars[index] * 26))
                                .frame(width: width)
                        }
                    }
                    .frame(height: 28)
                }
                .frame(height: 28)
                Text(duration).font(GasFont.text(11)).monospacedDigit().foregroundStyle(GasAppColor.textTertiary)
            }
        }
        .frame(width: 220)
        .padding(.vertical, 2)
    }
}
