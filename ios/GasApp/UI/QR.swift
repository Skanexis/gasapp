// SPDX-License-Identifier: Apache-2.0

import SwiftUI
#if canImport(VisionKit)
import VisionKit
#endif

/// QR-код из ядра (`FfiQrMatrix`): модули строит ядро, платформа только
/// рисует — одна и та же строка даёт один и тот же код на обеих
/// платформах.
struct QRView: View {
    let matrix: FfiQrMatrix

    /// Тёмные модули — ночное небо GasApp, «зрачки» углов — коричневый
    /// контур логотипа. Оба тёмные: сканеру нужен контраст с белым, а
    /// не чёрный цвет.
    private static let ink = Color(red: 0.055, green: 0.071, blue: 0.22)
    private static let eye = Color(red: 0.54, green: 0.20, blue: 0.08)

    var body: some View {
        Canvas { context, size in
            let count = Int(matrix.size)
            guard count > 0 else { return }
            // Тихая зона — четыре модуля с каждой стороны.
            let cell = min(size.width, size.height) / CGFloat(count + 8)
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(.white))

            func isFinder(_ row: Int, _ column: Int) -> Bool {
                (row < 7 && column < 7) || (row < 7 && column >= count - 7) || (row >= count - 7 && column < 7)
            }
            // Модули — скруглённые квадраты чуть меньше клетки: код
            // остаётся читаемым, но выглядит мягче обычной «сетки».
            let inset = cell * 0.06
            for row in 0..<count {
                for column in 0..<count where matrix.modules[row * count + column] && !isFinder(row, column) {
                    let rect = CGRect(x: CGFloat(column + 4) * cell + inset, y: CGFloat(row + 4) * cell + inset,
                                      width: cell - inset * 2, height: cell - inset * 2)
                    context.fill(Path(roundedRect: rect, cornerRadius: cell * 0.32), with: .color(Self.ink))
                }
            }
            // Три угловых «глаза»: кольцо 7×7 и зрачок 3×3, скруглённые.
            for (row, column) in [(0, 0), (0, count - 7), (count - 7, 0)] {
                let origin = CGPoint(x: CGFloat(column + 4) * cell, y: CGFloat(row + 4) * cell)
                let outer = CGRect(origin: origin, size: CGSize(width: cell * 7, height: cell * 7))
                var ring = Path(roundedRect: outer, cornerRadius: cell * 2)
                ring.addPath(Path(roundedRect: outer.insetBy(dx: cell, dy: cell), cornerRadius: cell * 1.3))
                context.fill(ring, with: .color(Self.ink), style: FillStyle(eoFill: true))
                context.fill(Path(roundedRect: outer.insetBy(dx: cell * 2, dy: cell * 2), cornerRadius: cell * 0.9),
                             with: .color(Self.eye))
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .clipShape(RoundedRectangle(cornerRadius: 18))
        .accessibilityLabel(L10n.t("QR-код", "QR code", "Codice QR"))
    }
}

/// Сканер QR камерой (VisionKit). Снимки никуда не уходят: распознаётся
/// на телефоне, наружу отдаётся только текст кода.
struct QRScanner: View {
    let onCode: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    init(onCode: @escaping (String) -> Void) {
        self.onCode = onCode
    }

    var body: some View {
        NavigationStack {
            Group {
                #if canImport(VisionKit)
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    ScannerRepresentable { code in
                        onCode(code)
                        dismiss()
                    }
                    .ignoresSafeArea()
                } else {
                    unavailable
                }
                #else
                unavailable
                #endif
            }
            .navigationTitle(L10n.t("Сканировать", "Scan", "Scansiona"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.t("Закрыть", "Close", "Chiudi")) { dismiss() }
                }
            }
        }
    }

    private var unavailable: some View {
        Text(L10n.t("Камера недоступна. Разрешите доступ в Настройках или вставьте ссылку.",
                    "Camera unavailable. Allow access in Settings or paste the link.", "Fotocamera non disponibile. Consenti l’accesso nelle Impostazioni o incolla il link."))
            .foregroundStyle(GasAppColor.textSecondary)
            .multilineTextAlignment(.center)
            .padding(32)
            .gasScreen()
    }
}

#if canImport(VisionKit)
private struct ScannerRepresentable: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        private var done = false

        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for item in items {
                if case let .barcode(code) = item, let text = code.payloadStringValue {
                    done = true
                    scanner.stopScanning()
                    onCode(text)
                    return
                }
            }
        }
    }
}
#endif
