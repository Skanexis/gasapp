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

    var body: some View {
        Canvas { context, size in
            let count = Int(matrix.size)
            guard count > 0 else { return }
            // Тихая зона — четыре модуля с каждой стороны.
            let cell = min(size.width, size.height) / CGFloat(count + 8)
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(.white))
            for row in 0..<count {
                for column in 0..<count where matrix.modules[row * count + column] {
                    let rect = CGRect(x: CGFloat(column + 4) * cell, y: CGFloat(row + 4) * cell,
                                      width: cell + 0.5, height: cell + 0.5)
                    context.fill(Path(rect), with: .color(.black))
                }
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .clipShape(RoundedRectangle(cornerRadius: 12))
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
