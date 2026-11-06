// swift-tools-version:5.10
// SPDX-License-Identifier: Apache-2.0
//
// Слой приложения без интерфейса (ядро, сеть, ключи) — отдельным
// пакетом, чтобы его можно было собрать и протестировать вне Xcode:
// на Linux против Linux-сборки ядра (tools/ios-kit-test.sh) и на Mac.
//
// Само приложение собирается проектом Xcode (project.yml) из тех же
// файлов; интерфейс (SwiftUI) в пакет не входит.
//
// Перед сборкой нужны биндинги и библиотека ядра:
//   GasApp/Generated/gasapp.swift   — uniffi-bindgen
//   build/headers/module.modulemap  — модуль gasappFFI (+ link "gasapp")

import PackageDescription

let package = Package(
    name: "GasAppKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "GasAppKit", targets: ["GasAppKit"]),
    ],
    targets: [
        .systemLibrary(name: "gasappFFI", path: "build/headers"),
        .target(
            name: "GasAppKit",
            dependencies: ["gasappFFI"],
            path: "GasApp",
            sources: ["Core", "Net", "App/AppConfig.swift", "Generated/gasapp.swift"]
        ),
        .testTarget(
            name: "GasAppKitTests",
            dependencies: ["GasAppKit"],
            path: "KitTests"
        ),
    ]
)
