#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Сборка и тесты слоя iOS без интерфейса (ios/Package.swift) — на Linux,
# против Linux-сборки ядра. Проверяет то, что можно проверить без Mac:
# биндинги UniFFI, транспорт, вывод ключа базы, PIN, правила отправки.
#
#     tools/ios-kit-test.sh <каталог с libgasapp.so и swift/>
#
# Каталог готовит сборка ядра с генерацией биндингов:
#     cargo build -p gasapp-ffi
#     cargo run -p gasapp-ffi --bin uniffi-bindgen -- generate \
#         --library target/debug/libgasapp.so --language swift --out-dir <каталог>/swift
#
# Запускать в контейнере swift (на хосте Windows Swift нет):
#     docker run --rm -v "$PWD:/repo:ro" -v <каталог>:/ffi swift:6.0-noble \
#         bash /repo/tools/ios-kit-test.sh /ffi
#
# SwiftUI, Security и CryptoKit на Linux нет: интерфейс здесь не
# собирается, а Keychain и Secure Enclave подменены (#if canImport).
# Их проверяет tools/mac-check.sh на Mac.

set -euo pipefail

FFI="${1:?каталог с libgasapp.so и swift/}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -r "$ROOT/ios" "$WORK/ios"
cd "$WORK/ios"

mkdir -p GasApp/Generated build/headers
cp "$FFI/swift/gasapp.swift" GasApp/Generated/
cp "$FFI/swift/gasappFFI.h" build/headers/
# Модуль заголовков ядра для SwiftPM — с указанием, какую библиотеку
# подключать.
cat > build/headers/module.modulemap <<'EOF'
module gasappFFI {
    header "gasappFFI.h"
    link "gasapp"
    export *
}
EOF

export LD_LIBRARY_PATH="$FFI${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
swift build --build-tests -Xlinker -L"$FFI" 2>&1 | grep -vE '^\[[0-9]+/[0-9]+\]' || true
swift test --skip-build -Xlinker -L"$FFI"
