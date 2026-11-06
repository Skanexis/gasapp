#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Сборка Rust-ядра под iOS: XCFramework + биндинги Swift.
#
# Использование:
#   tools/build-rust-ios.sh [--debug]
#
# Требуется macOS с установленным Xcode: lipo и xcodebuild входят в него
# и не имеют аналогов на других платформах.
#
# Собираются три среза:
#   aarch64-apple-ios       устройства
#   aarch64-apple-ios-sim   симулятор на Apple Silicon
#   x86_64-apple-ios        симулятор на Intel
#
# Два симуляторных среза объединяются через lipo в один fat-архив,
# потому что XCFramework не принимает два отдельных среза для одной
# платформы — он различает платформы, а не архитектуры.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATES="$ROOT/crates"
BUILD="$ROOT/ios/build"
XCFRAMEWORK="$ROOT/ios/GasAppCore.xcframework"
SWIFT_OUT="$ROOT/ios/GasApp/Generated"

DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)

PROFILE="release"
CARGO_PROFILE_FLAG="--release"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug) PROFILE="debug"; CARGO_PROFILE_FLAG=""; shift ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

# --- Проверка окружения -----------------------------------------------------

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: сборка под iOS возможна только на macOS" >&2
  echo "  требуются lipo и xcodebuild из состава Xcode" >&2
  exit 1
fi

for tool in lipo xcodebuild; do
  command -v "$tool" > /dev/null 2>&1 || {
    echo "error: не найден $tool — установите Xcode" >&2
    exit 1
  }
done

echo "профиль : $PROFILE"
echo "таргеты : $DEVICE_TARGET ${SIM_TARGETS[*]}"
echo

# --- Сборка срезов ----------------------------------------------------------

for target in "$DEVICE_TARGET" "${SIM_TARGETS[@]}"; do
  rustup target add "$target" > /dev/null 2>&1 || true
  echo "сборка $target"
  # --features vendored-openssl: как и в NDK, в SDK iOS нет OpenSSL,
  # а он нужен SQLCipher. Без флага сборка падала на поиске openssl.
  # shellcheck disable=SC2086
  cargo build $CARGO_PROFILE_FLAG \
    --manifest-path "$CRATES/Cargo.toml" -p gasapp-ffi --target "$target" \
    --features vendored-openssl
done

# --- Объединение симуляторных срезов ----------------------------------------

rm -rf "$BUILD" "$XCFRAMEWORK"
mkdir -p "$BUILD/sim" "$BUILD/device"

cp "$CRATES/target/$DEVICE_TARGET/$PROFILE/libgasapp.a" "$BUILD/device/libgasapp.a"

SIM_INPUTS=()
for target in "${SIM_TARGETS[@]}"; do
  SIM_INPUTS+=("$CRATES/target/$target/$PROFILE/libgasapp.a")
done
lipo -create "${SIM_INPUTS[@]}" -output "$BUILD/sim/libgasapp.a"

echo
echo "срезы симулятора объединены:"
lipo -info "$BUILD/sim/libgasapp.a"

# --- Генерация биндингов Swift ----------------------------------------------
#
# Заголовки и modulemap обязаны попасть в XCFramework: без них Xcode
# не сможет слинковать статическую библиотеку.

echo
echo "генерация биндингов Swift"
rm -rf "$SWIFT_OUT"
mkdir -p "$SWIFT_OUT"

cargo run --manifest-path "$CRATES/Cargo.toml" -p gasapp-ffi --bin uniffi-bindgen -- \
  generate --library "$BUILD/device/libgasapp.a" \
  --language swift --out-dir "$SWIFT_OUT"

# Заголовки уезжают в XCFramework, .swift остаётся в проекте.
mkdir -p "$BUILD/headers"
find "$SWIFT_OUT" -name '*.h' -exec mv {} "$BUILD/headers/" \;

# UniFFI генерирует отдельные modulemap для каждого модуля; Xcode ожидает
# один файл с фиксированным именем.
if compgen -G "$SWIFT_OUT/*.modulemap" > /dev/null; then
  cat "$SWIFT_OUT"/*.modulemap > "$BUILD/headers/module.modulemap"
  rm -f "$SWIFT_OUT"/*.modulemap
fi

# --- Сборка XCFramework -----------------------------------------------------

xcodebuild -create-xcframework \
  -library "$BUILD/device/libgasapp.a" -headers "$BUILD/headers" \
  -library "$BUILD/sim/libgasapp.a"    -headers "$BUILD/headers" \
  -output "$XCFRAMEWORK"

echo
echo "готово: $XCFRAMEWORK"
echo "        $SWIFT_OUT"
echo
echo "⚠️  Воспроизводимая сборка под iOS недостижима (ADR-020):"
echo "    Xcode встраивает пути и метки времени, которые мы не контролируем."
echo "    Для iOS уровень проверяемости — открытый код и спецификация,"
echo "    но не побайтовое сравнение с опубликованным артефактом."
