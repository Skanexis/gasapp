#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Сборка Rust-ядра под Android: libgasapp.so для четырёх ABI + биндинги Kotlin.
#
# Использование:
#   tools/build-rust-android.sh [--debug] [--abi arm64-v8a]
#
# Требуется:
#   ANDROID_NDK_HOME  — путь к NDK
#   cargo-ndk         — cargo install cargo-ndk
#   Rust targets      — rustup target add aarch64-linux-android \
#                         armv7-linux-androideabi x86_64-linux-android \
#                         i686-linux-android

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATES="$ROOT/crates"
JNI_LIBS="$ROOT/android/app/src/main/jniLibs"
KOTLIN_OUT="$ROOT/android/app/src/main/kotlin"

# minSdk из раздела 19.2 плана. Занижать нельзя: на API < 28 недоступны
# setUnlockedDeviceRequired и часть гарантий Keystore, на которых держится
# схема KEK/DEK (ADR-017).
API_LEVEL=28

PROFILE="release"
CARGO_PROFILE_FLAG="--release"
DEFAULT_ABIS=(arm64-v8a armeabi-v7a x86_64 x86)
ABIS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug) PROFILE="debug"; CARGO_PROFILE_FLAG=""; shift ;;
    # Накапливается, а не заменяется: `--abi a --abi b` собирает обе.
    # Прежде второй флаг молча отменял первый, и вызывающий получал
    # одну библиотеку там, где просил две.
    --abi)   ABIS+=("$2"); shift 2 ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

if [[ "${#ABIS[@]}" -eq 0 ]]; then
  ABIS=("${DEFAULT_ABIS[@]}")
fi

# --- Проверка окружения -----------------------------------------------------

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  echo "error: ANDROID_NDK_HOME не задан" >&2
  echo "  укажите путь к NDK, например:" >&2
  echo "  export ANDROID_NDK_HOME=\"\$HOME/Android/Sdk/ndk/29.0.14206865\"" >&2
  exit 1
fi

if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "error: NDK не найден по пути $ANDROID_NDK_HOME" >&2
  exit 1
fi

if ! command -v cargo-ndk > /dev/null 2>&1; then
  echo "error: cargo-ndk не установлен — cargo install cargo-ndk" >&2
  exit 1
fi

echo "NDK      : $ANDROID_NDK_HOME"
echo "профиль  : $PROFILE"
echo "API      : $API_LEVEL"
echo "ABI      : ${ABIS[*]}"
echo

# --- Сборка библиотек -------------------------------------------------------

TARGET_FLAGS=()
for abi in "${ABIS[@]}"; do
  TARGET_FLAGS+=(-t "$abi")
done

# 🔐 Защита Си-части ядра от эксплуатации (MASVS CODE-2.5).
#
# SQLCipher и OpenSSL собираются крейтом cc, а он флагов защиты
# не добавляет: до 2026-09 в libgasapp.so не было ни одной канарейки
# стека и ни одной проверки _FORTIFY_SOURCE, хотя чек-лист считал их
# «умолчаниями NDK». Именно Си-код разбирает содержимое базы
# и выполняет шифрование страниц — там переполнение буфера
# возможно, в отличие от Rust.
#
# Проверяется tools/check-so-hardening.sh по собранной библиотеке.
#
# Флаги по тройкам, а не общий CFLAGS: общий ушёл бы и в сборку
# для хоста. Крейт cc читает CFLAGS_<тройка> и передаёт его и в
# openssl-src. Bionic без оптимизации _FORTIFY_SOURCE молча не
# применяет, поэтому в отладочной сборке проверка его не найдёт.
HARDENING_CFLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2"
for triple in aarch64_linux_android armv7_linux_androideabi x86_64_linux_android i686_linux_android; do
  export "CFLAGS_${triple}=${HARDENING_CFLAGS}"
done

# `cargo ndk` читает Cargo.toml из текущего каталога, а не из
# --manifest-path: тот передаётся дальше, во вложенный `cargo build`.
# Без смены каталога сборка падает с «could not find Cargo.toml».
(
  cd "$CRATES" || exit 1

  # --features vendored-openssl: в NDK системного OpenSSL нет, а он
  # нужен SQLCipher. Флаг включается только здесь, чтобы обычные
  # сборки на Linux пользовались системным.
  #
  # shellcheck disable=SC2086
  cargo ndk "${TARGET_FLAGS[@]}" -P "$API_LEVEL" -o "$JNI_LIBS" \
    build $CARGO_PROFILE_FLAG -p gasapp-ffi --features vendored-openssl
)

# --- Генерация биндингов Kotlin ---------------------------------------------
#
# Библиотечный режим: биндинги строятся по собранной .so, а не по отдельному
# описанию интерфейса. Отдельное описание неизбежно расходится с кодом,
# потому что компилятор его не проверяет.

REFERENCE_ABI="${ABIS[0]}"
REFERENCE_LIB="$JNI_LIBS/$REFERENCE_ABI/libgasapp.so"

if [[ ! -f "$REFERENCE_LIB" ]]; then
  echo "error: не найдена собранная библиотека $REFERENCE_LIB" >&2
  exit 1
fi

echo
echo "генерация биндингов Kotlin по $REFERENCE_ABI"
mkdir -p "$KOTLIN_OUT"

# ⚠️ Запускается из каталога workspace, а не из корня репозитория.
#
# `--manifest-path` говорит cargo, что собирать, но сам
# `uniffi-bindgen` внутри зовёт `cargo metadata` в **текущем**
# каталоге. В корне репозитория `Cargo.toml` нет — workspace лежит
# в `crates/`, — и шаг падал с «could not find Cargo.toml».
#
# Заметно это было не сразу: вызывающий, пустивший вывод через
# `| tail`, получал код возврата `tail`, то есть ноль. Сборка
# выглядела успешной, а биндинги оставались от прошлого раза.
(
  cd "$CRATES" || exit 1

  cargo run -p gasapp-ffi --bin uniffi-bindgen -- \
    generate --library "$REFERENCE_LIB" --language kotlin \
    --out-dir "$KOTLIN_OUT" --no-format
)

# ⚠️ uniffi-bindgen завершается с кодом 0, даже если не сгенерировал ничего.
# Так бывает, когда из библиотеки вырезаны символы UNIFFI_META_*
# (см. strip в crates/Cargo.toml). Проверяем результат явно, иначе сборка
# «успешно» выдаст Android-проект без единого биндинга.
generated_count=$(find "$KOTLIN_OUT" -name '*.kt' -newer "$REFERENCE_LIB" 2>/dev/null | wc -l)
if [[ "$generated_count" -eq 0 ]]; then
  echo "error: uniffi-bindgen не создал ни одного файла Kotlin" >&2
  echo "  вероятная причина: из $REFERENCE_LIB вырезаны символы UNIFFI_META_*" >&2
  echo "  проверьте strip в профиле release (crates/Cargo.toml)" >&2
  exit 1
fi
echo "  сгенерировано файлов Kotlin: $generated_count"

# --- Проверка результата ----------------------------------------------------
#
# Библиотека без экспортируемых символов собирается без единой ошибки
# и падает только в рантайме при первом вызове — проверяем сразу.

# ⚠️ Без `-type f`: в NDK r27 llvm-readelf — символическая ссылка
# на llvm-readobj, и `-type f` её не находил. Проверка ниже всё это
# время печатала «?» и пропускалась — в том числе в CI.
READELF="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -name 'llvm-readelf*' 2>/dev/null | head -1)"

# Нечем проверить — значит не проверено: ошибка, а не пропуск.
if [[ -z "$READELF" ]]; then
  echo "error: llvm-readelf не найден в $ANDROID_NDK_HOME — проверить библиотеки нечем" >&2
  exit 1
fi

echo
echo "результат:"
failures=0
for abi in "${ABIS[@]}"; do
  lib="$JNI_LIBS/$abi/libgasapp.so"
  if [[ ! -f "$lib" ]]; then
    echo "  ✗ $abi — библиотека не собрана"
    failures=$((failures + 1))
    continue
  fi

  size=$(wc -c < "$lib")

  exported=$("$READELF" --dyn-syms "$lib" 2>/dev/null \
    | grep -cE '^\s+[0-9]+:' || true)
  undefined=$("$READELF" --dyn-syms "$lib" 2>/dev/null \
    | grep -cE '^\s+[0-9]+:.*\sUND\s' || true)
  defined=$((exported - undefined))

  if [[ "$defined" -eq 0 ]]; then
    echo "  ✗ $abi — ноль экспортируемых символов (${size} байт)"
    failures=$((failures + 1))
  else
    echo "  ✓ $abi — ${defined} символов, ${size} байт"
  fi
done

if [[ "$failures" -gt 0 ]]; then
  echo
  echo "error: $failures ABI собрано некорректно" >&2
  exit 1
fi

echo
echo "готово: $JNI_LIBS"
echo "        $KOTLIN_OUT"
