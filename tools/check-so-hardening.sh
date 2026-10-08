#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 🔐 Защита от эксплуатации в собранной libgasapp.so (MASVS CODE-2.5).
#
# Использование:
#   tools/check-so-hardening.sh [каталог-или-.so ...]
#
# По умолчанию проверяет все android/app/src/main/jniLibs/*/libgasapp.so.
# Нужен llvm-readelf: из PATH или из $ANDROID_NDK_HOME.
#
# Что проверяется у каждой библиотеки:
#
#   * тип DYN и нет TEXTREL — код позиционно-независим, страницы кода
#     не приходится делать записываемыми при загрузке;
#   * сегмент GNU_RELRO и флаг BIND_NOW — полный RELRO: таблица
#     переходов после загрузки только для чтения, и перезапись её
#     записи не перехватывает управление;
#   * GNU_STACK без флага E — стек неисполняем;
#   * импорт __stack_chk_fail — Си-часть ядра (SQLCipher, OpenSSL)
#     собрана с канарейками стека;
#   * функции __*_chk — Си-часть собрана с _FORTIFY_SOURCE.
#
# # Почему две последние проверки не «умолчание NDK»
#
# ⚠️ Строка CODE-2.5 чек-листа до 2026-09 держалась на «умолчаниях NDK
# для API 28». Проверка показала: в libgasapp.so нет ни одного импорта
# __stack_chk_fail и ни одной __*_chk. Крейт cc, которым собираются
# SQLCipher и OpenSSL, флагов защиты не добавляет, а clang без них
# канареек не ставит. Флаги теперь задаёт tools/build-rust-android.sh,
# а этот скрипт следит, чтобы они доходили до библиотеки.
#
# # Чего здесь не проверяется
#
# Канареек в коде на Rust. Стабильный компилятор их не ставит
# (-Z stack-protector — только nightly); Rust-часть защищена иначе —
# проверками границ и запретом unsafe (CODE-2.1, CODE-2.2).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

find_readelf() {
  if command -v llvm-readelf > /dev/null 2>&1; then
    command -v llvm-readelf
    return
  fi

  if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
    local candidate
    for candidate in "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf{,.exe}; do
      if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return
      fi
    done
  fi

  echo "error: llvm-readelf не найден — добавьте NDK в PATH или задайте ANDROID_NDK_HOME" >&2
  exit 2
}

READELF="$(find_readelf)"

libraries=()
if [[ $# -eq 0 ]]; then
  set -- "$ROOT/android/app/src/main/jniLibs"
fi

for arg in "$@"; do
  if [[ -d "$arg" ]]; then
    while IFS= read -r -d '' lib; do
      libraries+=("$lib")
    done < <(find "$arg" -name 'libgasapp.so' -print0)
  else
    libraries+=("$arg")
  fi
done

if [[ ${#libraries[@]} -eq 0 ]]; then
  echo "error: не найдено ни одной libgasapp.so — проверять нечего" >&2
  exit 2
fi

failures=0

fail() {
  echo "  ✗ $1"
  failures=$((failures + 1))
}

for lib in "${libraries[@]}"; do
  echo "$lib"

  header=$("$READELF" -hW "$lib")
  segments=$("$READELF" -lW "$lib")
  dynamic=$("$READELF" -dW "$lib")
  imports=$("$READELF" --dyn-syms -W "$lib" | awk '$7 == "UND" { print $8 }')

  grep -q 'Type:.*DYN' <<< "$header" || fail "не DYN: библиотека не позиционно-независима"
  grep -q 'TEXTREL' <<< "$dynamic" && fail "TEXTREL: код правится при загрузке"

  grep -q 'GNU_RELRO' <<< "$segments" || fail "нет GNU_RELRO"
  grep -qE 'BIND_NOW|FLAGS_1\).*NOW' <<< "$dynamic" || fail "нет BIND_NOW: RELRO частичный"

  stack=$(grep 'GNU_STACK' <<< "$segments" || true)
  if [[ -z "$stack" ]]; then
    fail "нет GNU_STACK: стек по умолчанию исполняемый"
  elif grep -qE 'RWE|\sE\s' <<< "$stack"; then
    fail "стек исполняемый"
  fi

  grep -q '^__stack_chk_fail' <<< "$imports" || fail "нет __stack_chk_fail: Си-часть без канареек стека"
  grep -qE '^__[a-z0-9_]+_chk(@|$)' <<< "$imports" || fail "нет __*_chk: Си-часть без _FORTIFY_SOURCE"

  if [[ $failures -eq 0 ]]; then
    echo "  ✓ DYN, полный RELRO, неисполняемый стек, канарейки и FORTIFY в Си-части"
  fi
done

if [[ $failures -gt 0 ]]; then
  echo
  echo "провалено проверок: $failures" >&2
  exit 1
fi
