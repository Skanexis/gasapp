#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Правило 1 (AEGIS_MASTER_PLAN.md §4.1): UI не занимается криптографией.
#
# UI-слой вызывает core.sendMessage(chatId, plaintext).
# UI-слой не вызывает deriveKey(), encryptAES(), updateRatchet().
#
# Причина правила: криптография, размазанная по двум UI-кодовым базам,
# не поддаётся аудиту и гарантированно разойдётся между платформами.
#
# Исключение ровно одно: платформенная обёртка аппаратного хранилища ключей.
# Она обязана использовать CryptoKit / javax.crypto, потому что это
# единственный способ обратиться к Secure Enclave и Android Keystore.

set -euo pipefail

# --- Запрещённые импорты и вызовы ---
FORBIDDEN_IOS='CryptoKit|CommonCrypto|CC_SHA|CCCrypt|SecKeyCreateSignature|SecKeyCreateEncryptedData'
FORBIDDEN_ANDROID='javax\.crypto|java\.security\.(KeyPairGenerator|Signature|MessageDigest)|bouncycastle|com\.google\.crypto\.tink|libsodium'

# --- Файлы-исключения (allow-list) ---
# Любое расширение этого списка требует явного обоснования в ревью.
ALLOWED='ios/AEGIS/Platform/KeyProtection.swift|android/app/src/main/kotlin/org/aegis/platform/KeyProtection.kt'

violations=0

scan() {
  local label="$1" dir="$2" pattern="$3" ext="$4"

  [ -d "$dir" ] || return 0

  local hits
  hits=$(grep -rnE --include="$ext" "$pattern" "$dir" 2>/dev/null | grep -vE "$ALLOWED" || true)

  if [ -n "$hits" ]; then
    echo "::error::[$label] запрещённое использование криптографии в UI-слое:"
    echo "$hits" | while IFS= read -r line; do
      echo "  $line"
    done
    echo ""
    echo "  Вся криптография принадлежит Rust-ядру (crates/aegis-protocol)."
    echo "  Если это платформенная обёртка аппаратного хранилища — добавьте"
    echo "  файл в ALLOWED и обоснуйте это в описании PR."
    violations=$((violations + 1))
  else
    echo "OK: [$label] криптографии в UI-слое не найдено"
  fi
}

scan "iOS"     "ios"     "$FORBIDDEN_IOS"     "*.swift"
scan "Android" "android" "$FORBIDDEN_ANDROID" "*.kt"

exit "$violations"
