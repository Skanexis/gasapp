#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 🧪 `no_secrets_in_logs` — MASVS STORAGE-2, раздел 25 плана.
#
# Журнал переживает приложение. Он попадает в отчёты о падениях, в вывод
# `adb logcat`, доступный любому приложению с разрешением на чтение логов
# до Android 4.1 и любому подключённому компьютеру сейчас, и в багрепорты,
# которые пользователи пересылают открытым текстом. Ключ, попавший туда
# один раз, оттуда не изымается.
#
# # Что проверяется
#
# Что в вызов макроса `tracing` не подставляется значение, названное как
# секрет. Проверка грубая — по имени, — и это её предел: переименованная
# переменная её обойдёт. Она ловит не злой умысел, а обычную отладочную
# строку, дописанную при поиске ошибки и забытую в коммите.
#
# # Чего она не заменяет
#
# Главная защита — типовая: `Secret<T>` не реализует `Display`, а его
# `Debug` печатает заглушку (`crates/gasapp-types/src/secret.rs`), поэтому
# записать секрет в лог нельзя, не сняв его из обёртки намеренно.
# Свойство закреплено тестами `debug_output_is_redacted`,
# `debug_output_is_redacted_when_nested` (gasapp-types/src/secret.rs)
# и `error_messages_do_not_leak_detail` (gasapp-types/src/lib.rs) —
# последний проверяет, что и текст ошибки не намекает на содержимое.
#
# Скрипт ниже — второй рубеж, для того что из обёртки уже вынуто.

set -euo pipefail

# Имена, появление которых внутри форматной строки лога означает секрет.
#
# `key` намеренно нет: он встречается в `PRAGMA key`, `key_changed`
# и десятке других мест, где речь не о материале ключа. Ложное
# срабатывание в проверке, которую гоняют на каждом PR, кончается тем,
# что проверку отключают.
SUSPECT='plaintext|passphrase|password|mnemonic|seed_phrase|recovery_key|private_key|secret_key|session_key|message_key|chain_key|root_key|pin_value|shared_secret'

LOG_MACROS='tracing::(trace|debug|info|warn|error)!|^\s*(trace|debug|info|warn|error)!'

echo "== no_secrets_in_logs: секреты в журнале =="

violations=0

# Собираются строки с макросом лога, затем среди них ищутся подозрительные
# имена. Два прохода, потому что аргументы часто переносятся на следующую
# строку; -A2 захватывает их.
hits=$(grep -rnE -A2 "$LOG_MACROS" \
        --include='*.rs' \
        crates/ server/ 2>/dev/null \
        | grep -iE "$SUSPECT" || true)

if [[ -n "$hits" ]]; then
  echo "❌ подозрительные значения в вызовах журнала:"
  echo "$hits"
  violations=1
fi

# Отдельно — печать секрета в обход обёртки: `.expose()` внутри формата.
exposed=$(grep -rnE -A2 "$LOG_MACROS" \
        --include='*.rs' \
        crates/ server/ 2>/dev/null \
        | grep -E 'expose\(\)|expose_secret\(\)' || true)

if [[ -n "$exposed" ]]; then
  echo "❌ раскрытие Secret внутри вызова журнала:"
  echo "$exposed"
  violations=1
fi

if [[ "$violations" -ne 0 ]]; then
  echo
  echo "Журнал переживает приложение: логи уходят в отчёты о падениях"
  echo "и в багрепорты, которые пересылают открытым текстом."
  exit 1
fi

echo "✅ секретов в вызовах журнала не найдено"
