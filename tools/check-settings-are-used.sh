#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 🔐 Каждая настройка на что-то влияет.
#
# # Что ловится
#
# Переключатель, который ничего не переключает. Экран настроек его
# показывает, запись в базу проходит, положение держится между
# запусками — и ни одна строка кода это значение не читает.
#
# Для приложения такого рода это не косметика. Человек, включивший
# «показывать содержимое», строит поведение на том, что содержимое
# показывается; человек, **выключивший** что-нибудь, строит поведение
# на том, что оно выключено. Настройка без читателя врёт в обе стороны.
#
# Так и оказалось с `notification_preview` и `notification_sound`:
# они есть на экранах, а системных уведомлений приложение не
# показывает вовсе — ни обращения к `NotificationManager`, ни
# разрешения `POST_NOTIFICATIONS` в манифесте.
#
# # Где ищется читатель
#
# В Kotlin — вне экранов настроек: экран, который сам же показывает
# и сам же сохраняет значение, использованием не считается. Именно
# так выглядит настройка-пустышка.
#
# В Rust — по строке ключа. Часть настроек читает ядро, а не платформа:
# `presence_sharing` гасит индикаторы набора в `aegis-core`, и через
# константу Kotlin этого не видно. Поэтому ищется и имя константы,
# и само строковое значение.
#
# ⚠️ Проверка не отличает «читается и учитывается» от «читается
# и игнорируется». Она ловит полное отсутствие читателя — самый
# частый и самый незаметный случай.
#
# Запуск: bash tools/check-settings-are-used.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

SETTINGS_FILE="android/app/src/main/kotlin/org/aegis/app/core/Settings.kt"

# Экраны, которые настройку только показывают и сохраняют.
# Центр безопасности тоже сюда: он перечисляет состояние настроек,
# а не действует по нему.
SETTINGS_SCREENS='PrivacyActivity\.kt|NotificationsActivity\.kt|AppearanceActivity\.kt|SettingsActivity\.kt|SecurityCenterActivity\.kt|core/Settings\.kt'

if [[ ! -f "$SETTINGS_FILE" ]]; then
  echo "error: не найден $SETTINGS_FILE" >&2
  exit 1
fi

# Пары «имя константы → строковое значение».
mapfile -t PAIRS < <(
  grep -oE 'const val [A-Z_]+ = "[a-z_]+"' "$SETTINGS_FILE" \
    | sed -E 's/const val ([A-Z_]+) = "([a-z_]+)"/\1 \2/'
)

if [[ "${#PAIRS[@]}" -lt 3 ]]; then
  echo "error: найдено ${#PAIRS[@]} ключей настроек — разбор сломан?" >&2
  exit 1
fi

echo "ключей настроек: ${#PAIRS[@]}"

unused=0
pending=0

# Сколько настроек без читателя признано на сегодня.
# ⚠️ Уменьшать можно, увеличивать — только вместе с решением
# продуктовой задачи, а не чтобы проверка замолчала.
EXPECTED_PENDING=3

for pair in "${PAIRS[@]}"; do
  name="${pair%% *}"
  value="${pair##* }"

  # 1. Kotlin вне экранов настроек.
  kotlin_users=$(grep -rn "Settings\.$name" \
                   --include='*.kt' android/app/src/main/kotlin 2>/dev/null \
                 | grep -vE "$SETTINGS_SCREENS" || true)

  # 2. Ядро — по строке ключа.
  #
  # Сначала там, где настройка применяется (хранилище и фасад),
  # потом везде: в отчёт попадёт первое совпадение, и оно должно
  # указывать на читателя, а не на тестовую заготовку из соседнего
  # крейта. Каталога `tests/` мало — фикстуры живут и внутри `src`
  # под `#[cfg(test)]`.
  rust_users=$(
    {
      grep -rn "\"$value\"\|'$value'" --include='*.rs' \
        crates/aegis-storage/src crates/aegis-core/src 2>/dev/null || true

      grep -rn "\"$value\"\|'$value'" --include='*.rs' crates 2>/dev/null || true
    } | grep -v "/tests/" || true
  )

  if [[ -z "$kotlin_users" && -z "$rust_users" ]]; then
    # Признанные пустышки помечены в самом Settings.kt строкой
    # «⏳ НЕ ЧИТАЕТСЯ» с объяснением, от чего зависит закрытие.
    #
    # ⚠️ Это не амнистия: их число закреплено ниже, и четвёртая
    # такая настройка уронит проверку. Пометка нужна, чтобы признание
    # лежало рядом с кодом, а не только в плане.
    if grep -B 12 "const val $name = " "$SETTINGS_FILE" | grep -q "НЕ ЧИТАЕТСЯ"; then
      echo "  ⏳ $name — читателя нет, признано в Settings.kt"
      pending=$((pending + 1))

      continue
    fi

    echo "::error::настройку $name (\"$value\") никто не читает" >&2
    unused=$((unused + 1))

    continue
  fi

  if [[ -n "$kotlin_users" ]]; then
    where=$(printf '%s\n' "$kotlin_users" | head -1 | cut -d: -f1)
    echo "  ✅ $name — ${where#android/app/src/main/kotlin/org/aegis/app/}"
  else
    where=$(printf '%s\n' "$rust_users" | head -1 | cut -d: -f1)
    echo "  ✅ $name — ${where} (ядро)"
  fi
done

if [[ "$pending" -ne "$EXPECTED_PENDING" ]]; then
  echo "" >&2
  echo "::error::настроек без читателя: $pending, ожидалось $EXPECTED_PENDING" >&2
  echo "  Если появилась новая — реализуйте поведение или уберите" >&2
  echo "  переключатель. Если закрыли старую — уменьшите" >&2
  echo "  EXPECTED_PENDING в этом файле." >&2
  exit 1
fi

if [[ "$unused" -gt 0 ]]; then
  echo "" >&2
  echo "  Настроек без читателя: $unused" >&2
  echo "" >&2
  echo "  Либо реализуйте поведение, либо уберите переключатель." >&2
  echo "  Настройка, которую никто не читает, обещает пользователю" >&2
  echo "  то, чего нет, — и в выключенном положении тоже." >&2
  exit 1
fi

if [[ "$pending" -gt 0 ]]; then
  echo ""
  echo "OK: новых настроек-пустышек нет (признанных: $pending)"
else
  echo "OK: у каждой настройки есть читатель"
fi
