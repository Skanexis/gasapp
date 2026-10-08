#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 🔐 Каждый файл исходного кода лежит в репозитории.
#
# # Почему такая проверка вообще нужна
#
# Потому что один файл уже пропал — и никто не заметил.
#
# `.gitignore` содержал `core.*` (правило для дампов памяти), а git
# на Windows сравнивает пути без учёта регистра. Под это правило попал
# `android/app/src/main/kotlin/org/gasapp/app/core/Core.kt` —
# единственное место, где собирается ключ базы. Файл не попадал
# в репозиторий **ни разу за всю историю проекта**.
#
# Заметить это было нечем. Локально файл на месте, приложение
# собирается, тесты зелёные; `git status` про игнорируемое молчит
# по определению, а `git add -A` его не добавляет. Обнаружилось
# случайно — при взгляде на список файлов очередного коммита.
#
# ⚠️ Отсутствие файла в репозитории означает, что клон не собирается
# вовсе, и что вся работа над этим файлом существует ровно на одной
# машине. Для файла, собирающего ключ базы, это означает ещё и то,
# что аудитор его не увидит.
#
# Запуск: bash tools/check-sources-tracked.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

# Каталоги с исходниками. Сборочные и целевые каталоги пропускаются:
# там сгенерированное, и ему в репозитории не место.
SOURCE_DIRS=(android/app/src crates server ios tools)

# Расширения, которые обязаны быть под контролем версий.
EXTENSIONS=(kt rs swift java xml gradle toml sh py)

missing=0
checked=0

for dir in "${SOURCE_DIRS[@]}"; do
  [[ -d "$dir" ]] || continue

  for ext in "${EXTENSIONS[@]}"; do
    while IFS= read -r file; do
      [[ -n "$file" ]] || continue

      case "$file" in
        */build/*|*/target/*|*/.gradle/*|*/node_modules/*) continue ;;
      esac

      checked=$((checked + 1))

      if ! git ls-files --error-unmatch "$file" >/dev/null 2>&1; then
        reason=$(git check-ignore -v "$file" 2>/dev/null || echo "не добавлен")

        echo "::error::файла нет в репозитории: $file" >&2
        echo "    причина: $reason" >&2

        missing=$((missing + 1))
      fi
    done < <(find "$dir" -type f -name "*.${ext}" 2>/dev/null)
  done
done

# 🔐 Проверка проверки: обход, ничего не нашедший, выглядит так же,
# как обход, где всё на месте. Трижды в этом проекте зелёной
# оказывалась проверка над пустым списком (раздел 23.5).
if [[ "$checked" -lt 100 ]]; then
  echo "error: просмотрено всего $checked файлов — обход сломан?" >&2
  exit 1
fi

echo "просмотрено файлов: $checked"

if [[ "$missing" -gt 0 ]]; then
  echo "" >&2
  echo "  Файлов не в репозитории: $missing" >&2
  echo "  Клон этого репозитория не соберётся." >&2
  exit 1
fi

echo "OK: все исходники под контролем версий"
