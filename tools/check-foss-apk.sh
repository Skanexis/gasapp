#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 🔐 Раздел 18.2: в сборке `foss` нет ни одного класса Google.
#
# # Почему проверка по APK, а не по исходникам
#
# `check-no-telemetry.sh` ищет запрещённые имена в исходном коде,
# и этого мало. В APK классы попадают не только из `src/`: их приносят
# транзитивные зависимости, манифесты библиотек и плагины Gradle —
# то есть места, куда никто не смотрит. Сборка для F-Droid обязана
# быть свободной от проприетарных сервисов **по факту**, а факт лежит
# в собранном файле.
#
# # Как устроена проверка
#
# DEX хранит имена типов обычными строками: класс
# `com.google.android.gms.common.GoogleApiAvailability` лежит в файле
# как `Lcom/google/android/gms/common/GoogleApiAvailability;`. Поэтому
# достаточно двоичного поиска по `classes*.dex` — без dexdump,
# без build-tools, без сети.
#
# ⚠️ Проверка сначала доказывает, что умеет находить. Поиск по DEX,
# который ничего не нашёл, выглядит одинаково и когда классов нет,
# и когда распаковка провалилась, и когда файл не тот. Трижды в этом
# проекте зелёной оказывалась проверка, сравнивавшая два пустых списка
# (раздел 23.5), поэтому здесь сначала ищется то, что обязано быть.
#
# Запуск:
#   bash tools/check-foss-apk.sh                 # соберёт APK сам
#   bash tools/check-foss-apk.sh путь/к/app.apk  # проверит готовый

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-}"

# --- Запрещённые пространства имён ------------------------------------------
#
# Записаны в форме дескриптора DEX: так они лежат в файле, и так их
# не спутать с упоминанием в строковой константе или в комментарии,
# попавшем в ресурсы.
FORBIDDEN=(
  'Lcom/google/android/gms/'
  'Lcom/google/firebase/'
  'Lcom/google/android/play/'
)

# --- Что обязано найтись ----------------------------------------------------
#
# Собственный пакет приложения. Если его нет, ищем не там или не то,
# и все отрицательные ответы ниже ничего не значат.
EXPECTED='Lorg/aegis/app/'

# --- Сборка, если APK не передан --------------------------------------------

if [[ -z "$APK" ]]; then
  echo "сборка foss-release…"
  (cd "$ROOT/android" && ./gradlew --console=plain -q :app:assembleFossRelease -PaegisAllowUnreleasable=true)

  # Только release и только этот flavor.
  #
  # ⚠️ Раньше здесь стоял поиск по всему каталогу `apk/foss`, и он
  # находил залежавшийся `foss/debug/app-foss-debug.apk`: проверка
  # рапортовала об успехе, проверив не тот файл. Отладочная сборка
  # собирается другими правилами (без R8, с другими зависимостями),
  # и её чистота ничего не говорит о релизной.
  APK=$(find "$ROOT/android/app/build/outputs/apk/foss/release" -name '*.apk' | head -1)
fi

if [[ ! -f "$APK" ]]; then
  echo "error: APK не найден: ${APK:-<пусто>}" >&2
  exit 1
fi

echo "проверяется: $APK"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

unzip -o -q "$APK" 'classes*.dex' -d "$WORK"

DEX_COUNT=$(find "$WORK" -name 'classes*.dex' | wc -l)

if [[ "$DEX_COUNT" -eq 0 ]]; then
  echo "error: в APK нет ни одного classes*.dex — проверять нечего" >&2
  exit 1
fi

echo "  файлов DEX: $DEX_COUNT"

# --- Шаг 1: проверка умеет находить -----------------------------------------

found_expected=0
for dex in "$WORK"/classes*.dex; do
  if grep -qa "$EXPECTED" "$dex"; then
    found_expected=1
    break
  fi
done

if [[ "$found_expected" -eq 0 ]]; then
  echo "error: в DEX не найден собственный пакет ($EXPECTED)." >&2
  echo "  Поиск не работает, и отсутствие классов Google ничего не значит." >&2
  exit 1
fi

echo "  ✅ поиск работает: собственный пакет на месте"

# --- Шаг 2: собственно проверка ---------------------------------------------

violations=0

for pattern in "${FORBIDDEN[@]}"; do
  hits=0

  for dex in "$WORK"/classes*.dex; do
    # ⚠️ `|| true` обязателен. `grep`, ничего не нашедший, возвращает 1,
    # а при `set -euo pipefail` это роняет скрипт прямо здесь —
    # молча, с кодом 1 и без единого сообщения. То есть «классов
    # Google нет» выглядело бы точно так же, как «проверка упала».
    #
    # Отличать «не нашёл» (1) от настоящей ошибки (>1) тоже нужно:
    # нечитаемый файл иначе засчитался бы как чистый.
    set +e
    matches=$(grep -oa "$pattern" "$dex")
    status=$?
    set -e

    if [[ "$status" -gt 1 ]]; then
      echo "error: grep не смог прочитать $dex (код $status)" >&2
      exit 1
    fi

    count=$(printf '%s' "$matches" | grep -c . || true)
    hits=$((hits + count))
  done

  if [[ "$hits" -gt 0 ]]; then
    echo "::error::в foss-сборке найдено $hits упоминаний $pattern" >&2
    violations=$((violations + 1))
  else
    echo "  ✅ $pattern — нет"
  fi
done

if [[ "$violations" -gt 0 ]]; then
  echo "" >&2
  echo "  Сборка foss обязана быть свободной от сервисов Google" >&2
  echo "  (раздел 18.2). Проверьте зависимости flavor'а и плагины." >&2
  exit 1
fi

echo "OK: в foss-сборке классов Google нет"
