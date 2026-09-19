#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Воспроизводимая сборка релизного APK и подсчёт контрольных сумм.
#
# Пункты M8: «Reproducible builds для Android» и «Подпись релизов +
# публикация SHA-256» (раздел 22), ADR-020, MASVS RESILIENCE-2.2.
#
# Использование:
#   tools/reproducible-build.sh              # собрать и посчитать суммы
#   tools/reproducible-build.sh --verify sums.txt   # сверить с эталоном
#
# # Зачем это нужно
#
# 🔐 Воспроизводимость — единственная проверяемая связь между
# опубликованным исходным кодом и тем APK, который люди ставят себе
# на телефон. Без неё «открытый исходный код» означает лишь то, что
# код можно прочитать, а не то, что собран именно он. Мессенджер,
# чей бинарник нельзя сверить с исходником, защищает ровно настолько,
# насколько ему верят на слово.
#
# Это же — главная мера против подмены сборки (MASVS RESILIENCE-2):
# обфускация и проверка подписи APK во время выполнения лишь поднимают
# цену, а воспроизводимость даёт ответ «да» или «нет».
#
# # Что уже закреплено
#
#   * версия Rust           — rust-toolchain.toml
#   * версия NDK            — tools/Dockerfile.android и build.gradle,
#                             совпадение проверяет tools/check-ndk-pins.sh
#   * версии зависимостей   — Cargo.lock, точные `=` в Cargo.toml
#   * версии Gradle и AGP   — gradle-wrapper.properties, build.gradle
#   * набор ABI             — abiFilters, четыре штуки
#   * источники артефактов  — settings.gradle, FAIL_ON_PROJECT_REPOS
#
# # ⚠️ Чего пока НЕ закреплено
#
# Полная воспроизводимость на этом не достигается, и объявлять её
# достигнутой рано. Известные источники расхождений:
#
#   * абсолютные пути в libaegis.so. Rust вписывает путь к исходникам
#     в отладочные данные; `strip = "debuginfo"` убирает большую часть,
#     но `--remap-path-prefix` всё равно нужен — см. ниже;
#   * сборка вне контейнера. На хосте с другим OpenSSL или другой libc
#     результат отличается. Эталон считается только из
#     tools/Dockerfile.android;
#   * baseline-профиль ART. AGP собирает его из порядка классов,
#     который не гарантирован между запусками;
#   * подпись. Подписанный APK отличается от неподписанного, и суммы
#     считаются **до** подписи — иначе сверять пришлось бы с ключом
#     на руках, а он есть только у выпускающего.
#
# Поэтому скрипт считает суммы неподписанного APK и отдельно — суммы
# каждой libaegis.so. Второе воспроизводимо уже сейчас; первое
# остаётся открытым пунктом M8.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 🔐 Детерминированное время сборки.
#
# SOURCE_DATE_EPOCH — соглашение проекта reproducible-builds.org:
# инструменты, которые его понимают, подставляют это время вместо
# текущего. Без него каждая сборка отличается отметками времени
# в архиве, и сверять суммы бессмысленно.
#
# Значение берётся из времени последнего коммита: оно одинаково
# у всех, кто собирает ту же ревизию, и растёт вместе с историей.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --pretty=%ct)}"

# 🔐 Убирает абсолютные пути из бинарника.
#
# Без этого в libaegis.so остаётся путь вида /home/<имя>/... или
# C:/Users/<имя>/... — он и ломает совпадение сумм, и выдаёт того,
# кто собирал.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/aegis --remap-path-prefix=$HOME/.cargo=/cargo"

VERIFY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) VERIFY="$2"; shift 2 ;;
    -h|--help) sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

echo "== Воспроизводимая сборка =="
echo "SOURCE_DATE_EPOCH : $SOURCE_DATE_EPOCH"
echo "ревизия           : $(git -C "$ROOT" rev-parse HEAD)"

# Незакоммиченные изменения делают сумму невоспроизводимой у всех
# остальных: они собирают ревизию, а не рабочее дерево.
if ! git -C "$ROOT" diff --quiet || ! git -C "$ROOT" diff --cached --quiet; then
  echo
  echo "⚠️  рабочее дерево изменено: посчитанные суммы никто не повторит" >&2
fi

bash "$ROOT/tools/check-ndk-pins.sh"

echo
echo "== Сборка =="
(cd "$ROOT/android" && ./gradlew --no-daemon :app:assembleGmsRelease :app:assembleFossRelease)

# --- Подсчёт сумм ------------------------------------------------------------

sums() {
  # find + sort: порядок обхода файловой системы не гарантирован,
  # а сумма списка обязана быть одинаковой.
  {
    find "$ROOT/android/app/build/outputs/apk" -name '*.apk' -print0 \
      | sort -z \
      | xargs -0 -r sha256sum

    find "$ROOT/android/app/src/main/jniLibs" -name 'libaegis.so' -print0 \
      | sort -z \
      | xargs -0 -r sha256sum
  } | sed "s#$ROOT/##"
}

echo
echo "== SHA-256 =="
sums | tee "$ROOT/android/app/build/outputs/SHA256SUMS.txt"

if [[ -n "$VERIFY" ]]; then
  echo
  echo "== Сверка с $VERIFY =="

  if diff <(sums) "$VERIFY"; then
    echo "✅ суммы совпадают с эталоном"
  else
    echo "❌ суммы расходятся с эталоном" >&2
    echo "   это либо другая ревизия, либо другое окружение сборки," >&2
    echo "   либо подменённый артефакт — разбирать обязательно" >&2
    exit 1
  fi
fi

echo
echo "Файл сумм: android/app/build/outputs/SHA256SUMS.txt"
echo
echo "⚠️  Полная воспроизводимость APK ещё не достигнута — известные"
echo "    источники расхождений перечислены в заголовке этого скрипта"
echo "    и в docs/ops/reproducible-builds.md. Суммы libaegis.so"
echo "    воспроизводимы уже сейчас при сборке в контейнере."
