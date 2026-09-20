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
#   tools/reproducible-build.sh --twice      # собрать дважды и сверить
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
TWICE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) VERIFY="$2"; shift 2 ;;
    --twice)  TWICE=1; shift ;;
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

# ⚠️ И ещё одно: дерево не должно меняться **во время** прогона.
#
# Между первой и второй сборкой проходят десятки минут, и правка
# исходника в этот промежуток выглядит как невоспроизводимость —
# хотя разошлись не сборки, а входные данные. Отпечаток снимается
# до первой сборки и сверяется после второй.
TREE_BEFORE=$(git -C "$ROOT" status --porcelain=v1 | sha256sum)

bash "$ROOT/tools/check-ndk-pins.sh"

# Какие ABI собирать: те, что уже лежат в jniLibs. Пусто — значит
# собирается полный набор, заданный самим build-rust-android.sh.
ABI_FLAGS_MAIN=()
for dir in "$ROOT"/android/app/src/main/jniLibs/*/; do
  [[ -d "$dir" ]] || continue
  ABI_FLAGS_MAIN+=(--abi "$(basename "$dir")")
done

echo
echo "== Сборка =="

# ⚠️ Нативные библиотеки собираются здесь, а не берутся из `jniLibs`.
#
# Gradle их не собирает — он упаковывает готовые. Первая версия
# `--twice` этого не учитывала: первый проход считал сумму того,
# что лежало в `jniLibs` от прошлого запуска, второй — того, что
# собрал сам. Две сборки «разошлись», хотя разошлись не они,
# а источники файлов.
#
# Вывод из той ошибки шире одного скрипта: сумма файла, который
# эта сборка не собирала, не говорит об этой сборке ничего.
if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  echo "  собирается ядро под Android…"
  bash "$ROOT/tools/build-rust-android.sh" "${ABI_FLAGS_MAIN[@]}"
elif [[ "$TWICE" -eq 1 ]]; then
  echo "error: для --twice нужен ANDROID_NDK_HOME." >&2
  echo "  Без пересборки libaegis.so сравнение её сумм бессмысленно:" >&2
  echo "  gradle берёт готовый файл из jniLibs и не трогает его." >&2
  exit 2
else
  echo "  ⚠️ ANDROID_NDK_HOME не задан: ядро не пересобирается,"
  echo "     и суммы libaegis.so относятся к тому, что уже лежит"
  echo "     в jniLibs, — то есть неизвестно к какой сборке."
fi

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

# --- Двойная сборка: сверка результата с самим собой -------------------------
#
# 🔐 Это и есть проверка воспроизводимости, а не подсчёт сумм.
# Сумма одной сборки не говорит ни о чём: она совпадает сама с собой
# всегда. Значение имеет только то, что **вторая** сборка той же
# ревизии дала те же байты.
#
# Между сборками сносится всё, что может донести результат первой:
# каталог сборки Gradle и собственные крейты в целевом каталоге cargo.
# Без этого вторая «сборка» просто переиспользует артефакты первой
# и совпадение ничего не доказывает.
if [[ "$TWICE" -eq 1 ]]; then
  echo
  echo "== Вторая сборка той же ревизии =="

  # ⚠️ Нативные библиотеки обязаны пересобираться тоже.
  #
  # Gradle их не собирает — он берёт готовые из `jniLibs`. Первая
  # версия этой проверки сравнивала суммы `libaegis.so` до и после,
  # не пересобрав их: один и тот же файл, естественно, совпадал сам
  # с собой, и проверка рапортовала о воспроизводимости, ничего
  # о ней не узнав. Ровно та ошибка, ради которой заведено
  # правило 0.1.
  if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "error: для --twice нужен ANDROID_NDK_HOME." >&2
    echo "  Без пересборки libaegis.so сравнение её сумм бессмысленно:" >&2
    echo "  gradle берёт готовый файл из jniLibs и не трогает его." >&2
    exit 2
  fi

  FIRST=$(sums)

  (cd "$ROOT/android" && ./gradlew --no-daemon -q clean)

  (cd "$ROOT/crates" && cargo clean --release \
    --target aarch64-linux-android --target x86_64-linux-android \
    -p aegis-ffi -p aegis-core -p aegis-protocol \
    -p aegis-storage -p aegis-net -p aegis-types >/dev/null 2>&1 || true)

  # Те же ABI, что и в первом проходе: сравнивать нужно то же самое,
  # а не подмножество и не надмножество.
  ABI_FLAGS=("${ABI_FLAGS_MAIN[@]}")

  if [[ "${#ABI_FLAGS[@]}" -eq 0 ]]; then
    echo "error: не определён ни один ABI — пересобирать нечего" >&2
    exit 1
  fi

  rm -f "$ROOT"/android/app/src/main/jniLibs/*/libaegis.so

  echo "  каталоги сборки очищены, пересобираем ядро и APK…"

  bash "$ROOT/tools/build-rust-android.sh" "${ABI_FLAGS[@]}"

  (cd "$ROOT/android" && ./gradlew --no-daemon -q :app:assembleGmsRelease :app:assembleFossRelease)

  SECOND=$(sums)

  TREE_AFTER=$(git -C "$ROOT" status --porcelain=v1 | sha256sum)

  if [[ "$TREE_BEFORE" != "$TREE_AFTER" ]]; then
    echo "error: рабочее дерево изменилось во время прогона." >&2
    echo "  Сравнивать нечего: две сборки получили разные исходники." >&2
    exit 1
  fi

  # 🔐 Проверка проверки: в сравнении обязаны участвовать и APK,
  # и библиотеки. Пустой или укороченный список совпал бы сам
  # с собой и здесь.
  if [[ "$(printf '%s\n' "$SECOND" | grep -c 'libaegis\.so')" -eq 0 ]]; then
    echo "error: после пересборки не нашлось ни одной libaegis.so" >&2
    exit 1
  fi

  if [[ "$(printf '%s\n' "$SECOND" | grep -c '\.apk')" -eq 0 ]]; then
    echo "error: после пересборки не нашлось ни одного APK" >&2
    exit 1
  fi

  echo
  if [[ "$FIRST" == "$SECOND" ]]; then
    echo "✅ две сборки одной ревизии дали одинаковые байты"
  else
    echo "❌ две сборки одной ревизии разошлись" >&2
    echo >&2
    diff <(printf '%s\n' "$FIRST") <(printf '%s\n' "$SECOND") >&2 || true
    echo >&2
    echo "   Это и есть невоспроизводимость: опубликованной сумме" >&2
    echo "   верить нельзя, потому что её никто не повторит." >&2
    exit 1
  fi
fi

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
echo "Проверить воспроизводимость: tools/reproducible-build.sh --twice"
echo
echo "⚠️  Совпадение двух сборок на ОДНОЙ машине — это не полная"
echo "    воспроизводимость. Оно доказывает, что сборка не зависит"
echo "    от времени и от состояния каталогов, но не доказывает"
echo "    независимости от машины: версии NDK, JDK и Gradle здесь"
echo "    одни и те же. Проверка на второй машине — отдельный шаг,"
echo "    см. docs/ops/reproducible-builds.md."
echo
echo "⚠️  Сверялся APK БЕЗ подписи. Подпись добавляет блок, который"
echo "    этой проверкой не покрыт."
