#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Выпуск Android одной командой — в окне Ubuntu (WSL):
#
#     bash /mnt/c/Users/be4ho/Desktop/WORK/AEGIS/tools/release-android.sh
#
# Что делает сам, по порядку (остановится с понятной причиной на любой
# ошибке; повторный запуск продолжает, а не начинает заново):
#
#   1. находит флешку V: (если Ubuntu её не видит — подключает: sudo
#      спросит пароль Ubuntu);
#   2. проверяет tools/release.conf: пины совпадают с файлами на флешке
#      и с тем, что сервер отдаёт ПРЯМО СЕЙЧАС, onion — с ключами onion;
#   3. ключ подписи: если его нет — создаёт (пароль дважды), если есть —
#      проверяет пароль;
#   4. ядро Rust для четырёх архитектур — в Docker (только если код
#      ядра изменился с прошлой сборки);
#   5. APK (сайт, тестовые телефоны) и AAB (Google Play) — в Docker;
#   6. проверяет подпись готового APK и кладёт всё в dist/android/.
#
# `--core-only` — только шаг 4 (ядро), без флешки и паролей.
#
# Пароль спрашивается один раз, живёт только в памяти этого запуска и
# в Docker попадает переменной окружения — не в файлы, не в историю
# команд, не в аргументы процессов.
#
# Что сохранить в Bitwarden — скрипт напечатает в самом конце.
#
# Нужно: Docker Desktop запущен (с интеграцией WSL), флешка V:
# подключена в VeraCrypt. Больше ничего ставить не надо.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JDK_IMAGE="eclipse-temurin:21-jdk"
CORE_IMAGE="gasapp-android"
ALIAS="gasapp"

say()  { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m✘ %s\033[0m\n\n' "$*" >&2; exit 1; }

# Docker Desktop видит пути Ubuntu как есть; из Git Bash на Windows —
# только в виде C:/… (MSYS иначе переписал бы их по-своему).
export MSYS_NO_PATHCONV=1
host_path() { if command -v cygpath > /dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

PY="$(command -v python3 || command -v python || true)"
# Репозиторий на диске Windows принадлежит «чужому» пользователю — без
# этого git в Ubuntu отказался бы его читать.
git() { command git -c safe.directory="$ROOT" -C "$ROOT" "$@"; }
mkdir -p "$ROOT/dist"

conf() { sed -n "s/^$1=//p" "$ROOT/tools/release.conf" | tail -1; }

# --- Ядро Rust (шаг 4; функция — чтобы --core-only собирал только его) ----

build_core() {
say "Ядро Rust для Android"
JNI="$ROOT/android/app/src/main/jniLibs"
STAMP_FILE="$ROOT/dist/.core-stamp"
stamp=$(
  {
    git ls-files -s crates rust-toolchain.toml tools/build-rust-android.sh tools/Dockerfile.android
    git diff HEAD -- crates rust-toolchain.toml 2> /dev/null
  } | sha256sum | cut -c1-32
)
have_all=1
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  [ -f "$JNI/$abi/libgasapp.so" ] || have_all=0
done
if [ "$have_all" = 1 ] && [ "$(cat "$STAMP_FILE" 2> /dev/null)" = "$stamp" ]; then
  ok "уже собрано из этого же кода — пропускаю"
else
  if ! docker image inspect "$CORE_IMAGE" > /dev/null 2>&1; then
    echo "  Первый раз: образ сборки (NDK и Rust), ~15 минут."
    docker build -q -f "$ROOT/tools/Dockerfile.android" -t "$CORE_IMAGE" "$ROOT/tools" > "$ROOT/dist/core-image.log" 2>&1 ||
      die "образ сборки не собрался — журнал: dist/core-image.log"
  fi
  echo "  Сборка ядра: 20–40 минут в первый раз, дальше быстрее."
  docker run --rm -m 8g \
    -v "$(host_path "$ROOT"):/work" -w /work \
    -v gasapp-android-target:/target -e CARGO_TARGET_DIR=/target \
    -v gasapp-cargo-registry:/usr/local/cargo/registry \
    -e CARGO_BUILD_JOBS=4 \
    "$CORE_IMAGE" bash tools/build-rust-android.sh > "$ROOT/dist/core-build.log" 2>&1 ||
    die "ядро не собралось — журнал: dist/core-build.log"
  printf '%s' "$stamp" > "$STAMP_FILE"
  ok "собрано (журнал: dist/core-build.log)"
fi
}

# --- 0. Docker ---------------------------------------------------------------

say "Docker"
command -v docker > /dev/null 2>&1 || die "нет docker: запустите Docker Desktop и включите Settings → Resources → WSL integration → Ubuntu"
docker info > /dev/null 2>&1 || die "Docker не отвечает: запустите Docker Desktop и подождите, пока внизу слева станет «Engine running»"
ok "работает"

free_gb=$(df -Pk "$ROOT" | awk 'NR==2 {print int($4/1048576)}')
if [ "${free_gb:-0}" -lt 15 ]; then
  die "на диске с проектом свободно ${free_gb} ГБ — нужно хотя бы 15 (ядро и Gradle)"
fi
ok "свободно на диске: ${free_gb} ГБ"

# Только ядро, без флешки и паролей: заранее, пока человек занят другим.
if [ "${1:-}" = "--core-only" ]; then
  build_core
  exit 0
fi

# --- 1. Флешка ---------------------------------------------------------------

say "Флешка V:"
OFF="${OFF:-}"
if [ -z "$OFF" ]; then
  for candidate in /mnt/v/gasapp /v/gasapp; do
    if [ -d "$candidate" ]; then OFF="$candidate"; break; fi
  done
fi
if [ -z "$OFF" ] && grep -qi microsoft /proc/version 2>/dev/null; then
  # Диск, подключённый в VeraCrypt после запуска Ubuntu, она сама не видит.
  echo "  Ubuntu не видит V: — подключаю (sudo спросит пароль пользователя Ubuntu)."
  sudo mkdir -p /mnt/v
  sudo mount -t drvfs V: /mnt/v -o "uid=$(id -u),gid=$(id -g)" || true
  [ -d /mnt/v/gasapp ] && OFF=/mnt/v/gasapp
fi
[ -n "$OFF" ] && [ -d "$OFF" ] || die "флешки нет: подключите контейнер в VeraCrypt как V: (шаг 2.3) и запустите снова"
for file in pin-primary.txt pin-backup.txt; do
  [ -f "$OFF/$file" ] || die "на флешке нет $file — это не та флешка или шаг 5 не выполнен"
done
ok "$OFF"

# --- 2. Настройки выпуска ----------------------------------------------------

say "Настройки выпуска (tools/release.conf)"
[ -n "$PY" ] || die "нет python3: sudo apt install -y python3"
"$PY" "$ROOT/tools/apply-release-config.py" --check > /dev/null ||
  die "настройки сборки расходятся с tools/release.conf — запустите: python3 tools/apply-release-config.py"

VERSION_NAME=$(conf VERSION_NAME)
VERSION_CODE=$(conf VERSION_CODE)
SERVER_URL=$(conf SERVER_URL)
DOCS_URL=$(conf DOCS_URL)
SERVER_ONION=$(conf SERVER_ONION)
PIN_PRIMARY=$(conf PIN_PRIMARY)
PIN_BACKUP=$(conf PIN_BACKUP)

[ "$PIN_PRIMARY" = "$(tr -d '[:space:]' < "$OFF/pin-primary.txt")" ] ||
  die "основной пин в release.conf не совпадает с $OFF/pin-primary.txt"
[ "$PIN_BACKUP" = "$(tr -d '[:space:]' < "$OFF/pin-backup.txt")" ] ||
  die "запасной пин в release.conf не совпадает с $OFF/pin-backup.txt"
ok "пины совпадают с флешкой"

host="${SERVER_URL#https://}"
live=$(openssl s_client -connect "$host:443" -servername "$host" < /dev/null 2> /dev/null |
  openssl x509 -pubkey -noout 2> /dev/null |
  openssl pkey -pubin -outform der 2> /dev/null |
  openssl dgst -sha256 -binary | openssl base64 -A)
if [ "$live" = "$PIN_PRIMARY" ]; then
  ok "сервер $host отдаёт ключ с основным пином"
elif [ "$live" = "$PIN_BACKUP" ]; then
  warn "сервер $host уже на ЗАПАСНОМ ключе — так бывает после ротации; проверьте docs/ops/cert-pin-rotation.md"
else
  die "сервер $host отдаёт ключ с пином ${live:-<нет ответа>}, а не с пинами из release.conf. Такое приложение ни к чему не подключится"
fi

if [ -n "$SERVER_ONION" ] && [ -f "$OFF/onion-keys.tar" ]; then
  onion_file=$(tar -xOf "$OFF/onion-keys.tar" --wildcards '*hostname' 2> /dev/null | tr -d '[:space:]')
  [ "${SERVER_ONION%:*}" = "$onion_file" ] || die "SERVER_ONION в release.conf не совпадает с onion-адресом из $OFF/onion-keys.tar ($onion_file)"
  ok "onion-адрес совпадает с ключами onion"
fi
ok "версия $VERSION_NAME (код $VERSION_CODE)"

# --- 3. Ключ подписи ---------------------------------------------------------

say "Ключ подписи"
KS="$OFF/gasapp-release.jks"
keytool() {
  docker run --rm -i -e KS_PASS -v "$(host_path "$OFF"):/keys" "$JDK_IMAGE" keytool "$@"
}
docker image inspect "$JDK_IMAGE" > /dev/null 2>&1 || docker pull -q "$JDK_IMAGE" > /dev/null

NEW_KEY=0
if [ -f "$KS" ]; then
  read -rsp "  Пароль ключа подписи (Bitwarden: «Android: пароль ключа подписи»): " KS_PASS; echo
  export KS_PASS
  keytool -list -keystore /keys/gasapp-release.jks -alias "$ALIAS" -storepass:env KS_PASS > /dev/null 2>&1 ||
    die "пароль не подошёл (или в ключе нет «$ALIAS»)"
  ok "пароль верный"
else
  echo "  Ключа ещё нет — создаю. 🔴 Он нужен для КАЖДОЙ следующей версии:"
  echo "  потеряете ключ или пароль — обновить приложение будет нельзя."
  echo "  Придумайте пароль от 12 знаков (лучше сгенерировать в Bitwarden)."
  while :; do
    read -rsp "  Новый пароль: " KS_PASS; echo
    read -rsp "  Ещё раз:      " again; echo
    if [ "$KS_PASS" != "$again" ]; then echo "  Не совпали — ещё раз."; continue; fi
    if [ "${#KS_PASS}" -lt 12 ]; then echo "  Короче 12 знаков — ещё раз."; continue; fi
    break
  done
  unset again
  export KS_PASS
  keytool -genkeypair -keystore /keys/gasapp-release.jks -storetype PKCS12 -alias "$ALIAS" \
    -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=GasApp" \
    -storepass:env KS_PASS -keypass:env KS_PASS > /dev/null 2>&1 || die "keytool не создал ключ"
  [ -f "$KS" ] || die "ключ не появился на флешке: $KS"
  NEW_KEY=1
  ok "создан: $KS"
fi
CERT_SHA256=$(keytool -list -v -keystore /keys/gasapp-release.jks -alias "$ALIAS" -storepass:env KS_PASS 2> /dev/null |
  sed -n 's/^[[:space:]]*SHA256: *//p' | head -1 | tr -d '\r')
[ -n "$CERT_SHA256" ] || die "не удалось прочесть отпечаток ключа"
ok "отпечаток: $CERT_SHA256"

# --- 4. Ядро Rust ------------------------------------------------------------

build_core

# --- 5. APK и AAB ------------------------------------------------------------

say "Сборка приложения (Gradle)"
PLAY_CERT=""
if [ -f "$OFF/play-app-signing-sha256.txt" ]; then
  PLAY_CERT=$(tr -d '[:space:]' < "$OFF/play-app-signing-sha256.txt")
  ok "ключ Google Play: $PLAY_CERT"
else
  warn "отпечатка ключа Google Play ещё нет ($OFF/play-app-signing-sha256.txt) — AAB годится только для ПЕРВОЙ выгрузки во внутреннее тестирование (см. server/deploy/ВЫПУСК-ПРИЛОЖЕНИЯ.md, раздел 1.4)"
fi

export ORG_GRADLE_PROJECT_gasappKeystorePassword="$KS_PASS"
export ORG_GRADLE_PROJECT_gasappKeyPassword="$KS_PASS"
props=(
  -PgasappKeystore=/keys/gasapp-release.jks
  -PgasappKeyAlias="$ALIAS"
  -PgasappServerUrl="$SERVER_URL"
  -PgasappDocsUrl="$DOCS_URL"
  -PgasappVersionName="$VERSION_NAME"
  -PgasappVersionCode="$VERSION_CODE"
)
[ -n "$SERVER_ONION" ] && props+=(-PgasappServerOnion="$SERVER_ONION")

gradle() {
  docker run --rm -m 8g \
    -v "$(host_path "$ROOT"):/repo" -w /repo/android \
    -v "$(host_path "$OFF"):/keys:ro" \
    -v gasapp-android-sdk:/sdk -e ANDROID_HOME=/sdk \
    -v gasapp-gradle-home:/gh -e GRADLE_USER_HOME=/gh \
    -e ORG_GRADLE_PROJECT_gasappKeystorePassword -e ORG_GRADLE_PROJECT_gasappKeyPassword \
    "$JDK_IMAGE" ./gradlew --no-daemon -q "$@"
}

echo "  APK для сайта и тестовых телефонов…"
gradle assembleFossRelease "${props[@]}" > "$ROOT/dist/gradle-apk.log" 2>&1 ||
  die "APK не собрался — журнал: dist/gradle-apk.log (последние строки: $(tail -3 "$ROOT/dist/gradle-apk.log" | tr '\n' ' '))"
ok "APK готов"

echo "  AAB для Google Play…"
aab_props=("${props[@]}")
[ -n "$PLAY_CERT" ] && aab_props+=(-PgasappSigningCertSha256="$PLAY_CERT")
gradle bundleGmsRelease "${aab_props[@]}" > "$ROOT/dist/gradle-aab.log" 2>&1 ||
  die "AAB не собрался — журнал: dist/gradle-aab.log"
ok "AAB готов"
unset ORG_GRADLE_PROJECT_gasappKeystorePassword ORG_GRADLE_PROJECT_gasappKeyPassword KS_PASS

# --- 6. Проверка и результат -------------------------------------------------

say "Проверка подписи и результат"
OUT="$ROOT/dist/android/gasapp-$VERSION_NAME-$VERSION_CODE"
rm -rf "$OUT"; mkdir -p "$OUT"
apk=$(ls "$ROOT"/android/app/build/outputs/apk/foss/release/*universal*release*.apk 2> /dev/null | head -1)
[ -n "$apk" ] || apk=$(ls "$ROOT"/android/app/build/outputs/apk/foss/release/*release*.apk | head -1)
aab="$ROOT/android/app/build/outputs/bundle/gmsRelease/app-gms-release.aab"
[ -f "$apk" ] && [ -f "$aab" ] || die "не нашёл готовые файлы в android/app/build/outputs"
cp "$apk" "$OUT/gasapp-$VERSION_NAME.apk"
cp "$aab" "$OUT/gasapp-$VERSION_NAME-play.aab"

apksigner=$(docker run --rm -v gasapp-android-sdk:/sdk "$JDK_IMAGE" sh -c 'ls /sdk/build-tools/*/apksigner | sort -V | tail -1')
signed=$(docker run --rm -v gasapp-android-sdk:/sdk -v "$(host_path "$OUT"):/out:ro" "$JDK_IMAGE" \
  "$apksigner" verify --print-certs "/out/gasapp-$VERSION_NAME.apk" 2>&1 |
  sed -n 's/.*certificate SHA-256 digest: *//p' | head -1)
want=$(printf '%s' "$CERT_SHA256" | tr -d ':' | tr 'A-F' 'a-f')
[ "$signed" = "$want" ] || die "APK подписан не тем ключом (в APK: ${signed:-нет подписи})"
ok "APK подписан вашим ключом"

(cd "$OUT" && sha256sum gasapp-* > SHA256SUMS.txt)
printf '%s\n' "$CERT_SHA256" > "$OUT/signing-cert-sha256.txt"
ok "готово: dist/android/$(basename "$OUT")/"
sed 's/^/      /' "$OUT/SHA256SUMS.txt"

cat <<EOF

────────────────────────────────────────────────────────────────────
 ✅ ВЫПУСК ANDROID ГОТОВ — $VERSION_NAME (код $VERSION_CODE)

 Файлы (в Windows: папка проекта → dist\\android\\$(basename "$OUT")):
   gasapp-$VERSION_NAME.apk        — на телефоны напрямую и на сайт
   gasapp-$VERSION_NAME-play.aab   — в Google Play Console
   SHA256SUMS.txt          — суммы файлов (опубликовать рядом с APK)

 Дальше: server/deploy/ВЫПУСК-ПРИЛОЖЕНИЯ.md, раздел 1.3 — проверка на двух телефонах.

 ── СОХРАНИТЬ В BITWARDEN (сейчас, всё сразу) ──────────────────────
EOF
if [ "$NEW_KEY" = 1 ]; then
  cat <<EOF
   1. Запись «Android: пароль ключа подписи» — пароль, который вы
      только что придумали (если ещё не там).
   2. Туда же, в заметку: отпечаток ключа
      $CERT_SHA256
   3. Флешка изменилась (новый файл gasapp-release.jks): отключите V:
      в VeraCrypt и обновите вложение-контейнер в Bitwarden (шаг 2.4).
EOF
else
  cat <<EOF
   Ничего нового: ключ подписи тот же. Отпечаток для сверки:
   $CERT_SHA256
EOF
fi
echo "────────────────────────────────────────────────────────────────────"
