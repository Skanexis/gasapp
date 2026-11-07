#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Проверка и сборка iOS-версии на Mac — одним запуском, со всеми
# ошибками в одном отчёте.
#
#     bash tools/mac-check.sh                    # ядро, проект, Swift, симулятор, снимки
#     bash tools/mac-check.sh --device TEAMID    # то же + установка на подключённый iPhone
#     bash tools/mac-check.sh --rust-tests       # плюс тесты ядра на macOS (долго)
#
# TEAMID — 10 символов, developer.apple.com → Account → Membership.
#
# Результат — mac-report/ и mac-report.zip в корне проекта: журналы,
# список ошибок Swift, снимки экранов, отчёты о падениях. Архив
# отправляют разработчику целиком.
#
# Скрипт не останавливается на первой ошибке: каждый шаг пишет свой
# журнал, итог — mac-report/SUMMARY.txt. Ставит только Rust (rustup,
# в домашний каталог, с согласия) и XcodeGen (Homebrew или архив
# с GitHub в ios/build/tools).
#
# ⚠️ Под bash 3.2 (он в macOS по умолчанию): без ассоциативных массивов,
# mapfile и пустых массивов под set -u.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/mac-report"
IOS="$ROOT/ios"
DERIVED="$IOS/build/dd"
BUNDLE_ID="org.gasapp.messenger"
SCREENS="onboarding lock chats channels contacts addcontact settings backup security privacy"

RUST_TESTS=0
TEAM=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rust-tests) RUST_TESTS=1; shift ;;
        --device) TEAM="${2:-}"; shift 2 ;;
        *) echo "неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done

cd "$ROOT" || exit 1
rm -rf "$OUT" "$ROOT/mac-report.zip"
mkdir -p "$OUT/screens" "$OUT/crashes"
SUMMARY="$OUT/SUMMARY.txt"
START_MARK="$OUT/.start"
touch "$START_MARK"

say()    { echo; echo "== $*"; }
status() { printf '%-36s %s\n' "$1" "$2" | tee -a "$SUMMARY"; }

# run_step <название> <журнал> <команда…>
run_step() {
    local name="$1" log="$2" started=$SECONDS
    shift 2
    say "$name (журнал: mac-report/$log)"
    if "$@" > "$OUT/$log" 2>&1; then
        status "$name" "OK ($((SECONDS - started)) с)"
        return 0
    fi
    status "$name" "ОШИБКА — см. $log"
    tail -15 "$OUT/$log" | sed 's/^/    /'
    return 1
}

{
    echo "Проверка GasApp на Mac — $(date)"
    echo "Коммит: $(git -C "$ROOT" log -1 --oneline 2>/dev/null || cat "$ROOT/COMMIT.txt" 2>/dev/null || echo 'неизвестен')"
    echo
} > "$SUMMARY"

# --- 0. Окружение ------------------------------------------------------------------

say "окружение"
[[ "$(uname -s)" == "Darwin" ]] || { echo "Это не macOS — скрипт только для Mac." >&2; exit 1; }

if ! xcodebuild -version > /dev/null 2>&1; then
    cat >&2 <<'EOF'
Не найден Xcode. Нужно:
  1. App Store → Xcode → установить (около 15 ГБ).
  2. Один раз открыть Xcode, согласиться с лицензией, дождаться установки компонентов.
  3. В Terminal: sudo xcode-select -s /Applications/Xcode.app
Потом запустить этот скрипт снова.
EOF
    exit 1
fi

[[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"
if ! command -v cargo > /dev/null 2>&1; then
    echo "Для сборки ядра нужен Rust (rustup ставится в ~/.rustup и ~/.cargo, без sudo)."
    printf 'Установить сейчас? [y/N] '
    read -r answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        . "$HOME/.cargo/env"
    fi
fi

# XcodeGen: проект Xcode собирается из ios/project.yml.
XCODEGEN="$(command -v xcodegen || true)"
if [[ -z "$XCODEGEN" ]] && command -v brew > /dev/null 2>&1; then
    brew install xcodegen > "$OUT/xcodegen-install.txt" 2>&1 || true
    XCODEGEN="$(command -v xcodegen || true)"
fi
if [[ -z "$XCODEGEN" ]]; then
    mkdir -p "$IOS/build/tools"
    if curl -fsSL -o "$IOS/build/tools/xcodegen.zip" \
        https://github.com/yonaskolb/XcodeGen/releases/latest/download/xcodegen.zip; then
        (cd "$IOS/build/tools" && unzip -oq xcodegen.zip)
        XCODEGEN="$(find "$IOS/build/tools" -type f -name xcodegen -perm -u+x | head -1)"
    fi
fi

{
    sw_vers
    echo "архитектура: $(uname -m)"
    xcodebuild -version
    echo "xcode-select: $(xcode-select -p)"
    echo "xcodegen: ${XCODEGEN:-НЕТ}"
    echo
    echo "Симуляторы iOS:"
    xcrun simctl list runtimes
    echo
    command -v cargo > /dev/null && cargo --version && rustc --version
    echo
    df -h "$HOME" | tail -1
} > "$OUT/environment.txt" 2>&1
status "Окружение" "см. environment.txt"

if ! xcrun simctl list runtimes 2>/dev/null | grep -q '^iOS'; then
    status "Симулятор iOS" "НЕТ — Xcode → Settings → Components → iOS"
fi

# --- 1. Ядро Rust под iOS + биндинги Swift ------------------------------------------------

rust_ok=0
if command -v cargo > /dev/null 2>&1; then
    profile_flag="--debug"
    [[ -n "$TEAM" ]] && profile_flag=""      # на телефон — оптимизированное ядро
    if run_step "Ядро Rust для iOS" rust-ios.txt bash "$ROOT/tools/build-rust-ios.sh" $profile_flag; then
        rust_ok=1
    else
        grep -E '^error' "$OUT/rust-ios.txt" | sort -u > "$OUT/rust-errors.txt"
    fi
else
    status "Ядро Rust для iOS" "ПРОПУЩЕНО — Rust не установлен"
fi

# --- 2. Все ошибки Swift сразу: проверка типов -------------------------------------------------

SDK="$(xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)"
ARCH="$(uname -m)"
[[ "$ARCH" == "arm64" ]] || ARCH="x86_64"
TRIPLE="${ARCH}-apple-ios17.0-simulator"

find "$IOS/GasApp" -name '*.swift' | sort > "$OUT/swift-files.txt"
typecheck() {
    xcrun swiftc -typecheck -parse-as-library -sdk "$SDK" -target "$TRIPLE" -module-name GasApp \
        -D GASAPP_GALLERY -I "$IOS/build/headers" @"$OUT/swift-files.txt"
}
run_step "Swift: проверка типов" swift-typecheck.txt typecheck
grep -E ': (error|warning):' "$OUT/swift-typecheck.txt" | sed "s|$ROOT/||" | sort -u > "$OUT/swift-errors.txt"
status "  ошибок Swift" "$(grep -c ': error:' "$OUT/swift-errors.txt" || true)"
status "  предупреждений Swift" "$(grep -c ': warning:' "$OUT/swift-errors.txt" || true)"

# --- 3. Проект Xcode ---------------------------------------------------------------------------

project_ok=0
if [[ -n "$XCODEGEN" ]]; then
    if run_step "Проект Xcode (XcodeGen)" xcodegen.txt bash -c "cd '$IOS' && '$XCODEGEN' generate"; then
        project_ok=1
    fi
else
    status "Проект Xcode (XcodeGen)" "ПРОПУЩЕНО — XcodeGen не установился (brew install xcodegen)"
fi

# --- 4. Симулятор: сборка, запуск каждого экрана, снимки -----------------------------------------

UDID="$(xcrun simctl list devices available | grep -E '^[[:space:]]+iPhone' | head -1 \
    | grep -oE '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}')"

app_ok=0
if (( rust_ok && project_ok )) && [[ -n "$UDID" ]]; then
    build_sim() {
        xcodebuild -project "$IOS/GasApp.xcodeproj" -scheme GasApp -configuration Debug \
            -destination "platform=iOS Simulator,id=$UDID" -derivedDataPath "$DERIVED" \
            CODE_SIGNING_ALLOWED=NO 'OTHER_SWIFT_FLAGS=$(inherited) -DGASAPP_GALLERY' build
    }
    if run_step "Сборка приложения (симулятор)" xcodebuild-sim.txt build_sim; then
        app_ok=1
    fi
    grep -E '(error:|Undefined symbols|ld: )' "$OUT/xcodebuild-sim.txt" | sed "s|$ROOT/||" | sort -u > "$OUT/build-errors.txt"
elif [[ -z "$UDID" ]]; then
    status "Сборка приложения (симулятор)" "ПРОПУЩЕНО — нет симулятора iPhone"
else
    status "Сборка приложения (симулятор)" "ПРОПУЩЕНО — сначала исправить ошибки выше"
fi

APP="$DERIVED/Build/Products/Debug-iphonesimulator/GasApp.app"
if (( app_ok )) && [[ -d "$APP" ]]; then
    say "симулятор"
    xcrun simctl list devices | grep "$UDID" | sed 's/^ */устройство: /' | tee -a "$SUMMARY"
    xcrun simctl boot "$UDID" > /dev/null 2>&1 || true
    xcrun simctl bootstatus "$UDID" -b > /dev/null 2>&1
    open -a Simulator > /dev/null 2>&1 || true

    if run_step "Установка в симулятор" sim-install.txt xcrun simctl install "$UDID" "$APP"; then
        for screen in $SCREENS; do
            say "экран: $screen"
            SIMCTL_CHILD_GASAPP_SCREEN="$screen" xcrun simctl launch --console-pty \
                --terminate-running-process "$UDID" "$BUNDLE_ID" > "$OUT/console-$screen.txt" 2>&1 &
            console_pid=$!
            sleep 7
            xcrun simctl io "$UDID" screenshot "$OUT/screens/$screen.png" > /dev/null 2>&1
            # Жив ли процесс — по его PID: приложение симулятора — обычный
            # процесс Mac, `simctl launch` печатает его номер первой строкой.
            # Прежняя проверка через `launchctl list` симулятора давала
            # «упало» на живых экранах (чаты, контакты — снимки были).
            app_pid=$(sed -n "s/^${BUNDLE_ID}: \([0-9][0-9]*\).*/\1/p" "$OUT/console-$screen.txt" | head -1)
            if [[ -n "$app_pid" ]] && kill -0 "$app_pid" 2>/dev/null; then
                status "Экран «${screen}»" "запущен, снимок screens/$screen.png"
            else
                status "Экран «${screen}»" "🔴 ПРИЛОЖЕНИЕ УПАЛО — см. console-$screen.txt и crashes/"
            fi
            xcrun simctl terminate "$UDID" "$BUNDLE_ID" > /dev/null 2>&1 || true
            kill "$console_pid" > /dev/null 2>&1 || true
            wait "$console_pid" 2>/dev/null || true
        done
        xcrun simctl spawn "$UDID" log show --last 15m --style compact \
            --predicate 'process == "GasApp"' > "$OUT/app-log.txt" 2>&1 || true
    fi
fi

# --- 5. Установка на iPhone (по желанию) ------------------------------------------------------------

if [[ -n "$TEAM" ]] && (( rust_ok && project_ok )); then
    build_device() {
        xcodebuild -project "$IOS/GasApp.xcodeproj" -scheme GasApp -configuration Debug \
            -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED" \
            -allowProvisioningUpdates DEVELOPMENT_TEAM="$TEAM" build
    }
    if run_step "Сборка для iPhone" xcodebuild-device.txt build_device; then
        DEVICE_APP="$DERIVED/Build/Products/Debug-iphoneos/GasApp.app"
        DEVICE_ID="$(xcrun devicectl list devices 2>/dev/null | awk '/connected|available/ && /iPhone/ {for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F-]{25,}$/) {print $i; exit}}')"
        if [[ -n "$DEVICE_ID" ]]; then
            run_step "Установка на iPhone" device-install.txt \
                xcrun devicectl device install app --device "$DEVICE_ID" "$DEVICE_APP"
        else
            status "Установка на iPhone" "iPhone не найден — подключите кабелем, разблокируйте, «Доверять»"
        fi
    fi
fi

# Отчёты о падениях — симулятор кладёт их в журналы самого Mac.
find "$HOME/Library/Logs/DiagnosticReports" -name 'GasApp*' -newer "$START_MARK" \
    -exec cp {} "$OUT/crashes/" \; 2>/dev/null
status "Отчётов о падениях" "$(find "$OUT/crashes" -type f | wc -l | tr -d ' ')"

# --- 6. Тесты ядра на macOS (по желанию) ------------------------------------------------------------

if (( RUST_TESTS )) && command -v cargo > /dev/null 2>&1; then
    run_step "Тесты ядра Rust (macOS)" rust-tests.txt \
        cargo test --manifest-path "$ROOT/crates/Cargo.toml" --workspace
    grep -E '^test .* FAILED|^failures:|panicked at' "$OUT/rust-tests.txt" > "$OUT/rust-test-failures.txt" || true
fi

# --- Итог ----------------------------------------------------------------------------------------------

rm -f "$START_MARK"
cat >> "$SUMMARY" <<'EOF'

Где смотреть:
  swift-errors.txt   — все ошибки и предупреждения Swift сразу (файл:строка: текст)
  build-errors.txt   — ошибки сборки Xcode и компоновки
  rust-errors.txt    — ошибки сборки ядра
  screens/*.png      — снимки каждого экрана в симуляторе
  console-*.txt      — вывод приложения на каждом экране
  app-log.txt        — системный журнал приложения
  crashes/           — отчёты о падениях
EOF

(cd "$ROOT" && ditto -c -k --keepParent mac-report mac-report.zip)

echo
echo "================================================================"
cat "$SUMMARY"
echo "================================================================"
echo "Готово. Отправьте разработчику файл:"
echo "  $ROOT/mac-report.zip"
open "$OUT" > /dev/null 2>&1 || true
