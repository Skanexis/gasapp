#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Проверка iOS-части на Mac: собрать всё, что собирается, запустить
# в симуляторе и сложить ВСЕ ошибки в один отчёт.
#
#     bash tools/mac-check.sh               # ядро, Swift, запуск, снимки
#     bash tools/mac-check.sh --rust-tests  # плюс тесты ядра на macOS (долго)
#
# Результат — каталог mac-report/ и архив mac-report.zip в корне проекта.
# Архив отправляют разработчику целиком: в нём журналы, список ошибок
# компиляции, снимки экранов и отчёты о падениях.
#
# Скрипт не останавливается на первой ошибке: каждый шаг пишет свой
# журнал, а итог — в mac-report/SUMMARY.txt. Ничего не ставит в систему,
# кроме Rust (rustup, в домашний каталог — только с согласия) и целей
# сборки Rust под iOS.
#
# ⚠️ Пишется под bash 3.2 (он стоит в macOS по умолчанию): без
# ассоциативных массивов, mapfile и пустых массивов под set -u.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/mac-report"
APP="$ROOT/ios/build/check-app/GasApp.app"
HEADERS="$ROOT/ios/build/headers"
SIM_LIB="$ROOT/ios/build/sim"
BUNDLE_ID="org.gasapp.messenger"
SCREENS="ffi onboarding lock chats chat"

RUST_TESTS=0
[[ "${1:-}" == "--rust-tests" ]] && RUST_TESTS=1

cd "$ROOT" || exit 1
rm -rf "$OUT" "$ROOT/mac-report.zip"
mkdir -p "$OUT/screens" "$OUT/crashes"
SUMMARY="$OUT/SUMMARY.txt"
START_MARK="$OUT/.start"
touch "$START_MARK"

say()    { echo; echo "== $*"; }
status() { printf '%-34s %s\n' "$1" "$2" | tee -a "$SUMMARY"; }

# run_step <название> <журнал> <команда…>: журнал — в mac-report/,
# в итог — «OK» или «ОШИБКА».
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

# --- 0. Окружение ---------------------------------------------------------------

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

if ! command -v cargo > /dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi
if ! command -v cargo > /dev/null 2>&1; then
    echo "Для сборки ядра нужен Rust (rustup ставится в ~/.rustup и ~/.cargo, без sudo)."
    printf 'Установить сейчас? [y/N] '
    read -r answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
fi

{
    sw_vers
    echo "архитектура: $(uname -m)"
    xcodebuild -version
    echo "xcode-select: $(xcode-select -p)"
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

# --- 1. Ядро Rust под iOS -----------------------------------------------------------

rust_ok=0
if command -v cargo > /dev/null 2>&1; then
    if run_step "Ядро Rust для iOS" rust-ios.txt bash "$ROOT/tools/build-rust-ios.sh" --debug; then
        rust_ok=1
    else
        grep -E '^(error|warning: unused)' "$OUT/rust-ios.txt" | sort -u > "$OUT/rust-errors.txt"
    fi
else
    status "Ядро Rust для iOS" "ПРОПУЩЕНО — Rust не установлен"
fi

# --- 2. Проверка типов Swift: все ошибки компиляции сразу -------------------------------

SDK="$(xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)"
ARCH="$(uname -m)"
[[ "$ARCH" == "arm64" ]] || ARCH="x86_64"
TRIPLE="${ARCH}-apple-ios17.0-simulator"

# Список файлов — в файл ответов swiftc: без массивов и без пробелов в путях.
find "$ROOT/ios/GasApp" -name '*.swift' -not -path '*/Tests/*' | sort > "$OUT/swift-files.txt"
# Модуль заголовков ядра — только если ядро собралось.
CLANG_FLAGS="-I$ROOT/ios/GasApp"
if [[ -f "$HEADERS/module.modulemap" ]]; then
    CLANG_FLAGS="-I$HEADERS"
fi

swift_common() {
    xcrun swiftc -parse-as-library -sdk "$SDK" -target "$TRIPLE" -module-name GasApp \
        -D GASAPP_GALLERY -Xcc "$CLANG_FLAGS" -I "$HEADERS" "$@" @"$OUT/swift-files.txt"
}

swift_ok=0
if run_step "Swift: проверка типов" swift-typecheck.txt swift_common -typecheck; then
    swift_ok=1
fi
grep -E ': (error|warning):' "$OUT/swift-typecheck.txt" | sed "s|$ROOT/||" | sort -u > "$OUT/swift-errors.txt"
status "  ошибок Swift" "$(grep -c ': error:' "$OUT/swift-errors.txt" || true)"
status "  предупреждений Swift" "$(grep -c ': warning:' "$OUT/swift-errors.txt" || true)"

# --- 3. Сборка приложения для симулятора ---------------------------------------------------

app_ok=0
if (( swift_ok && rust_ok )); then
    rm -rf "$APP" && mkdir -p "$APP"
    build_app() {
        swift_common -Onone -g -o "$APP/GasApp" \
            -L "$SIM_LIB" -lgasapp \
            -framework Security -framework SystemConfiguration -framework CoreFoundation \
            -lc++ -lresolv -lz -liconv || return 1

        cp "$ROOT/ios/GasApp/Info.plist" "$APP/Info.plist"
        plutil -replace CFBundleExecutable -string GasApp "$APP/Info.plist"
        plutil -replace CFBundleName -string GasApp "$APP/Info.plist"
        plutil -replace CFBundleDevelopmentRegion -string en "$APP/Info.plist"
        plutil -replace MinimumOSVersion -string 17.0 "$APP/Info.plist"
        plutil -replace UIDeviceFamily -json '[1]' "$APP/Info.plist"
        plutil -replace CFBundleSupportedPlatforms -json '["iPhoneSimulator"]' "$APP/Info.plist"

        if ! xcrun ibtool --compile "$APP/LaunchScreen.storyboardc" "$ROOT/ios/Base.lproj/LaunchScreen.storyboard"; then
            echo "⚠️ LaunchScreen не скомпилировался — убран из Info.plist"
            plutil -remove UILaunchStoryboardName "$APP/Info.plist"
        fi
        xcrun actool "$ROOT/ios/GasApp/Assets.xcassets" --compile "$APP" --platform iphonesimulator \
            --minimum-deployment-target 17.0 --app-icon AppIcon \
            --output-partial-info-plist "$ROOT/ios/build/check-app/assets.plist" \
            || echo "⚠️ каталог ресурсов (иконки) не скомпилировался"

        codesign --force --sign - --timestamp=none "$APP"
    }
    if run_step "Сборка приложения (симулятор)" app-build.txt build_app; then
        app_ok=1
    else
        grep -E '(error|Undefined symbols|ld:)' "$OUT/app-build.txt" | sort -u > "$OUT/link-errors.txt"
    fi
else
    status "Сборка приложения (симулятор)" "ПРОПУЩЕНО — сначала исправить ошибки выше"
fi

# --- 4. Запуск в симуляторе и снимки экранов --------------------------------------------------

if (( app_ok )); then
    say "симулятор"
    UDID="$(xcrun simctl list devices available | grep -E '^[[:space:]]+iPhone' | head -1 \
        | grep -oE '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}')"
    if [[ -z "$UDID" ]]; then
        status "Симулятор" "НЕ НАЙДЕН iPhone — Xcode → Settings → Components → iOS"
    else
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
                if xcrun simctl spawn "$UDID" launchctl list 2>/dev/null | grep -q "$BUNDLE_ID"; then
                    status "Экран «$screen»" "запущен, снимок screens/$screen.png"
                else
                    status "Экран «$screen»" "🔴 ПРИЛОЖЕНИЕ УПАЛО — см. console-$screen.txt и crashes/"
                fi
                xcrun simctl terminate "$UDID" "$BUNDLE_ID" > /dev/null 2>&1 || true
                kill "$console_pid" > /dev/null 2>&1 || true
                wait "$console_pid" 2>/dev/null || true
            done

            xcrun simctl spawn "$UDID" log show --last 15m --style compact \
                --predicate 'process == "GasApp"' > "$OUT/app-log.txt" 2>&1 || true
        fi
    fi
fi

# Отчёты о падениях — симулятор кладёт их в журналы самого Mac.
find "$HOME/Library/Logs/DiagnosticReports" -name 'GasApp*' -newer "$START_MARK" \
    -exec cp {} "$OUT/crashes/" \; 2>/dev/null
crashes="$(find "$OUT/crashes" -type f | wc -l | tr -d ' ')"
status "Отчётов о падениях" "$crashes"

# --- 5. Тесты ядра на macOS (по желанию) ----------------------------------------------------

if (( RUST_TESTS )) && command -v cargo > /dev/null 2>&1; then
    run_step "Тесты ядра Rust (macOS)" rust-tests.txt \
        cargo test --manifest-path "$ROOT/crates/Cargo.toml" --workspace
    grep -E '^test .* FAILED|^failures:|panicked at' "$OUT/rust-tests.txt" > "$OUT/rust-test-failures.txt" || true
fi

# --- Итог -----------------------------------------------------------------------------------

rm -f "$START_MARK"
cat >> "$SUMMARY" <<'EOF'

Где смотреть:
  swift-errors.txt   — все ошибки и предупреждения Swift сразу (файл:строка: текст)
  rust-errors.txt    — ошибки сборки ядра (если были)
  link-errors.txt    — ошибки компоновки (если были)
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
