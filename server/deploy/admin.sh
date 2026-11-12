#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Админ-центр оператора — одной командой в Ubuntu (шаг 20 инструкции).
#
#     bash /mnt/c/Users/be4ho/Desktop/WORK/AEGIS/server/deploy/admin.sh
#         — открыть: туннель до БАЗЫ, браузер сам откроет панель.
#           Ctrl+C — закрыть туннель.
#
#     bash …/admin.sh --install
#         — поставить или обновить админ-центр на БАЗЕ и уведомления о
#           жалобах в Telegram. Спросит пароль ops (sudo) и, только если
#           токена ещё нет или вы решили сменить, — токен из Bitwarden.
#
# 🔐 Что остаётся как в плане (docs/ops/admin-center.md):
#   * админ-центр слушает ТОЛЬКО 127.0.0.1:8480 на БАЗЕ — из интернета
#     его нет; скрипт проверяет это после установки и останавливает
#     службу, если адрес другой;
#   * доступ — только туннелем SSH, и на ПК он тоже открывается только
#     на 127.0.0.1 (не на все адреса ПК);
#   * на сервере — только SHA-256 токена; сам токен вводится скрыто
#     (read -s), не попадает ни в аргументы, ни в журнал, ни в историю;
#   * программа ставится, только если её сумма совпадает с вашей
#     сборкой, а контрольные суммы монитора переписываются после этого.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY="$ROOT/server/deploy"
HOST=gasapp-db
REMOTE_PORT=8480

say() { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m✘ %s\033[0m\n\n' "$*" >&2; exit 1; }

mode=open
case "${1:-}" in
    "") ;;
    --install) mode=install ;;
    *) die "неизвестный ключ: $1 (есть --install)" ;;
esac

# shellcheck disable=SC1090
[[ -f ~/.gasapp-env ]] && source ~/.gasapp-env

# --- Одно подключение SSH на всё (лимит подключений на VPS-1, шаг 13) -----

SSHCFG="$(mktemp)"
CMDIR="$(mktemp -d)"
cat > "$SSHCFG" << EOF
Host *
    ControlMaster auto
    ControlPath ${CMDIR}/%C
    ControlPersist 30m
Include ~/.ssh/config
EOF
TUNNEL_PID=""
cleanup() {
    [[ -n "$TUNNEL_PID" ]] && kill "$TUNNEL_PID" 2> /dev/null || true
    command ssh -F "$SSHCFG" -O exit "$HOST" > /dev/null 2>&1 || true
    rm -rf "$SSHCFG" "$CMDIR"
    [[ -n "${AGENT_STARTED:-}" ]] && ssh-agent -k > /dev/null 2>&1
    return 0
}
trap cleanup EXIT
trap 'echo; exit 0' INT
ssh() { command ssh -F "$SSHCFG" "$@"; }
rsync() { command rsync -e "ssh -F $SSHCFG" "$@"; }

if ! ssh-add -l > /dev/null 2>&1; then
    eval "$(ssh-agent -s)" > /dev/null
    AGENT_STARTED=1
    key="$(ssh -G "$HOST" | awk '/^identityfile / {print $2; exit}')"
    key="${key/#\~/$HOME}"
    echo "  Фраза ключа SSH (Bitwarden: «SSH: фраза ключа»):"
    ssh-add "$key" || die "ключ не добавился — неверная фраза?"
fi
ssh -o BatchMode=yes -o ConnectTimeout=20 "$HOST" true 2> /dev/null ||
    die "нет связи с $HOST (интернет? вход через VPS-1 — шаг 23.1)"

# --- Установка -------------------------------------------------------------

if [[ "$mode" == install ]]; then
    say "Программа админ-центра"
    binary=""
    for candidate in "${REPO:-}/server/target/release/gasapp-server-admin" "$ROOT/server/target/release/gasapp-server-admin"; do
        [[ -x "$candidate" ]] && { binary="$candidate"; break; }
    done
    if [[ -z "$binary" ]]; then
        build="${REPO:-$ROOT}/server"
        echo "  Собранной программы нет — собираю в $build (5–15 минут)…"
        (cd "$build" && cargo build --release --locked -j 2 -p gasapp-server-admin) ||
            die "сборка не удалась — см. сообщения cargo выше"
        binary="$build/target/release/gasapp-server-admin"
    fi
    sum="$(sha256sum "$binary" | cut -d' ' -f1)"
    ok "программа: ${binary} (${sum:0:16}…)"

    kit="$(mktemp -d)"
    cp "$binary" "$kit/gasapp-server-admin"
    cp "$DEPLOY/admin-remote.sh" "$kit/install.sh"
    cp "$DEPLOY/systemd/gasapp-admin.service" "$DEPLOY/systemd/gasapp-reports.service" "$DEPLOY/systemd/gasapp-reports.timer" "$kit/"
    printf '%s  gasapp-server-admin\n' "$sum" > "$kit/expected-sum"
    ssh "$HOST" 'rm -rf ~/admin-kit && mkdir -m 700 ~/admin-kit'
    rsync -a "$kit/" "$HOST:admin-kit/"
    rm -rf "$kit"

    # Монитор и его скрипт сверки сумм — тоже свежие.
    rsync -a "$DEPLOY/notify-telegram.sh" "$DEPLOY/check-nodes.sh" "$DEPLOY/update-remote.sh" "$HOST:deploy/"
    rsync -a "$DEPLOY/monitor/gasapp-monitor.sh" "$HOST:deploy/monitor/"
    {
        [[ -n "${OFF:-}" && -f "$OFF/build-sha256.txt" ]] && cat "$OFF/build-sha256.txt"
        printf '%s  gasapp-server-admin\n' "$sum"
    } | awk '{print $1, $2}' | ssh "$HOST" 'cat > ~/deploy/expected-sums.txt'

    say "Установка на $HOST"
    echo "  Пароль ops на $HOST (sudo):"
    ssh -t "$HOST" 'bash ~/admin-kit/install.sh' || die "установка на $HOST не прошла — причина выше"

    # Новая программа — новые контрольные суммы монитора (с проверкой).
    ssh -t "$HOST" "sudo bash ~/deploy/update-remote.sh $HOST ~/deploy" || true
    ok "установка закончена"
    echo
    echo "  Открыть панель: bash $DEPLOY/admin.sh"
    exit 0
fi

# --- Открыть ---------------------------------------------------------------

say "Админ-центр"
state="$(ssh "$HOST" 'systemctl is-active gasapp-admin' 2> /dev/null || true)"
[[ "$state" == active ]] || die "на $HOST админ-центр не запущен ($state). Поставить: bash $DEPLOY/admin.sh --install"

local_port=$REMOTE_PORT
while ss -Hlnt "sport = :$local_port" 2> /dev/null | grep -q .; do local_port=$((local_port + 1)); done

# 🔐 -L 127.0.0.1:… — туннель открыт только для этого ПК, не для сети.
ssh -N -o ExitOnForwardFailure=yes -L "127.0.0.1:${local_port}:127.0.0.1:${REMOTE_PORT}" "$HOST" &
TUNNEL_PID=$!

url="http://127.0.0.1:${local_port}/login"
for _ in $(seq 1 30); do
    curl -fsS -o /dev/null "$url" 2> /dev/null && break
    kill -0 "$TUNNEL_PID" 2> /dev/null || die "туннель не открылся"
    sleep 0.5
done
ok "туннель открыт: $url"

# Браузер Windows (WSL) или Linux.
if command -v cmd.exe > /dev/null 2>&1; then
    cmd.exe /c start "" "$url" > /dev/null 2>&1 || true
elif command -v xdg-open > /dev/null 2>&1; then
    xdg-open "$url" > /dev/null 2>&1 || true
fi

cat << EOF

────────────────────────────────────────────────────────────────────
 Браузер открыт: $url
 Токен — Bitwarden, запись «GasApp: токен админ-центра».
 Пять неверных токенов подряд закрывают вход на 10 минут.

 Закончили — Ctrl+C здесь: туннель закроется, панель станет
 недоступна. Сессия в браузере сама истечёт через 30 минут простоя.
────────────────────────────────────────────────────────────────────
EOF
wait "$TUNNEL_PID" || true
