#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Мониторинг серверов Beszel — одной командой в Ubuntu на ПК:
#
#     bash /mnt/c/Users/be4ho/Desktop/WORK/AEGIS/server/deploy/beszel.sh
#
# Открывать — вместе с админ-центром: `admin.sh` пробрасывает и его
# (http://127.0.0.1:8090), ссылка «Servers» есть в меню админ-центра.
#
# # Почему так
#
# * Программы скачиваются здесь, на ПК, и ставятся, только если их
#   SHA-256 совпал со списком сумм выпуска. На серверы ничего не
#   скачивается из интернета.
# * Версия закреплена и не моложе двух недель на день выбора — защита
#   от свежеподменённого выпуска. Обновлять — сменить VERSION и запустить.
# * Центр — на БАЗЕ, слушает только 127.0.0.1: из интернета и из сети
#   WireGuard его не видно; открывается туннелем SSH, как админ-центр.
# * Центр сам ходит к агентам по SSH-ключу (агент пускает только этот
#   ключ); агенты слушают только адрес WireGuard, брандмауэр пускает к
#   ним только базу. Наружу ни центру, ни агентам ходить нельзя
#   (IPAddressDeny в их службах).

set -euo pipefail

VERSION=0.21.1          # выпуск 2026-10-22
DB=gasapp-db
HOSTS=(gasapp-db gasapp-lb gasapp-node2 gasapp-node3)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY="$ROOT/server/deploy"
BASE="https://github.com/henrygd/beszel/releases/download/v${VERSION}"

say() { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m✘ %s\033[0m\n\n' "$*" >&2; exit 1; }

# shellcheck disable=SC1090
[[ -f ~/.gasapp-env ]] && source ~/.gasapp-env

# --- Одно подключение на машину (лимит SSH на VPS-1, шаг 13) ------------------
SSHCFG="$(mktemp)"
CMDIR="$(mktemp -d)"
WORK="$(mktemp -d)"
cat > "$SSHCFG" << EOF
Host *
    ControlMaster auto
    ControlPath ${CMDIR}/%C
    ControlPersist 15m
Include ~/.ssh/config
EOF
cleanup() {
    for h in "${HOSTS[@]}"; do command ssh -F "$SSHCFG" -O exit "$h" > /dev/null 2>&1 || true; done
    rm -rf "$SSHCFG" "$CMDIR" "$WORK"
    [[ -n "${AGENT_STARTED:-}" ]] && ssh-agent -k > /dev/null 2>&1
    return 0
}
trap cleanup EXIT
ssh() { command ssh -F "$SSHCFG" "$@"; }
rsync() { command rsync -e "ssh -F $SSHCFG" "$@"; }

# --- 1. Скачать и проверить -------------------------------------------------------
say "Beszel ${VERSION}: скачиваю и проверяю"
cd "$WORK"
for file in beszel_linux_amd64.tar.gz beszel-agent_linux_amd64.tar.gz "beszel_${VERSION}_checksums.txt"; do
    curl -fsSLo "$file" "$BASE/$file" || die "не скачался $file — интернет?"
done
grep -E ' (beszel_linux_amd64|beszel-agent_linux_amd64)\.tar\.gz$' "beszel_${VERSION}_checksums.txt" > sums.txt
[[ "$(wc -l < sums.txt)" -eq 2 ]] || die "в списке сумм выпуска нет нужных файлов"
sha256sum --check --quiet sums.txt || die "СУММА НЕ СОВПАЛА — файл подменён или испорчен. Ничего не ставлю."
ok "суммы совпали со списком выпуска"
tar -xzf beszel_linux_amd64.tar.gz beszel
tar -xzf beszel-agent_linux_amd64.tar.gz beszel-agent
chmod 755 beszel beszel-agent

# --- 2. Ключ SSH и связь ----------------------------------------------------------
if ! ssh-add -l > /dev/null 2>&1; then
    eval "$(ssh-agent -s)" > /dev/null
    AGENT_STARTED=1
    key="$(ssh -G "$DB" | awk '/^identityfile / {print $2; exit}')"
    key="${key/#\~/$HOME}"
    echo "  Фраза ключа SSH (Bitwarden: «SSH: фраза ключа»):"
    ssh-add "$key" || die "ключ не добавился — неверная фраза?"
fi
for h in "${HOSTS[@]}"; do
    ssh -o BatchMode=yes -o ConnectTimeout=20 "$h" true 2> /dev/null || die "нет связи с $h"
done
ok "связь со всеми машинами"

send_kit() {
    local host="$1"; shift
    ssh "$host" 'rm -rf ~/beszel-kit && mkdir -m 700 ~/beszel-kit'
    rsync -a "$@" "$DEPLOY/beszel-remote.sh" "$host:beszel-kit/"
}

# --- 3. Центр на базе ---------------------------------------------------------------
say "Центр на ${DB}"
send_kit "$DB" "$WORK/beszel"
echo "  Пароль ops на ${DB} (sudo):"
out="$(ssh -t "$DB" 'sudo bash ~/beszel-kit/beszel-remote.sh hub' | tr -d '\r' | tee /dev/stderr)"
hub_key="$(sed -n 's/^HUB_KEY=//p' <<< "$out")"
hub_ip="$(sed -n 's/^HUB_IP=//p' <<< "$out")"
[[ "$hub_key" == ssh-ed25519\ * && -n "$hub_ip" ]] || die "центр не отдал свой ключ — см. выше"

# --- 4. Агенты ----------------------------------------------------------------------
declare -A addr
for h in "${HOSTS[@]}"; do
    say "Агент на ${h}"
    send_kit "$h" "$WORK/beszel-agent"
    echo "  Пароль ops на ${h} (sudo):"
    ssh -t "$h" "sudo bash ~/beszel-kit/beszel-remote.sh agent '${hub_key}' '${hub_ip}'" || die "агент на $h не встал — см. выше"
    if [[ "$h" == "$DB" ]]; then
        addr[$h]="127.0.0.1"
    else
        addr[$h]="$(ssh "$h" "ip -4 -o addr show wg0 | awk '{print \$4}' | cut -d/ -f1 | head -1")"
    fi
done

cat << EOF

────────────────────────────────────────────────────────────────────
 ✅ BESZEL УСТАНОВЛЕН
 1. Откройте админ-центр: bash $DEPLOY/admin.sh
    и в его меню — «Servers» (или http://127.0.0.1:8090).
 2. Первый вход: создайте учётную запись (почта — любая ваша, пароль —
    из генератора Bitwarden; сохраните запись «GasApp: Beszel»).
 3. «Add System» → вкладка «SSH» — четыре машины (порт 45876):
EOF
for h in "${HOSTS[@]}"; do
    printf '      %-14s Host: %-12s Port: 45876\n' "$h" "${addr[$h]}"
done
cat << 'EOF'
    Ключ, который покажет окно «Add System», уже стоит на агентах —
    просто нажмите «Add».
 Оповещения о сбоях по-прежнему присылает монитор в Telegram; Beszel —
 графики и история нагрузки.
────────────────────────────────────────────────────────────────────
EOF
