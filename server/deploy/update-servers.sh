#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Обновить сайт и мониторинг на всех серверах — одной командой в Ubuntu:
#
#     bash /mnt/c/Users/be4ho/Desktop/WORK/AEGIS/server/deploy/update-servers.sh
#
# Спросит: фразу ключа SSH — один раз; пароль ops — по разу на машину
# (sudo); «да/нет» — только если нужно решение (перезагрузка, лишняя
# почта). Запускайте после каждого обновления скриптов, сайта или
# программ сервера и когда монитор пишет «Изменились файлы программ»
# после ВАШЕГО обновления.
#
# Только сайт:      update-servers.sh --site
# Только монитор:   update-servers.sh --monitor

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY="$ROOT/server/deploy"
HOSTS=(gasapp-lb gasapp-node2 gasapp-node3 gasapp-db)
SITE_URL="https://gasapp.eu"

say() { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m✘ %s\033[0m\n\n' "$*" >&2; exit 1; }

do_site=1; do_monitor=1
case "${1:-}" in
    --site) do_monitor=0 ;;
    --monitor) do_site=0 ;;
    "") ;;
    *) die "неизвестный ключ: $1 (есть --site и --monitor)" ;;
esac

# shellcheck disable=SC1090
[[ -f ~/.gasapp-env ]] && source ~/.gasapp-env

# --- Одно подключение на машину ----------------------------------------------
#
# 🔐 На VPS-1 брандмауэр пускает не больше шести новых подключений SSH
# за 30 секунд (ufw limit, шаг 13), а ко внутренним машинам ходят через
# него же. Поэтому все команды идут через одно постоянное подключение к
# каждой машине (ControlMaster): без этого скрипт упирался в лимит.
SSHCFG="$(mktemp)"
CMDIR="$(mktemp -d)"
cat > "$SSHCFG" << EOF
Host *
    ControlMaster auto
    ControlPath ${CMDIR}/%C
    ControlPersist 15m
Include ~/.ssh/config
EOF
cleanup() {
    for h in "${HOSTS[@]}"; do command ssh -F "$SSHCFG" -O exit "$h" > /dev/null 2>&1 || true; done
    rm -rf "$SSHCFG" "$CMDIR"
    [[ -n "${AGENT_STARTED:-}" ]] && ssh-agent -k > /dev/null 2>&1
    return 0
}
trap cleanup EXIT
ssh() { command ssh -F "$SSHCFG" "$@"; }
rsync() { command rsync -e "ssh -F $SSHCFG" "$@"; }

# --- Ключ SSH: фраза один раз на весь запуск ---------------------------------

say "Ключ SSH"
if ! ssh-add -l > /dev/null 2>&1; then
    eval "$(ssh-agent -s)" > /dev/null
    AGENT_STARTED=1
    key="$(ssh -G gasapp-lb | awk '/^identityfile / {print $2; exit}')"
    key="${key/#\~/$HOME}"
    echo "  Фраза ключа SSH (Bitwarden: «SSH: фраза ключа») — спросится один раз:"
    ssh-add "$key" || die "ключ не добавился — неверная фраза?"
fi
ok "ключ загружен"

for h in "${HOSTS[@]}"; do
    if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$h" true 2> /dev/null; then
        # Отказ может быть от лимита после прошлого запуска — ждём и пробуем ещё.
        echo "  $h не ответил — жду 40 секунд (лимит подключений) и пробую ещё раз…"
        sleep 40
        ssh -o BatchMode=yes -o ConnectTimeout=15 "$h" true 2> /dev/null || die "нет связи с $h (проверьте интернет и шаг 23.1 — вход через VPS-1)"
    fi
done
ok "связь со всеми четырьмя машинами"

# --- Сайт ------------------------------------------------------------------------

if (( do_site )); then
    say "Сайт ${SITE_URL}"
    out="$(mktemp -d)"
    python3 "$ROOT/tools/build-site.py" --out "$out/site" --base-url "$SITE_URL" > "$out/build.log" 2>&1 ||
        die "сайт не собрался: $(tail -3 "$out/build.log" | tr '\n' ' ')"
    ok "собран: $(tail -1 "$out/build.log")"
    rsync -a --delete "$out/site/" gasapp-lb:site/
    rsync -a "$DEPLOY/nginx/site.conf" gasapp-lb:site-nginx.conf
    echo "  Пароль ops на gasapp-lb (sudo):"
    # Настройки nginx для сайта (страница /add, файл для Apple) — с
    # откатом: не прошла проверка nginx -t — возвращается прежний файл,
    # и сайт продолжает работать как был.
    ssh -t gasapp-lb 'set -e
        sudo rsync -a --delete --chown=root:root --chmod=D755,F644 ~/site/ /var/www/gasapp-site/
        conf=/etc/nginx/conf.d/site.conf
        sudo cp -p "$conf" "$conf.before-update" 2> /dev/null || true
        sudo install -m 644 ~/site-nginx.conf "$conf"
        if ! sudo nginx -t -q; then
            sudo mv "$conf.before-update" "$conf"
            echo "  ✘ новые настройки nginx не прошли проверку — вернул прежние"
            exit 1
        fi
        sudo rm -f "$conf.before-update"
        sudo systemctl reload-or-restart nginx' ||
        die "сайт не установился на gasapp-lb"
    aasa="$(curl -fsS "$SITE_URL/.well-known/apple-app-site-association" | python3 -c 'import json,sys; print(json.load(sys.stdin)["applinks"]["details"][0]["appIDs"][0])' 2> /dev/null || true)"
    [[ -n "$aasa" ]] && ok "файл ссылок для iPhone отдаётся ($aasa)" ||
        echo "  ⚠ $SITE_URL/.well-known/apple-app-site-association не отдаётся как JSON — ссылки на iPhone не откроют приложение"
    want="$(sha256sum < "$out/site/index.html" | cut -d' ' -f1)"
    have="$(curl -fsS "$SITE_URL/" | sha256sum | cut -d' ' -f1)"
    rm -rf "$out"
    [[ "$want" == "$have" ]] && ok "сайт обновлён и отдаётся снаружи" ||
        die "сайт установлен, но снаружи отдаётся другая страница (кэш?) — откройте $SITE_URL"
fi

# --- Монитор, суммы, перезагрузки ---------------------------------------------

if (( do_monitor )); then
    # Суммы программ, которые собирались на этом ПК: из сборки шага 6
    # ($OFF/build-sha256.txt) и из текущей папки сборки ($REPO).
    sums="$(mktemp)"
    {
        [[ -n "${OFF:-}" && -f "$OFF/build-sha256.txt" ]] && cat "$OFF/build-sha256.txt"
        [[ -n "${REPO:-}" ]] && sha256sum "$REPO"/server/target/release/gasapp-server-{api,admin} 2> /dev/null
        sha256sum "$ROOT"/server/target/release/gasapp-server-{api,admin} 2> /dev/null
    } | awk '{print $1, $2}' > "$sums" || true
    [[ -s "$sums" ]] || echo "  ⚠ сумм своих сборок не нашёл (подключите флешку V:) — программы будут помечены как неизвестные"

    for h in "${HOSTS[@]}"; do
        say "$h"
        rsync -a "$DEPLOY/notify-telegram.sh" "$DEPLOY/check-nodes.sh" "$DEPLOY/update-remote.sh" "$h:deploy/"
        rsync -a "$DEPLOY/monitor/gasapp-monitor.sh" "$h:deploy/monitor/"
        rsync -a "$DEPLOY/mail/send-code.sh" "$h:deploy/mail/"
        rsync -a "$sums" "$h:deploy/expected-sums.txt"
        echo "  Пароль ops на $h (sudo):"
        ssh -t "$h" 'sudo bash ~/deploy/update-remote.sh '"$h"' ~/deploy' || echo "  ⚠ на $h что-то не так — см. выше"
    done
    rm -f "$sums"
fi

cat << 'EOF'

────────────────────────────────────────────────────────────────────
 ✅ ГОТОВО
 В Telegram придут «✅ Решено: …» по закрытым проблемам. Завтра в
 10:00 — «Монитор работает: проблем нет ✅» с каждой машины.
 Сохранять ничего не нужно: пароли и ключи не менялись.
────────────────────────────────────────────────────────────────────
EOF
