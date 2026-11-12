#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Часть admin.sh --install, которая выполняется НА БАЗЕ. Вручную не
# запускается: admin.sh кладёт её в ~/admin-kit/ вместе с программой,
# суммой и юнитами и вызывает «ssh -t gasapp-db bash ~/admin-kit/install.sh».
set -euo pipefail
ok()  { printf '    \033[32m✔\033[0m %s\n' "$*"; }
bad() { printf '    \033[1;31m✘ %s\033[0m\n' "$*"; }
kit=~/admin-kit
sudo -v
cd "$kit"
sha256sum --check --quiet expected-sum || { bad "сумма программы не совпала с вашей сборкой — не ставлю"; exit 1; }

# Атомарная замена: служба никогда не видит недописанный файл.
sudo install -m 755 gasapp-server-admin /usr/local/bin/gasapp-server-admin.new
sudo mv /usr/local/bin/gasapp-server-admin.new /usr/local/bin/gasapp-server-admin
sudo install -m 644 gasapp-admin.service gasapp-reports.service gasapp-reports.timer /etc/systemd/system/
ok "программа и службы на месте"

[[ -s /etc/gasapp/credentials/admin_database_url ]] ||
    { bad "нет /etc/gasapp/credentials/admin_database_url — сделайте шаг 20.1 инструкции"; exit 1; }

token_file=/etc/gasapp/credentials/admin_token_sha256
change=n
if sudo test -s "$token_file"; then
    read -r -p "    Токен уже задан. Сменить его? [y/N] " change < /dev/tty
fi
if ! sudo test -s "$token_file" || [[ "$change" == [yYдД]* ]]; then
    echo "    Токен из Bitwarden «GasApp: токен админ-центра» (не виден при вводе)."
    echo "    Нет записи — в другом окне: openssl rand -base64 32, сохраните её в Bitwarden и вставьте сюда."
    read -rs -p "    Токен: " TOKEN < /dev/tty; echo
    [[ ${#TOKEN} -ge 32 ]] || { unset TOKEN; bad "токен короче 32 знаков — слишком слабый"; exit 1; }
    printf '%s' "$TOKEN" | /usr/local/bin/gasapp-server-admin hash-token \
        | sudo install -m 600 /dev/stdin "$token_file"
    unset TOKEN
    ok "токен записан (на сервере — только его хеш)"
fi

sudo systemctl daemon-reload
sudo systemctl enable --quiet gasapp-admin
sudo systemctl restart gasapp-admin
sleep 2
systemctl is-active --quiet gasapp-admin || { bad "служба не запустилась: sudo journalctl -u gasapp-admin -n 30"; exit 1; }

# 🔐 Только петля. Любой другой адрес — служба останавливается.
listen="$(sudo ss -Hlntp 'sport = :8480' | awk '{print $4}')"
if [[ -z "$listen" ]] || grep -qvE '^(127\.0\.0\.1|\[::1\]):8480$' <<< "$listen"; then
    sudo systemctl stop gasapp-admin
    bad "админ-центр слушает не только петлю (${listen:-ничего}) — остановлен"
    exit 1
fi
ok "админ-центр работает и слушает только $listen"

if sudo test -s /etc/gasapp/credentials/telegram; then
    sudo systemctl enable --now --quiet gasapp-reports.timer
    ok "уведомления о жалобах: раз в 10 минут, в Telegram — только число"
else
    printf '    \033[33m⚠\033[0m Telegram на БАЗЕ не настроен (шаг 21) — уведомления о жалобах выключены\n'
fi
rm -rf "$kit"
