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

# Проверки — до того, как что-то менять на сервере.
sudo test -s /etc/gasapp/credentials/admin_database_url ||
    { bad "нет /etc/gasapp/credentials/admin_database_url — сделайте шаг 20.1 инструкции"; exit 1; }

# Атомарная замена: служба никогда не видит недописанный файл.
sudo install -m 755 gasapp-server-admin /usr/local/bin/gasapp-server-admin.new
sudo mv /usr/local/bin/gasapp-server-admin.new /usr/local/bin/gasapp-server-admin
sudo install -m 644 gasapp-admin.service gasapp-migrate.service gasapp-reports.service gasapp-reports.timer /etc/systemd/system/
ok "программа и службы на месте"

# 🔐 Миграции — под владельцем схемы, отдельной службой (аудит
# 2026-11-28, S-10). До раздельных ролей строку владельца держал
# admin_database_url — она же и становится owner_database_url.
owner_file=/etc/gasapp/credentials/owner_database_url
if ! sudo test -s "$owner_file"; then
    sudo grep -q '^postgres://gasapp:' /etc/gasapp/credentials/admin_database_url ||
        { bad "нет $owner_file, а admin_database_url — не владельца: положите строку владельца в $owner_file"; exit 1; }
    sudo install -m 600 /etc/gasapp/credentials/admin_database_url "$owner_file"
    ok "строка владельца схемы: owner_database_url"
fi


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

# 🔐 Ключ улик к жалобам: телефоны шифруют им сообщения и скриншоты,
# которые жалобщик решил показать. Создаётся один раз и только здесь;
# в базу уходит лишь открытый ключ. Потеря ключа — потеря улик за
# последние 30 дней, не больше: копии в Bitwarden не нужно.
evidence_file=/etc/gasapp/credentials/evidence_key
if ! sudo test -s "$evidence_file"; then
    openssl rand -hex 32 | sudo install -m 600 /dev/stdin "$evidence_file"
    ok "ключ улик к жалобам создан"
else
    ok "ключ улик к жалобам на месте"
fi

sudo systemctl daemon-reload
sudo systemctl start gasapp-migrate ||
    { bad "миграции не прошли: sudo journalctl -u gasapp-migrate -n 30"; exit 1; }
ok "миграции применены (gasapp-migrate)"
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
