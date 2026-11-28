#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Узел API переходит на свою роль базы gasapp_api (аудит 2026-11-28,
# S-10) — на каждом узле, от root:
#
#     sudo bash ~/deploy/postgres/node-role.sh
#
# Спросит пароль узлов (Bitwarden «GasApp: пароль базы для узлов», он же
# /etc/gasapp/credentials/api_database_password на машине базы) — ввод
# не виден. Заменит в строке подключения имя и пароль, остальное (адрес,
# TLS, сертификат клиента) оставит, и перезапустит узел.
set -euo pipefail

ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m✘ %s\033[0m\n\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускайте от root: sudo bash $0"
file=/etc/gasapp/credentials/database_url
[[ -s "$file" ]] || die "нет $file — это не узел API?"

read -rs -p "Пароль базы для узлов: " password < /dev/tty; echo
[[ "$password" =~ ^[0-9a-f]{48}$ ]] || { unset password; die "не тот пароль: ждал 48 знаков hex"; }

install -m 600 "$file" "$file.before-roles"
sed -E "s#^postgres://[^:/@]+:[^@]*@#postgres://gasapp_api:${password}@#" "$file.before-roles" |
    install -m 600 /dev/stdin "$file"
unset password
ok "строка подключения: роль gasapp_api (прежняя — $file.before-roles)"

systemctl restart gasapp-server
sleep 3
if systemctl is-active --quiet gasapp-server; then
    rm -f "$file.before-roles"
    ok "узел работает под gasapp_api"
else
    install -m 600 "$file.before-roles" "$file"
    systemctl restart gasapp-server || true
    die "узел не поднялся под новой ролью — вернул прежнюю строку; journalctl -u gasapp-server -n 30"
fi
