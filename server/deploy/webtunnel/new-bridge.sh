#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Поднимает свой мост WebTunnel и печатает строку для сборки GasApp.
#
#   ./new-bridge.sh bridge1.example.com admin@example.com [имя]
#
# Домен должен уже указывать на эту машину (A/AAAA), порты 80 и 443 —
# открыты: Caddy получит сертификат Let's Encrypt сам.
set -euo pipefail

DOMAIN="${1:?домен моста}"
EMAIL="${2:?почта для Let's Encrypt и контакта моста}"
NICKNAME="${3:-GasAppBridge$(date +%s | tail -c 5)}"

cd "$(dirname "$0")"

# Секретный путь: без него по адресу сайта туннель не найти.
if [[ ! -f .env ]]; then
  WT_PATH="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
  cat > .env <<EOF
DOMAIN=$DOMAIN
EMAIL=$EMAIL
NICKNAME=$NICKNAME
WT_PATH=$WT_PATH
EOF
  chmod 600 .env
fi

docker compose up -d

echo "Жду, пока мост создаст ключи…"
for _ in $(seq 1 60); do
  if line="$(docker compose exec -T webtunnel get-bridge-line.sh 2>/dev/null | grep '^webtunnel ')"; then
    echo
    echo "Строка моста — в android/tor/bridges.txt (или в свой файл для -PgasappBridgesFile):"
    echo
    echo "$line"
    exit 0
  fi
  sleep 5
done

echo "Мост не ответил за 5 минут: docker compose logs webtunnel" >&2
exit 1
