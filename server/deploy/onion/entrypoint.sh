#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Собирает torrc из окружения и запускает tor.
#
#   AEGIS_UPSTREAM — куда вести onion-порт: `узел:порт` сервера AEGIS
#                    (TLS остаётся сквозным — onion его не заменяет).
#   AEGIS_ONION_PORT — порт onion-адреса, по умолчанию 443.
set -eu

: "${AEGIS_UPSTREAM:?задайте AEGIS_UPSTREAM=узел:порт сервера AEGIS}"
ONION_PORT="${AEGIS_ONION_PORT:-443}"

mkdir -p /var/lib/tor/aegis
chown -R debian-tor:debian-tor /var/lib/tor
chmod 0700 /var/lib/tor/aegis

cat > /etc/tor/torrc <<EOF
# Только onion-сервис: без SOCKS для клиентов и без ретрансляции.
SocksPort 0
DataDirectory /var/lib/tor
Log notice stdout

HiddenServiceDir /var/lib/tor/aegis
HiddenServiceVersion 3
HiddenServicePort ${ONION_PORT} ${AEGIS_UPSTREAM}
EOF

# Адрес печатается, как только tor его создаст: его вписывают в сборку
# приложения (aegisServerOnion).
( while [ ! -s /var/lib/tor/aegis/hostname ]; do sleep 1; done
  echo "AEGIS onion: $(cat /var/lib/tor/aegis/hostname):${ONION_PORT}" ) &

exec su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc"
