#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Собирает torrc из окружения и запускает tor.
#
#   GASAPP_UPSTREAM    — куда вести onion-порт: onion-вход балансировщика
#                       (`адрес:8444`, РАЗВЁРТЫВАНИЕ.md), не узел API напрямую
#                       (TLS остаётся сквозным — onion его не заменяет).
#   GASAPP_ONION_PORT  — порт onion-адреса, по умолчанию 443.
#   GASAPP_TOR_BRIDGES — там, где сеть Tor блокируют:
#                       «snowflake» — официальные мосты snowflake из
#                       образа (добывать ничего не нужно);
#                       либо строки мостов через «\n», либо файл
#                       /etc/gasapp/bridges.txt (том). Поддерживаются
#                       obfs4, meek_lite, webtunnel (lyrebird) и snowflake.
set -eu

: "${GASAPP_UPSTREAM:?задайте GASAPP_UPSTREAM=узел:порт сервера GasApp}"
ONION_PORT="${GASAPP_ONION_PORT:-443}"

mkdir -p /var/lib/tor/gasapp
chown -R debian-tor:debian-tor /var/lib/tor
chmod 0700 /var/lib/tor/gasapp

if [ "${GASAPP_TOR_BRIDGES:-}" = snowflake ]; then
  BRIDGES="$(cat /usr/share/gasapp/snowflake-bridges.txt)"
else
  BRIDGES="$(printf '%b' "${GASAPP_TOR_BRIDGES:-}")"
fi
if [ -z "$BRIDGES" ] && [ -s /etc/gasapp/bridges.txt ]; then
  BRIDGES="$(cat /etc/gasapp/bridges.txt)"
fi

{
  echo "# Только onion-сервис: без SOCKS для клиентов и без ретрансляции."
  echo "SocksPort 0"
  echo "DataDirectory /var/lib/tor"
  echo "Log notice stdout"
  echo
  echo "HiddenServiceDir /var/lib/tor/gasapp"
  echo "HiddenServiceVersion 3"
  echo "HiddenServicePort ${ONION_PORT} ${GASAPP_UPSTREAM}"

  if [ -n "$BRIDGES" ]; then
    echo
    echo "# Сеть Tor здесь блокируют — через мосты."
    echo "UseBridges 1"
    echo "ClientTransportPlugin obfs4,meek_lite,webtunnel exec /usr/local/bin/lyrebird"
    echo "ClientTransportPlugin snowflake exec /usr/local/bin/snowflake-client"
    printf '%s\n' "$BRIDGES" | sed -e 's/^[Bb]ridge //' -e '/^[[:space:]]*$/d' -e '/^#/d' -e 's/^/Bridge /'
  fi
} > /etc/tor/torrc

# Адрес печатается, как только tor его создаст: его вписывают в сборку
# приложения (gasappServerOnion).
( while [ ! -s /var/lib/tor/gasapp/hostname ]; do sleep 1; done
  echo "GasApp onion: $(cat /var/lib/tor/gasapp/hostname):${ONION_PORT}" ) &

exec su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc"
