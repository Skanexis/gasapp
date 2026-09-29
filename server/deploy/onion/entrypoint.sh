#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Собирает torrc из окружения и запускает tor.
#
#   AEGIS_UPSTREAM    — куда вести onion-порт: `узел:порт` сервера AEGIS
#                       (TLS остаётся сквозным — onion его не заменяет).
#   AEGIS_ONION_PORT  — порт onion-адреса, по умолчанию 443.
#   AEGIS_TOR_BRIDGES — там, где сеть Tor блокируют:
#                       «snowflake» — официальные мосты snowflake из
#                       образа (добывать ничего не нужно);
#                       либо строки мостов через «\n», либо файл
#                       /etc/aegis/bridges.txt (том). Поддерживаются
#                       obfs4, meek_lite, webtunnel (lyrebird) и snowflake.
set -eu

: "${AEGIS_UPSTREAM:?задайте AEGIS_UPSTREAM=узел:порт сервера AEGIS}"
ONION_PORT="${AEGIS_ONION_PORT:-443}"

mkdir -p /var/lib/tor/aegis
chown -R debian-tor:debian-tor /var/lib/tor
chmod 0700 /var/lib/tor/aegis

if [ "${AEGIS_TOR_BRIDGES:-}" = snowflake ]; then
  BRIDGES="$(cat /usr/share/aegis/snowflake-bridges.txt)"
else
  BRIDGES="$(printf '%b' "${AEGIS_TOR_BRIDGES:-}")"
fi
if [ -z "$BRIDGES" ] && [ -s /etc/aegis/bridges.txt ]; then
  BRIDGES="$(cat /etc/aegis/bridges.txt)"
fi

{
  echo "# Только onion-сервис: без SOCKS для клиентов и без ретрансляции."
  echo "SocksPort 0"
  echo "DataDirectory /var/lib/tor"
  echo "Log notice stdout"
  echo
  echo "HiddenServiceDir /var/lib/tor/aegis"
  echo "HiddenServiceVersion 3"
  echo "HiddenServicePort ${ONION_PORT} ${AEGIS_UPSTREAM}"

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
# приложения (aegisServerOnion).
( while [ ! -s /var/lib/tor/aegis/hostname ]; do sleep 1; done
  echo "AEGIS onion: $(cat /var/lib/tor/aegis/hostname):${ONION_PORT}" ) &

exec su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc"
