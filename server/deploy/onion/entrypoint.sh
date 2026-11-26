#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Собирает torrc из окружения и запускает tor.
#
#   GASAPP_UPSTREAM    — куда вести onion-порт: onion-вход балансировщика
#                       (`адрес:8444`, РАЗВЁРТЫВАНИЕ.md), не узел API напрямую
#                       (TLS остаётся сквозным — onion его не заменяет).
#   GASAPP_ONION_PORT  — порт onion-адреса, по умолчанию 443.
#
# Onion-сервис — быстрый (single onion service): со стороны сервера один
# узел Tor вместо трёх, путь клиент → сервер — четыре узла вместо шести,
# каждый запрос через Tor заметно быстрее. Скрывать, где стоит сервер,
# незачем: gasapp.eu и так публичен; клиент остаётся анонимным, как прежде.
# Прежний (анонимный, трёхузловой) режим убран (решение владельца,
# 2026-11-26). Ключи — в /var/lib/tor/gasapp-fast: tor не переводит
# каталог анонимного сервиса в этот режим, поэтому адрес новый — его
# вписывают в сборку (GASAPP_SERVER_ONION, gasappServerOnion).
# Мостов нет: быстрый сервис ходит к узлам Tor напрямую.
#
#   GASAPP_TOR_BRIDGES — больше не поддерживается (см. выше): заданные
#                       мосты — ошибка запуска, а не тихий откат.
#                       «snowflake» — официальные мосты snowflake из
#                       образа (добывать ничего не нужно);
#                       либо строки мостов через «\n», либо файл
#                       /etc/gasapp/bridges.txt (том). Поддерживаются
#                       obfs4, meek_lite, webtunnel (lyrebird) и snowflake.
set -eu

: "${GASAPP_UPSTREAM:?задайте GASAPP_UPSTREAM=узел:порт сервера GasApp}"
ONION_PORT="${GASAPP_ONION_PORT:-443}"

SERVICE_DIR=/var/lib/tor/gasapp-fast
mkdir -p "$SERVICE_DIR"
chown -R debian-tor:debian-tor /var/lib/tor
chmod 0700 "$SERVICE_DIR"

if [ "${GASAPP_TOR_BRIDGES:-}" = snowflake ]; then
  BRIDGES="$(cat /usr/share/gasapp/snowflake-bridges.txt)"
else
  BRIDGES="$(printf '%b' "${GASAPP_TOR_BRIDGES:-}")"
fi
if [ -z "$BRIDGES" ] && [ -s /etc/gasapp/bridges.txt ]; then
  BRIDGES="$(cat /etc/gasapp/bridges.txt)"
fi

if [ -n "$BRIDGES" ]; then
  echo "мосты не поддерживаются: быстрый onion-сервис ходит к узлам Tor напрямую" >&2
  exit 1
fi

{
  echo "# Только onion-сервис: без SOCKS для клиентов и без ретрансляции."
  echo "SocksPort 0"
  echo "DataDirectory /var/lib/tor"
  echo "Log notice stdout"
  echo
  echo "# Быстрый onion-сервис: местоположение сервера не скрывается"
  echo "# (оно публично), клиенты анонимны как прежде."
  echo "HiddenServiceSingleHopMode 1"
  echo "HiddenServiceNonAnonymousMode 1"
  echo "HiddenServiceDir $SERVICE_DIR"
  echo "HiddenServiceVersion 3"
  echo "HiddenServicePort ${ONION_PORT} ${GASAPP_UPSTREAM}"

} > /etc/tor/torrc

# Адрес печатается, как только tor его создаст: его вписывают в сборку
# приложения (gasappServerOnion).
( while [ ! -s "$SERVICE_DIR/hostname" ]; do sleep 1; done
  echo "GasApp onion: $(cat "$SERVICE_DIR/hostname"):${ONION_PORT}" ) &

exec su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc"
