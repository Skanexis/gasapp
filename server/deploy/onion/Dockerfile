# SPDX-License-Identifier: AGPL-3.0-only
#
# Onion-сервис сервера AEGIS: C tor из пакетов Debian, только
# HiddenService, без SOCKS и без ретрансляции.
#
# 🔐 Ключ onion-адреса лежит в томе /var/lib/tor/aegis: кто держит
# ключ, тот и есть этот адрес. Том копируется в резервную копию
# вместе с ключами TLS, а не раздаётся.

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends tor ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/aegis-onion
RUN chmod 0755 /usr/local/bin/aegis-onion

VOLUME ["/var/lib/tor/aegis"]

ENTRYPOINT ["/usr/local/bin/aegis-onion"]
