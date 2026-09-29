# SPDX-License-Identifier: AGPL-3.0-only
#
# Onion-сервис сервера AEGIS: C tor только с HiddenService, без SOCKS
# и без ретрансляции. Умеет подключаться к сети Tor через мосты — там,
# где Tor блокируют (см. AEGIS_TOR_BRIDGES в entrypoint.sh).
#
# 🔐 Ключ onion-адреса лежит в томе /var/lib/tor/aegis: кто держит
# ключ, тот и есть этот адрес. Том копируется в резервную копию
# вместе с ключами TLS, а не раздаётся.
#
# Подключаемые транспорты — только в этом серверном образе, не в
# приложении: lyrebird (obfs4, meek, webtunnel) и snowflake собираются
# из исходников Tor Project через proxy.golang.org — сам torproject.org
# там, где его блокируют, недоступен. Официальные строки мостов
# snowflake берутся оттуда же (client/torrc), а не пишутся от руки.

FROM golang:1.25 AS transports
ENV GOPROXY=https://proxy.golang.org GOFLAGS=-mod=mod CGO_ENABLED=0
COPY fetch-module.sh /usr/local/bin/fetch-module
RUN set -e; \
    fetch-module gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird /lyrebird; \
    fetch-module gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 /snowflake; \
    mkdir -p /out; \
    cd /lyrebird && go build -trimpath -ldflags="-s -w" -o /out/lyrebird ./cmd/lyrebird; \
    cd /snowflake/client && go build -trimpath -ldflags="-s -w" -o /out/snowflake-client .; \
    sed -n 's/^Bridge //p' /snowflake/client/torrc > /out/snowflake-bridges.txt; \
    test -s /out/snowflake-bridges.txt

FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends tor ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=transports /out/lyrebird /out/snowflake-client /usr/local/bin/
COPY --from=transports /out/snowflake-bridges.txt /usr/share/aegis/snowflake-bridges.txt
COPY entrypoint.sh /usr/local/bin/aegis-onion
RUN chmod 0755 /usr/local/bin/aegis-onion

VOLUME ["/var/lib/tor/aegis"]

ENTRYPOINT ["/usr/local/bin/aegis-onion"]
