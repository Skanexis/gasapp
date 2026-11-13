#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Часть beszel.sh, которая выполняется НА СЕРВЕРЕ под sudo. Вручную не
# запускается:
#
#     sudo bash ~/beszel-kit/beszel-remote.sh hub
#     sudo bash ~/beszel-kit/beszel-remote.sh agent "<ключ центра>" <адрес центра>
#
# 🔐 Как устроено (server/deploy/beszel.sh, «Почему так»):
#   * центр (hub) — на БАЗЕ, слушает только 127.0.0.1:8090; сам ходит к
#     агентам по SSH-ключу; в сеть ему можно только в WireGuard;
#   * агент — на каждой машине, слушает только свой адрес WireGuard и
#     принимает лишь центр с этим ключом; брандмауэр пускает к нему
#     только базу; в сеть агенту можно только к центру.

set -euo pipefail

mode="${1:?hub или agent}"
kit="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ok()  { printf '    \033[32m✔\033[0m %s\n' "$*"; }
bad() { printf '    \033[1;31m✘ %s\033[0m\n' "$*"; }

id beszel > /dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin beszel

wg_ip="$(ip -4 -o addr show wg0 2> /dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
[[ -n "$wg_ip" ]] || { bad "нет WireGuard (wg0) — монитору не по чему ходить"; exit 1; }

# Общая песочница: без прав, без записи в систему, без чужих устройств.
sandbox='NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
CapabilityBoundingSet=
UMask=0077
Restart=on-failure
RestartSec=5'

case "$mode" in
hub)
    install -m 755 "$kit/beszel" /usr/local/bin/beszel
    cat > /etc/systemd/system/beszel-hub.service << EOF
[Unit]
Description=Beszel hub — GasApp server monitor (loopback only)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target wg-quick@wg0.service

[Service]
User=beszel
Group=beszel
StateDirectory=beszel
WorkingDirectory=/var/lib/beszel
ExecStart=/usr/local/bin/beszel serve --http 127.0.0.1:8090
Environment=CHECK_UPDATES=false
Environment=APP_URL=http://127.0.0.1:8090
# В сеть — только сама машина и WireGuard: центр ходит к агентам и
# никуда больше (обновления и чужие сайты ему не нужны).
IPAddressDeny=any
IPAddressAllow=localhost 10.0.0.0/24
$sandbox

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now --quiet beszel-hub
    for _ in $(seq 1 30); do
        [[ -s /var/lib/beszel/beszel_data/id_ed25519 ]] && break
        sleep 1
    done
    [[ -s /var/lib/beszel/beszel_data/id_ed25519 ]] || { bad "центр не создал свой ключ — journalctl -u beszel-hub -n 30"; exit 1; }
    listen="$(ss -Hlntp 'sport = :8090' | awk '{print $4}')"
    if grep -qvE '^(127\.0\.0\.1|\[::1\]):8090$' <<< "$listen"; then
        systemctl stop beszel-hub
        bad "центр слушает не только петлю (${listen}) — остановлен"
        exit 1
    fi
    ok "центр Beszel работает и слушает только ${listen}"
    printf 'HUB_KEY=%s\n' "$(ssh-keygen -y -f /var/lib/beszel/beszel_data/id_ed25519)"
    printf 'HUB_IP=%s\n' "$wg_ip"
    ;;
agent)
    key="${2:?ключ центра}"
    hub_ip="${3:?адрес центра}"
    [[ "$key" == ssh-ed25519\ * ]] || { bad "ключ центра не похож на ssh-ed25519"; exit 1; }
    install -m 755 "$kit/beszel-agent" /usr/local/bin/beszel-agent

    # На самой базе центр рядом — агенту хватает петли.
    if [[ "$wg_ip" == "$hub_ip" ]]; then
        listen_on="127.0.0.1:45876"
    else
        listen_on="${wg_ip}:45876"
    fi
    cat > /etc/systemd/system/beszel-agent.service << EOF
[Unit]
Description=Beszel agent — GasApp server monitor
After=network-online.target wg-quick@wg0.service
Wants=network-online.target wg-quick@wg0.service

[Service]
User=beszel
Group=beszel
StateDirectory=beszel-agent
Environment="KEY=${key}"
Environment=LISTEN=${listen_on}
ExecStart=/usr/local/bin/beszel-agent
# В сеть — только центр.
IPAddressDeny=any
IPAddressAllow=localhost ${hub_ip}
$sandbox

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --quiet beszel-agent
    systemctl restart beszel-agent
    sleep 2
    systemctl is-active --quiet beszel-agent || { bad "агент не запустился — journalctl -u beszel-agent -n 30"; exit 1; }

    if [[ "$listen_on" != 127.* ]]; then
        # 🔐 К агенту — только база, только по WireGuard.
        ufw allow from "$hub_ip" to "$wg_ip" port 45876 proto tcp comment 'beszel agent' > /dev/null
        env_file=/etc/gasapp/monitor.env
        if [[ -f "$env_file" ]] && ! grep -q '^GASAPP_ALLOWED_PORTS=.*45876/tcp' "$env_file"; then
            sed -i '/^GASAPP_ALLOWED_PORTS=/ s/"$/ 45876\/tcp"/' "$env_file"
        fi
        ok "агент слушает ${listen_on}; пускает только центр ${hub_ip}"
    else
        ok "агент слушает ${listen_on} (центр на этой же машине)"
    fi
    ;;
*)
    bad "неизвестный режим: $mode"
    exit 1
    ;;
esac
rm -rf "$kit"
