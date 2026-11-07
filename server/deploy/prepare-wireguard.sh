#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Generate a four-VPS WireGuard mesh locally. Never run this on a VPS.
set -euo pipefail

if (( $# != 5 )); then
    echo "usage: $0 LB_PUBLIC_IP NODE2_PUBLIC_IP NODE3_PUBLIC_IP DB_PUBLIC_IP OUTPUT_DIR" >&2
    exit 2
fi

command -v wg >/dev/null || { echo "install wireguard-tools first" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

python3 - "$1" "$2" "$3" "$4" <<'PY'
import ipaddress
import sys

try:
    addresses = [ipaddress.IPv4Address(value) for value in sys.argv[1:]]
except ipaddress.AddressValueError as error:
    raise SystemExit(f"invalid public IPv4: {error}")
if len(set(addresses)) != 4 or not all(address.is_global for address in addresses):
    raise SystemExit("use four distinct, globally routable IPv4 addresses")
PY

out="$5"
[[ ! -e "$out" ]] || { echo "output already exists: $out (keys must not be overwritten)" >&2; exit 1; }
umask 077
mkdir -m 700 -p "$out"

names=(lb node2 node3 db)
public=("$1" "$2" "$3" "$4")
private=(10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5)
declare -a secret_key public_key

for i in 0 1 2 3; do
    secret_key[$i]="$(wg genkey)"
    public_key[$i]="$(printf '%s' "${secret_key[$i]}" | wg pubkey)"
done

for i in 0 1 2 3; do
    file="$out/${names[$i]}.conf"
    {
        echo '[Interface]'
        echo "Address = ${private[$i]}/24"
        echo 'ListenPort = 51820'
        echo "PrivateKey = ${secret_key[$i]}"
        for j in 0 1 2 3; do
            (( i == j )) && continue
            echo
            echo "# ${names[$j]}"
            echo '[Peer]'
            echo "PublicKey = ${public_key[$j]}"
            echo "AllowedIPs = ${private[$j]}/32"
            echo "Endpoint = ${public[$j]}:51820"
            echo 'PersistentKeepalive = 25'
        done
    } > "$file"
    chmod 600 "$file"
done

echo "created four private WireGuard configs in $out"
echo 'Copy each file only to its matching VPS as /etc/wireguard/wg0.conf.'
