#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Собирает комплект развёртывания под ваши адреса и домены.
#
#     ./prepare-bundle.sh bundle.conf        # → server/deploy-bundle/
#     ./prepare-bundle.sh bundle.conf /путь  # → в указанный каталог
#
# Зачем: адреса WireGuard машин и домены вписаны в десяток файлов
# (nginx, Postgres, systemd, монитор). Правка вручную — самый частый
# источник ошибок: пропущенный адрес выглядит как «всё настроено», а
# узел не пускают в базу или балансировщик ходит не туда. Здесь адреса
# задаются один раз и проверяются.
#
# Что получается в каталоге:
#
#   deploy/             копия server/deploy с подставленными значениями —
#                       именно её копируют на машины (scp -r)
#   machines/           несекретная настройка по машинам: nodeN-server.env
#                       (server.env узла N), mail, cert.env, monitor-*.env
#   КОМАНДЫ.txt         команды выпуска сертификатов и укрепления машин
#                       с вашими адресами — чтобы не набирать их руками
#
# Секретов скрипт не трогает и не создаёт.
set -euo pipefail

conf="${1:?файл настроек: ./prepare-bundle.sh bundle.conf}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${2:-$(dirname "$here")/deploy-bundle}"

die() { echo "ОШИБКА: $*" >&2; exit 1; }

[[ -r "$conf" ]] || die "нет файла ${conf}"

# Файл читается построчно, а не исполняется: строка в нём не должна
# уметь запустить команду.
declare -A cfg=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<< "$line")"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]] || die "непонятная строка: ${line}"
    value="${BASH_REMATCH[2]}"
    value="${value#\"}"; value="${value%\"}"
    cfg["${BASH_REMATCH[1]}"]="$value"
done < "$conf"

need() { [[ -n "${cfg[$1]:-}" ]] || die "в ${conf} не задано $1"; printf '%s' "${cfg[$1]}"; }

domain="$(need DOMAIN)"
site="$(need SITE_DOMAIN)"
acme="$(need ACME_EMAIL)"
mail_from="$(need MAIL_FROM)"
net="$(need NET)"
lb="$(need LB)"
read -r -a nodes <<< "$(need NODES)"
db="$(need DB)"
pin_expiration="$(need PIN_EXPIRATION)"

# --- Проверки -----------------------------------------------------------------

is_ip() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local part
    for part in "${BASH_REMATCH[@]:1}"; do (( part <= 255 )) || return 1; done
}
is_domain() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; }

is_domain "$domain" || die "DOMAIN «${domain}» — не домен (строчные латинские буквы, цифры, точки)"
is_domain "$site"   || die "SITE_DOMAIN «${site}» — не домен"
[[ "$domain" != "$site" ]] || die "DOMAIN и SITE_DOMAIN должны различаться: у сервера сообщений свой ключ, который пинит приложение"
[[ "$acme" == *@*.* && "$mail_from" == *@*.* ]] || die "ACME_EMAIL и MAIL_FROM — адреса почты"
[[ "$net" =~ ^([0-9.]+)/([0-9]{1,2})$ ]] && is_ip "${BASH_REMATCH[1]}" || die "NET «${net}» — нужно вида 10.0.0.0/24"
is_ip "$lb" || die "LB «${lb}» — не адрес"
is_ip "$db" || die "DB «${db}» — не адрес"
(( ${#nodes[@]} >= 1 )) || die "NODES пуст"
for ip in "${nodes[@]}"; do is_ip "$ip" || die "в NODES «${ip}» — не адрес"; done
[[ "${nodes[0]}" == "$lb" ]] || die "первый адрес в NODES должен совпадать с LB: узел 1 живёт на балансировщике"
for ip in "${nodes[@]}"; do [[ "$ip" != "$db" ]] || die "адрес базы ${db} не может быть адресом узла"; done
[[ "$(printf '%s\n' "${nodes[@]}" | sort | uniq -d)" == "" ]] || die "в NODES повторяются адреса"
[[ "$pin_expiration" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "PIN_EXPIRATION — дата вида 2027-12-01"

# Адрес в сети NET? Сравнение по маске — без внешних программ.
to_int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
net_ip="${net%/*}" net_bits="${net#*/}"
(( net_bits >= 8 && net_bits <= 30 )) || die "маска сети /${net_bits} — ожидается от /8 до /30"
mask=$(( (0xFFFFFFFF << (32 - net_bits)) & 0xFFFFFFFF ))
in_net() { (( ($(to_int "$1") & mask) == ($(to_int "$net_ip") & mask) )); }
for ip in "$lb" "$db" "${nodes[@]}"; do in_net "$ip" || die "адрес ${ip} не из сети ${net}"; done

# --- Копия и подстановка -------------------------------------------------------

[[ ! -e "$out" ]] || die "каталог ${out} уже есть — удалите его (rm -rf) и запустите снова"
case "$(realpath -m "$out")/" in
    "$(realpath "$here")"/*) die "каталог результата не может лежать внутри ${here}" ;;
esac
mkdir -p "$out/machines" "$out/deploy"
# Копия без настроек и без отладочного ключа TLS (tls/ — только для стенда).
tar -C "$here" -cf - --exclude=./bundle.conf --exclude=./tls . | tar -C "$out/deploy" -xf -
d="$out/deploy"

# nginx: домен, вход onion, список узлов.
upstream=""
for ip in "${nodes[@]}"; do
    upstream+="    server ${ip}:8443 max_fails=2 fail_timeout=10s;"$'\n'
done
python3 - "$d/nginx/gasapp.conf" "$domain" "$lb" "$upstream" <<'PY'
import re, sys
path, domain, lb, upstream = sys.argv[1:]
text = open(path, encoding="utf-8").read()
# Внутри блока upstream сначала идут комментарии, потом строки узлов.
text, replaced = re.subn(r"(upstream gasapp_nodes \{\n(?:    #[^\n]*\n)*)(?:    server [^\n]*\n)+",
                         lambda m: m.group(1) + upstream, text, count=1)
assert replaced == 1, "блок upstream gasapp_nodes не найден"
assert text.count("listen 10.0.0.1:8444 ssl http2;") == 1, "вход onion не найден"
text = text.replace("listen 10.0.0.1:8444 ssl http2;", f"listen {lb}:8444 ssl http2;")
text = text.replace("gasapp.example.com", domain)
open(path, "w", encoding="utf-8", newline="\n").write(text)
PY
sed -i "s/gasapp\.chat/${site}/g" "$d/nginx/site.conf"

# Postgres: свой адрес базы, доступ узлам.
sed -i "s/^listen_addresses = .*/listen_addresses = 'localhost,${db}'/" "$d/postgres/90-gasapp.conf"
hba=""
for ip in "${nodes[@]}"; do
    hba+="hostssl   gasapp     gasapp     ${ip}/32    scram-sha-256  clientcert=verify-full"$'\n'
done
python3 - "$d/postgres/pg_hba.conf" "$hba" <<'PY'
import re, sys
path, hba = sys.argv[1:]
text = open(path, encoding="utf-8").read()
text = re.sub(r"(?:hostssl   gasapp[^\n]*\n)+", hba, text, count=1)
open(path, "w", encoding="utf-8", newline="\n").write(text)
PY

# systemd: узлу — только своя частная сеть.
sed -i "s|^IPAddressAllow=localhost 10\.0\.0\.0/24|IPAddressAllow=localhost ${net}|" "$d/systemd/gasapp-server.service"

# --- Настройка по машинам --------------------------------------------------------

count="${#nodes[@]}"
n=0
for ip in "${nodes[@]}"; do
    n=$((n + 1))
    cat > "$out/machines/node${n}-server.env" <<EOF
# /etc/gasapp/server.env на узле ${n} (${ip}).
# 🔐 Внутренний адрес ЭТОГО узла, не 0.0.0.0.
GASAPP_BIND=${ip}:8443
GASAPP_TLS_CERT=/etc/gasapp/tls/node.pem
# Лимиты частоты делятся на число узлов.
GASAPP_CLUSTER_NODES=${count}
EOF
done

cat > "$out/machines/mail" <<EOF
SMTP_URL=smtp://${lb}:25
SMTP_CACERT=/etc/gasapp/pki/ca.pem
MAIL_FROM=${mail_from}
MAIL_FROM_NAME=GasApp
EOF

printf 'GASAPP_DOMAIN=%s\nGASAPP_ACME_EMAIL=%s\n' "$domain" "$acme" > "$out/machines/cert.env"

monitor() {
    local file="$1" roles="$2" units="$3" ports="$4" certs="$5" extra="$6"
    cat > "$out/machines/${file}" <<EOF
# /etc/gasapp/monitor.env — см. deploy/monitor/monitor.env.example
GASAPP_ROLES="${roles}"
GASAPP_UNITS="${units}"
GASAPP_ALLOWED_PORTS="${ports}"
GASAPP_DISK_MAX=85
GASAPP_WATCH_CERTS="${certs}"
GASAPP_CHECKSUMS=/etc/gasapp/checksums.sha256
GASAPP_HEARTBEAT_HOUR=09
${extra}
EOF
}
monitor monitor-vps1.env "lb" "nginx gasapp-server tor@default postfix" \
    "22 25 80 443 8443 8444 51820/udp 68/udp" "/etc/gasapp/tls/node.pem" \
"GASAPP_DOMAIN=${domain}
GASAPP_PINS_FILE=/etc/gasapp/pins.txt
GASAPP_PIN_EXPIRATION=${pin_expiration}
GASAPP_NODES=\"${nodes[*]}\"
GASAPP_HEALTH_PORT=8443
GASAPP_INTERNAL_CA=/etc/gasapp/pki/ca.pem"
monitor monitor-node.env "node" "gasapp-server" "22 8443 51820/udp 68/udp" "/etc/gasapp/tls/node.pem" ""
monitor monitor-db.env "db" "postgresql gasapp-admin" "22 5432 51820/udp 68/udp" "/etc/postgresql/gasapp-tls/db.pem" \
"GASAPP_PROBE_PUBLIC=${domain}:443
GASAPP_PINS_FILE=/etc/gasapp/pins.txt"

# --- Команды ------------------------------------------------------------------------

{
    echo "КОМАНДЫ С ВАШИМИ АДРЕСАМИ (собраны prepare-bundle.sh $(date -u +%Y-%m-%d))"
    echo
    echo "== Сертификаты внутреннего центра — на СВОЁМ компьютере (WSL), каталог с ключом центра:"
    echo "server/deploy/pki/internal-ca.sh server db gasapp-db ${db}"
    n=0
    for ip in "${nodes[@]}"; do
        n=$((n + 1))
        echo "server/deploy/pki/internal-ca.sh server node${n} gasapp-node ${ip}"
    done
    echo "server/deploy/pki/internal-ca.sh client gasapp"
    echo
    echo "== Укрепление — на каждой машине, после входа под своим пользователем:"
    # Релей — только узлам WireGuard, а не всей подсети.
    echo "VPS-1 (${lb}):  sudo ~/deploy/hardening/harden-host.sh --role lb,node --admin ВАШ_ПОЛЬЗОВАТЕЛЬ --lb ${lb} --relay-from \"${nodes[*]}\""
    n=1
    for ip in "${nodes[@]:1}"; do
        n=$((n + 1))
        echo "VPS-${n} (${ip}):  sudo ~/deploy/hardening/harden-host.sh --role node --admin ВАШ_ПОЛЬЗОВАТЕЛЬ --lb ${lb} --auto-reboot"
    done
    echo "VPS-БАЗА (${db}):  sudo ~/deploy/hardening/harden-host.sh --role db --admin ВАШ_ПОЛЬЗОВАТЕЛЬ --nodes \"${nodes[*]}\""
    echo
    echo "== Строка подключения к базе (пароль подставит команда из инструкции):"
    echo "postgres://gasapp:ПАРОЛЬ@${db}:5432/gasapp?sslmode=verify-full&sslrootcert=/etc/gasapp/pki/ca.pem&sslcert=/etc/gasapp/pki/client-gasapp.pem&sslkey=/run/credentials/gasapp-server.service/db_client_key"
    echo
    echo "== Почтовый релей (Postfix) на VPS-1:"
    echo "inet_interfaces = ${lb}, 127.0.0.1"
    echo "mynetworks = 127.0.0.0/8 $(printf '%s/32 ' "${nodes[@]}" | sed 's/ $//')"
    echo
    echo "== Onion-сервис на VPS-1 (/etc/tor/torrc):"
    echo "HiddenServicePort 443 ${lb}:8444"
    echo
    echo "== Проверка здоровья узлов с VPS-1:"
    for ip in "${nodes[@]}"; do
        echo "curl -s --cacert /etc/gasapp/pki/ca.pem --resolve gasapp-node:8443:${ip} https://gasapp-node:8443/health"
    done
} > "$out/КОМАНДЫ.txt"

# --- Последняя проверка: не осталось ли примерных значений --------------------------

leftover="$(grep -rIl "gasapp\.example\.com" "$d/nginx" "$d/postgres" "$d/systemd/gasapp-server.service" 2>/dev/null || true)"
[[ -z "$leftover" ]] || die "в файлах остался примерный домен: ${leftover}"
grep -q "listen ${lb}:8444" "$d/nginx/gasapp.conf" || die "не подставился вход onion"
[[ "$(grep -cE '^    server [0-9.]+:8443' "$d/nginx/gasapp.conf")" == "$count" ]] || die "не подставились узлы"
[[ "$(grep -c '^hostssl' "$d/postgres/pg_hba.conf")" == "$count" ]] || die "не подставился доступ узлов к базе"

echo "готово: ${out}"
echo "  deploy/        — копировать на машины"
echo "  machines/      — настройка по машинам"
echo "  КОМАНДЫ.txt    — команды с вашими адресами"
echo "узлов: ${count}; балансировщик ${lb}; база ${db}; домен ${domain}; сайт ${site}"
