#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Монитор хоста GasApp. Запускается gasapp-monitor.timer раз в две минуты.
#
# Что проверять, решает роль машины — /etc/gasapp/monitor.env:
#
#     GASAPP_ROLES="lb"            # балансировщик
#     GASAPP_ROLES="node"          # узел API
#     GASAPP_ROLES="db admin"      # база + админ-центр
#
# Полный список переменных — в monitor.env.example рядом.
#
# # Что проверяется
#
# Везде: диск, упавшие службы, обязательные службы, NTP, перезагрузка
# после обновлений, свежесть автообновлений, неожиданные открытые порты,
# подмена исполняемых файлов, входы по SSH, сроки внутренних
# сертификатов.
#
# lb:    публичный сертификат — срок и пин (тот ли ключ отдаёт nginx
#        на самом деле), срок набора пинов в приложении, узлы
#        (check-nodes.sh).
# db:    база отвечает, резервная копия свежая.
# Любая: GASAPP_PROBE_PUBLIC — проверка публичного входа ИЗВНЕ
#        балансировщика (с машины базы): если умрёт сам балансировщик,
#        его монитор молчит, а этот — нет.
#
# # Как оповещает
#
# Только при СМЕНЕ состояния: «сломалось» и «починилось». Отказ,
# длящийся час, не даёт тридцати одинаковых сообщений — их перестают
# читать, и следующий настоящий отказ проходит незамеченным.
#
# Раз в сутки — «монитор жив» (GASAPP_HEARTBEAT_HOUR). Мёртвый монитор
# молчит так же, как монитор без проблем; без ежедневного сигнала их
# не отличить.
#
# # 🔐 Чего в оповещениях нет
#
# Числа пользователей, подключений, сообщений, нагрузки, адресов
# клиентов. Оповещения уходят через чужой канал и оседают у посредника;
# «узел 2 недоступен» безвредно, «на узле 2 было 400 подключений» —
# уже метаданные. Входы по SSH сообщаются именем пользователя, без
# адреса: адрес остаётся в журнале машины.

set -uo pipefail
export LC_ALL=C

readonly STATE="${GASAPP_MONITOR_STATE:-/var/lib/gasapp-monitor}"
readonly NOTIFY="${GASAPP_NOTIFY_CMD:-logger -t gasapp-monitor}"
readonly ROLES=" ${GASAPP_ROLES:-} "
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE

mkdir -p "$STATE"
umask 077

has_role() { [[ "$ROLES" == *" $1 "* ]]; }

send() { printf '%s\n' "$1" | $NOTIFY; }

# check <ключ> <проблема или пусто> — оповещение при смене состояния.
#
# Текст проблемы — часть состояния, поэтому в нём пороги, а не точные
# числа: «истекает через 19 дн.», «через 18 дн.» слали бы сообщение
# каждый день, а «меньше 21 дня» — один раз.
problems=0
open_issues=()
resolved_label() {
    case "$1" in
        disk:*) echo "Disk ${1#disk:}" ;;
        unit:*) echo "Service ${1#unit:}" ;;
        cert:*) echo "Certificate ${1#cert:}" ;;
        units-failed) echo "Failed services" ;;
        ntp) echo "Clock synchronization" ;;
        reboot) echo "Pending reboot" ;;
        unattended) echo "Automatic updates" ;;
        ports) echo "Unexpected ports" ;;
        binaries) echo "Binary integrity" ;;
        postgres) echo "Database" ;;
        backup) echo "Database backups" ;;
        pin-expiration) echo "App pin set" ;;
        public:*) echo "Public endpoint ${1#public:}" ;;
        extra:*) echo "Site ${1#extra:}" ;;
        extra-backup:*) echo "Backups ${1#extra-backup:}" ;;
        probe:*) echo "External probe ${1#probe:}" ;;
        *) echo "$1" ;;
    esac
}
check() {
    local key="$1" problem="$2"
    local file
    file="${STATE}/check-$(tr -c 'A-Za-z0-9_-' '_' <<< "$key")"
    local previous=""
    [[ -f "$file" ]] && previous="$(cat "$file")"

    if [[ -n "$problem" ]]; then
        problems=$((problems + 1))
        open_issues+=("$problem")
        if [[ "$problem" != "$previous" ]]; then
            send "⚠️ ${problem}"
        fi
        printf '%s' "$problem" > "$file"
    elif [[ -n "$previous" ]]; then
        send "✅ Resolved: $(resolved_label "$key")"
        rm -f "$file"
    fi
}

days_until() {
    local end
    end="$(date -u -d "$1" +%s 2>/dev/null)" || { echo ""; return; }
    echo $(( (end - $(date -u +%s)) / 86400 ))
}

cert_days_left() {
    local end
    end="$(openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2)" || return 1
    [[ -n "$end" ]] || return 1
    days_until "$end"
}

pin_of_cert_stdin() {
    openssl x509 -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary | openssl enc -base64
}

pin_allowed() {
    local pins="${GASAPP_PINS_FILE:-/etc/gasapp/pins.txt}"
    [[ -r "$pins" ]] && grep -v '^[[:space:]]*#' "$pins" | tr -d '[:blank:]' | grep -qxF "$1"
}

# --- Везде ------------------------------------------------------------------

check_disk() {
    local max="${GASAPP_DISK_MAX:-85}"
    local mount used
    while read -r used mount; do
        used="${used%\%}"
        [[ "$used" =~ ^[0-9]+$ ]] || continue
        if (( used >= 95 )); then
            check "disk:${mount}" "Disk ${mount} is at least 95% full; database and logs may stop"
        elif (( used >= max )); then
            check "disk:${mount}" "Disk ${mount} is above ${max}% full"
        else
            check "disk:${mount}" ""
        fi
    done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR > 1 { print $5, $6 }')
}

check_units() {
    local failed
    failed="$(systemctl --failed --plain --no-legend 2>/dev/null | awk '{ print $1 }' | sort | tr '\n' ' ')"
    check "units-failed" "${failed:+Failed services: ${failed% }}"

    local unit
    for unit in ${GASAPP_UNITS:-}; do
        if systemctl is-active --quiet "$unit"; then
            check "unit:${unit}" ""
        else
            check "unit:${unit}" "Service ${unit} is not running"
        fi
    done
}

check_time() {
    # Неверные часы ломают проверку подписей запросов и сертификатов.
    local synced
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
    check "ntp" "$([[ "$synced" == "yes" ]] || echo "Clock is not synchronized (NTP)")"
}

check_updates() {
    check "reboot" "$([[ -f /var/run/reboot-required ]] && echo "Reboot required after a security update")"

    # Автообновления не запускались три дня — сломан apt или таймер.
    local stamp=/var/lib/apt/periodic/unattended-upgrades-stamp
    if [[ -f "$stamp" ]]; then
        local age=$(( ($(date +%s) - $(stat -c %Y "$stamp")) / 86400 ))
        check "unattended" "$( (( age >= 3 )) && echo "Automatic updates have not run for over three days")"
    fi
}

check_ports() {
    # 🔐 Новый слушающий порт — то, чего не ставили: забытая служба,
    # пакет с открытым по умолчанию портом или чужая программа.
    local allowed=" ${GASAPP_ALLOWED_PORTS:-22} "
    local unexpected=""
    local proto local_addr port
    while read -r proto local_addr; do
        port="${local_addr##*:}"
        case "$local_addr" in
            127.*|\[::1\]:*|::1:*|*%lo:*) continue ;;
        esac
        [[ "$allowed" == *" ${port} "* || "$allowed" == *" ${port}/${proto} "* ]] && continue
        unexpected="${unexpected} ${port}/${proto}"
    done < <(ss -Hlntu 2>/dev/null | awk '{ print $1, $5 }')

    unexpected="$(tr ' ' '\n' <<< "$unexpected" | sort -u | tr '\n' ' ' | sed 's/^ *//; s/ *$//')"
    check "ports" "${unexpected:+Unexpected listening ports: ${unexpected}}"
}

check_binaries() {
    # 🔐 Подмена бинаря сервера — признак взлома, а не сбоя. Суммы
    # записываются при установке (sha256sum ... > /etc/gasapp/checksums.sha256).
    local sums="${GASAPP_CHECKSUMS:-/etc/gasapp/checksums.sha256}"
    [[ -r "$sums" ]] || return 0
    local bad
    bad="$(sha256sum --check --quiet "$sums" 2>/dev/null | cut -d: -f1 | tr '\n' ' ')"
    check "binaries" "${bad:+🔴 Changed binaries: ${bad% }. If you did not update them, investigate immediately}"
}

check_ssh_logins() {
    local mark="${STATE}/ssh-since"
    local since="-10min"
    [[ -f "$mark" ]] && since="@$(cat "$mark")"
    date +%s > "$mark"

    local user
    while read -r user; do
        [[ -n "$user" ]] && send "🔐 SSH login: ${user}"
    done < <(journalctl -q -o cat --since "$since" -t sshd -t sshd-session 2>/dev/null \
        | sed -n 's/^Accepted [a-z0-9-]* for \([A-Za-z0-9._-]*\) from .*/\1/p')
}

check_certs() {
    # Внутренние сертификаты (узел, база): год с небольшим, продление
    # вручную — монитор напоминает за 30 дней.
    local cert left
    for cert in ${GASAPP_WATCH_CERTS:-}; do
        left="$(cert_days_left "$cert")" || { check "cert:${cert}" "Cannot read certificate ${cert}"; continue; }
        if (( left < 30 )); then
            check "cert:${cert}" "Certificate ${cert} expires in under 30 days; run internal-ca.sh"
        else
            check "cert:${cert}" ""
        fi
    done
}

# --- Балансировщик ----------------------------------------------------------

# Срок и пин того, что отдаёт адрес <host:port> с именем <sni>.
probe_public() {
    local key="$1" target="$2" sni="$3"
    local pem
    pem="$(timeout 10 openssl s_client -connect "$target" -servername "$sni" </dev/null 2>/dev/null \
        | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | head -n 200)"

    if [[ -z "$pem" ]]; then
        check "${key}:up" "Public endpoint ${target} is not responding over TLS"
        return
    fi
    check "${key}:up" ""

    # 🔴 Пин того, что отдаётся НА САМОМ ДЕЛЕ. Ключ не из набора — все
    # установки приложения уже без связи.
    local pin
    pin="$(pin_of_cert_stdin <<< "$pem")"
    if pin_allowed "$pin"; then
        check "${key}:pin" ""
    else
        check "${key}:pin" "🔴 ${target} serves a key outside the pin set (${pin}); the app cannot connect"
    fi

    local end left
    end="$(openssl x509 -noout -enddate <<< "$pem" 2>/dev/null | cut -d= -f2)"
    left="$(days_until "$end")"
    if [[ -z "$left" ]]; then
        check "${key}:expiry" ""
    elif (( left < 7 )); then
        check "${key}:expiry" "🔴 Public certificate expires in under 7 days; run gasapp-cert.sh renew --force"
    elif (( left < 21 )); then
        check "${key}:expiry" "Public certificate expires in under 21 days; renewal failed"
    else
        check "${key}:expiry" ""
    fi
}

check_lb() {
    local domain="${GASAPP_DOMAIN:?в monitor.env нужен GASAPP_DOMAIN}"
    probe_public "public" "127.0.0.1:443" "$domain"

    # Срок набора пинов в приложении (`expiration` в pin-set): после
    # него Android перестаёт проверять пины. Нужен релиз с новой датой
    # задолго до неё — обновляются не все и не сразу.
    if [[ -n "${GASAPP_PIN_EXPIRATION:-}" ]]; then
        local left
        left="$(days_until "$GASAPP_PIN_EXPIRATION")"
        if [[ -n "$left" ]] && (( left < 30 )); then
            check "pin-expiration" "🔴 App pin set expires in under 30 days; release an app update"
        elif [[ -n "$left" ]] && (( left < 120 )); then
            check "pin-expiration" "App pin set expires in under 120 days; prepare an update (cert-pin-rotation.md)"
        else
            check "pin-expiration" ""
        fi
    fi

    if [[ -n "${GASAPP_NODES:-}" ]]; then
        GASAPP_MONITOR_STATE="${STATE}/nodes" GASAPP_NOTIFY_CMD="$NOTIFY" \
            "${HERE}/../check-nodes.sh" || true
    fi
}

# --- База -------------------------------------------------------------------

check_db() {
    if pg_isready -q -h "${GASAPP_PG_SOCKET:-/var/run/postgresql}" 2>/dev/null; then
        check "postgres" ""
    else
        check "postgres" "🔴 Database is not responding; all API nodes are affected"
    fi

    local mark="${GASAPP_BACKUP_MARKER:-/var/lib/gasapp-backup/last-success}"
    if [[ -e "$mark" ]]; then
        # The backup service writes this marker with mode 0600. The monitor
        # can stat it through the 0755 StateDirectory, but cannot read it.
        local modified
        modified="$(stat -c %Y "$mark" 2>/dev/null)" || {
            check "backup" "Cannot inspect the backup success marker"
            return
        }
        local hours=$(( ($(date +%s) - modified) / 3600 ))
        check "backup" "$( (( hours >= 26 )) && echo "No successful backup in over 26 hours")"
    else
        check "backup" "No successful backup yet"
    fi
}

# --- Дополнительные сайты на этой машине (например, GAS на поддомене) -------
#
# GASAPP_EXTRA_SITES="shop.gasapp.eu=http://127.0.0.1:8790/api/stores"
#   домен=адрес проверки приложения на петле; через пробел — несколько.
# Проверяется: приложение отвечает локально, nginx отдаёт HTTPS для этого
# имени, срок сертификата. Пин НЕ проверяется: у таких сайтов обычный
# сертификат certbot (ключ меняется при продлении) — probe_public здесь
# дал бы ложную 🔴-тревогу.
#
# GASAPP_EXTRA_BACKUPS="/opt/gas/backups/last-success"
#   файлы-отметки об успешной копии: тревога, если старше 26 часов.
#   Каталог копий — 711: монитор видит возраст отметки, но не сами копии.

check_extra_sites() {
    local entry domain url pem end left
    for entry in ${GASAPP_EXTRA_SITES:-}; do
        domain="${entry%%=*}"; url="${entry#*=}"
        if [[ "$url" == "$entry" ]] || ! curl -fsS -o /dev/null --max-time 8 "$url" 2>/dev/null; then
            check "extra:${domain}:app" "Site ${domain}: application is not responding locally (container down?)"
        else
            check "extra:${domain}:app" ""
        fi

        pem="$(timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$domain" </dev/null 2>/dev/null \
            | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | head -n 200)"
        if [[ -z "$pem" ]]; then
            check "extra:${domain}:tls" "Site ${domain}: nginx does not serve HTTPS for this name"
            continue
        fi
        check "extra:${domain}:tls" ""

        end="$(openssl x509 -noout -enddate <<< "$pem" 2>/dev/null | cut -d= -f2)"
        left="$(days_until "$end")"
        if [[ -n "$left" ]] && (( left < 7 )); then
            check "extra:${domain}:expiry" "🔴 Certificate of ${domain} expires in under 7 days; check certbot renew"
        elif [[ -n "$left" ]] && (( left < 21 )); then
            check "extra:${domain}:expiry" "Certificate of ${domain} expires in under 21 days; certbot renewal failed"
        else
            check "extra:${domain}:expiry" ""
        fi
    done
}

check_extra_backups() {
    local mark modified hours
    for mark in ${GASAPP_EXTRA_BACKUPS:-}; do
        if [[ -e "$mark" ]]; then
            modified="$(stat -c %Y "$mark" 2>/dev/null)" || { check "extra-backup:${mark}" "Cannot inspect backup marker ${mark}"; continue; }
            hours=$(( ($(date +%s) - modified) / 3600 ))
            check "extra-backup:${mark}" "$( (( hours >= 26 )) && echo "No successful backup in over 26 hours (${mark%/*})")"
        else
            check "extra-backup:${mark}" "No successful backup yet (${mark%/*})"
        fi
    done
}

# --- Запуск -----------------------------------------------------------------

check_disk
check_units
check_time
check_updates
check_ports
check_binaries
check_ssh_logins
check_certs

has_role lb && check_lb
has_role db && check_db
check_extra_sites
check_extra_backups

if [[ -n "${GASAPP_PROBE_PUBLIC:-}" ]]; then
    probe_public "probe" "$GASAPP_PROBE_PUBLIC" "${GASAPP_PROBE_PUBLIC%%:*}"
fi

# Ежедневный сигнал жизни.
readonly HEARTBEAT_HOUR="${GASAPP_HEARTBEAT_HOUR:-09}"
today="$(date -u +%F)"
if [[ "$(date -u +%H)" == "$HEARTBEAT_HOUR" && "$(cat "${STATE}/heartbeat" 2>/dev/null)" != "$today" ]]; then
    echo "$today" > "${STATE}/heartbeat"
    if (( problems == 0 )); then
        send "Monitor heartbeat: all checks are healthy"
    else
        summary="Monitor heartbeat: ${problems} open problem(s)"
        for issue in "${open_issues[@]}"; do
            (( ${#summary} > 700 )) && break
            summary+=$'\n'"- ${issue}"
        done
        send "$summary"
    fi
fi

exit 0
