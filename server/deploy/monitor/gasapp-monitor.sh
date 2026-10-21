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
check() {
    local key="$1" problem="$2"
    local file
    file="${STATE}/check-$(tr -c 'A-Za-z0-9_-' '_' <<< "$key")"
    local previous=""
    [[ -f "$file" ]] && previous="$(cat "$file")"

    if [[ -n "$problem" ]]; then
        problems=$((problems + 1))
        if [[ "$problem" != "$previous" ]]; then
            send "GasApp: ⚠️ ${problem}"
        fi
        printf '%s' "$problem" > "$file"
    elif [[ -n "$previous" ]]; then
        send "GasApp: ✅ решено — ${previous}"
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
            check "disk:${mount}" "диск ${mount} заполнен на 95%+ — база и журнал вот-вот встанут"
        elif (( used >= max )); then
            check "disk:${mount}" "диск ${mount} заполнен больше чем на ${max}%"
        else
            check "disk:${mount}" ""
        fi
    done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR > 1 { print $5, $6 }')
}

check_units() {
    local failed
    failed="$(systemctl --failed --plain --no-legend 2>/dev/null | awk '{ print $1 }' | sort | tr '\n' ' ')"
    check "units-failed" "${failed:+упали службы: ${failed% }}"

    local unit
    for unit in ${GASAPP_UNITS:-}; do
        if systemctl is-active --quiet "$unit"; then
            check "unit:${unit}" ""
        else
            check "unit:${unit}" "служба ${unit} не работает"
        fi
    done
}

check_time() {
    # Неверные часы ломают проверку подписей запросов и сертификатов.
    local synced
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
    check "ntp" "$([[ "$synced" == "yes" ]] || echo "часы не синхронизированы (NTP)")"
}

check_updates() {
    check "reboot" "$([[ -f /var/run/reboot-required ]] && echo "нужна перезагрузка после обновления безопасности")"

    # Автообновления не запускались три дня — сломан apt или таймер.
    local stamp=/var/lib/apt/periodic/unattended-upgrades-stamp
    if [[ -f "$stamp" ]]; then
        local age=$(( ($(date +%s) - $(stat -c %Y "$stamp")) / 86400 ))
        check "unattended" "$( (( age >= 3 )) && echo "автообновления не запускались больше трёх дней")"
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
    check "ports" "${unexpected:+слушают неожиданные порты: ${unexpected}}"
}

check_binaries() {
    # 🔐 Подмена бинаря сервера — признак взлома, а не сбоя. Суммы
    # записываются при установке (sha256sum ... > /etc/gasapp/checksums.sha256).
    local sums="${GASAPP_CHECKSUMS:-/etc/gasapp/checksums.sha256}"
    [[ -r "$sums" ]] || return 0
    local bad
    bad="$(sha256sum --check --quiet "$sums" 2>/dev/null | cut -d: -f1 | tr '\n' ' ')"
    check "binaries" "${bad:+🔴 изменились файлы: ${bad% } — если это не ваше обновление, это взлом}"
}

check_ssh_logins() {
    local mark="${STATE}/ssh-since"
    local since="-10min"
    [[ -f "$mark" ]] && since="@$(cat "$mark")"
    date +%s > "$mark"

    local user
    while read -r user; do
        [[ -n "$user" ]] && send "GasApp: вход по SSH — ${user}"
    done < <(journalctl -q -o cat --since "$since" -t sshd -t sshd-session 2>/dev/null \
        | sed -n 's/^Accepted [a-z0-9-]* for \([A-Za-z0-9._-]*\) from .*/\1/p')
}

check_certs() {
    # Внутренние сертификаты (узел, база): год с небольшим, продление
    # вручную — монитор напоминает за 30 дней.
    local cert left
    for cert in ${GASAPP_WATCH_CERTS:-}; do
        left="$(cert_days_left "$cert")" || { check "cert:${cert}" "не читается сертификат ${cert}"; continue; }
        if (( left < 30 )); then
            check "cert:${cert}" "сертификат ${cert} истекает меньше чем через 30 дней — internal-ca.sh"
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
        check "${key}:up" "публичный вход ${target} не отвечает по TLS"
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
        check "${key}:pin" "🔴 ${target} отдаёт ключ НЕ из набора пинов (${pin}) — приложение не подключится"
    fi

    local end left
    end="$(openssl x509 -noout -enddate <<< "$pem" 2>/dev/null | cut -d= -f2)"
    left="$(days_until "$end")"
    if [[ -z "$left" ]]; then
        check "${key}:expiry" ""
    elif (( left < 7 )); then
        check "${key}:expiry" "🔴 публичный сертификат истекает меньше чем через 7 дней — gasapp-cert.sh renew --force"
    elif (( left < 21 )); then
        check "${key}:expiry" "публичный сертификат истекает меньше чем через 21 день — продление не сработало"
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
            check "pin-expiration" "🔴 срок набора пинов в приложении — меньше 30 дней; нужен релиз с новой датой"
        elif [[ -n "$left" ]] && (( left < 120 )); then
            check "pin-expiration" "срок набора пинов в приложении — меньше 120 дней; готовьте релиз (cert-pin-rotation.md)"
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
        check "postgres" "🔴 база не отвечает — все узлы без базы"
    fi

    local mark=/var/lib/gasapp-backup/last-success
    if [[ -r "$mark" ]]; then
        local hours=$(( ($(date +%s) - $(cat "$mark")) / 3600 ))
        check "backup" "$( (( hours >= 26 )) && echo "резервной копии нет больше суток")"
    else
        check "backup" "ни одной успешной резервной копии"
    fi
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

if [[ -n "${GASAPP_PROBE_PUBLIC:-}" ]]; then
    probe_public "probe" "$GASAPP_PROBE_PUBLIC" "${GASAPP_PROBE_PUBLIC%%:*}"
fi

# Ежедневный сигнал жизни.
readonly HEARTBEAT_HOUR="${GASAPP_HEARTBEAT_HOUR:-09}"
today="$(date -u +%F)"
if [[ "$(date -u +%H)" == "$HEARTBEAT_HOUR" && "$(cat "${STATE}/heartbeat" 2>/dev/null)" != "$today" ]]; then
    echo "$today" > "${STATE}/heartbeat"
    if (( problems == 0 )); then
        send "GasApp: монитор работает, проблем нет"
    else
        send "GasApp: монитор работает, открытых проблем: ${problems}"
    fi
fi

exit 0
