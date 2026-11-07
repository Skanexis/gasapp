#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Публичный сертификат балансировщика — с ключом, который пинит
# приложение.
#
#     gasapp-cert.sh bootstrap          # один раз: ключ + заглушка, печатает пин
#     gasapp-cert.sh renew              # выпустить/продлить (таймер — ежедневно)
#     gasapp-cert.sh renew --force      # выпустить сейчас, даже если срок не подошёл
#     gasapp-cert.sh switch-key <файл>  # 🔴 перейти на запасной ключ
#     gasapp-cert.sh status             # пин, срок, совпадение с набором
#
# Настройка — /etc/gasapp/cert.env:
#
#     GASAPP_DOMAIN=gasapp.example.com
#     GASAPP_ACME_EMAIL=ops@example.com
#
# Разрешённые пины — /etc/gasapp/pins.txt (по одному на строку, `#` —
# комментарий): ровно те, что вписаны в сборку приложения
# (docs/ops/cert-pin-rotation.md).
#
# # 🔴 Почему не обычный certbot
#
# Приложение пинит КЛЮЧ сертификата (SPKI), а certbot по умолчанию при
# каждом продлении создаёт новый. Первое же продление — через 60 дней
# после запуска — оборвало бы связь у всех установок разом, и починить
# это могло бы только обновление приложения. `--reuse-key` держится на
# одной строке в файле продления, которую легко потерять (перевыпуск
# с нуля, перенос на новую машину, `--new-key`), и вернуть прежний ключ
# в цепочку certbot потом нечем.
#
# Поэтому ключ здесь — свой, а certbot только подписывает запрос
# (`certonly --csr`). Ключ не меняется, пока оператор не решит этого
# сам (`switch-key`). И каждый раз, до того как nginx увидит сертификат,
# проверяется, что его ключ — из набора пинов.

set -euo pipefail

[[ -r /etc/gasapp/cert.env ]] && . /etc/gasapp/cert.env

readonly PINS="${GASAPP_PINS_FILE:-/etc/gasapp/pins.txt}"
readonly DEST="${GASAPP_PUBLIC_TLS_DIR:-/etc/gasapp/tls/public}"
readonly WEBROOT="${GASAPP_ACME_WEBROOT:-/var/www/acme}"
readonly NOTIFY="${GASAPP_NOTIFY_CMD:-/opt/gasapp/notify-telegram.sh}"
# Продлевать, когда до конца осталось меньше стольких дней. Let's
# Encrypt выдаёт на 90 (с 2026 — меньше); 30 оставляют две недели
# на повторы, если ACME недоступен.
readonly RENEW_DAYS="${GASAPP_RENEW_DAYS:-30}"

readonly KEY="${DEST}/privkey.pem"
readonly CHAIN="${DEST}/fullchain.pem"

notify() {
    echo "$1" >&2
    if [[ -x "${NOTIFY%% *}" ]]; then
        echo "$1" | $NOTIFY || true
    else
        logger -t gasapp-cert -- "$1" || true
    fi
}

die() { notify "⚠️ API certificate: $1"; exit 1; }

pin_of_key() {
    openssl pkey -in "$1" -pubout -outform der \
        | openssl dgst -sha256 -binary | openssl enc -base64
}

pin_of_cert() {
    openssl x509 -in "$1" -pubkey -noout \
        | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | openssl enc -base64
}

pin_allowed() {
    [[ -r "$PINS" ]] || return 1
    grep -v '^[[:space:]]*#' "$PINS" | tr -d '[:blank:]' | grep -qxF "$1"
}

need_domain() {
    [[ "${GASAPP_DOMAIN:-}" =~ ^[A-Za-z0-9.-]+$ ]] || die "GASAPP_DOMAIN is missing from /etc/gasapp/cert.env"
    [[ -n "${GASAPP_ACME_EMAIL:-}" ]] || die "GASAPP_ACME_EMAIL is missing from /etc/gasapp/cert.env"
}

reload_nginx() {
    nginx -t -q || die "nginx -t failed; nginx was not reloaded"
    systemctl reload nginx
}

# Самоподписанный ли сертификат (заглушка bootstrap).
is_placeholder() {
    [[ "$(openssl x509 -in "$CHAIN" -noout -issuer 2>/dev/null)" == *gasapp-bootstrap* ]]
}

cmd_bootstrap() {
    umask 077
    mkdir -p "$DEST" "$WEBROOT"
    chmod 755 "$WEBROOT"

    if [[ ! -f "$KEY" ]]; then
        # P-256: быстро на телефоне, поддерживается Android 9+.
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEY"
        echo "создан ключ ${KEY}"
    fi
    chmod 600 "$KEY"

    if [[ ! -f "$CHAIN" ]]; then
        # Заглушка на сутки: только чтобы nginx запустился и отдал
        # порт 80 для проверки ACME. Приложение её не примет.
        openssl req -x509 -new -key "$KEY" -days 1 -subj "/CN=gasapp-bootstrap" -out "$CHAIN"
        chmod 644 "$CHAIN"
    fi

    echo
    echo "пин основного ключа (вписать в приложение ПЕРВЫМ и в ${PINS}):"
    echo "  $(pin_of_key "$KEY")"
    echo "🔐 запасной ключ создаётся НЕ здесь, а оффлайн — см. РАЗВЁРТЫВАНИЕ.md"
}

# Выпуск сертификата на ключ $KEY.
issue() {
    need_domain
    [[ -f "$KEY" ]] || die "Key ${KEY} is missing; run bootstrap first"

    local pin
    pin="$(pin_of_key "$KEY")"
    # Проверка ДО выпуска: незачем просить сертификат, который всё равно
    # не будет установлен.
    pin_allowed "$pin" || die "🔴 Key ${KEY} (${pin}) is outside pin set ${PINS}; issuance cancelled"

    local work
    work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT

    openssl req -new -key "$KEY" -subj "/CN=${GASAPP_DOMAIN}" \
        -addext "subjectAltName=DNS:${GASAPP_DOMAIN}" -out "${work}/req.csr"

    certbot certonly --non-interactive --agree-tos --no-eff-email \
        --email "$GASAPP_ACME_EMAIL" \
        --webroot -w "$WEBROOT" \
        --csr "${work}/req.csr" \
        --cert-path "${work}/cert.pem" \
        --chain-path "${work}/chain.pem" \
        --fullchain-path "${work}/fullchain.pem" \
        --quiet \
        || die "certbot could not issue a certificate for ${GASAPP_DOMAIN}"

    [[ "$(pin_of_cert "${work}/fullchain.pem")" == "$pin" ]] \
        || die "Issued certificate does not match key ${KEY}; not installed"

    cp "${work}/fullchain.pem" "${DEST}/.fullchain.pem.new"
    chmod 644 "${DEST}/.fullchain.pem.new"
    mv -f "${DEST}/.fullchain.pem.new" "$CHAIN"
    reload_nginx

    notify "✅ API certificate issued; pin verified; valid until $(openssl x509 -in "$CHAIN" -noout -enddate | cut -d= -f2)"
}

cmd_renew() {
    if [[ "${1:-}" != "--force" && -f "$CHAIN" ]] && ! is_placeholder \
        && openssl x509 -in "$CHAIN" -noout -checkend $((RENEW_DAYS * 86400)) > /dev/null; then
        # Ещё рано — молча: таймер запускает это ежедневно.
        exit 0
    fi
    issue
}

cmd_switch_key() {
    local new="${1:?файл запасного ключа}"
    [[ -r "$new" ]] || die "Key file ${new} is missing"

    local pin
    pin="$(pin_of_key "$new")"
    pin_allowed "$pin" || die "🔴 Key ${new} (${pin}) is outside the pin set; switch cancelled"

    umask 077
    if [[ -f "$KEY" ]]; then
        # Прежний ключ не удаляется молча: при компрометации его нужно
        # отозвать, при ошибке — вернуть.
        mv -f "$KEY" "${DEST}/retired-$(date -u +%Y%m%d%H%M%S)-privkey.pem"
    fi
    cp "$new" "$KEY"
    chmod 600 "$KEY"

    issue
    notify "🔴 Load balancer switched to the backup key (${pin}). Generate a new backup key and release an app update: docs/ops/cert-pin-rotation.md"
}

cmd_status() {
    echo "ключ:        $(pin_of_key "$KEY")"
    echo "сертификат:  $(pin_of_cert "$CHAIN")"
    echo "действует до $(openssl x509 -in "$CHAIN" -noout -enddate | cut -d= -f2)"
    if pin_allowed "$(pin_of_key "$KEY")"; then
        echo "набор пинов: ключ в наборе"
    else
        echo "набор пинов: 🔴 ключа НЕТ в ${PINS}"
    fi
}

case "${1:-}" in
    bootstrap)  cmd_bootstrap ;;
    renew)      shift; cmd_renew "$@" ;;
    switch-key) shift; cmd_switch_key "$@" ;;
    status)     cmd_status ;;
    *)
        sed -n '3,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
