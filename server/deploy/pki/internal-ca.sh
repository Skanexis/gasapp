#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Внутренний удостоверяющий центр AEGIS: сертификаты для связей ВНУТРИ
# кластера — балансировщик → узлы и узлы → база.
#
#     internal-ca.sh init                          # один раз
#     internal-ca.sh server db   aegis-db   10.0.0.4
#     internal-ca.sh server node1 aegis-node 10.0.0.1
#     internal-ca.sh client aegis                  # клиент базы (CN = роль)
#     internal-ca.sh show node1                    # срок и имена
#
# Каталог — $AEGIS_PKI_DIR (по умолчанию /root/aegis-pki).
#
# # 🔐 Зачем свой центр, если сеть внутренняя
#
# «Внутренняя» сеть у VPS — это сеть хостера: в ней соседи, ошибки
# изоляции и сам хостер. Шифрование без проверки сертификата
# (`sslmode=require`, `curl -k`) от того, кто встал посредине,
# не защищает: он предъявит свой сертификат, и его примут. Между узлами
# и базой идут конверты и время их доставки — то есть кто кому пишет.
#
# Свой центр, а не Let's Encrypt: внутренним адресам публичный центр
# сертификат не выдаст, а каждый выданный им сертификат попадает
# в публичный журнал (Certificate Transparency) — вместе с внутренними
# именами.
#
# # 🔐 Где держать ключ центра
#
# **Не на серверах.** На машине администратора, а лучше — на носителе,
# который подключается только для выпуска. Кто владеет ключом центра,
# выпускает «базу» и «узел», которым поверит кластер. На серверы уходят
# только `ca.pem` (открытый) и пара конкретной машины.

set -euo pipefail

readonly DIR="${AEGIS_PKI_DIR:-/root/aegis-pki}"

# Срок сертификата машины. Год с небольшим: продление раз в год
# достаточно редко, чтобы не мешать, и достаточно часто, чтобы
# украденный ключ не жил вечно. Монитор предупреждает за 30 дней.
readonly DAYS="${AEGIS_PKI_DAYS:-397}"

# Срок центра: десять лет. Смена центра — замена доверия на всех машинах.
readonly CA_DAYS=3650

umask 077

die() { echo "error: $*" >&2; exit 1; }

need_ca() {
    [[ -f "${DIR}/ca.key" && -f "${DIR}/ca.pem" ]] \
        || die "центр не создан: сначала '$0 init'"
}

# Имя файла — только буквы, цифры, точка, дефис: оно попадает в путь.
check_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "недопустимое имя «$1»"
}

cmd_init() {
    mkdir -p "$DIR"
    [[ -f "${DIR}/ca.key" ]] && die "центр уже есть в ${DIR} — второй не создаётся"

    # P-256: его понимают Postgres, nginx и rustls; ключ короткий,
    # рукопожатие быстрое.
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${DIR}/ca.key"
    openssl req -x509 -new -key "${DIR}/ca.key" -sha256 -days "$CA_DAYS" \
        -subj "/CN=AEGIS internal CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "${DIR}/ca.pem"
    chmod 644 "${DIR}/ca.pem"

    echo "центр создан: ${DIR}/ca.pem (открытый — раздать на все машины)"
    echo "🔐 ${DIR}/ca.key — НЕ копировать на серверы"
}

# issue <файл> <CN> <extendedKeyUsage> <subjectAltName|"">
issue() {
    local name="$1" cn="$2" usage="$3" san="$4"
    local ext
    ext="$(mktemp)"

    {
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature"
        echo "extendedKeyUsage=${usage}"
        # `if`, а не `&&`: пустой SAN (клиентский сертификат) дал бы
        # код 1 последней команды, и set -e оборвал бы выпуск.
        if [[ -n "$san" ]]; then
            echo "subjectAltName=${san}"
        fi
    } > "$ext"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${DIR}/${name}.key"
    openssl req -new -key "${DIR}/${name}.key" -subj "/CN=${cn}" -out "${DIR}/${name}.csr"
    openssl x509 -req -in "${DIR}/${name}.csr" \
        -CA "${DIR}/ca.pem" -CAkey "${DIR}/ca.key" -CAcreateserial \
        -days "$DAYS" -sha256 -extfile "$ext" \
        -out "${DIR}/${name}.pem"
    rm -f "${DIR}/${name}.csr" "$ext"
    chmod 644 "${DIR}/${name}.pem"

    openssl verify -CAfile "${DIR}/ca.pem" "${DIR}/${name}.pem" > /dev/null \
        || die "выпущенный сертификат не проверяется центром"
}

# server <файл> <dns-имя> [ip...]
cmd_server() {
    need_ca
    local name="${1:?имя файла}" dns="${2:?DNS-имя}"
    shift 2
    check_name "$name"
    check_name "$dns"

    # Имя — то, которое проверяет клиент: `proxy_ssl_name aegis-node`
    # у nginx, хост в DATABASE_URL у узла. Адреса — чтобы проверка
    # проходила и по IP.
    local san="DNS:${dns}"
    for ip in "$@"; do
        [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "недопустимый адрес «$ip»"
        san="${san},IP:${ip}"
    done

    issue "$name" "$dns" "serverAuth" "$san"
    echo "выпущен ${DIR}/${name}.pem (${san}), ключ ${DIR}/${name}.key"
}

# client <роль базы>
cmd_client() {
    need_ca
    local role="${1:?роль базы}"
    check_name "$role"

    # Postgres с `clientcert=verify-full` сверяет CN с именем роли.
    issue "client-${role}" "$role" "clientAuth" ""
    echo "выпущен ${DIR}/client-${role}.pem (CN=${role}), ключ ${DIR}/client-${role}.key"
}

cmd_show() {
    local name="${1:?имя}"
    check_name "$name"
    openssl x509 -in "${DIR}/${name}.pem" -noout -subject -enddate -ext subjectAltName
}

case "${1:-}" in
    init)   cmd_init ;;
    server) shift; cmd_server "$@" ;;
    client) shift; cmd_client "$@" ;;
    show)   shift; cmd_show "$@" ;;
    *)
        sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
