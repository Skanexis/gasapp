#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Считает пин SPKI для сертификата или для приватного ключа.
#
# Использование:
#   server/deploy/compute-pin.sh server/deploy/tls/cert.pem
#   server/deploy/compute-pin.sh --key server/deploy/tls/backup-key.pem
#   server/deploy/compute-pin.sh --host gasapp.chat:443
#
# # 🔐 Что именно пинится
#
# SubjectPublicKeyInfo, а не сертификат целиком. Разница существенна:
# сертификат меняется при каждом продлении (новые даты, новый серийный
# номер), а ключ внутри остаётся тем же. Пин на сертификат обрывал бы
# связь с клиентами при каждом продлении Let's Encrypt, то есть раз
# в три месяца.
#
# Отсюда же вытекает главное правило ротации: **запасной пин снимается
# с ключа, который ещё не используется**. Ключ можно сгенерировать
# заранее и держать оффлайн — сертификат для него не нужен.

set -euo pipefail

usage() {
  sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

if [[ $# -eq 0 ]]; then
  usage 2
fi

mode="cert"
target=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)  mode="key";  target="$2"; shift 2 ;;
    --host) mode="host"; target="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) mode="cert"; target="$1"; shift ;;
  esac
done

if ! command -v openssl > /dev/null 2>&1; then
  echo "error: нужен openssl" >&2
  exit 1
fi

# Общий хвост для всех трёх режимов: DER публичного ключа → SHA-256 → base64.
# Ровно эту величину считает `pin_from_spki` в crates/gasapp-net/src/pinning.rs
# и ровно её ожидает `<pin digest="SHA-256">` в network_security_config.
to_pin() {
  openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64
}

case "$mode" in
  cert)
    [[ -f "$target" ]] || { echo "error: нет файла $target" >&2; exit 1; }
    openssl x509 -in "$target" -pubkey -noout | to_pin
    ;;

  key)
    [[ -f "$target" ]] || { echo "error: нет файла $target" >&2; exit 1; }
    # Приватный ключ: публичная часть извлекается из него, сертификат
    # не нужен. Это и позволяет посчитать пин запасного ключа заранее.
    openssl pkey -in "$target" -pubout | to_pin
    ;;

  host)
    # Живой сервер. 🔐 Проверка того, что развёрнуто **на самом деле**:
    # пин, посчитанный с файла в репозитории, совпадает с сервером
    # только пока никто не подменил конфигурацию балансировщика.
    #
    # </dev/null обязателен: без него s_client ждёт ввода и висит.
    openssl s_client -connect "$target" -servername "${target%%:*}" </dev/null 2>/dev/null \
      | openssl x509 -pubkey -noout \
      | to_pin
    ;;
esac
