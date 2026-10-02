#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Оповещение в Telegram: текст — на stdin.
#
#     echo "AEGIS: проверка" | /opt/aegis/notify-telegram.sh
#
# Подходит в AEGIS_NOTIFY_CMD для check-nodes.sh, aegis-monitor.sh
# и `aegis-server-admin watch-reports`.
#
# # Где токен
#
# Файл из двух строк (права 600, владелец root):
#
#     TOKEN=123456:ABC...
#     CHAT_ID=-100123456789
#
# Ищется так:
#
# 1. `$CREDENTIALS_DIRECTORY/telegram` — учётные данные systemd
#    (`LoadCredential=telegram:/etc/aegis/credentials/telegram`);
# 2. `$AEGIS_TELEGRAM_FILE`;
# 3. `/etc/aegis/credentials/telegram` — при ручном запуске от root.
#
# Файл **читается, а не исполняется** (`source` не используется):
# строка в нём не должна уметь запустить команду от имени монитора.
#
# # 🔐 Токен не попадает в командную строку
#
# Адрес API Telegram содержит токен (`/bot<TOKEN>/sendMessage`).
# Переданный curl аргументом, он виден любому пользователю машины
# в `ps` и `/proc/<pid>/cmdline` — пока curl работает. Поэтому адрес
# уходит curl через `--config` на stdin.
#
# # 🔐 Что можно писать в оповещение
#
# Только состояние: «узел недоступен», «сертификат истекает через N
# дней». Ни числа пользователей, ни нагрузки, ни адресов: всё, что
# отправлено, оседает на серверах Telegram. Скрипт не фильтрует текст
# — это обязанность того, кто его формирует, — но обрезает до 1000
# знаков, чтобы случайный вывод команды не ушёл целиком.

set -uo pipefail

credential_file() {
    if [[ -n "${CREDENTIALS_DIRECTORY:-}" && -r "${CREDENTIALS_DIRECTORY}/telegram" ]]; then
        echo "${CREDENTIALS_DIRECTORY}/telegram"
    elif [[ -n "${AEGIS_TELEGRAM_FILE:-}" ]]; then
        echo "$AEGIS_TELEGRAM_FILE"
    else
        echo "/etc/aegis/credentials/telegram"
    fi
}

# Значение по ключу из файла вида KEY=VALUE, без исполнения.
value_of() {
    local key="$1" file="$2"
    sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "$file" \
        | head -n1 \
        | tr -d "\"'[:space:]"
}

text="$(head -c 1000)"
[[ -n "$text" ]] || exit 0

# Чтобы по сообщению было понятно, с какой машины оно пришло.
text="[$(hostname -s)] ${text}"

file="$(credential_file)"
if [[ ! -r "$file" ]]; then
    # Канал не настроен — оповещение не теряется, а уходит в журнал.
    logger -t aegis-notify -- "$text"
    echo "notify-telegram: нет файла с токеном (${file}) — записано в журнал" >&2
    exit 0
fi

token="$(value_of TOKEN "$file")"
chat="$(value_of CHAT_ID "$file")"

# Пустой файл — канал сознательно не настроен: оповещение в журнал.
# (Файл всё равно нужен: без него systemd не запустит службу
# с LoadCredential=telegram.)
if [[ -z "$token" ]]; then
    logger -t aegis-notify -- "$text"
    exit 0
fi

if [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ || ! "$chat" =~ ^-?[0-9]+$ ]]; then
    logger -t aegis-notify -- "$text"
    echo "notify-telegram: TOKEN или CHAT_ID в ${file} неверного вида" >&2
    exit 1
fi

# Три попытки: Telegram бывает недоступен минуту, а оповещение об отказе
# важнее всего именно тогда, когда что-то ещё не в порядке.
for attempt in 1 2 3; do
    if printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$token" \
        | curl --silent --show-error --fail --max-time 15 \
            --proto '=https' --tlsv1.2 \
            --config - \
            --data-urlencode "chat_id=${chat}" \
            --data-urlencode "text=${text}" \
            --data "disable_web_page_preview=true" \
            --output /dev/null; then
        exit 0
    fi
    sleep $((attempt * 5))
done

# Не ушло — в журнал, чтобы оповещение не пропало совсем.
logger -t aegis-notify -- "не доставлено в Telegram: ${text}"
exit 1
