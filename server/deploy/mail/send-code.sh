#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Письмо с кодом подтверждения — программа для GASAPP_EMAIL_CMD.
#
#     printf 'anna@example.org\n123456\n' | /opt/gasapp/mail/send-code.sh
#
# Сервер запускает её при каждом запросе кода и передаёт на stdin две
# строки: адрес и код. Код возврата 0 — письмо принято почтовой службой;
# любой другой — сервер ответит приложению «не удалось отправить».
#
# # Чем отправляет
#
# curl по SMTP с обязательным TLS: без посредника вроде msmtp и без
# почтового сервера на машине. Подойдёт любая служба с SMTP-входом
# (свой Postfix, Mailgun, Amazon SES, Postmark, Brevo…).
#
# # Где настройки
#
# Файл «ключ=значение» (права 600, владелец — пользователь сервера):
#
#     SMTP_URL=smtps://smtp.example.org:465
#     SMTP_USER=postmaster@example.org
#     SMTP_PASSWORD=...
#     MAIL_FROM=no-reply@example.org
#     MAIL_FROM_NAME=GasApp
#
# Ищется так:
#
# 1. `$CREDENTIALS_DIRECTORY/mail` — учётные данные systemd
#    (`LoadCredential=mail:/etc/gasapp/credentials/mail`);
# 2. `$GASAPP_MAIL_FILE`;
# 3. `/etc/gasapp/credentials/mail`.
#
# Файл **читается, а не исполняется** (`source` не используется):
# строка в нём не должна уметь запустить команду от имени сервера.
#
# # 🔐 Что не попадает в командную строку и в журнал
#
# Пароль SMTP и адрес получателя уходят curl через `--config` на stdin,
# а не аргументами: аргументы видны любому пользователю машины в `ps`.
# Скрипт ничего не пишет о получателе ни в stdout, ни в stderr — журнал
# сервера не должен становиться списком тех, кто регистрировался.
#
# # 🔐 Что видит почтовая служба
#
# Адрес получателя, время и сам код. Это вне сервера GasApp: сервер
# хранит только хеш адреса, а журналы почтовой службы — её журналы.
# Политика конфиденциальности говорит об этом прямо; выбирайте службу,
# срокам хранения журналов которой вы доверяете.

set -euo pipefail

fail() {
    # Причина — без адреса и без кода.
    echo "send-code: $1" >&2
    exit 1
}

config_file=""
for candidate in "${CREDENTIALS_DIRECTORY:-/nonexistent}/mail" "${GASAPP_MAIL_FILE:-}" /etc/gasapp/credentials/mail; do
    if [[ -n "$candidate" && -r "$candidate" ]]; then
        config_file="$candidate"
        break
    fi
done
[[ -n "$config_file" ]] || fail "не найден файл настроек почты"

setting() {
    # Первое совпадение «ключ=значение»; значение — как есть, без исполнения.
    local line
    line="$(grep -m1 -E "^$1=" "$config_file" || true)"
    printf '%s' "${line#*=}"
}

smtp_url="$(setting SMTP_URL)"
smtp_user="$(setting SMTP_USER)"
smtp_password="$(setting SMTP_PASSWORD)"
mail_from="$(setting MAIL_FROM)"
mail_from_name="$(setting MAIL_FROM_NAME)"

[[ -n "$smtp_url" && -n "$mail_from" ]] || fail "в настройках почты нет SMTP_URL или MAIL_FROM"

IFS= read -r recipient || fail "на stdin нет адреса"
IFS= read -r code || fail "на stdin нет кода"

# Сервер уже проверил адрес и сам породил код, но письмо собирается
# здесь — и здесь же стоит последняя проверка: ни перевода строки,
# ни кавычек, которыми в заголовок или в конфигурацию curl
# подставляют лишнее.
[[ "$recipient" =~ ^[A-Za-z0-9.!#\$%\&\'*+/=?^_\`{|}~-]+@[A-Za-z0-9.-]+$ ]] || fail "адрес не прошёл проверку"
[[ "$recipient" != *\'* && "$recipient" != *\\* ]] || fail "адрес не прошёл проверку"
[[ "$code" =~ ^[0-9]{6}$ ]] || fail "код не прошёл проверку"

message="$(mktemp)"
trap 'rm -f "$message"' EXIT

# Тема без кода: темы писем видны в уведомлениях на заблокированном
# экране и в списках входящих у всех, кто стоит рядом.
{
    printf 'From: %s <%s>\r\n' "${mail_from_name:-GasApp}" "$mail_from"
    printf 'To: <%s>\r\n' "$recipient"
    # Только ASCII: заголовок с кириллицей без кодирования RFC 2047
    # почтовые службы отвергают или портят.
    printf 'Subject: GasApp confirmation code\r\n'
    printf 'Date: %s\r\n' "$(LC_ALL=C date -R)"
    printf 'MIME-Version: 1.0\r\n'
    printf 'Content-Type: text/plain; charset=UTF-8\r\n'
    printf 'Content-Transfer-Encoding: 8bit\r\n'
    printf 'Auto-Submitted: auto-generated\r\n'
    printf '\r\n'
    printf 'Код подтверждения GasApp: %s\r\n' "$code"
    printf 'Он действует 15 минут. Введите его в приложении.\r\n'
    printf '\r\n'
    printf 'GasApp confirmation code: %s\r\n' "$code"
    printf 'It is valid for 15 minutes. Enter it in the app.\r\n'
    printf '\r\n'
    printf 'Если вы не регистрировались в GasApp, просто не отвечайте на это письмо:\r\n'
    printf 'без кода аккаунт на ваш адрес не создать.\r\n'
    printf 'If you did not sign up for GasApp, ignore this email: no account can be\r\n'
    printf 'created for your address without the code.\r\n'
} > "$message"

# Двойные кавычки в значениях конфигурации curl экранируются обратной
# косой; адрес уже проверен и их не содержит.
escape() {
    local value="${1//\\/\\\\}"
    printf '%s' "${value//\"/\\\"}"
}

{
    printf 'url = "%s"\n' "$(escape "$smtp_url")"
    printf 'ssl-reqd\n'
    printf 'mail-from = "%s"\n' "$(escape "$mail_from")"
    printf 'mail-rcpt = "%s"\n' "$(escape "$recipient")"
    if [[ -n "$smtp_user" ]]; then
        printf 'user = "%s:%s"\n' "$(escape "$smtp_user")" "$(escape "$smtp_password")"
    fi
    printf 'upload-file = "%s"\n' "$message"
    printf 'max-time = 20\n'
    printf 'silent\n'
} | curl --config - || fail "почтовая служба не приняла письмо"
