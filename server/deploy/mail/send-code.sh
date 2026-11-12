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
#     SMTP_CACERT=/etc/gasapp/pki/ca.pem
#
# `SMTP_USER`/`SMTP_PASSWORD` и `SMTP_CACERT` необязательны. Последний
# нужен, когда письмо уходит не прямо в почтовую службу, а на свой
# релей во внутренней сети с сертификатом внутреннего центра — так
# устроено развёртывание из РАЗВЁРТЫВАНИЕ.md: узлу API запрещена
# внешняя сеть, и в интернет ходит только релей.
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
smtp_cacert="$(setting SMTP_CACERT)"

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
    printf 'Subject: Your GasApp verification code\r\n'
    printf 'Date: %s\r\n' "$(LC_ALL=C date -R)"
    printf 'MIME-Version: 1.0\r\n'
    printf 'Content-Type: multipart/alternative; boundary="gasapp-verification"\r\n'
    printf 'Auto-Submitted: auto-generated\r\n'
    printf '\r\n'
    printf '%s\r\n' '--gasapp-verification'
    printf 'Content-Type: text/plain; charset=UTF-8\r\n'
    printf 'Content-Transfer-Encoding: 7bit\r\n\r\n'
    printf 'GASAPP  /  ACCOUNT VERIFICATION\r\n'
    printf '%s\r\n\r\n' '--------------------------------'
    printf 'Your verification code is: %s\r\n' "$code"
    printf 'Enter it in GasApp within 15 minutes. Never share this code.\r\n'
    printf '\r\n'
    printf 'If you did not request this code, you can safely ignore this email.\r\n'
    printf 'This is an automated message. Please do not reply.\r\n'
    printf '\r\n%s\r\n' '--gasapp-verification'
    printf 'Content-Type: text/html; charset=UTF-8\r\n'
    printf 'Content-Transfer-Encoding: 7bit\r\n\r\n'
    while IFS= read -r line; do
        printf '%s\r\n' "${line//CODE_PLACEHOLDER/$code}"
    done <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="supported-color-schemes" content="dark"><title>GasApp verification code</title></head>
<body style="margin:0;padding:0;background:#0b0f2e;color:#f5f6ff;font-family:Arial,Helvetica,sans-serif">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#0b0f2e">Your code is valid for 15 minutes. Never share it with anyone.</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0b0f2e"><tr><td align="center" style="padding:36px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px">
<tr><td align="center" style="padding:0 0 22px">
<span style="font-family:'Arial Black',Arial,sans-serif;font-size:46px;font-weight:900;line-height:1;letter-spacing:2px;color:#ffcb2e;text-shadow:3px 3px 0 #8a3414,-1px -1px 0 #8a3414,1px -1px 0 #8a3414,-1px 1px 0 #8a3414">GAS</span>
<div style="margin-top:6px;color:#8f98d6;font-size:11px;font-weight:bold;letter-spacing:4px">MESSENGER</div>
</td></tr>
<tr><td style="border:1px solid #343e85;border-radius:20px;background:#141a4a;padding:34px 30px">
<p style="margin:0 0 10px;color:#ffcb2e;font-size:12px;font-weight:bold;letter-spacing:3px">ACCOUNT VERIFICATION</p>
<h1 style="margin:0 0 14px;font-size:27px;line-height:1.25;color:#f5f6ff">One step to get started</h1>
<p style="margin:0 0 26px;color:#c2c8f0;font-size:16px;line-height:1.6">Enter this code in GasApp to confirm your email address.</p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
<td align="center" style="padding:22px 10px 22px 22px;border:2px solid #ffcb2e;border-radius:14px;background:#1b2259;color:#ffcb2e;font-family:'Courier New',monospace;font-size:38px;font-weight:bold;letter-spacing:12px">CODE_PLACEHOLDER</td>
</tr></table>
<p style="margin:24px 0 6px;color:#f5f6ff;font-size:15px">&#9201; Valid for <b>15 minutes</b>.</p>
<p style="margin:0 0 6px;color:#f5f6ff;font-size:15px">&#128274; Never share this code. GasApp will never ask you for it.</p>
<p style="margin:18px 0 0;padding-top:18px;border-top:1px solid #2a3374;color:#a3abdd;font-size:13px;line-height:1.6">Didn&#8217;t request a code? Someone may have typed your address by mistake. You can safely ignore this email &#8212; no account is created without the code.</p>
</td></tr>
<tr><td align="center" style="padding:20px 0 0;color:#7c85c4;font-size:12px;line-height:1.6">
Automated message from GasApp &#183; please do not reply<br>
<a href="https://gasapp.eu" style="color:#ffcb2e;text-decoration:none">gasapp.eu</a>
</td></tr>
</table>
</td></tr></table>
</body></html>
HTML
    printf '\r\n%s\r\n' '--gasapp-verification--'
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
    if [[ -n "$smtp_cacert" ]]; then
        printf 'cacert = "%s"\n' "$(escape "$smtp_cacert")"
    fi
    printf 'upload-file = "%s"\n' "$message"
    printf 'max-time = 20\n'
    printf 'silent\n'
} | curl --config - || fail "почтовая служба не приняла письмо"
