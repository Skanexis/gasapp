#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

deploy="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
config="$(cat)"
if [[ "$config" == *'upload-file = '* ]]; then
    file="$(sed -n 's/^upload-file = "\(.*\)"$/\1/p' <<< "$config")"
    cp "$file" "$MAIL_CAPTURE"
else
    printf '%s\n' "$*" > "$TELEGRAM_CAPTURE"
fi
MOCK
chmod +x "$work/curl"

printf 'SMTP_URL=smtp://localhost:25\nMAIL_FROM=no-reply@gasapp.eu\n' > "$work/mail"
printf 'reader@example.org\n123456\n' \
    | PATH="$work:$PATH" GASAPP_MAIL_FILE="$work/mail" MAIL_CAPTURE="$work/message" \
      bash "$deploy/mail/send-code.sh"

grep -aq 'Subject: Your GasApp verification code' "$work/message"
grep -aq 'Content-Type: multipart/alternative' "$work/message"
grep -aq 'Content-Type: text/plain' "$work/message"
grep -aq 'Content-Type: text/html' "$work/message"
grep -aq 'Your verification code is: 123456' "$work/message"
grep -aq '>123456</td>' "$work/message"
grep -aq 'Auto-Submitted: auto-generated' "$work/message"
if grep -aq 'Код подтверждения' "$work/message"; then
    echo 'Russian text remained in the verification email' >&2
    exit 1
fi

printf 'TOKEN=123456:abcdef\nCHAT_ID=123456\n' > "$work/telegram"
printf 'gasapp-node2\n' > "$work/node-label"
printf 'SSH login: ops\n' \
    | PATH="$work:$PATH" CREDENTIALS_DIRECTORY="$work" \
      GASAPP_NODE_LABEL_FILE="$work/node-label" TELEGRAM_CAPTURE="$work/telegram-request" \
      bash "$deploy/notify-telegram.sh"
grep -q 'text=\[GasApp / gasapp-node2\] SSH login: ops' "$work/telegram-request"

cat > "$work/timedatectl" <<'MOCK'
#!/usr/bin/env bash
echo no
MOCK
cat > "$work/capture-alert" <<'MOCK'
#!/usr/bin/env bash
cat >> "$HEARTBEAT_CAPTURE"
MOCK
chmod +x "$work/timedatectl" "$work/capture-alert"
PATH="$work:$PATH" GASAPP_MONITOR_STATE="$work/monitor-state" \
    GASAPP_NOTIFY_CMD="$work/capture-alert" GASAPP_ROLES="" GASAPP_DISK_MAX=100 \
    GASAPP_HEARTBEAT_HOUR="$(date -u +%H)" HEARTBEAT_CAPTURE="$work/heartbeat" \
    bash "$deploy/monitor/gasapp-monitor.sh"
grep -q 'Монитор работает, открытых проблем: ' "$work/heartbeat"
grep -q -- '- Часы не синхронизированы (NTP)' "$work/heartbeat"

mkdir -p "$work/old-state"
printf 'OLD-STATE-TEXT clock drift' > "$work/old-state/check-ntp_"
cat > "$work/timedatectl" <<'MOCK'
#!/usr/bin/env bash
echo yes
MOCK
PATH="$work:$PATH" GASAPP_MONITOR_STATE="$work/old-state" \
    GASAPP_NOTIFY_CMD="$work/capture-alert" GASAPP_ROLES="" GASAPP_DISK_MAX=100 \
    HEARTBEAT_CAPTURE="$work/recovered-alerts" \
    bash "$deploy/monitor/gasapp-monitor.sh"
grep -q 'Решено: Синхронизация часов' "$work/recovered-alerts"
if grep -q 'OLD-STATE-TEXT' "$work/recovered-alerts"; then
    echo 'A stored problem text leaked into the resolved message' >&2
    exit 1
fi

printf '%s\n' "$(date +%s)" > "$work/backup-marker"
chmod 000 "$work/backup-marker"
cat > "$work/pg_isready" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$work/pg_isready"
PATH="$work:$PATH" GASAPP_MONITOR_STATE="$work/db-state-fresh" \
    GASAPP_NOTIFY_CMD="$work/capture-alert" GASAPP_ROLES="db" GASAPP_DISK_MAX=100 \
    GASAPP_BACKUP_MARKER="$work/backup-marker" HEARTBEAT_CAPTURE="$work/db-fresh-alerts" \
    bash "$deploy/monitor/gasapp-monitor.sh"
if grep -q 'Нет успешной копии' "$work/db-fresh-alerts"; then
    echo 'A fresh, unreadable backup marker was reported as missing' >&2
    exit 1
fi

touch -d '2 days ago' "$work/backup-marker"
PATH="$work:$PATH" GASAPP_MONITOR_STATE="$work/db-state-old" \
    GASAPP_NOTIFY_CMD="$work/capture-alert" GASAPP_ROLES="db" GASAPP_DISK_MAX=100 \
    GASAPP_BACKUP_MARKER="$work/backup-marker" HEARTBEAT_CAPTURE="$work/db-old-alerts" \
    bash "$deploy/monitor/gasapp-monitor.sh"
grep -q 'Нет успешной копии больше 26 часов' "$work/db-old-alerts"

echo 'Communications checks passed'
