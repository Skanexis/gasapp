#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Восстановление базы GasApp из резервной копии.
#
# # ⚠️ Что будет потеряно
#
# Все недоставленные конверты. Их нет в бэкапе намеренно (см.
# `backup.sh`), поэтому после восстановления отправители будут считать
# сообщения отправленными, а получатели их не увидят.
#
# Это не дефект восстановления, а следствие обещания «сообщения
# не хранятся на сервере».
#
# # Что нужно сделать до запуска
#
# Остановить **все** узлы API. Восстановление в работающую базу
# оставит узлы с кешем соединений, указывающим на данные, которых
# больше нет, и приведёт к отказам, причину которых искать долго.
#
#     systemctl stop gasapp   # на каждом узле
#
# # Запуск
#
#     ./restore.sh /var/backups/gasapp/gasapp-20260821-040000.sql.age

set -euo pipefail

readonly SOURCE="${1:?укажите файл бэкапа}"
readonly DB_NAME="${GASAPP_DB_NAME:-gasapp}"
readonly DB_USER="${GASAPP_DB_USER:-gasapp}"

if [[ ! -f "$SOURCE" ]]; then
    echo "файл не найден: $SOURCE" >&2
    exit 1
fi

# 🔐 Права до создания временных файлов.
umask 077

readonly WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$SOURCE" == *.age ]]; then
    echo "расшифровка бэкапа"

    # Приватный ключ задаётся отдельно и на машине бэкапа отсутствует:
    # там лежит только публичная часть, поэтому взлом сервера не даёт
    # доступа к истории.
    readonly KEY="${GASAPP_BACKUP_AGE_KEY:?укажите GASAPP_BACKUP_AGE_KEY}"

    age --decrypt --identity "$KEY" --output "${WORK}/dump.sql" "$SOURCE"
    readonly DUMP="${WORK}/dump.sql"
else
    readonly DUMP="$SOURCE"
fi

# Проверка перед восстановлением: файл должен содержать схему GasApp,
# а не чужой дамп. Восстановление постороннего файла поверх рабочей
# базы обнаружилось бы уже после потери данных.
if ! grep -q 'CREATE TABLE public.accounts' "$DUMP"; then
    echo "ОШИБКА: файл не похож на дамп базы GasApp" >&2
    exit 1
fi

echo "⚠️  База ${DB_NAME} будет ПЕРЕЗАПИСАНА."
echo "⚠️  Недоставленные сообщения будут потеряны — их нет в бэкапе."
read -r -p "Продолжить? [yes/NO] " answer

if [[ "$answer" != "yes" ]]; then
    echo "отменено"
    exit 1
fi

echo "восстановление"

# --single-transaction: при ошибке посреди восстановления база
# останется прежней, а не полувосстановленной. Полувосстановленная
# хуже пустой: её можно принять за рабочую.
psql \
    --username="$DB_USER" \
    --dbname="$DB_NAME" \
    --single-transaction \
    --set ON_ERROR_STOP=on \
    --file="$DUMP"

echo "готово. Запустите узлы: systemctl start gasapp-server (на каждом)"
