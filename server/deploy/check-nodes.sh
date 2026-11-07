#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Проверка узлов GasApp и оповещение при отказе.
#
# # Что проверяется
#
# Ручка `/health` каждого узла. Она отдаёт состояние процесса:
# доступна ли база, жив ли слушатель уведомлений. Ничего про
# пользователей она не знает — см. `gasapp-server-api/src/health.rs`.
#
# # 🔐 Почему оповещение скупое
#
# В сообщение об отказе попадает адрес узла, состояние и время.
# Не попадает ничего про нагрузку и активность: оповещения уходят
# через сторонний канал (почта, Telegram, вебхук), и всё, что в них
# написано, оседает у посредника. Строка «узел 2 недоступен» безвредна;
# строка «на узле 2 было 400 подключений» — уже метаданные,
# накопленные в чужом журнале.
#
# # Почему отдельный скрипт, а не Prometheus
#
# Prometheus умеет больше, но требует отдельной машины, собственной
# защиты и настройки, при которой он **не** собирает счётчики
# активности — а по умолчанию он собирает всё, что отдаёт цель.
# Скрипт из cron решает задачу «сообщить, что узел умер» полностью.
# Настройка Prometheus описана в `РАЗВЁРТЫВАНИЕ.md` для тех, кому
# нужен график.
#
# # Запуск
#
#     GASAPP_NODES="10.0.0.1 10.0.0.2 10.0.0.3" ./check-nodes.sh
#
# Из cron, раз в минуту:
#
#     * * * * * . /etc/gasapp/monitor.env && /opt/gasapp/check-nodes.sh
#
# Обычно его запускает gasapp-monitor.sh на балансировщике (роль lb),
# отдельная строка cron не нужна.

set -uo pipefail

# Узлы через пробел.
readonly NODES="${GASAPP_NODES:?укажите GASAPP_NODES}"

# Порт узла.
readonly PORT="${GASAPP_HEALTH_PORT:-8443}"

# Команда оповещения: получает текст на stdin.
#
# По умолчанию — запись в системный журнал. Он локален, и это
# осознанный выбор по умолчанию: внешний канал требует решения
# о том, кому доверить сведения об отказах.
readonly NOTIFY="${GASAPP_NOTIFY_CMD:-logger -t gasapp-monitor}"

# 🔐 Центр, которым подписаны сертификаты узлов (pki/internal-ca.sh).
#
# С ним узел проверяется по имени gasapp-node: ответ «я здоров» от того,
# кто встал посреди внутренней сети, не принимается. Без него — прежнее
# поведение (-k), только чтобы не сломать уже настроенные установки.
readonly CA="${GASAPP_INTERNAL_CA:-/etc/gasapp/pki/ca.pem}"

# Файл состояния: чтобы не слать оповещение каждую минуту.
readonly STATE_DIR="${GASAPP_MONITOR_STATE:-/var/lib/gasapp-monitor}"

mkdir -p "$STATE_DIR"

# 🔐 Права до создания файлов: список узлов и их состояние — сведения
# об инфраструктуре, читать их посторонним незачем.
umask 077

failed=0
node_index=0

for node in $NODES; do
    node_index=$((node_index + 1))
    state_file="${STATE_DIR}/$(echo "$node" | tr -c 'a-zA-Z0-9' '_')"

    # --max-time: зависший узел не должен задерживать проверку
    # остальных. --resolve: сертификат узла выписан на имя gasapp-node,
    # а ходим по адресу.
    #
    # Код возврата берётся отдельной проверкой `if`, а не через `$?`
    # после присваивания: `$?` в этом случае относится к подстановке
    # команды, а не к curl, и недоступный узел определялся бы как
    # «не видит базу» — то есть дежурный искал бы проблему не там.
    if [[ -r "$CA" ]]; then
        url="https://gasapp-node:${PORT}/health"
        tls=(--cacert "$CA" --resolve "gasapp-node:${PORT}:${node}")
    else
        url="https://${node}:${PORT}/health"
        tls=(-k)
    fi

    if body="$(curl -s "${tls[@]}" --max-time 5 "$url" 2>/dev/null)"; then
        if ! grep -q '"database":true' <<< "$body"; then
            status="database unavailable"
        elif ! grep -q '"listener":true' <<< "$body"; then
            # 🔐 Самый коварный отказ: узел отвечает на запросы
            # и принимает сообщения, молча перестав будить клиентов.
            # Снаружи он выглядит здоровым.
            status="notification listener is down"
        else
            status="ok"
        fi
    else
        status="unreachable"
    fi

    previous="$(cat "$state_file" 2>/dev/null || echo "ok")"
    echo "$status" > "$state_file"

    if [[ "$status" == "ok" ]]; then
        # Оповещение о восстановлении: без него дежурный не узнает,
        # что проблема ушла, и будет считать узел мёртвым.
        if [[ "$previous" != "ok" ]]; then
            echo "✅ API node ${node_index} (${node}) recovered" | $NOTIFY
        fi

        continue
    fi

    failed=$((failed + 1))

    # Оповещение только при смене состояния: отказ, длящийся час,
    # не должен давать шестьдесят одинаковых сообщений — их перестают
    # читать, и следующий настоящий отказ пройдёт незамеченным.
    if [[ "$previous" != "$status" ]]; then
        echo "⚠️ API node ${node_index} (${node}): ${status}" | $NOTIFY
    fi
done

total="$(wc -w <<< "$NODES")"

# 🔐 Отдельное оповещение, когда отказали все узлы.
#
# Оно означает, что сервис не работает целиком, а не «один узел
# просел», — и требует другой реакции. Без этого различия отказ
# кластера выглядит как три обычных сообщения.
#
# Подавление повторов такое же, как для узлов: сообщение раз в минуту
# в течение часа перестают читать, и следующий настоящий отказ
# проходит незамеченным.
readonly CLUSTER_STATE="${STATE_DIR}/_cluster"
cluster_previous="$(cat "$CLUSTER_STATE" 2>/dev/null || echo "ok")"

if [[ $failed -eq $total && $total -gt 0 ]]; then
    cluster_status="down"
else
    cluster_status="ok"
fi

echo "$cluster_status" > "$CLUSTER_STATE"

if [[ "$cluster_status" != "$cluster_previous" ]]; then
    if [[ "$cluster_status" == "down" ]]; then
        echo "🔴 All ${total} API nodes are down; service is unavailable" | $NOTIFY
    else
        echo "✅ API service recovered" | $NOTIFY
    fi
fi

exit 0
