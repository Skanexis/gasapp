#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Часть update-servers.sh, которая выполняется НА СЕРВЕРЕ под sudo.
# Вручную не запускается: update-servers.sh кладёт её в ~/deploy/ вместе
# со скриптами и списком ожидаемых сумм программ и вызывает
#
#     sudo bash ~/deploy/update-remote.sh <имя-машины> <~/deploy>
#
# Что делает:
#   1. ставит свежие скрипты монитора и оповещений;
#   2. DHCP-клиент IONOS (68/udp) — в ожидаемые порты, если его слушает
#      именно systemd-networkd/dhclient;
#   3. лишняя почта на узлах (25/tcp не на балансировщике) — объясняет
#      и предлагает выключить;
#   4. программы /usr/local/bin/gasapp-server-* сверяет с суммами своей
#      сборки: совпали — записывает новые контрольные суммы; не совпали —
#      НЕ записывает и поднимает тревогу (это может быть подмена);
#   5. запускает монитор, чтобы старые тревоги закрылись сразу;
#   6. «нужна перезагрузка» — спрашивает, перезагрузить ли.

set -uo pipefail

host="${1:?имя машины}"
kit="${2:?каталог с файлами}"
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m⚠\033[0m %s\n' "$*"; }
bad()  { printf '    \033[1;31m✘ %s\033[0m\n' "$*"; }
ask()  { local a; read -r -p "    $1 [y/N] " a < /dev/tty; [[ "$a" == [yYдД]* ]]; }

env_file=/etc/gasapp/monitor.env
roles="$(sed -n 's/^GASAPP_ROLES="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$env_file" 2>/dev/null)"

# --- 1. Скрипты -------------------------------------------------------------

install -d -m 755 /opt/gasapp/monitor
install -m 755 "$kit/notify-telegram.sh" /opt/gasapp/notify-telegram.sh
install -m 755 "$kit/check-nodes.sh" /opt/gasapp/check-nodes.sh
install -m 755 "$kit/monitor/gasapp-monitor.sh" /opt/gasapp/monitor/gasapp-monitor.sh
ok "скрипты монитора обновлены (тексты оповещений — по-русски)"

# --- 2. DHCP IONOS ------------------------------------------------------------

if ss -Hlunp 'sport = :68' 2>/dev/null | grep -Eq 'systemd-network|dhclient|dhcpcd'; then
    if grep -q '^GASAPP_ALLOWED_PORTS=.*68/udp' "$env_file"; then
        ok "68/udp (DHCP IONOS) уже в ожидаемых портах"
    else
        sed -i '/^GASAPP_ALLOWED_PORTS=/ s/"$/ 68\/udp"/' "$env_file"
        ok "68/udp — это DHCP-клиент IONOS: добавлен в ожидаемые порты"
    fi
elif ss -Hlun 'sport = :68' 2>/dev/null | grep -q .; then
    warn "68/udp слушает НЕ DHCP-клиент: $(ss -Hlunp 'sport = :68' | sed 's/.*users://')"
fi

# --- 3. Почта не на балансировщике -------------------------------------------

if [[ " $roles " != *" lb "* ]]; then
    owner="$(ss -Hlntp 'sport = :25' 2>/dev/null | grep -v '127\.0\.0\.1\|\[::1\]' | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1)"
    if [[ -n "$owner" ]]; then
        warn "здесь слушает почтовый порт 25 ($owner), хотя почта идёт только через VPS-1 (шаг 16)."
        echo "      Обычно это Postfix, поставленный сюда по ошибке. Узлу он не нужен,"
        echo "      а открытый порт — лишняя точка атаки."
        unit=""
        for candidate in postfix exim4 sendmail; do
            systemctl list-unit-files "${candidate}.service" > /dev/null 2>&1 && systemctl is-enabled --quiet "$candidate" 2>/dev/null && unit="$candidate"
        done
        if [[ -n "$unit" ]] && ask "Выключить ${unit} на этой машине?"; then
            systemctl disable --now "$unit" > /dev/null 2>&1 && ok "${unit} выключен, порт 25 закрыт"
        else
            warn "оставлено как есть — монитор продолжит напоминать про 25/tcp"
        fi
    fi
fi

# --- 4. Программы и контрольные суммы ----------------------------------------

expected="$kit/expected-sums.txt"
suspicious=0
for binary in /usr/local/bin/gasapp-server-*; do
    [[ -f "$binary" ]] || continue
    sum="$(sha256sum "$binary" | cut -d' ' -f1)"
    if grep -q "^${sum} " "$expected" 2>/dev/null; then
        ok "$(basename "$binary"): совпадает с вашей сборкой"
    else
        bad "$(basename "$binary"): сумма ${sum:0:16}… НЕ совпадает ни с одной вашей сборкой"
        suspicious=1
    fi
done

if (( suspicious )); then
    bad "Контрольные суммы НЕ перезаписаны: монитор продолжит тревогу."
    echo "      Если вы обновляли эту программу с другого компьютера — пересоберите на этом"
    echo "      ПК и запустите update-servers.sh снова. Если нет — это может быть подмена:"
    echo "      не трогайте машину и разберитесь (РАЗВЁРТЫВАНИЕ.md, «Если случилось плохое»)."
else
    sha256sum /usr/local/bin/gasapp-server-* /opt/gasapp/*.sh /opt/gasapp/*/*.sh 2> /dev/null > /etc/gasapp/checksums.sha256
    chmod 644 /etc/gasapp/checksums.sha256
    if sha256sum --check --quiet /etc/gasapp/checksums.sha256 > /dev/null 2>&1; then
        ok "контрольные суммы записаны заново ($(wc -l < /etc/gasapp/checksums.sha256) файлов)"
    else
        bad "контрольные суммы не сходятся сразу после записи"
    fi
fi

# --- 5. Монитор ----------------------------------------------------------------

systemctl start gasapp-monitor.service 2> /dev/null && ok "монитор перезапущен: исправленное придёт в Telegram как «✅ Решено»"

# --- 6. Перезагрузка -------------------------------------------------------------

if [[ -f /var/run/reboot-required ]]; then
    pkgs="$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2> /dev/null)"
    warn "после обновления безопасности нужна перезагрузка${pkgs:+ (${pkgs% })}"
    if [[ " $roles " == *" db "* ]]; then
        echo "      Это БАЗА: на минуту-две приложение не будет работать ни у кого."
    elif [[ " $roles " == *" lb "* ]]; then
        echo "      Это VPS-1 (вход для всех): на минуту-две приложение недоступно."
    else
        echo "      Это узел API: остальные узлы обслужат людей, пока он перезагружается."
    fi
    if ask "Перезагрузить ${host} сейчас?"; then
        rm -f "$kit/expected-sums.txt"
        systemd-run --quiet --on-active=5 /bin/systemctl reboot
        ok "перезагрузка через 5 секунд — вернётся через 1–2 минуты, монитор сам сообщит"
    else
        warn "не перезагружено — монитор будет напоминать"
    fi
fi
rm -f "$kit/expected-sums.txt"
exit 0
