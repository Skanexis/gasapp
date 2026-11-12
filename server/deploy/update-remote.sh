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

# Письмо с кодом — только там, где оно уже стоит (узлы API): на других
# машинах его нет и не должно быть. Без этого шага на серверах оставалась
# первая, русская текстовая версия письма (2026-11-12).
if [[ -f /opt/gasapp/mail/send-code.sh && -f "$kit/mail/send-code.sh" ]]; then
    install -m 755 "$kit/mail/send-code.sh" /opt/gasapp/mail/send-code.sh
    ok "письмо с кодом обновлено (английское, оформленное)"

    # Службе сервера можно запускать только перечисленное в ExecPaths.
    # На части узлов стоял прежний юнит без сценария письма: сервер
    # отвечал «программа отправки писем не запустилась: Permission
    # denied», и регистрация через этот узел не проходила (2026-11-13).
    # Дополнение (drop-in) не трогает сам юнит узла: ExecPaths из него
    # добавляются к тем, что уже есть.
    chmod 755 /opt/gasapp /opt/gasapp/mail
    mail_dropin=/etc/systemd/system/gasapp-server.service.d/20-gasapp-mail.conf
    mail_want='[Unit]
# GasApp: служба запускает сценарий письма с кодом (GASAPP_EMAIL_CMD)
# и ровно те программы, что ему нужны.
[Service]
ExecPaths=/opt/gasapp/mail/send-code.sh /usr/bin/bash /usr/bin/env /usr/bin/curl /usr/bin/grep /usr/bin/mktemp /usr/bin/date /usr/bin/rm
'
    if [[ "$(cat "$mail_dropin" 2> /dev/null)" != "$mail_want" ]]; then
        install -d -m 755 "${mail_dropin%/*}"
        printf '%s' "$mail_want" > "$mail_dropin"
        systemctl daemon-reload
        systemctl restart gasapp-server && ok "служба сервера может запускать письмо с кодом — перезапущена" ||
            bad "служба сервера не перезапустилась: journalctl -u gasapp-server -n 30"
    fi
    if runuser -u gasapp -- test -x /opt/gasapp/mail/send-code.sh 2> /dev/null; then
        ok "пользователь службы может запустить письмо с кодом"
    else
        bad "пользователь gasapp не может запустить /opt/gasapp/mail/send-code.sh — проверьте права"
    fi
fi

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

# --- 3б. Службы ждут WireGuard -------------------------------------------------
#
# nginx, PostgreSQL, Postfix и сервер API слушают внутренний адрес 10.0.0.x,
# который появляется только с WireGuard. При загрузке они стартовали раньше
# него и падали: «bind() to 10.0.0.2:8444 failed (Cannot assign requested
# address)» — после любой перезагрузки VPS-1 сайт и API лежали, пока
# nginx не перезапустят руками (2026-11-12).

if [[ -f /etc/wireguard/wg0.conf ]]; then
    fixed=""
    for unit in nginx postgresql@ postfix@ gasapp-server gasapp-admin; do
        systemctl cat "${unit}.service" > /dev/null 2>&1 || continue
        dir="/etc/systemd/system/${unit}.service.d"
        install -d -m 755 "$dir"
        printf '[Unit]
# GasApp: внутренний адрес 10.0.0.x появляется с WireGuard.
Wants=wg-quick@wg0.service
After=wg-quick@wg0.service
' > "$dir/10-gasapp-wireguard.conf"
        fixed="${fixed} ${unit%@}"
    done
    systemctl enable --quiet wg-quick@wg0.service 2> /dev/null || true
    systemctl daemon-reload
    [[ -n "$fixed" ]] && ok "после перезагрузки службы ждут WireGuard:${fixed}"
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
