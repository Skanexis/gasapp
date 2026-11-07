#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Базовое укрепление машины GasApp (Debian 12 / Ubuntu 22.04+).
#
#     harden-host.sh --role node --admin alice --lb 10.0.0.1
#     harden-host.sh --role lb   --admin alice --onion 10.0.0.1
#     harden-host.sh --role db   --admin alice --nodes "10.0.0.1 10.0.0.2 10.0.0.3"
#     harden-host.sh --role lb,node --admin alice --lb 10.0.0.1 --onion 10.0.0.1
#                                   # балансировщик и узел 1 на одной машине
#
# Необязательно:
#     --ssh-from 203.0.113.0/24   SSH только с этих адресов (через пробел)
#     --relay-from 10.0.0.0/24    почтовый релей (порт 25) — только для этих
#                                 адресов: узлы отдают ему письма с кодом
#     --auto-reboot               перезагружаться после обновлений ядра в 04:30
#     --dry-run                   показать, что будет сделано
#
# Запускать от root. Повторный запуск безопасен: файлы перезаписываются
# целиком, правила брандмауэра не дублируются.
#
# # Что делает
#
#  1. Пакеты: автообновления безопасности, брандмауэр, NTP, fail2ban.
#  2. SSH: только ключи, без root, без пересылки агента и X11;
#     пускает только --admin.
#  3. Ядро (sysctl): закрытые указатели и dmesg, без ptrace чужих
#     процессов, без BPF для непривилегированных, защита сети.
#  4. Без дампов памяти — ни у одного процесса.
#  5. Журнал: хранится 14 дней, не копируется в /var/log/syslog.
#  6. Брандмауэр по роли: снаружи — только то, что нужно этой машине.
#  7. Пользователи служб: gasapp (узел), gasapp-admin (админ-центр),
#     gasapp-monitor (монитор, на каждой машине).
#
# # 🔐 Чтобы не запереть себя
#
# Вход по паролю выключается, только если у --admin есть ключ
# в ~/.ssh/authorized_keys и право sudo. Иначе — отказ ДО изменений.
# Конфигурация sshd проверяется (`sshd -t`) до перезапуска.
#
# Не закрывайте текущую сессию, пока не войдёте второй — новой —
# по ключу.

set -euo pipefail

role="" admin="" lb="" nodes="" onion="" ssh_from="" relay_from="" auto_reboot=0 dry=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)        role="$2"; shift 2 ;;
        --admin)       admin="$2"; shift 2 ;;
        --lb)          lb="$2"; shift 2 ;;
        --nodes)       nodes="$2"; shift 2 ;;
        --onion)       onion="$2"; shift 2 ;;
        --ssh-from)    ssh_from="$2"; shift 2 ;;
        --relay-from)  relay_from="$2"; shift 2 ;;
        --auto-reboot) auto_reboot=1; shift ;;
        --dry-run)     dry=1; shift ;;
        -h|--help)     sed -n '3,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done

die() { echo "ОТКАЗ: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }
run() { if (( dry )); then echo "  [dry-run] $*"; else "$@"; fi; }

# Записать файл целиком (или показать в dry-run).
put() {
    local path="$1" mode="$2" content
    content="$(cat)"
    if (( dry )); then
        echo "  [dry-run] ${path} (${mode}):"
        sed 's/^/      /' <<< "$content"
        return
    fi
    install -d -m 755 "$(dirname "$path")"
    printf '%s\n' "$content" > "${path}.gasapp-new"
    chmod "$mode" "${path}.gasapp-new"
    mv -f "${path}.gasapp-new" "$path"
}

# --- Проверки до изменений ----------------------------------------------------

(( EUID == 0 )) || die "запускать от root"
[[ "$role" =~ ^(node|lb|db)(,(node|lb|db))*$ ]] || die "--role: node, lb, db или несколько через запятую"
has_role() { [[ ",${role}," == *",$1,"* ]]; }
[[ "$admin" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "--admin: имя пользователя для входа"
[[ -r /etc/os-release ]] && . /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *debian* ]] \
    || die "поддерживаются Debian и Ubuntu"

if has_role node && [[ -z "$lb" ]]; then die "для node нужен --lb <адрес балансировщика>"; fi
if has_role db && [[ -z "$nodes" ]]; then die "для db нужен --nodes \"<адреса узлов>\""; fi

id "$admin" > /dev/null 2>&1 || die "пользователя ${admin} нет: adduser ${admin}"
admin_home="$(getent passwd "$admin" | cut -d: -f6)"
keys="${admin_home}/.ssh/authorized_keys"
[[ -s "$keys" ]] && grep -qE '^(ssh-|ecdsa-|sk-)' "$keys" \
    || die "у ${admin} нет ключа в ${keys} — вход по паролю выключать нельзя, вы запрёте себя"
id -nG "$admin" | grep -qwE 'sudo|wheel' \
    || die "${admin} не в группе sudo — без root-входа на машину будет не попасть: usermod -aG sudo ${admin}"

# --- 1. Пакеты ---------------------------------------------------------------

step "пакеты"
export DEBIAN_FRONTEND=noninteractive
run apt-get update -q
run apt-get install -y -q unattended-upgrades apt-listchanges ufw chrony fail2ban \
    needrestart curl ca-certificates openssl jq
# Узел времени — chrony; второй клиент NTP не нужен.
run systemctl disable --now systemd-timesyncd 2>/dev/null || true

step "автообновления безопасности"
put /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
put /etc/apt/apt.conf.d/52gasapp-unattended 644 <<EOF
// GasApp: только обновления безопасности, без участия человека.
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$( (( auto_reboot )) && echo true || echo false )";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
# needrestart: перезапускать службы после обновления библиотек самому,
# а не спрашивать (спросить некого).
put /etc/needrestart/conf.d/90-gasapp.conf 644 <<'EOF'
$nrconf{restart} = 'a';
EOF

# --- 2. SSH -------------------------------------------------------------------

step "SSH"
put /etc/ssh/sshd_config.d/10-gasapp.conf 600 <<EOF
# GasApp: вход только по ключу и только для ${admin}.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
AllowUsers ${admin}

MaxAuthTries 3
MaxSessions 4
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

# Туннель к админ-центру (ssh -L) нужен; остальное — нет.
AllowTcpForwarding local
AllowAgentForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no
PermitUserEnvironment no

# Сессии видно в журнале с отпечатком ключа.
LogLevel VERBOSE
EOF
if (( ! dry )); then
    sshd -t || { rm -f /etc/ssh/sshd_config.d/10-gasapp.conf; die "sshd -t не прошёл — изменения SSH отменены"; }
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
fi

put /etc/fail2ban/jail.d/gasapp.local 644 <<'EOF'
# GasApp: только sshd. Адреса тех, кто перебирает SSH, — не адреса
# пользователей мессенджера: эти в журналы не попадают нигде.
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
run systemctl enable --now fail2ban
run systemctl restart fail2ban

# --- 3. Ядро ------------------------------------------------------------------

step "sysctl"
put /etc/sysctl.d/90-gasapp.conf 644 <<'EOF'
# GasApp: укрепление ядра.

# Адреса ядра и его журнал — не для непривилегированных: подсказки
# для эксплойтов.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# ptrace — только root: взломанная служба не прочитает память другой
# (в памяти узла — ключ подписи сертификатов).
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0

# Без дампов памяти: в них ключи.
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Сеть.
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# 🔐 log_martians намеренно НЕ включается: он пишет в журнал адреса
# источников странных пакетов — то есть адреса клиентов.
net.ipv4.conf.all.log_martians = 0
EOF
# Ключа может не быть в ядре (bpf_jit_harden — без BPF JIT): это не
# повод обрывать укрепление на середине.
run sysctl --system -q -e > /dev/null     || echo "  ⚠️ часть ключей sysctl не применилась — посмотрите: sysctl --system"

# --- 4. Дампы памяти ----------------------------------------------------------

step "без дампов памяти"
put /etc/security/limits.d/90-gasapp.conf 644 <<'EOF'
*    hard    core    0
root hard    core    0
EOF
put /etc/systemd/coredump.conf.d/90-gasapp.conf 644 <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
put /etc/systemd/system.conf.d/90-gasapp.conf 644 <<'EOF'
[Manager]
DefaultLimitCORE=0
EOF

# --- 5. Журнал ----------------------------------------------------------------

step "журнал"
put /etc/systemd/journald.conf.d/90-gasapp.conf 644 <<'EOF'
# GasApp: журнал — тоже данные, которые изымают вместе с диском.
# Две недели хватает разобрать сбой; дольше — незачем.
[Journal]
Storage=persistent
MaxRetentionSec=14day
SystemMaxUse=500M
# Не дублировать в /var/log/syslog: там свой срок (logrotate),
# и про него забывают.
ForwardToSyslog=no
EOF
run systemctl restart systemd-journald
run systemctl daemon-reload

# --- 6. Брандмауэр ------------------------------------------------------------

step "брандмауэр (${role})"
run ufw --force reset > /dev/null
run ufw default deny incoming
run ufw default allow outgoing
run ufw default deny routed
if [[ -f /etc/wireguard/wg0.conf ]]; then
    # Four VPS on separate IONOS contracts exchange only WireGuard packets
    # over public IPs. The role rules below still guard tunneled services.
    run ufw allow 51820/udp
fi

if [[ -n "$ssh_from" ]]; then
    for net in $ssh_from; do run ufw allow from "$net" to any port 22 proto tcp; done
else
    # limit: больше шести попыток за 30 с с одного адреса — отказ.
    run ufw limit 22/tcp
fi

if has_role node; then
    # Узел — только для балансировщика (и монитора на нём).
    run ufw allow from "$lb" to any port 8443 proto tcp
fi
if has_role lb; then
    run ufw allow 80/tcp
    run ufw allow 443/tcp
    if [[ -n "$onion" ]]; then
        run ufw allow from "$onion" to any port 8444 proto tcp
    fi
fi
if has_role db; then
    for node in $nodes; do run ufw allow from "$node" to any port 5432 proto tcp; done
fi
# Почтовый релей (Postfix) на балансировщике: письма с кодом от узлов.
# Только внутренней сети — открытый в интернет релей рассылал бы спам
# от имени домена.
for net in $relay_from; do run ufw allow from "$net" to any port 25 proto tcp; done
run ufw logging off
run ufw --force enable

# --- 7. Пользователи и каталоги ----------------------------------------------

step "пользователи служб и каталоги"
make_user() {
    id "$1" > /dev/null 2>&1 && return
    run useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$1"
}
if has_role node; then make_user gasapp; fi
if has_role db; then make_user gasapp-admin; fi
# Монитор — на каждой машине; журнал читает через группу.
make_user gasapp-monitor
run usermod -aG systemd-journal gasapp-monitor

run install -d -m 755 -o root -g root /etc/gasapp /etc/gasapp/pki /opt/gasapp
# Секреты: только root. Службы получают их через LoadCredential.
run install -d -m 700 -o root -g root /etc/gasapp/credentials
if has_role db; then
    # Зашифрованные копии базы администратор забирает на свою машину
    # (rsync под --admin): каталог принадлежит группе gasapp-backup,
    # и файлы получают её сами (setgid). Читать группе можно только
    # готовый .age — открытый дамп backup.sh создаёт с правами 600.
    getent group gasapp-backup > /dev/null || run groupadd --system gasapp-backup
    run usermod -aG gasapp-backup "$admin"
    if id postgres > /dev/null 2>&1; then
        run install -d -m 2750 -o postgres -g gasapp-backup /var/backups/gasapp
    else
        echo "  ⚠️ PostgreSQL ещё не установлен — каталог копий создайте после установки:"
        echo "     install -d -m 2750 -o postgres -g gasapp-backup /var/backups/gasapp"
    fi
    # ⚠️ PostgreSQL в Debian/Ubuntu ждёт только network.target — то есть
    # может стартовать раньше, чем частная сеть получит адрес. Тогда он
    # не падает, а молча слушает один localhost: после перезагрузки узлы
    # не видят базу. Ждать сети по-настоящему.
    put /etc/systemd/system/postgresql@.service.d/10-gasapp-network.conf 644 <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target
EOF
    run systemctl daemon-reload
fi

step "готово"
cat <<EOF

Проверьте, НЕ закрывая эту сессию:

  1. новый вход по ключу:   ssh ${admin}@<адрес>
  2. sudo:                   sudo -v
  3. брандмауэр:             ufw status verbose
  4. пароль не принимается:  ssh -o PubkeyAuthentication=no ${admin}@<адрес>   # → Permission denied

Если что-то не так — в этой сессии:
  rm /etc/ssh/sshd_config.d/10-gasapp.conf && systemctl reload ssh
EOF
