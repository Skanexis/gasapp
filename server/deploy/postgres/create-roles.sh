#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Раздельные роли базы (аудит 2026-11-28, S-10) — на машине базы, от root:
#
#     sudo bash ~/deploy/postgres/create-roles.sh
#
# Повторяем: существующие роли не пересоздаются, но получают новый пароль
# (так же меняют пароли, если один утёк). Порядок перехода целиком —
# docs/ops/db-roles.md.
#
# Делает:
#   0. добавляет в pg_hba.conf строки новых ролей рядом с прежними и
#      ставит pg_ident.conf (сертификат узла CN=gasapp → gasapp_api);
#   1. сохраняет строку владельца схемы `gasapp` как owner_database_url
#      (до перехода её держал admin_database_url) — ею пользуется только
#      gasapp-migrate.service;
#   2. заводит роли gasapp_api, gasapp_admin, gasapp_push (LOGIN, без
#      прав суперпользователя) со случайными паролями;
#   3. пишет admin_database_url (gasapp_admin) и push_database_url
#      (gasapp_push), пароль узлов — в api_database_password;
#   4. заводит системного пользователя gasapp-push;
#   5. запускает gasapp-migrate.service — права ролей (roles.sql).
#
# 🔐 Пароли не печатаются: они в файлах 600 в /etc/gasapp/credentials и
# уходят в Postgres через stdin, а не аргументами (их видно в ps).
set -euo pipefail

ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m✘ %s\033[0m\n\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускайте от root: sudo bash $0"
cred=/etc/gasapp/credentials
[[ -d "$cred" ]] || die "нет $cred — машина базы ещё не настроена"

hba="$(sudo -u postgres psql -X -tAc 'SHOW hba_file')"
ident="$(sudo -u postgres psql -X -tAc 'SHOW ident_file')"

# --finish: все узлы перешли — владелец схемы больше не входит с узлов.
if [[ "${1:-}" == "--finish" ]]; then
    cp -p "$hba" "$hba.before-finish"
    sed -i -E '/^hostssl[[:space:]]+gasapp[[:space:]]+gasapp[[:space:]]/d' "$hba"
    systemctl reload postgresql
    ok "владелец схемы gasapp с узлов больше не входит (копия: $hba.before-finish)"
    exit 0
fi

# Переход: рядом со строками владельца — строки новых ролей (узлы ещё
# входят прежней строкой, пока не выполнят node-role.sh). Повторный
# запуск ничего не дублирует.
if ! grep -qE '^local[[:space:]]+gasapp[[:space:]]+gasapp_admin' "$hba"; then
    cp -p "$hba" "$hba.before-roles"
    awk '
        /^local[[:space:]]+gasapp[[:space:]]+gasapp[[:space:]]/ {
            print
            print "local     gasapp    gasapp_admin                  scram-sha-256"
            print "local     gasapp    gasapp_push                   scram-sha-256"
            next
        }
        /^hostssl[[:space:]]+gasapp[[:space:]]+gasapp[[:space:]]/ {
            print "hostssl   gasapp    gasapp_api     " $4 "    scram-sha-256  clientcert=verify-full map=gasapp_nodes"
        }
        { print }
    ' "$hba.before-roles" > "$hba"
    install -m 640 -o postgres -g postgres "$(dirname "$0")/pg_ident.conf" "$ident"
    systemctl reload postgresql
    ok "pg_hba.conf: строки новых ролей добавлены (копия: $hba.before-roles), pg_ident.conf на месте"
fi

# 1. Строка владельца.
if [[ ! -s "$cred/owner_database_url" ]]; then
    [[ -s "$cred/admin_database_url" ]] || die "нет ни owner_database_url, ни admin_database_url"
    grep -q '^postgres://gasapp:' "$cred/admin_database_url" ||
        die "admin_database_url уже не владельца — положите строку владельца в $cred/owner_database_url сами"
    install -m 600 "$cred/admin_database_url" "$cred/owner_database_url"
    ok "строка владельца схемы сохранена: owner_database_url"
fi
owner_url="$(cat "$cred/owner_database_url")"

# Строка той же базы под другой ролью: меняются только имя и пароль.
url_for() { printf '%s' "$owner_url" | sed -E "s#^postgres://[^:/@]+:[^@]*@#postgres://$1:$2@#"; }

# 2–3. Роли и пароли (hex — без знаков, которые пришлось бы кодировать в URL).
for role in gasapp_api gasapp_admin gasapp_push; do
    password="$(openssl rand -hex 24)"
    sudo -u postgres psql -X -q -v ON_ERROR_STOP=1 -d gasapp > /dev/null << SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${role}') THEN
        CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
\$\$;
ALTER ROLE ${role} PASSWORD '${password}';
SQL
    case "$role" in
        gasapp_api)   printf '%s' "$password" | install -m 600 /dev/stdin "$cred/api_database_password" ;;
        gasapp_admin) url_for "$role" "$password" | install -m 600 /dev/stdin "$cred/admin_database_url" ;;
        gasapp_push)  url_for "$role" "$password" | install -m 600 /dev/stdin "$cred/push_database_url" ;;
    esac
    unset password
    ok "роль ${role}"
done

# 4. Пользователь отправщика пушей.
if ! id gasapp-push > /dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gasapp-push
    ok "пользователь gasapp-push"
fi

# 5. Права ролей.
install -m 644 "$(dirname "$0")/../systemd/gasapp-migrate.service" /etc/systemd/system/
systemctl daemon-reload
systemctl start gasapp-migrate.service ||
    die "миграции не прошли: journalctl -u gasapp-migrate -n 30 (программа gasapp-server-admin новая?)"
journalctl -u gasapp-migrate -n 5 --no-pager -o cat | grep -q "права ролей розданы" ||
    die "права ролей не розданы: journalctl -u gasapp-migrate -n 30"
ok "права ролей розданы"

cat << EOF

Дальше (docs/ops/db-roles.md, шаги 3–5):
  • пароль узлов — в $cred/api_database_password: сохраните в Bitwarden
    «GasApp: пароль базы для узлов» и на каждом узле выполните
        sudo bash ~/deploy/postgres/node-role.sh
  • перезапустите админ-центр и пуши: systemctl restart gasapp-admin gasapp-push
  • когда все узлы перешли — убрать вход владельца с узлов:
        sudo bash ~/deploy/postgres/create-roles.sh --finish
EOF
