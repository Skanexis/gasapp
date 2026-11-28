<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Раздельные роли базы и закреплённый ключ улик

Аудит 2026-11-28, находки S-10 и S-4.

## Зачем

До перехода все службы входили в базу одной ролью `gasapp`, владельцем
схемы:

* **узлы API** смотрят в интернет;
* **админ-центр** работает на машине базы;
* **отправщик пушей** ходит к Apple и Google.

Взломанный узел мог менять схему, читать журнал действий оператора и
подменить открытый ключ улик в `admin_state`. Тогда телефоны отдали бы
цитаты переписки и скриншоты из жалоб под чужой ключ.

После перехода:

| Роль | Кто | Что может |
|---|---|---|
| `gasapp` | `gasapp-migrate.service`, только с машины базы | схема: миграции, права ролей |
| `gasapp_api` | узлы API | строки таблиц сервера; из `admin_state` — только открытый ключ улик; журнала оператора не видит; схему не меняет |
| `gasapp_admin` | админ-центр, `watch-reports` | строки всех таблиц; схему не меняет |
| `gasapp_push` | отправщик пушей (свой пользователь ОС `gasapp-push`) | только `push_tokens`: прочесть токен, забыть мёртвый |

Права описаны в [`server/deploy/postgres/roles.sql`](../../server/deploy/postgres/roles.sql).
Их раздаёт `gasapp-server-admin migrate` после каждой миграции, так что
таблицы новых миграций получают права тем же проходом. Служба без права
менять схему ничего не мигрирует. Она только сверяет, что все миграции её
сборки уже в базе, а если нет — не стартует и пишет, что делать.

Ключ улик закрепляется в приложении. Узел по-прежнему отдаёт его
(`/v1/sealed/report-key`), но телефон запечатывает улики только под ключ,
вшитый в сборку. Если ключ от узла другой, жалоба уходит без улик, а в
журнал безопасности телефона пишется `report_evidence_key_mismatch`.
Админ-центр каждые пять минут сверяет ключ в базе со своим. Подмену он
отмечает в журнале и возвращает свой ключ.

## Порядок перехода (один раз)

Все шаги — после выкладки новых программ `gasapp-server-api` и
`gasapp-server-admin`.

1. **Админ-центр.** Выполните `server/deploy/admin.sh --install`. Он
   поставит `gasapp-migrate.service` и сохранит строку владельца как
   `/etc/gasapp/credentials/owner_database_url`, затем применит миграции.
2. **Роли.** На машине базы:

       sudo bash ~/deploy/postgres/create-roles.sh

   Скрипт:
   * добавит в `pg_hba.conf` строки новых ролей рядом с прежними и
     поставит `pg_ident.conf`. Сертификат узла с `CN = gasapp` пускает
     только ролью `gasapp_api`, перевыпускать его не нужно;
   * заведёт роли со случайными паролями и запишет `admin_database_url`
     и `push_database_url`;
   * сохранит пароль узлов в `api_database_password`, заведёт
     пользователя ОС `gasapp-push` и раздаст права.

   Пароли не печатаются.
3. **Пароль узлов в Bitwarden.** Создайте запись «GasApp: пароль базы для
   узлов» и вставьте туда вывод `sudo cat /etc/gasapp/credentials/api_database_password`.
4. **Службы на машине базы.** Скопируйте новый `gasapp-push.service` в
   `/etc/systemd/system/`, затем выполните:

       sudo systemctl daemon-reload
       sudo systemctl restart gasapp-admin gasapp-push

5. **Каждый узел.** Скопируйте на узел `server/deploy/postgres/node-role.sh`
   в `~/deploy/postgres/` и выполните:

       sudo bash ~/deploy/postgres/node-role.sh

   Скрипт спросит пароль из шага 3 (ввод не виден) и перезапустит узел.
   Если узел не поднимется, скрипт вернёт прежнюю строку подключения.
6. **Убрать вход владельца с узлов.** Когда все узлы перешли:

       sudo bash ~/deploy/postgres/create-roles.sh --finish

7. **Ключ улик в приложение.** На машине базы:

       sudo env GASAPP_EVIDENCE_KEY_FILE=/etc/gasapp/credentials/evidence_key \
           /usr/local/bin/gasapp-server-admin evidence-public-key

   Команда печатает **открытый** ключ, это не секрет. Впишите его в
   `tools/release.conf` как `EVIDENCE_KEY=` и выполните
   `python3 tools/apply-release-config.py`. Ключ войдёт в следующие сборки
   Android и iOS.

## Обновления после перехода

Перед выкладкой новых программ на узлы применяйте миграции на машине
базы:

    sudo systemctl start gasapp-migrate

Узел с программой новее схемы не стартует и пишет: «схема базы старше
программы … выполните `gasapp-server-admin migrate`». `admin.sh --install`
применяет миграции сам.

## Проверка

* `sudo journalctl -u gasapp-migrate -n 5` — «миграции применены, права
  ролей розданы».
* На машине базы: `sudo -u postgres psql -d gasapp -c '\du'` показывает
  `gasapp_api`, `gasapp_admin`, `gasapp_push` без атрибутов
  суперпользователя.
* Тест `service_roles_get_only_their_rights`
  (`server/gasapp-server-db/tests/postgres.rs`) проверяет права на
  настоящем Postgres.

## Откат

* **Узел:** верните его прежнюю строку подключения из Bitwarden (роль
  `gasapp`) и выполните `systemctl restart gasapp-server`. Это работает,
  пока не выполнен шаг 6.
* **После шага 6:** восстановите `pg_hba.conf` из копии
  `pg_hba.conf.before-finish`.
* **Админ-центр и пуши:** скопируйте `owner_database_url` в
  `admin_database_url` и `push_database_url`.
* **Смена ключа улик:** оператор выпускает новую сборку с новым
  `EVIDENCE_KEY`. Телефоны со старой сборкой будут отправлять жалобы без
  улик, пока не обновятся.
