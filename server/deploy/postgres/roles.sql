-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Права ролей базы GasApp (аудит 2026-11-28, S-10).
--
-- Прежде узлы API (смотрят в интернет), админ-центр и отправщик пушей
-- (ходит к Apple и Google) работали под одной ролью `gasapp` — владельцем
-- схемы. Взломанный узел мог всё: менять схему, читать журнал действий
-- оператора, подменить открытый ключ улик в `admin_state`. Теперь:
--
-- * `gasapp`        — владелец схемы; только миграции
--                     (`gasapp-server-admin migrate`), только с машины базы;
-- * `gasapp_api`    — узлы API: строки таблиц сервера, без схемы; из
--                     `admin_state` — только открытый ключ улик, журнала
--                     действий оператора не видит;
-- * `gasapp_admin`  — админ-центр: строки всех таблиц, без схемы;
-- * `gasapp_push`   — отправщик пушей: только `push_tokens` (прочесть
--                     токен, забыть мёртвый).
--
-- Роли заводит суперпользователь (`create-roles.sh`). Этот файл
-- выполняет владелец после каждой миграции (`gasapp-server-admin
-- migrate`), поэтому он повторяем: таблицы новых миграций получают права
-- тем же проходом.

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO gasapp_api, gasapp_admin, gasapp_push;

-- Строки — да, схема — нет.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gasapp_api, gasapp_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gasapp_api, gasapp_admin;

-- 🔐 Узлу — ни журнала оператора, ни записи в его состояние: подменённый
-- ключ улик читался бы взломанным узлом.
REVOKE ALL ON admin_state, admin_actions FROM gasapp_api;
GRANT SELECT (evidence_key) ON admin_state TO gasapp_api;

-- Журнал миграций — только прочесть: служба сверяет, что схема не старше
-- кода (`GASAPP_DB_MIGRATIONS=check`).
REVOKE ALL ON _sqlx_migrations FROM gasapp_api, gasapp_admin, gasapp_push;
GRANT SELECT ON _sqlx_migrations TO gasapp_api, gasapp_admin, gasapp_push;

-- Отправщику пушей — только токены.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM gasapp_push;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM gasapp_push;
GRANT SELECT ON _sqlx_migrations TO gasapp_push;
GRANT SELECT, DELETE ON push_tokens TO gasapp_push;
