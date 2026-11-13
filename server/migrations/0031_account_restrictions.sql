-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0031: заморозка и блокировка аккаунта — решения оператора мягче
-- удаления.
--
-- * Заморозка — до срока (`restricted_until` в будущем): аккаунт и его
--   переписка целы, но подписанные запросы его устройств сервер
--   отвергает (`423`), кроме вопроса о статусе — по нему приложение
--   показывает, что случилось и до какого времени. Срок вышел —
--   ограничение снято само, без задач по расписанию.
-- * Блокировка — `restricted_until = 'infinity'`: то же, пока оператор
--   не снимет. Имя и адрес почты остаются занятыми — заново под ними не
--   зарегистрироваться, а по имени аккаунт не находится.
--
-- Ограничение владельца действует и на его ботов (проверяется при
-- каждом запросе, а не копируется).
--
-- 🔐 Хранятся только срок и причина (из того же короткого списка, что
-- у удаления). Кто пожаловался, здесь нет.

ALTER TABLE accounts
    ADD COLUMN restricted_until   TIMESTAMPTZ,
    ADD COLUMN restriction_reason TEXT
        CHECK (restriction_reason IS NULL OR restriction_reason IN
               ('spam', 'harassment', 'csae', 'impersonation', 'illegal', 'other'));

-- Журнал оператора узнаёт о новых решениях — как и прежде, без имён.
ALTER TABLE admin_actions
    DROP CONSTRAINT admin_actions_action_check,
    ADD CONSTRAINT admin_actions_action_check
        CHECK (action IN ('account_deleted', 'reports_dismissed',
                          'channel_deleted', 'channel_reports_dismissed',
                          'account_frozen', 'account_blocked',
                          'restriction_lifted'));
