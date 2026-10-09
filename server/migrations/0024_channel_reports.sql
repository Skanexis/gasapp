-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0024: жалобы на каналы.
--
-- Канал — пользовательский контент, который видят многие. Магазины
-- приложений требуют, чтобы на такой контент можно было пожаловаться из
-- приложения, а оператор — отреагировать (Google Play: User Generated
-- Content; Apple: Guideline 1.2).
--
-- # 🔐 Что видит оператор
--
-- Записи канала без публичного имени сервер прочитать не может. Поэтому
-- жалобщик может **сам** приложить к жалобе ссылку канала — ключ
-- чтения: тогда оператор открывает канал и видит, на что жалуются.
-- Приложение говорит об этом до отправки; без согласия ссылка не
-- уходит, и оператор судит по числу жалоб и по разговору с владельцем.
--
-- У закрытого канала после смены ключа ссылка новых записей не
-- открывает — приложение её не прикладывает.
--
-- # Что хранится
--
-- Кто пожаловался, на какой канал, причина, номер записи (если указан)
-- и, по выбору жалобщика, ссылка канала. Одна жалоба от аккаунта на
-- канал: повторная заменяет прежнюю.

CREATE TABLE channel_reports (
    channel_id       UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    reporter_account UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- 1 спам, 2 незаконное содержимое, 3 безопасность детей,
    -- 4 насилие и ненависть, 5 другое.
    reason           SMALLINT NOT NULL CHECK (reason BETWEEN 1 AND 5),
    post_seq         BIGINT CHECK (post_seq IS NULL OR post_seq > 0),
    channel_link     TEXT CHECK (channel_link IS NULL OR length(channel_link) <= 512),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, reporter_account)
);

-- Журнал действий оператора узнаёт о каналах: удалён по жалобам либо
-- жалобы отклонены. Как и прежде — без имён и идентификаторов.
ALTER TABLE admin_actions
    DROP CONSTRAINT admin_actions_action_check,
    ADD CONSTRAINT admin_actions_action_check
        CHECK (action IN ('account_deleted', 'reports_dismissed',
                          'channel_deleted', 'channel_reports_dismissed'));
