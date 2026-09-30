-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Админ-центр оператора (`aegis-server-admin`).
--
-- 🔐 Здесь нет ничего о людях. Журнал действий оператора хранит, ЧТО
-- сделано и ПОЧЕМУ, но не с кем: имя удалённого аккаунта в нём
-- нарушило бы обещание политики «после удаления об аккаунте не остаётся
-- ничего». Из журнала собирается отчёт о прозрачности — сколько
-- аккаунтов удалено по жалобам и за что, по месяцам.

CREATE TABLE admin_actions (
    action_id  BIGSERIAL PRIMARY KEY,

    action     TEXT NOT NULL
        CHECK (action IN ('account_deleted', 'reports_dismissed')),

    reason     TEXT NOT NULL
        CHECK (reason IN ('spam', 'harassment', 'csae', 'impersonation',
                          'illegal', 'other', 'unfounded')),

    -- Сколько разных людей пожаловались — основание решения.
    reporters  INTEGER NOT NULL CHECK (reporters >= 0),

    -- С точностью до часа, как всё остальное (раздел 15.4).
    created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now())
);

-- Порядковый номер жалобы: по нему уведомление о новых жалобах
-- (`aegis-server-admin watch-reports`) знает, какие уже видело.
-- Номер, а не время: время жалобы огрублено до часа, и по нему не
-- отличить новую жалобу от старой в том же часе.
ALTER TABLE sealed_sender_reports ADD COLUMN report_seq BIGSERIAL;

CREATE TABLE admin_state (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    -- Последняя жалоба, о которой оператор уже уведомлён.
    last_report_seq  BIGINT NOT NULL DEFAULT 0
);

INSERT INTO admin_state (id, last_report_seq) VALUES (1, 0);
