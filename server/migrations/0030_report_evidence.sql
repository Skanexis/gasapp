-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Центр жалоб: причина жалобы и улики, запечатанные ключом оператора.
--
-- Причина — открыто: по ней жалобы разбираются по срочности
-- (безопасность детей — сразу). Коды: 1 спам или мошенничество,
-- 2 незаконное, 3 безопасность детей, 4 травля или угрозы, 5 другое,
-- 6 выдаёт себя за другого. У старых жалоб причины нет (NULL).
--
-- 🔐 Улики — то, что жалобщик сам решил показать (сообщения обидчика,
-- скриншоты). Телефон шифрует их открытым ключом админ-центра
-- (`gasapp_protocol::report_evidence`); здесь лежит только шифр.
-- Закрытый ключ — у админ-центра в его учётных данных, не в базе.
-- Дамп базы улик не раскрывает.
--
-- Хранятся, пока дело открыто, и не дольше 30 дней: решение по
-- аккаунту (отклонить, удалить) уносит их; старше 30 дней удаляются
-- при новой жалобе и при открытии центра жалоб.

ALTER TABLE sealed_sender_reports
    ADD COLUMN reason SMALLINT CHECK (reason IS NULL OR reason BETWEEN 1 AND 6);

-- Открытый ключ X25519 админ-центра: его пишет сам админ-центр при
-- запуске, узлы отдают его телефонам (`/v1/sealed/report-key`).
ALTER TABLE admin_state
    ADD COLUMN evidence_key BYTEA CHECK (evidence_key IS NULL OR octet_length(evidence_key) = 32);

CREATE TABLE report_evidence (
    reported_account   UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- Чтобы повторная жалоба заменяла улики, а не копила их. Админ-центр
    -- его не показывает: кто пожаловался, оператору знать незачем.
    complainant_device UUID NOT NULL,
    sealed             BYTEA NOT NULL CHECK (octet_length(sealed) BETWEEN 64 AND 1945600),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (reported_account, complainant_device)
);

CREATE INDEX report_evidence_by_age ON report_evidence (created_at);
