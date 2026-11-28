-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0033: жалобы переживают устройство, улики уходят с жалобщиком
-- (аудит 2026-11-28).
--
-- # Что здесь чинится
--
-- * `sealed_sender_reports.reported_device` ссылался на `devices` с
--   ON DELETE CASCADE (0006). Устройство удаляют не только вместе с
--   аккаунтом: основное отключает подключённое (MULTI-DEVICE.md §5), а
--   восстановление аккаунта ключом удаляет все прежние устройства. Тот,
--   на кого жаловались, отключал устройство, с которого слал спам, или
--   «восстанавливал» аккаунт — и жалобы на него исчезали. Теперь
--   устройство — просто метка; жалобу уносит только удаление
--   **аккаунта** (`reported_account`, как и прежде).
-- * Жалобщик тоже считался по устройству (`complainant_device`, тот же
--   каскад): с пятью устройствами аккаунта один человек выглядел как
--   пять, а отключение устройства стирало его жалобы. Теперь у жалобы
--   есть `complainant_account`: по нему считаются «разные люди», одна
--   жалоба — от одного аккаунта на один аккаунт, а удаление аккаунта
--   жалобщика уносит его жалобы, как обещает политика удаления.
-- * `report_evidence.complainant_device` не ссылался ни на что: улики
--   переживали жалобщика. Теперь они уходят вместе с его устройством.
--
-- 🔐 Кто пожаловался, админ-центр по-прежнему не показывает: аккаунт
-- жалобщика нужен только для подсчёта.

ALTER TABLE sealed_sender_reports ADD COLUMN complainant_account UUID;

UPDATE sealed_sender_reports AS r
   SET complainant_account = d.account_id
  FROM devices AS d
 WHERE d.device_id = r.complainant_device;

-- Каскад по `complainant_device` не давал жалобе пережить устройство,
-- так что безымянных строк быть не должно; если есть — им не на чем
-- держаться.
DELETE FROM sealed_sender_reports WHERE complainant_account IS NULL;

-- Повторные жалобы одного аккаунта на один аккаунт (с разных своих
-- устройств или на разные устройства обидчика) сводятся к первой.
-- Причина, если её не было у первой, берётся у повторной.
UPDATE sealed_sender_reports AS keep
   SET reason = later.reason
  FROM sealed_sender_reports AS later
 WHERE keep.reason IS NULL
   AND later.reason IS NOT NULL
   AND later.complainant_account = keep.complainant_account
   AND later.reported_account = keep.reported_account
   AND later.report_seq <> keep.report_seq;

DELETE FROM sealed_sender_reports AS r
 USING sealed_sender_reports AS earlier
 WHERE earlier.complainant_account = r.complainant_account
   AND earlier.reported_account = r.reported_account
   AND earlier.report_seq < r.report_seq;

ALTER TABLE sealed_sender_reports
    ALTER COLUMN complainant_account SET NOT NULL,
    ADD CONSTRAINT sealed_sender_reports_complainant_account_fkey
        FOREIGN KEY (complainant_account) REFERENCES accounts(account_id) ON DELETE CASCADE,
    DROP CONSTRAINT sealed_sender_reports_reported_device_fkey,
    DROP CONSTRAINT sealed_sender_reports_complainant_device_fkey;

DROP INDEX sealed_sender_reports_unique;

CREATE UNIQUE INDEX sealed_sender_reports_unique
    ON sealed_sender_reports (complainant_account, reported_account);

-- Улики без жалобщика — прочь, иначе внешний ключ не встанет.
DELETE FROM report_evidence AS e
 WHERE NOT EXISTS (SELECT 1 FROM devices WHERE device_id = e.complainant_device);

ALTER TABLE report_evidence
    ADD CONSTRAINT report_evidence_complainant_device_fkey
        FOREIGN KEY (complainant_device) REFERENCES devices(device_id) ON DELETE CASCADE;
