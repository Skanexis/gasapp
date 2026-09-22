-- 0006: оставшиеся точные метки времени и жалобы, пережившие аккаунт.
--
-- # Что здесь чинится
--
-- 0005 округлила до часа время конвертов и вложений. Точными остались
-- две метки (аудит, 2026-09):
--
-- * `signed_prekeys.updated_at` — момент публикации подписанного
--   предключа, то есть момент, когда устройство было в сети и
--   обслуживало ключи; ряд таких моментов — распорядок владельца;
-- * `sealed_sender_reports.created_at` — момент жалобы. Комментарий
--   в 0004 обещал, что оно «округляется до часа при выдаче», но
--   от дампа это не защищает — как и было с конвертами до 0005.
--
-- И жалобы переживали удаление аккаунта: `reported_account`
-- и `reported_device` не ссылались ни на что, и после удаления
-- в базе оставалось «на этот аккаунт жаловались вот эти устройства».
-- Политика удаления обещает, что после удаления аккаунта о нём
-- не остаётся ничего.
--
-- ⚠️ Старые версии строк после UPDATE и DELETE ниже остаются в файлах
-- Postgres до VACUUM — см. руководство по развёртыванию, как для 0005.

ALTER TABLE signed_prekeys
    ALTER COLUMN updated_at SET DEFAULT date_trunc('hour', now());

UPDATE signed_prekeys
SET updated_at = date_trunc('hour', updated_at);

ALTER TABLE sealed_sender_reports
    ALTER COLUMN created_at SET DEFAULT date_trunc('hour', now());

UPDATE sealed_sender_reports
SET created_at = date_trunc('hour', created_at);

-- Жалобы на уже удалённые аккаунты — прочь, иначе внешний ключ
-- ниже не встанет.
DELETE FROM sealed_sender_reports AS report
WHERE NOT EXISTS (SELECT 1 FROM accounts WHERE account_id = report.reported_account)
   OR NOT EXISTS (SELECT 1 FROM devices WHERE device_id = report.reported_device);

ALTER TABLE sealed_sender_reports
    ADD CONSTRAINT sealed_sender_reports_reported_account_fkey
        FOREIGN KEY (reported_account) REFERENCES accounts(account_id) ON DELETE CASCADE,
    ADD CONSTRAINT sealed_sender_reports_reported_device_fkey
        FOREIGN KEY (reported_device) REFERENCES devices(device_id) ON DELETE CASCADE;
