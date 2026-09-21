-- 0005: время в хранимых метаданных — с точностью до часа.
--
-- # Что здесь чинится
--
-- Документ о сроках хранения обещал, что сервер не может выдать время
-- отправки недоставленного конверта: «перечисленного нет в базе».
-- В базе оно было — с точностью до микросекунды:
--
-- * `envelopes.queued_at DEFAULT now()` — момент постановки в очередь,
--   то есть момент отправки;
-- * `envelopes.expires_at = now() + ttl` — тот же момент, сдвинутый
--   на тридцать суток;
-- * `attachments.uploaded_at` и `attachments.expires_at` — то же для
--   вложений, **рядом с `uploader_device_id`**.
--
-- Последнее хуже всего. Sealed sender скрывает отправителя конверта,
-- но вложение хранит, кто его загрузил. Точное время загрузки плюс
-- точное время конверта позволяли по дампу связать загрузившего
-- с получателем — то есть обойти sealed sender для любого сообщения
-- с вложением.
--
-- Округление до часа прежде делалось только **при выдаче клиенту**
-- (`bucket_to_hour`). От того, кому оно было нужно, — от дампа —
-- оно не защищало вовсе.
--
-- # Как сохраняется порядок доставки
--
-- Порядок держался на `ORDER BY queued_at`. С часовой точностью
-- конверты одного часа стали бы неупорядочены, а начальное сообщение
-- сессии, пришедшее после следующего за ним, не расшифровалось бы.
--
-- Поэтому у конверта есть позиция в очереди **своего получателя**.
-- Не глобальный счётчик: тот выдал бы порядок сообщений между разными
-- людьми — «A написал B, и сразу B ответил A». Позиция считается от
-- уже лежащих в очереди этого устройства и сбрасывается, когда очередь
-- пуста, так что она не накапливает и число полученных сообщений.
--
-- ⚠️ Старые версии строк после UPDATE ниже остаются в файлах Postgres
-- до VACUUM. Миграция выполняется один раз; VACUUM после неё указан
-- в руководстве по развёртыванию.

ALTER TABLE envelopes ADD COLUMN queue_position BIGINT NOT NULL DEFAULT 0;

-- Позиции для уже лежащих конвертов — по прежнему точному времени,
-- пока оно ещё есть.
UPDATE envelopes AS target
SET queue_position = ranked.position
FROM (
    SELECT envelope_id,
           ROW_NUMBER() OVER (PARTITION BY destination_device_id ORDER BY queued_at) AS position
    FROM envelopes
) AS ranked
WHERE target.envelope_id = ranked.envelope_id;

UPDATE envelopes
SET queued_at  = date_trunc('hour', queued_at),
    expires_at = date_trunc('hour', expires_at);

UPDATE attachments
SET uploaded_at = date_trunc('hour', uploaded_at),
    expires_at  = date_trunc('hour', expires_at);

ALTER TABLE envelopes   ALTER COLUMN queued_at   SET DEFAULT date_trunc('hour', now());
ALTER TABLE attachments ALTER COLUMN uploaded_at SET DEFAULT date_trunc('hour', now());

DROP INDEX IF EXISTS envelopes_by_destination;
CREATE INDEX envelopes_by_destination ON envelopes (destination_device_id, queue_position);
