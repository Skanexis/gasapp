-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0021: закрытые каналы — вход по заявке, которую одобряют.
--
-- # Как это устроено
--
-- У открытого канала ссылка-приглашение несёт ключ чтения: кто её
-- получил, тот и читает. У закрытого ссылка ключа не несёт. По ней
-- человек подаёт **заявку**; владелец или администратор её одобряет,
-- и его приложение передаёт одобренному ключ чтения — зашифровав под
-- ключ из заявки. Сервер хранит и заявку, и ответ, но прочитать ответ
-- не может.
--
-- Записи закрытого канала сервер отдаёт только участникам: владельцу,
-- администраторам и одобренным подписчикам.
--
-- # 🔐 Что сервер узнаёт нового — и чего по-прежнему не знает
--
-- * Кто подавал заявку в какой канал и кого одобрили. Подписчиков он
--   знал и раньше (миграция 0019).
-- * Владельцу и администраторам канала сервер теперь называет имена
--   подавших заявку и подписчиков: без этого некого одобрять и некого
--   удалять.
-- * Ключ чтения закрытого канала сервер не получает: заявка несёт
--   открытый ключ, ответ — шифротекст под него.
--
-- # ⚠️ Чего это НЕ даёт
--
-- * Удалённый подписчик ключ чтения помнит. Сервер перестаёт отдавать
--   ему записи, но ключ у канала прежний: получи он шифротекст новых
--   записей другим путём — прочтёт. Смены ключа при удалении нет.
-- * Сервер, подменивший открытый ключ в чужой заявке, получил бы ключ
--   чтения, когда заявку одобрят. Заявка подписана ключом аккаунта, и
--   приложение одобряющего сверяет подпись — но сам ключ аккаунта оно
--   узнаёт от сервера, если этот человек не сверенный контакт.

ALTER TABLE channels
    ADD COLUMN closed BOOLEAN NOT NULL DEFAULT false,
    -- Закрытый канал по @имени не находится: имя отдаёт ссылку с ключом.
    ADD CONSTRAINT channel_closed_is_not_public CHECK (NOT (closed AND handle IS NOT NULL));

-- Ссылки-приглашения закрытого канала. Сервер хранит хеш метки из
-- ссылки: по дампу ссылку не восстановить, а отозванная — не действует.
CREATE TABLE channel_invites (
    channel_id  UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    invite_hash BYTEA NOT NULL CHECK (octet_length(invite_hash) = 32),
    revoked     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, invite_hash)
);

-- Заявки на вход. `request` — открытый ключ заявителя с подписью его
-- аккаунта; сервер его не разбирает.
CREATE TABLE channel_join_requests (
    channel_id   UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    account_id   UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    request      BYTEA NOT NULL CHECK (octet_length(request) BETWEEN 1 AND 512),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, account_id)
);

CREATE INDEX channel_join_requests_by_account ON channel_join_requests (account_id);

-- Ответ на одобренную заявку: ключ чтения, зашифрованный под ключ из
-- заявки. Для сервера — непрозрачные байты.
CREATE TABLE channel_grants (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    grant_blob BYTEA NOT NULL CHECK (octet_length(grant_blob) BETWEEN 1 AND 512),
    PRIMARY KEY (channel_id, account_id)
);

-- Удалённые из канала: новая заявка от них не принимается.
CREATE TABLE channel_bans (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    banned_at  TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, account_id)
);
