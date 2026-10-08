-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0018: премиум-аккаунты и каналы.
--
-- # Премиум
--
-- Флаг на аккаунте. Выдаётся оператором вручную (админ-центр или
-- `gasapp-server-admin premium grant`). Пока даёт одно право —
-- создавать каналы.
--
-- Дамп даёт: у каких аккаунтов есть премиум.

ALTER TABLE accounts
    ADD COLUMN premium BOOLEAN NOT NULL DEFAULT false;

-- В журнал действий оператора (`admin_actions`) выдача премиума не
-- пишется: журнал — основа отчёта о прозрачности модерации, а премиум
-- к модерации не относится.

-- # Каналы
--
-- Канал — лента записей одного автора для многих читателей.
--
-- 🔐 Что сервер знает о канале и чего не знает:
--
--   * знает: что канал есть, какому аккаунту он принадлежит, сколько
--     в нём записей, их размер и час публикации;
--   * НЕ знает: название, описание и текст записей — это шифротекст
--     на ключе канала, который живёт в ссылке-приглашении и на сервер
--     не попадает;
--   * НЕ знает: кто канал читает. Таблицы подписчиков нет намеренно —
--     она была бы социальным графом. Читатель забирает записи без
--     подписи, зная только идентификатор канала; подписка хранится
--     на его устройстве.
--
-- Дамп даёт: список каналов с владельцами и шифроблобы записей.

CREATE TABLE channels (
    channel_id    UUID PRIMARY KEY,
    owner_account UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- Публичный ключ подписи записей (Ed25519). Сервер подписи не
    -- проверяет: её проверяют читатели, получившие ключ из ссылки.
    -- Здесь он лежит, чтобы читатель мог сверить его со ссылкой.
    verify_key    BYTEA NOT NULL CHECK (octet_length(verify_key) = 32),
    -- Название и описание — шифротекст с подписью автора.
    meta          BYTEA NOT NULL CHECK (octet_length(meta) BETWEEN 1 AND 8192),
    -- Номер последней записи; следующая получает `last_seq + 1`.
    last_seq      BIGINT NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now())
);

CREATE INDEX channels_by_owner ON channels (owner_account);

CREATE TABLE channel_posts (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    seq        BIGINT NOT NULL CHECK (seq >= 1),
    -- Шифротекст записи с подписью автора. Предел — 64 КБ.
    body       BYTEA NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 65536),
    -- С точностью до часа, как всё остальное (раздел 15.4). Точное
    -- время автор кладёт внутрь шифротекста — его видят читатели.
    posted_at  TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, seq)
);
