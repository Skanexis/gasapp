-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0019: каналы «как в Telegram» — правка и удаление записей, медиа,
-- публичные каналы с @именем, счётчики подписчиков и просмотров, реакции.
--
-- # 🔐 Что из этого сервер узнаёт нового — и чего по-прежнему не знает
--
-- * **На какие каналы подписан аккаунт — знает.** Подписка, отметка
--   «дочитал» и реакция делаются за подписью устройства: один аккаунт —
--   один подписчик. Иначе подписчиков накручивали бы циклом; анонимную
--   подписку нечем ограничить (решение владельца, ADR-035). Дамп базы
--   даёт список подписчиков каждого канала по аккаунтам.
-- * **Кто просто читает канал — не знает.** Записи и файлы по-прежнему
--   отдаются без подписи запроса: по ссылке канал читается и без
--   подписки.
-- * **Публичный канал сервер читать может.** Чтобы канал находился по
--   @имени, автор отдаёт серверу ссылку-приглашение — а в ней ключ
--   чтения. Это осознанная цена публичности: канал, который может
--   прочитать любой, знающий имя, может прочитать и сервер.
--   У канала без @имени (`public_link IS NULL`) всё по-старому: ключа
--   у сервера нет.
-- * Счётчики (подписчики, просмотры, реакции) ничем не подписаны:
--   сервер мог бы показать любые числа. Это статистика, а не
--   доказательство.

-- Ревизии. Каждое изменение канала — новая запись, правка, удаление —
-- получает следующий номер ревизии. Читатель помнит последнюю и
-- забирает только то, что изменилось после неё.
ALTER TABLE channels
    ADD COLUMN last_rev BIGINT NOT NULL DEFAULT 0 CHECK (last_rev >= 0),
    -- Число подписчиков — готовым числом. Чтение канала анонимно, и
    -- подсчёт строк при каждом запросе был бы работой, растущей с
    -- числом подписчиков: способом положить базу одним циклом.
    ADD COLUMN subscribers BIGINT NOT NULL DEFAULT 0 CHECK (subscribers >= 0);

ALTER TABLE channel_posts
    ADD COLUMN rev BIGINT NOT NULL DEFAULT 0 CHECK (rev >= 0),
    -- Удалённая запись остаётся строкой: в `body` — подписанная автором
    -- отметка об удалении. Без неё читатель, уже загрузивший запись,
    -- не узнал бы, что её больше нет.
    ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false,
    -- Просмотры — тоже готовым числом, по той же причине.
    ADD COLUMN views BIGINT NOT NULL DEFAULT 0 CHECK (views >= 0);

UPDATE channel_posts SET rev = seq;
UPDATE channels SET last_rev = last_seq;

CREATE INDEX channel_posts_by_rev ON channel_posts (channel_id, rev);

-- Публичное имя канала и ссылка-приглашение для него.
--
-- Дамп даёт: у публичных каналов — имя и ключ чтения, то есть их
-- содержимое. У остальных — ничего нового.
ALTER TABLE channels
    ADD COLUMN handle TEXT
        CHECK (handle IS NULL OR handle ~ '^[a-z][a-z0-9_]{2,31}$'),
    ADD COLUMN public_link TEXT
        CHECK (public_link IS NULL OR length(public_link) BETWEEN 1 AND 512),
    -- Имя без ссылки бессмысленно, ссылка без имени — утечка ключа.
    ADD CONSTRAINT channel_public_pair
        CHECK ((handle IS NULL) = (public_link IS NULL));

CREATE UNIQUE INDEX channels_by_handle ON channels (handle) WHERE handle IS NOT NULL;

-- Медиа канала: зашифрованные блобы (фото, файлы, аватар).
--
-- Не в общей таблице вложений: у тех срок тридцать суток, а запись
-- канала живёт, пока жив канал. Удаляются вместе с каналом либо
-- автором — вместе с записью.
--
-- Дамп даёт: шифроблобы и их размер (дополненный до сетки). Ключ —
-- внутри зашифрованной записи.
CREATE TABLE channel_media (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    media_id   UUID NOT NULL,
    blob       BYTEA NOT NULL CHECK (octet_length(blob) BETWEEN 1 AND 33554432),
    -- Размер отдельным столбцом: квота канала по объёму считается
    -- суммой, не читая сами блобы.
    size       INTEGER NOT NULL CHECK (size BETWEEN 1 AND 33554432),
    created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    PRIMARY KEY (channel_id, media_id)
);

-- Подписчики — аккаунты (см. шапку): один аккаунт — один подписчик.
--
-- Дамп даёт: какие аккаунты подписаны на какие каналы и до какой
-- записи каждый дочитал.
CREATE TABLE channel_subscribers (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- До какой записи дочитал: когда отметка идёт вперёд, пройденным
    -- записям засчитывается просмотр (`channel_posts.views`).
    seen_seq   BIGINT NOT NULL DEFAULT 0 CHECK (seen_seq >= 0),
    PRIMARY KEY (channel_id, account_id)
);

-- «На что подписан аккаунт» — при удалении аккаунта.
CREATE INDEX channel_subscribers_by_account ON channel_subscribers (account_id);

-- Реакции: одна на подписчика на запись.
CREATE TABLE channel_reactions (
    channel_id UUID NOT NULL,
    seq        BIGINT NOT NULL,
    account_id UUID NOT NULL,
    -- Набор закрыт: произвольная строка здесь была бы каналом, по
    -- которому читатели пишут в чужой канал что угодно.
    emoji      TEXT NOT NULL
        CHECK (emoji IN ('👍', '❤️', '🔥', '😂', '😮', '😢', '👏', '🎉')),
    PRIMARY KEY (channel_id, seq, account_id),
    FOREIGN KEY (channel_id, seq)
        REFERENCES channel_posts(channel_id, seq) ON DELETE CASCADE,
    FOREIGN KEY (channel_id, account_id)
        REFERENCES channel_subscribers(channel_id, account_id) ON DELETE CASCADE
);

-- Отписка снимает реакции подписчика: ищутся по нему.
CREATE INDEX channel_reactions_by_account ON channel_reactions (channel_id, account_id);

-- Счётчики реакций записи — готовыми числами (не больше восьми строк
-- на запись), по той же причине, что подписчики и просмотры.
CREATE TABLE channel_reaction_counts (
    channel_id UUID NOT NULL,
    seq        BIGINT NOT NULL,
    emoji      TEXT NOT NULL
        CHECK (emoji IN ('👍', '❤️', '🔥', '😂', '😮', '😢', '👏', '🎉')),
    n          BIGINT NOT NULL DEFAULT 0 CHECK (n >= 0),
    PRIMARY KEY (channel_id, seq, emoji),
    FOREIGN KEY (channel_id, seq)
        REFERENCES channel_posts(channel_id, seq) ON DELETE CASCADE
);

-- Счётчики уменьшаются триггерами, а не кодом сервера.
--
-- Подписка и реакция исчезают разными путями: отпиской, снятием
-- реакции, удалением записи, канала и — каскадом — удалением аккаунта
-- (самим человеком, оператором, по неактивности). Уменьшать счётчик
-- в каждом из них вручную значило бы однажды забыть один: готовое
-- число разошлось бы с таблицей и осталось завышенным навсегда.
CREATE OR REPLACE FUNCTION channel_subscriber_gone() RETURNS trigger AS $$
BEGIN
    UPDATE channels SET subscribers = GREATEST(subscribers - 1, 0)
     WHERE channel_id = OLD.channel_id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER channel_subscriber_gone
    AFTER DELETE ON channel_subscribers
    FOR EACH ROW EXECUTE FUNCTION channel_subscriber_gone();

CREATE OR REPLACE FUNCTION channel_reaction_gone() RETURNS trigger AS $$
BEGIN
    UPDATE channel_reaction_counts SET n = GREATEST(n - 1, 0)
     WHERE channel_id = OLD.channel_id AND seq = OLD.seq AND emoji = OLD.emoji;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER channel_reaction_gone
    AFTER DELETE ON channel_reactions
    FOR EACH ROW EXECUTE FUNCTION channel_reaction_gone();
