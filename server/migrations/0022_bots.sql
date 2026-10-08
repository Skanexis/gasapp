-- SPDX-License-Identifier: AGPL-3.0-only
--
-- 0022: боты — аккаунты, которые ведёт программа владельца.
--
-- # Как это устроено
--
-- Бот — обычный аккаунт со своими ключами: ему пишут, он отвечает, его
-- назначают администратором канала. Отличий два: его заводит другой
-- аккаунт (владелец, с премиумом), и у него нет адреса почты.
--
-- Владелец просит у сервера **одноразовый токен** под выбранное имя.
-- Токен он отдаёт программе бота, и та регистрируется сама: ключи бота
-- рождаются там, где бот работает, и ни сервер, ни приложение владельца
-- их не видят.
--
-- Сервер за бота ничего не делает. Всё, что бот умеет, делает его
-- программа — теми же запросами, что и приложение.
--
-- # 🔐 Что сервер узнаёт
--
-- * Чей это бот: связь «бот → владелец» хранится, пока жив бот. Без неё
--   владельцу нечем было бы бота удалить, а пределу числа ботов — не на
--   что опереться.
-- * Токен хранится хешем и живёт час: по дампу базы бота не завести.
--
-- # ⚠️ Чего это НЕ даёт
--
-- * Имя на `bot` говорит только «этот аккаунт заведён как бот». Что
--   делает его программа и кто её написал, сервер не знает.
-- * Бот-администратор закрытого канала знает ключ чтения канала, как
--   любой администратор: его программа и машина, где она работает,
--   становятся частью того, чему доверяет канал.

-- Токены, по которым ещё не зарегистрировались.
CREATE TABLE bot_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    owner_id   UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    username   TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX bot_tokens_by_owner ON bot_tokens (owner_id);

-- Боты и их владельцы.
CREATE TABLE bots (
    account_id UUID PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    owner_id   UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now())
);

CREATE INDEX bots_by_owner ON bots (owner_id);

-- Удалён владелец — удалены и его боты: аккаунт без хозяина никому не
-- подотчётен. Срабатывает до удаления, пока связь ещё на месте.
CREATE OR REPLACE FUNCTION bots_follow_owner() RETURNS trigger AS $$
BEGIN
    DELETE FROM accounts
     WHERE account_id IN (SELECT account_id FROM bots WHERE owner_id = OLD.account_id);

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER bots_follow_owner
    BEFORE DELETE ON accounts
    FOR EACH ROW EXECUTE FUNCTION bots_follow_owner();
